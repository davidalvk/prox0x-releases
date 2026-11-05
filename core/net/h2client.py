"""Cliente HTTP/2 multiplexado sobre ``h2`` (Plan.md §3.4.3).

Una conexión puede tener N streams en vuelo: el lector de fondo despacha los
eventos de ``h2`` a una cola por stream y los envíos concurrentes comparten la
misma conexión (pool). El control de flujo se respeta con una ``Condition``:
si la ventana está llena se espera a ``WindowUpdated`` sin bloquear el lector.
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

import h2.events
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.exceptions import H2Error as LibraryH2Error

from core.logging import get_logger
from core.model import HttpService, Response, Timing
from core.net.http2 import h2_request_headers, response_from_h2
from core.net.tls import client_context

_READ_SIZE = 65_536
MAX_BODY_BYTES = 32 * 1024 * 1024
_log = get_logger("prox0x.net.h2client")


class H2Error(Exception):
    """Error base del cliente HTTP/2."""


class H2TransportError(H2Error):
    """Fallo de socket/TLS."""


class H2Timeout(H2TransportError):
    """El origen no respondió a tiempo."""


class H2ProtocolError(H2Error):
    """El peer violó HTTP/2 o cerró el stream."""


class AlpnMismatch(H2Error):
    """El origen no negoció ``h2`` por ALPN."""


@dataclass(frozen=True, slots=True)
class H2Result:
    response: Response
    peer_ip: str
    complete: bool
    timing: Timing


@dataclass(slots=True)
class _Stream:
    headers: list[tuple[bytes, bytes]] | None = None
    body: bytearray = field(default_factory=bytearray)
    done: asyncio.Event = field(default_factory=asyncio.Event)
    error: str | None = None
    first_byte_at: datetime | None = None
    completed_at: datetime | None = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


class H2Client:
    """Conexión HTTP/2 cliente con streams concurrentes."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        service: HttpService,
        selected_alpn: str | None,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self.service = service
        self.selected_alpn = selected_alpn
        self.peer_ip = ""
        peer = writer.get_extra_info("peername")
        if peer:
            self.peer_ip = peer[0]

        self._conn = H2Connection(
            config=H2Configuration(client_side=True, header_encoding=None)
        )
        self._lock = asyncio.Condition()
        self._streams: dict[int, _Stream] = {}
        self._closed = False
        self._reader_task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------ ciclo

    @classmethod
    async def connect(
        cls,
        service: HttpService,
        *,
        verify: bool,
        timeout_s: float,
        alpn: tuple[str, ...] = ("h2", "http/1.1"),
        require_h2: bool = True,
    ) -> "H2Client":
        context = client_context(service, verify, alpn)
        try:
            async with asyncio.timeout(timeout_s):
                reader, writer = await asyncio.open_connection(
                    service.host,
                    service.port,
                    ssl=context,
                    server_hostname=service.effective_sni if context else None,
                )
        except TimeoutError as exc:
            raise H2Timeout(f"timeout conectando a {service}") from exc
        except (OSError, ssl.SSLError) as exc:
            raise H2TransportError(f"no se pudo conectar a {service}: {exc}") from exc

        ssl_object = writer.get_extra_info("ssl_object")
        selected = ssl_object.selected_alpn_protocol() if ssl_object else None
        if require_h2 and selected != "h2":
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass
            raise AlpnMismatch(
                f"el origen {service} no negocia h2 (ALPN={selected!r})"
            )

        client = cls(reader, writer, service=service, selected_alpn=selected)
        await client._start()
        return client

    @property
    def closed(self) -> bool:
        return self._closed

    async def _start(self) -> None:
        self._conn.initiate_connection()
        self._writer.write(self._conn.data_to_send())
        await self._writer.drain()
        self._reader_task = asyncio.create_task(
            self._reader_loop(), name=f"prox0x-h2-{self.service.authority}"
        )

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            async with self._lock:
                try:
                    self._conn.close_connection()
                    payload = self._conn.data_to_send()
                    if payload:
                        self._writer.write(payload)
                        await self._writer.drain()
                except (LibraryH2Error, OSError, ssl.SSLError):
                    pass
                self._fail_all("conexión HTTP/2 cerrada")
                self._lock.notify_all()
        finally:
            if self._reader_task is not None and self._reader_task is not asyncio.current_task():
                self._reader_task.cancel()
                try:
                    await self._reader_task
                except (asyncio.CancelledError, H2Error):
                    pass
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass

    # ------------------------------------------------------------------ envío

    async def request(self, request, options) -> H2Result:
        if self._closed:
            raise H2TransportError("la conexión HTTP/2 está cerrada")

        body = request.body
        try:
            headers = h2_request_headers(request, self.service)
        except (UnicodeError, ValueError) as exc:
            raise H2ProtocolError(f"cabeceras HTTP/2 inválidas: {exc}") from exc

        state = _Stream()
        async with self._lock:
            if self._closed:
                raise H2TransportError("la conexión HTTP/2 está cerrada")
            stream_id = self._conn.get_next_available_stream_id()
            self._streams[stream_id] = state
            try:
                self._conn.send_headers(stream_id, headers, end_stream=not body)
            except LibraryH2Error as exc:
                self._streams.pop(stream_id, None)
                raise H2ProtocolError(f"no se pudo abrir el stream: {exc}") from exc
            await self._flush_locked()

        offset = 0
        try:
            while offset < len(body):
                async with self._lock:
                    while True:
                        if state.error is not None:
                            raise H2ProtocolError(state.error)
                        if self._closed:
                            raise H2TransportError("la conexión HTTP/2 se cerró")
                        window = self._conn.local_flow_control_window(stream_id)
                        if window > 0:
                            break
                        await self._lock.wait()
                    chunk_size = min(window, self._conn.max_outbound_frame_size)
                    chunk = body[offset : offset + chunk_size]
                    end_stream = offset + len(chunk) >= len(body)
                    try:
                        self._conn.send_data(stream_id, chunk, end_stream=end_stream)
                    except LibraryH2Error as exc:
                        raise H2ProtocolError(f"error enviando datos: {exc}") from exc
                    await self._flush_locked()
                    offset += len(chunk)

            sent_at = _now()
            try:
                async with asyncio.timeout(options.timeout_s):
                    await state.done.wait()
            except TimeoutError as exc:
                async with self._lock:
                    try:
                        self._conn.reset_stream(stream_id)
                    except LibraryH2Error:
                        pass
                    await self._flush_locked()
                raise H2Timeout(
                    f"timeout esperando respuesta de {self.service}"
                ) from exc
        finally:
            async with self._lock:
                self._streams.pop(stream_id, None)

        if state.error is not None:
            raise H2ProtocolError(state.error)
        if state.headers is None:
            raise H2ProtocolError("el stream terminó sin cabeceras de respuesta")

        response = response_from_h2(state.headers, bytes(state.body))
        timing = Timing(
            sent_at=sent_at,
            first_byte_at=state.first_byte_at,
            completed_at=state.completed_at or _now(),
        )
        return H2Result(
            response=response,
            peer_ip=self.peer_ip,
            complete=state.completed_at is not None,
            timing=timing,
        )

    # ---------------------------------------------------------------- interno

    async def _flush_locked(self) -> None:
        """Escribe lo que h2 tenga pendiente. Debe llamarse con ``_lock`` tomado."""
        payload = self._conn.data_to_send()
        if not payload:
            return
        try:
            self._writer.write(payload)
            await self._writer.drain()
        except (OSError, ssl.SSLError) as exc:
            self._closed = True
            self._fail_all(f"fallo de transporte HTTP/2: {exc}")
            self._lock.notify_all()
            raise H2TransportError(str(exc)) from exc

    async def _reader_loop(self) -> None:
        reason = "conexión HTTP/2 cerrada por el peer"
        try:
            while not self._closed:
                data = await self._reader.read(_READ_SIZE)
                if not data:
                    break
                async with self._lock:
                    try:
                        events = self._conn.receive_data(data)
                    except LibraryH2Error as exc:
                        reason = f"error de protocolo HTTP/2: {exc}"
                        break
                    for event in events:
                        try:
                            self._handle_event(event)
                        except Exception:
                            # Un evento raro no debe tumbar toda la conexión ni
                            # el bucle de escucha: se registra y se continúa.
                            _log.exception(
                                "h2_event_error", event=type(event).__name__
                            )
                    try:
                        await self._flush_locked()
                    except H2TransportError:
                        raise
                    except Exception:
                        _log.exception("h2_flush_error")
                    self._lock.notify_all()
                if self._closed:
                    break
        except asyncio.CancelledError:
            return
        except (OSError, ssl.SSLError) as exc:
            reason = f"fallo de transporte HTTP/2: {exc}"
        finally:
            if not self._closed:
                self._closed = True
                async with self._lock:
                    self._fail_all(reason)
                    self._lock.notify_all()

    def _handle_event(self, event: h2.events.Event) -> None:
        if isinstance(event, h2.events.ResponseReceived):
            state = self._streams.get(event.stream_id)
            if state is not None:
                state.headers = list(event.headers)
                state.first_byte_at = _now()
        elif isinstance(event, h2.events.DataReceived):
            state = self._streams.get(event.stream_id)
            if state is not None:
                if state.first_byte_at is None:
                    state.first_byte_at = _now()
                if len(state.body) + len(event.data) > MAX_BODY_BYTES:
                    state.error = (
                        f"cuerpo de respuesta excede el límite de {MAX_BODY_BYTES} bytes"
                    )
                    state.done.set()
                    try:
                        self._conn.reset_stream(event.stream_id)
                    except LibraryH2Error:
                        pass
                    return
                state.body += event.data
            try:
                self._conn.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
            except LibraryH2Error:
                pass
        elif isinstance(event, h2.events.StreamEnded):
            state = self._streams.get(event.stream_id)
            if state is not None:
                state.completed_at = _now()
                state.done.set()
        elif isinstance(event, h2.events.StreamReset):
            state = self._streams.get(event.stream_id)
            if state is not None:
                state.error = f"stream cancelado por el origen (error={event.error_code})"
                state.done.set()
        elif isinstance(event, h2.events.ConnectionTerminated):
            self._closed = True
            self._fail_all(
                f"conexión HTTP/2 terminada (error={event.error_code})"
            )
        elif isinstance(event, h2.events.PingReceived):
            # h2 ya encola automáticamente el ACK del PING en data_to_send();
            # _flush_locked() lo envía. No existe ping_ack/acknowledge_ping en
            # esta versión de la librería, así que no se llama a nada aquí.
            _log.debug("h2_ping_received", data=event.ping_data.hex())
        elif isinstance(event, h2.events.PingAckReceived):
            _log.debug("h2_ping_ack_received", data=event.ping_data.hex())

    def _fail_all(self, reason: str) -> None:
        for state in self._streams.values():
            if not state.done.is_set():
                state.error = reason
                state.done.set()


class H2Pool:
    """Pool de conexiones HTTP/2 reutilizables y multiplexadas por destino."""

    def __init__(self) -> None:
        self._clients: dict[tuple, H2Client] = {}
        self._no_h2: set[tuple] = set()
        self._lock = asyncio.Lock()

    async def get(
        self,
        service: HttpService,
        *,
        verify: bool,
        timeout_s: float,
        alpn: tuple[str, ...] = ("h2", "http/1.1"),
        require_h2: bool = True,
    ) -> H2Client:
        key = (service.host, service.port, service.secure, service.sni, verify)
        async with self._lock:
            if require_h2 and key in self._no_h2:
                raise AlpnMismatch(f"el origen {service} no soporta HTTP/2 (caché)")
            client = self._clients.get(key)
            if client is not None and not client.closed:
                return client
            try:
                client = await H2Client.connect(
                    service,
                    verify=verify,
                    timeout_s=timeout_s,
                    alpn=alpn,
                    require_h2=require_h2,
                )
            except AlpnMismatch:
                if require_h2:
                    self._no_h2.add(key)
                raise
            self._clients[key] = client
            return client

    async def aclose(self) -> None:
        async with self._lock:
            clients = list(self._clients.values())
            self._clients.clear()
        for client in clients:
            await client.aclose()
