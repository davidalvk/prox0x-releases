"""Servidor HTTP/2 del Proxy MITM (Plan.md §3.4.3).

Cada stream entrante se convierte en una ``Request`` independiente, se ejecuta
en su propia tarea (multiplexación real) y su respuesta se traduce de vuelta a
HTTP/2. El control de flujo se respeta con una ``Condition`` compartida: si la
ventana de un stream se llena, se espera a ``WindowUpdated`` sin bloquear el
resto de streams.
"""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

import h2.events
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.exceptions import H2Error as LibraryH2Error

from core.logging import get_logger
from core.model import Header, HttpService, Request, Response
from core.net.http2 import h2_response_headers, request_from_h2

from .errors import RequestDropped
from .upstream import UpstreamError

_log = get_logger("prox0x.proxy.h2")

MAX_BODY_BYTES = 32 * 1024 * 1024

Handler = Callable[[Request], Awaitable[Response]]


def error_response(status: int, message: str) -> Response:
    """Respuesta sintética para errores de upstream/parseo."""
    body = message.encode("utf-8") + b"\n"
    headers = (
        Header("Content-Type", "text/plain; charset=utf-8"),
        Header("Content-Length", str(len(body))),
    )
    start = f"HTTP/2 {status} \r\n".encode("ascii")
    head = start + b"".join(header.to_bytes() for header in headers) + b"\r\n"
    return Response(
        raw=head + body,
        headers=headers,
        body=body,
        body_offset=len(head),
        version="HTTP/2",
        status_code=status,
        reason="",
    )


@dataclass(slots=True)
class _Inbound:
    headers: list[tuple[bytes, bytes]]
    body: bytearray = field(default_factory=bytearray)
    task: asyncio.Task[None] | None = None


class H2ProxySession:
    """Una conexión HTTP/2 cliente→proxy con N streams concurrentes."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        service: HttpService,
        handler: Handler,
        log,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._service = service
        self._handler = handler
        self._log = log
        self._conn = H2Connection(
            config=H2Configuration(client_side=False, header_encoding=None)
        )
        self._lock = asyncio.Condition()
        self._inbound: dict[int, _Inbound] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self._stream_tasks: dict[int, asyncio.Task[None]] = {}
        self._closed = False

    async def run(self) -> None:
        self._conn.initiate_connection()
        try:
            self._writer.write(self._conn.data_to_send())
            await self._writer.drain()
        except (OSError, ssl.SSLError) as exc:
            self._log.warning("h2_preface_failed", error=str(exc))
            return

        reason = "conexión HTTP/2 cerrada"
        try:
            while not self._closed:
                data = await self._reader.read(65_536)
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
                            # Un evento no crítico (p. ej. un PING con una API
                            # inesperada) no debe tumbar toda la sesión h2.
                            self._log.exception(
                                "h2_server_event_error",
                                event=type(event).__name__,
                            )
                    await self._flush_locked()
                    self._lock.notify_all()
        except asyncio.CancelledError:
            raise
        except (OSError, ssl.SSLError) as exc:
            reason = f"fallo de transporte HTTP/2: {exc}"
        finally:
            self._closed = True
            async with self._lock:
                for state in self._inbound.values():
                    if state.task is not None:
                        state.task.cancel()
                self._inbound.clear()
                self._lock.notify_all()
            for task in list(self._tasks):
                task.cancel()
            for task in list(self._stream_tasks.values()):
                task.cancel()
            self._stream_tasks.clear()
            if self._tasks:
                await asyncio.gather(*self._tasks, return_exceptions=True)
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass
            self._log.info("h2_session_closed", reason=reason)

    # ------------------------------------------------------------------ eventos

    def _handle_event(self, event: h2.events.Event) -> None:
        if isinstance(event, h2.events.RequestReceived):
            self._inbound[event.stream_id] = _Inbound(headers=list(event.headers))
        elif isinstance(event, h2.events.DataReceived):
            state = self._inbound.get(event.stream_id)
            if state is not None:
                if len(state.body) + len(event.data) > MAX_BODY_BYTES:
                    self._inbound.pop(event.stream_id, None)
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
            state = self._inbound.pop(event.stream_id, None)
            if state is not None:
                self._start_stream(event.stream_id, state)
        elif isinstance(event, h2.events.StreamReset):
            self._inbound.pop(event.stream_id, None)
            task = self._stream_tasks.get(event.stream_id)
            if task is not None:
                task.cancel()
        elif isinstance(event, h2.events.ConnectionTerminated):
            self._closed = True
        elif isinstance(event, h2.events.PingReceived):
            # h2 encola automáticamente el ACK del PING en data_to_send();
            # _flush_locked() lo envía. No llamar a ping_ack/acknowledge_ping
            # (no existen en h2 4.4.x y matarían la sesión).
            self._log.debug("h2_server_ping_received", data=event.ping_data.hex())
        elif isinstance(event, h2.events.PingAckReceived):
            self._log.debug(
                "h2_server_ping_ack_received", data=event.ping_data.hex()
            )

    def _start_stream(self, stream_id: int, state: _Inbound) -> None:
        task = asyncio.create_task(
            self._handle_stream(stream_id, state.headers, bytes(state.body)),
            name=f"prox0x-h2-stream-{stream_id}",
        )
        state.task = task
        self._tasks.add(task)
        self._stream_tasks[stream_id] = task

        def _done(_task: asyncio.Task[None]) -> None:
            self._stream_tasks.pop(stream_id, None)

        task.add_done_callback(self._tasks.discard)
        task.add_done_callback(_done)

    async def _handle_stream(
        self, stream_id: int, headers: list[tuple[bytes, bytes]], body: bytes
    ) -> None:
        method = _pseudo(headers, b":method") or b"GET"
        try:
            request = request_from_h2(headers, body, self._service)
            response = await self._handler(request)
        except RequestDropped:
            await self._reset_stream(stream_id)
            return
        except UpstreamError as exc:
            self._log.warning("h2_upstream_failed", error=str(exc))
            response = error_response(502, f"Bad Gateway: {exc}")
        except asyncio.CancelledError:
            raise
        except Exception:
            self._log.exception("h2_stream_error")
            response = error_response(502, "Bad Gateway")

        try:
            await self._send_response(
                stream_id, response, request_method=method.decode("latin-1")
            )
        except asyncio.CancelledError:
            raise
        except (LibraryH2Error, OSError, ssl.SSLError) as exc:
            self._log.warning("h2_send_failed", stream=stream_id, error=str(exc))

    # ------------------------------------------------------------------ envío

    async def _send_response(
        self, stream_id: int, response: Response, *, request_method: str
    ) -> None:
        headers, bodyless = h2_response_headers(
            response, request_method=request_method
        )
        body = b"" if bodyless else response.body

        async with self._lock:
            if self._closed:
                return
            self._conn.send_headers(
                stream_id, headers, end_stream=not body
            )
            await self._flush_locked()

        offset = 0
        while offset < len(body):
            async with self._lock:
                while True:
                    if self._closed:
                        return
                    window = self._conn.local_flow_control_window(stream_id)
                    if window > 0:
                        break
                    await self._lock.wait()
                chunk_size = min(window, self._conn.max_outbound_frame_size)
                chunk = body[offset : offset + chunk_size]
                end_stream = offset + len(chunk) >= len(body)
                self._conn.send_data(stream_id, chunk, end_stream=end_stream)
                await self._flush_locked()
                offset += len(chunk)

    async def _reset_stream(self, stream_id: int) -> None:
        async with self._lock:
            if self._closed:
                return
            try:
                self._conn.reset_stream(stream_id)
                await self._flush_locked()
            except LibraryH2Error:
                pass

    async def _flush_locked(self) -> None:
        payload = self._conn.data_to_send()
        if payload:
            self._writer.write(payload)
            await self._writer.drain()


def _pseudo(headers: list[tuple[bytes, bytes]], name: bytes) -> bytes | None:
    for header_name, value in headers:
        if header_name.lower() == name:
            return value
    return None
