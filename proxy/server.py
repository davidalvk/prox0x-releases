"""Servidor proxy HTTP/1.1 de prox0x: listener, CONNECT, MITM TLS e historial.

Ciclo de vida de una conexión (Plan.md §3.2):

1. Se acepta la conexión y se parsea la petición con h11 (estricto).
2. Si el método es ``CONNECT``, se responde `200 Connection Established` y se
   hace el upgrade TLS con el certificado hoja del host (MITM); a partir de
   ahí, cada petición dentro del túnel recorre el mismo pipeline.
3. Los 4 puntos de intercepción ven el mensaje; por ahora solo registran.
4. La petición se reenvía al origen y la respuesta vuelve al cliente.
5. El par completo se guarda como ``Flow`` en el buffer circular.

ALPN: F1 ofrece **solo** ``http/1.1`` para que la negociación siempre termine
en un protocolo que sabemos parsear; F4 añadirá ``h2`` con su máquina de
estados y degradación a 1.1. El ALPN negociado queda registrado en cada
intercepción.
"""

from __future__ import annotations

import asyncio
from collections import deque
import ssl
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

import h11

from core.ca import CertificateAuthority
from core.logging import get_logger
from core.model import (
    Flow,
    HttpService,
    MimeType,
    Request,
    Response,
    Timing,
    WebSocketDirection,
    WebSocketFrame,
)
from core.net.h2client import H2Pool
from core.match_replace import MatchReplace, MatchReplaceError
from core.scanner import scan_flow_async
from core.scope import Scope, ScopeError
from core.store import FlowCapture, FlowStore, SQLiteFlowStore
from . import h11io, websocket
from .control import ControlServer
from .errors import RequestDropped
from .h2server import H2ProxySession
from .h11io import IncompleteMessage
from .intercept import (
    BreakpointManager,
    InterceptionAction,
    InterceptionContext,
    InterceptionPoint,
    InteractiveInterceptor,
    Interceptor,
    LoggingInterceptor,
)
from .upstream import UpstreamError, send_request

# Protocolos que el proxy sabe parsear (F4: h2 + degradación a 1.1).
ALPN_OFFERED: tuple[str, ...] = ("h2", "http/1.1")

_CONNECT_ESTABLISHED = b"HTTP/1.1 200 Connection Established\r\n\r\n"
_CONTINUE = b"HTTP/1.1 100 Continue\r\n\r\n"
_MAX_WEBSOCKET_FRAMES = 1_000

_log = get_logger("prox0x.proxy")


@dataclass(frozen=True, slots=True)
class ProxyConfig:
    """Ajustes del listener y del reenvío."""

    host: str = "127.0.0.1"
    port: int = 8080
    verify_upstream: bool = True
    upstream_timeout: float = 60.0
    alpn: tuple[str, ...] = ALPN_OFFERED
    flow_buffer: int = 5_000
    flows_file: Path | None = None  # JSONL para `prox0x flows` (None = sin volcado)
    db_file: Path | None = None  # SQLite WAL para la API (None = sin persistencia)
    control_socket: Path | None = None  # socket Unix de breakpoints
    embedded_control: bool = False  # control in-process (binario único)
    breakpoint_timeout: float = 300.0
    scope_file: Path | None = None  # JSON con reglas de inclusión/exclusión
    match_replace_file: Path | None = None  # JSON con reglas Match & Replace


class ProxyServer:
    """Proxy interceptador HTTP/1.1 + CONNECT/MITM sobre asyncio."""

    def __init__(
        self,
        ca: CertificateAuthority,
        store: FlowStore,
        *,
        config: ProxyConfig | None = None,
        interceptor: Interceptor | None = None,
    ) -> None:
        self._ca = ca
        self._store = store
        self._config = config or ProxyConfig()
        self._log = _log
        self._scope = Scope()
        if self._config.scope_file is not None:
            try:
                self._scope = Scope.from_file(self._config.scope_file)
            except ScopeError:
                self._log.exception(
                    "scope_load_failed", path=str(self._config.scope_file)
                )
        self._match_replace = MatchReplace()
        if self._config.match_replace_file is not None:
            try:
                self._match_replace = MatchReplace.from_file(
                    self._config.match_replace_file
                )
            except MatchReplaceError:
                self._log.exception(
                    "match_replace_load_failed",
                    path=str(self._config.match_replace_file),
                )
        self._breakpoints: BreakpointManager | None = None
        self._control: ControlServer | None = None
        if interceptor is None and (
            self._config.control_socket is not None or self._config.embedded_control
        ):
            self._breakpoints = BreakpointManager(
                timeout=self._config.breakpoint_timeout
            )
            self._interceptor: Interceptor = InteractiveInterceptor(
                self._breakpoints,
                scope=self._scope,
            )
            if (
                self._config.control_socket is not None
                and not self._config.embedded_control
            ):
                self._control = ControlServer(
                    self._breakpoints,
                    self._config.control_socket,
                    scope=self._scope,
                    match_replace=self._match_replace,
                    on_project_load=self._handle_project_load,
                    on_scope_change=self._handle_scope_change,
                )
        else:
            self._interceptor = interceptor or LoggingInterceptor()
        self._server: asyncio.Server | None = None
        self._h2_pool = H2Pool()
        self._scope_update_lock = asyncio.Lock()
        self._sqlite: SQLiteFlowStore | None = None
        self._scan_tasks: set[asyncio.Task[None]] = set()
        if self._config.db_file is not None:
            try:
                self._sqlite = SQLiteFlowStore(self._config.db_file)
                self._store.ensure_next_id(self._sqlite.max_id())
            except Exception:
                self._log.exception(
                    "sqlite_open_failed", path=str(self._config.db_file)
                )
                self._sqlite = None
        self._capture = (
            FlowCapture(self._config.flows_file) if self._config.flows_file else None
        )

    def _apply_match_replace(
        self, point: InterceptionPoint, message: Message
    ) -> tuple[Message, bool]:
        """Aplica Match & Replace tras la edición manual, antes de la red.

        Devuelve el mensaje resultante y si alguna regla lo modificó. El motor
        devuelve el mismo objeto cuando no hay cambios, así que la identidad es
        una señal fiable incluso si varias reglas se aplican en cadena.
        """
        should_apply = (
            point is InterceptionPoint.REQUEST_TO_BE_SENT
            and isinstance(message, Request)
        ) or (
            point is InterceptionPoint.RESPONSE_TO_BE_SENT
            and isinstance(message, Response)
        )
        if not should_apply:
            return message, False
        try:
            applied = self._match_replace.apply(message)
        except MatchReplaceError:
            self._log.exception(
                "match_replace_failed", point=point.value
            )
            return message, False
        return applied, applied is not message

    def _record(self, flow: Flow) -> Flow:
        """Guarda el flujo en el store y (si está activo) lo vuelca a JSONL/SQLite.

        El volcado es solo diagnóstico: un fallo de disco se loguea y nunca
        interrumpe el camino de red (Plan.md §7.5.6).
        """
        if isinstance(flow.request, Request):
            in_scope = self._scope.matches(flow.service, flow.request.target)
            if flow.in_scope != in_scope:
                flow = replace(flow, in_scope=in_scope)
        self._store.add(flow)
        if self._capture is not None:
            try:
                self._capture.append(flow)
            except Exception:
                # Un fallo del JSONL no debe impedir la persistencia SQLite/API.
                self._log.error(
                    "flows_capture_failed",
                    path=str(self._capture.path),
                    flow_id=flow.id,
                    exc_info=True,
                )
        self._persist(flow)
        self._schedule_scan(flow)
        return flow

    def _persist(self, flow: Flow) -> None:
        if self._sqlite is None:
            return
        request = flow.request if isinstance(flow.request, Request) else None
        response = flow.response if isinstance(flow.response, Response) else None
        size = (
            len(response.body)
            if response is not None
            else (len(request.body) if request is not None else 0)
        )
        self._log.info(
            "[DEBUG] Guardando flujo",
            flow_id=flow.id,
            mime=flow.mime.value,
            size=size,
        )
        try:
            self._sqlite.save(flow)
        except Exception:
            self._log.error(
                "sqlite_save_failed",
                flow_id=flow.id,
                mime=flow.mime.value,
                method=request.method if request is not None else None,
                target=request.target if request is not None else None,
                status=response.status_code if response is not None else None,
                size=size,
                exc_info=True,
            )

    def _schedule_scan(self, flow: Flow) -> None:
        if self._sqlite is None:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        task = loop.create_task(self._scan_flow(flow))
        self._scan_tasks.add(task)
        task.add_done_callback(self._scan_tasks.discard)

    async def _scan_flow(self, flow: Flow) -> None:
        try:
            findings = await scan_flow_async(flow)
            if not findings or self._sqlite is None:
                return
            inserted = await asyncio.to_thread(
                self._sqlite.add_findings, findings
            )
            if inserted:
                self._log.info(
                    "findings_detected",
                    flow_id=flow.id,
                    count=len(inserted),
                )
        except Exception:
            self._log.error(
                "finding_scan_failed", flow_id=flow.id, exc_info=True
            )

    def _record_dropped(
        self,
        *,
        flow_id: int,
        request: Request,
        final_request: Request,
        service: HttpService,
        listener_port: int,
        source_ip: str,
        timing: Timing,
        reason: str,
        response: Response | None = None,
        original_response: Response | None = None,
        dest_ip: str = "",
        modified_by_rule: bool = False,
    ) -> Flow:
        timing = timing.with_completed()
        mime = (
            MimeType.from_content_type(response.header("Content-Type"))
            if response is not None
            else MimeType.NONE
        )
        return self._record(
            Flow(
                id=flow_id,
                service=service,
                listener_port=listener_port,
                received_at=timing.sent_at,
                request=request,
                final_request=final_request,
                response=response,
                original_response=original_response,
                edited=final_request is not request,
                modified_by_rule=modified_by_rule,
                dropped=True,
                drop_reason=reason,
                mime=mime,
                timing=timing,
                source_ip=source_ip,
                dest_ip=dest_ip,
            )
        )

    # ------------------------------------------------------------------ ciclo

    @property
    def port(self) -> int:
        """Puerto realmente escuchado (útil con ``port=0`` en tests)."""
        if self._server is None or not self._server.sockets:
            raise RuntimeError("el servidor no está arrancado")
        return self._server.sockets[0].getsockname()[1]

    @property
    def store(self) -> FlowStore:
        return self._store

    @property
    def breakpoints(self) -> BreakpointManager | None:
        return self._breakpoints

    @property
    def scope(self) -> Scope:
        return self._scope

    @property
    def match_replace(self) -> MatchReplace:
        return self._match_replace

    @property
    def control_socket(self) -> Path | None:
        return self._control.path if self._control is not None else None

    def switch_project(
        self,
        *,
        db_file: Path,
        scope_file: Path,
        match_replace_file: Path,
        flows_file: Path | None = None,
        name: str = "",
    ) -> dict[str, object]:
        """Cambia en caliente la base SQLite, Scope, Match & Replace y captura JSONL."""
        if self._breakpoints is not None:
            cancelled = self._breakpoints.cancel_all(
                reason="project_switch",
                cancel_waiters=True,
            )
            self._log.info(
                "breakpoints_cleared",
                count=cancelled,
                reason="project_switch",
            )
        for task in list(self._scan_tasks):
            task.cancel()
        new_sqlite = SQLiteFlowStore(db_file)
        previous_sqlite = self._sqlite
        self._sqlite = new_sqlite
        if previous_sqlite is not None:
            try:
                previous_sqlite.close()
            except Exception:
                pass
        self._store.clear(last_used=new_sqlite.max_id())
        scope_state = self._scope.load_file(scope_file)
        rules_state = self._match_replace.load_file(match_replace_file)
        if flows_file is not None:
            self._capture = FlowCapture(flows_file)
        self._log.info(
            "project_switched",
            project=name,
            db_file=str(db_file),
            scope_file=str(scope_file),
            match_replace_file=str(match_replace_file),
        )
        return {
            "project": name,
            "scope": scope_state,
            "rules": rules_state,
        }

    def _handle_project_load(self, request: dict) -> dict[str, object]:
        db_raw = request.get("db_file")
        scope_raw = request.get("scope_file")
        mr_raw = request.get("match_replace_file")
        flows_raw = request.get("flows_file")
        name = str(request.get("name") or "")
        if not db_raw or not scope_raw or not mr_raw:
            raise ValueError(
                "project_load requiere db_file, scope_file y match_replace_file"
            )
        return self.switch_project(
            name=name,
            db_file=Path(str(db_raw)),
            scope_file=Path(str(scope_raw)),
            match_replace_file=Path(str(mr_raw)),
            flows_file=Path(str(flows_raw)) if flows_raw else None,
        )

    async def _handle_scope_change(self, scope: Scope) -> None:
        """Reevalúa los flujos persistidos sin bloquear el event loop del Proxy.

        El escaneo y las actualizaciones SQLite se ejecutan en un hilo aparte;
        el Proxy sigue aceptando y reenviando tráfico mientras dura.
        """
        store = self._sqlite
        if store is None:
            return
        try:
            async with self._scope_update_lock:
                updated = await asyncio.to_thread(
                    store.update_scope, scope.include, scope.exclude
                )
            self._log.info("scope_reevaluated", updated=updated)
        except Exception:
            self._log.exception("scope_reevaluate_failed")

    async def start(self) -> None:
        if self._control is not None:
            try:
                await self._control.start()
            except Exception:
                self._log.exception(
                    "control_socket_failed",
                    path=str(self._control.path),
                )
        self._server = await asyncio.start_server(
            self._handle_client, self._config.host, self._config.port
        )
        self._log.info(
            "proxy_listening",
            host=self._config.host,
            port=self.port,
            alpn=list(self._config.alpn),
            verify_upstream=self._config.verify_upstream,
            ca=str(self._ca.ca_dir),
            flows_file=str(self._capture.path) if self._capture else None,
        )

    async def serve(self) -> None:
        """Arranca (si hace falta) y sirve hasta cancelar la tarea."""
        if self._server is None:
            await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._control is not None:
            await self._control.stop()
        if self._breakpoints is not None:
            self._breakpoints.close()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            await self._h2_pool.aclose()
        if self._scan_tasks:
            for task in list(self._scan_tasks):
                task.cancel()
            await asyncio.gather(*self._scan_tasks, return_exceptions=True)
            self._scan_tasks.clear()
        if self._sqlite is not None:
            self._sqlite.close()
            self._sqlite = None
        self._log.info("proxy_stopped")

    # ------------------------------------------------------------- conexiones

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        source_ip = peer[0] if peer else ""
        listener_port = writer.get_extra_info("sockname")[1]
        log = self._log.bind(source=source_ip, listener=listener_port)
        conn = h11.Connection(h11.SERVER)
        try:
            while True:
                try:
                    event = await h11io.read_event(conn, reader)
                except h11.RemoteProtocolError as exc:
                    log.warning("protocol_error", error=str(exc))
                    break
                if event is None or isinstance(event, h11.ConnectionClosed):
                    break
                if not isinstance(event, h11.Request):
                    log.warning("unexpected_event", event=type(event).__name__)
                    break
                if event.method.upper() == b"CONNECT":
                    # El túnel MITM gestiona el resto de la conexión.
                    await self._handle_connect(
                        event, reader, writer, source_ip, listener_port, log
                    )
                    return
                keep_alive = await self._handle_request(
                    conn, event, reader, writer, None, source_ip, listener_port, log
                )
                if not keep_alive:
                    break
        except (ConnectionError, asyncio.IncompleteReadError, IncompleteMessage) as exc:
            log.info("connection_closed", reason=str(exc) or type(exc).__name__)
        except Exception:
            log.exception("connection_error")
        finally:
            await _close_writer(writer)

    async def _handle_connect(
        self,
        event: h11.Request,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        source_ip: str,
        listener_port: int,
        log: "structlog.stdlib.BoundLogger",  # noqa: F821 (solo anotación)
    ) -> None:
        """Túnel MITM: 200 + TLS servidor con el certificado hoja del host."""
        try:
            service = h11io.service_from_connect(event.target.decode("latin-1"))
        except ValueError as exc:
            log.warning("bad_connect_target", target=event.target, error=str(exc))
            await _close_writer(writer)
            return

        flow_id = self._store.next_id()
        log = log.bind(flow_id=flow_id)
        log.info("connect", target=service.authority, sni=service.effective_sni)

        writer.write(_CONNECT_ESTABLISHED)
        await writer.drain()

        try:
            context = self._ca.server_context(service.host, self._config.alpn)
        except Exception:
            log.exception("leaf_cert_error", host=service.host)
            await _close_writer(writer)
            return

        # No existe API pública en asyncio 3.14 para subir a TLS con rol servidor
        # sobre streams: se usa loop.start_tls(server_side=True) y se reengancha
        # el transport del writer (mismo mecanismo interno de StreamWriter.start_tls).
        loop = asyncio.get_running_loop()
        transport = writer.transport
        try:
            new_transport = await loop.start_tls(
                transport, transport.get_protocol(), context, server_side=True
            )
        except (OSError, ssl.SSLError) as exc:
            log.warning("tls_handshake_failed", host=service.host, error=str(exc))
            await _close_writer(writer)
            return
        writer._transport = new_transport  # noqa: SLF001 — sin alternativa pública

        ssl_object = new_transport.get_extra_info("ssl_object")
        client_alpn = ssl_object.selected_alpn_protocol() if ssl_object else None
        # El watchdog del sni_callback guardó el SNI real del cliente (ver core/ca).
        sni = getattr(ssl_object, "_prox0x_sni", None) if ssl_object else None
        log = log.bind(alpn=client_alpn, sni=sni)
        if client_alpn is not None and client_alpn not in self._config.alpn:
            log.warning("alpn_unsupported", negotiated=client_alpn)
            await _close_writer(writer)
            return

        if client_alpn == "h2":
            session = H2ProxySession(
                reader,
                writer,
                service=service,
                handler=lambda request: self._handle_h2_request(
                    request,
                    service,
                    source_ip,
                    listener_port,
                    client_alpn,
                    log,
                ),
                log=log,
            )
            await session.run()
            return

        tunnel = h11.Connection(h11.SERVER)
        try:
            while True:
                try:
                    inner = await h11io.read_event(tunnel, reader)
                except h11.RemoteProtocolError as exc:
                    log.warning("protocol_error", error=str(exc))
                    break
                if inner is None or isinstance(inner, h11.ConnectionClosed):
                    break
                if not isinstance(inner, h11.Request):
                    log.warning("unexpected_event", event=type(inner).__name__)
                    break
                keep_alive = await self._handle_request(
                    tunnel,
                    inner,
                    reader,
                    writer,
                    service,
                    source_ip,
                    listener_port,
                    log,
                    client_alpn=client_alpn,
                )
                if not keep_alive:
                    break
        except (ConnectionError, asyncio.IncompleteReadError, IncompleteMessage) as exc:
            log.info("tunnel_closed", reason=str(exc) or type(exc).__name__)
        except Exception:
            log.exception("tunnel_error")
        finally:
            await _close_writer(writer)

    # -------------------------------------------------------------- peticiones

    def _start_client_watch(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> tuple[asyncio.Event | None, asyncio.Task[None] | None]:
        if self._breakpoints is None:
            return None, None
        abort_event = asyncio.Event()
        task = asyncio.create_task(
            _watch_client(reader, writer, abort_event),
            name="prox0x-client-watch",
        )
        return abort_event, task

    async def _stop_client_watch(self, task: asyncio.Task[None] | None) -> None:
        if task is None:
            return
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def _handle_request(
        self,
        conn: h11.Connection,
        event: h11.Request,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        service: HttpService | None,
        source_ip: str,
        listener_port: int,
        log: "structlog.stdlib.BoundLogger",  # noqa: F821 (solo anotación)
        *,
        client_alpn: str | None = None,
    ) -> bool:
        """Pipeline HTTP/1.1 de una petición. Devuelve ``False`` si hay que cerrar."""
        flow_id = self._store.next_id()
        log = log.bind(flow_id=flow_id)

        # 100-continue: el cliente espera antes de mandar el cuerpo (§3.4.2).
        for name, value in event.headers:
            if name.lower() == b"expect" and b"100-continue" in value.lower():
                writer.write(_CONTINUE)
                await writer.drain()
                break

        try:
            body = await h11io.read_body(conn, reader)
        except IncompleteMessage:
            log.warning("incomplete_request")
            return False

        try:
            request_service = service or h11io.service_from_request(event)
        except ValueError as exc:
            log.warning("bad_request_target", target=event.target, error=str(exc))
            await _send_error(conn, writer, 400, f"Bad Request: {exc}")
            return False

        request = h11io.request_from_event(event, body)
        if websocket.is_upgrade(request):
            return await self._handle_websocket(
                conn,
                request,
                request_service,
                reader,
                writer,
                source_ip,
                listener_port,
                log,
                client_alpn=client_alpn,
            )
        abort_event, watcher = self._start_client_watch(reader, writer)
        try:
            try:
                response = await self._execute(
                    request,
                    request_service,
                    flow_id=flow_id,
                    source_ip=source_ip,
                    listener_port=listener_port,
                    client_alpn=client_alpn,
                    log=log,
                    abort_event=abort_event,
                )
            except RequestDropped:
                log.info("flow_dropped")
                return False
            except UpstreamError as exc:
                log.warning("upstream_failed", error=str(exc))
                await _send_error(conn, writer, 502, f"Bad Gateway: {exc}")
                return False
        finally:
            await self._stop_client_watch(watcher)
        return await _send_downstream(conn, writer, request, response, close=False)

    async def _handle_websocket(
        self,
        conn: h11.Connection,
        request: Request,
        request_service: HttpService,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        source_ip: str,
        listener_port: int,
        log: "structlog.stdlib.BoundLogger",  # noqa: F821
        *,
        client_alpn: str | None,
    ) -> bool:
        """Handshake WebSocket + relay opaco; devuelve ``False`` (no keep-alive)."""
        flow_id = self._store.next_id()
        log = log.bind(flow_id=flow_id)
        timing = Timing.start()
        abort_event, _client_watcher = self._start_client_watch(reader, writer)

        ctx = InterceptionContext(
            flow_id=flow_id,
            point=InterceptionPoint.REQUEST_RECEIVED,
            service=request_service,
            listener_port=listener_port,
            source_ip=source_ip,
            request_target=request.target,
            client_alpn=client_alpn,
            abort_event=abort_event,
        )
        result = await self._interceptor.on_message(ctx, request)
        if result.action is InterceptionAction.DROP:
            self._record_dropped(
                flow_id=flow_id,
                request=request,
                final_request=request,
                service=request_service,
                listener_port=listener_port,
                source_ip=source_ip,
                timing=timing,
                reason="websocket_request_received",
            )
            return False
        final_request = result.message if result.message is not None else request
        assert isinstance(final_request, Request)

        ctx = InterceptionContext(
            flow_id=flow_id,
            point=InterceptionPoint.REQUEST_TO_BE_SENT,
            service=request_service,
            listener_port=listener_port,
            source_ip=source_ip,
            request_target=final_request.target,
            client_alpn=client_alpn,
            abort_event=abort_event,
        )
        result = await self._interceptor.on_message(ctx, final_request)
        if result.action is InterceptionAction.DROP:
            self._record_dropped(
                flow_id=flow_id,
                request=request,
                final_request=final_request,
                service=request_service,
                listener_port=listener_port,
                source_ip=source_ip,
                timing=timing,
                reason="websocket_request_to_be_sent",
            )
            return False
        if result.message is not None:
            final_request = result.message
            assert isinstance(final_request, Request)
        final_request, request_modified = self._apply_match_replace(
            ctx.point, final_request
        )
        assert isinstance(final_request, Request)
        request_edited = final_request is not request

        try:
            handshake = await websocket.open_upstream(
                final_request,
                request_service,
                verify=self._config.verify_upstream,
                timeout=self._config.upstream_timeout,
            )
        except websocket.WebSocketError as exc:
            log.warning("websocket_handshake_failed", error=str(exc))
            await _send_error(conn, writer, 502, f"Bad Gateway: {exc}")
            return False

        original_response = handshake.response
        if original_response.status_code != 101:
            handshake.writer.close()
            try:
                await handshake.writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass
            log.warning(
                "websocket_upgrade_rejected",
                status=original_response.status_code,
            )
            await _send_error(
                conn, writer, 502, "Bad Gateway: el origen rechazó el upgrade"
            )
            return False

        timing = timing.with_first_byte()

        ctx = InterceptionContext(
            flow_id=flow_id,
            point=InterceptionPoint.RESPONSE_RECEIVED,
            service=request_service,
            listener_port=listener_port,
            source_ip=source_ip,
            request_target=final_request.target,
            dest_ip=handshake.peer_ip,
            client_alpn=client_alpn,
            abort_event=abort_event,
        )
        result = await self._interceptor.on_message(ctx, original_response)
        if result.action is InterceptionAction.DROP:
            handshake.writer.close()
            return False
        response = result.message if result.message is not None else original_response
        assert isinstance(response, Response)

        ctx = InterceptionContext(
            flow_id=flow_id,
            point=InterceptionPoint.RESPONSE_TO_BE_SENT,
            service=request_service,
            listener_port=listener_port,
            source_ip=source_ip,
            request_target=final_request.target,
            dest_ip=handshake.peer_ip,
            client_alpn=client_alpn,
            abort_event=abort_event,
        )
        result = await self._interceptor.on_message(ctx, response)
        if result.action is InterceptionAction.DROP:
            handshake.writer.close()
            return False
        if result.message is not None:
            response = result.message
            assert isinstance(response, Response)
        response, response_modified = self._apply_match_replace(
            ctx.point, response
        )
        assert isinstance(response, Response)
        response_edited = response is not original_response

        raw_head = (
            response.to_bytes() if response_edited else handshake.raw_head
        )
        try:
            writer.write(raw_head)
            await writer.drain()
        except (ConnectionError, OSError, ssl.SSLError) as exc:
            log.info("websocket_client_closed", reason=str(exc))
            handshake.writer.close()
            return False

        frames: deque[WebSocketFrame] = deque(maxlen=_MAX_WEBSOCKET_FRAMES)
        handshake_timing = timing.with_completed()
        flow_state = Flow(
            id=flow_id,
            service=request_service,
            listener_port=listener_port,
            received_at=timing.sent_at,
            request=request,
            final_request=final_request,
            response=response,
            original_response=original_response,
            edited=request_edited or response_edited,
            modified_by_rule=request_modified or response_modified,
            mime=MimeType.from_content_type(response.header("Content-Type")),
            timing=handshake_timing,
            source_ip=source_ip,
            dest_ip=handshake.peer_ip,
        )
        # Visible en el store en vivo desde el handshake; la persistencia final
        # con los frames en SQLite y la captura JSONL se escriben al cerrar.
        self._store.add(flow_state)

        def on_frame(direction: WebSocketDirection, info) -> None:
            nonlocal flow_state
            frames.append(
                WebSocketFrame(
                    direction=direction,
                    opcode=info.opcode,
                    size=info.size,
                    at=datetime.now(timezone.utc),
                )
            )
            flow_state = replace(flow_state, websocket_frames=tuple(frames))
            self._store.update(flow_state)

        extensions = response.header("Sec-WebSocket-Extensions")

        async def intercept_frame(direction, frame):
            if self._breakpoints is None or not self._breakpoints.enabled:
                return frame.raw
            # Con permessage-deflate el payload está comprimido y editarlo
            # rompería el contexto de compresión.
            if extensions:
                return frame.raw
            if self._scope.has_rules and not self._scope.matches(
                request_service, final_request.target
            ):
                return frame.raw
            breakpoint = self._breakpoints.register_frame(
                flow_id=flow_id,
                direction=direction.value,
                opcode=frame.info.opcode,
                fin=frame.info.fin,
                masked=frame.info.masked,
                payload=frame.payload,
                service=request_service,
                listener_port=listener_port,
                source_ip=source_ip,
                dest_ip=handshake.peer_ip,
                client_alpn=client_alpn,
            )
            if breakpoint is None:
                return frame.raw
            try:
                result = await self._breakpoints.wait(
                    breakpoint, abort_event
                )
            finally:
                self._breakpoints.finish(breakpoint)
            if result.action is InterceptionAction.DROP:
                return None
            payload = (
                result.payload
                if result.payload is not None
                else frame.payload
            )
            return websocket.build_frame(
                frame.info.opcode,
                payload,
                fin=frame.info.fin,
                masked=frame.info.masked,
            )

        try:
            await websocket.relay(
                reader,
                writer,
                handshake.reader,
                handshake.writer,
                on_frame,
                intercept_frame=intercept_frame,
            )
        except (ConnectionError, OSError, ssl.SSLError) as exc:
            log.info("websocket_relay_closed", reason=str(exc))
        finally:
            handshake.writer.close()
            try:
                await handshake.writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass
            timing = timing.with_completed()
            flow_state = replace(
                flow_state, timing=timing, websocket_frames=tuple(frames)
            )
            self._store.update(flow_state)
            self._persist(flow_state)
            if self._capture is not None:
                try:
                    self._capture.append(flow_state)
                except OSError:
                    log.warning(
                        "flows_capture_failed",
                        path=str(self._capture.path),
                        flow_id=flow_id,
                    )
            log.info(
                "websocket_closed",
                frames=len(frames),
                total_ms=round(timing.total_ms or 0.0, 2),
            )
        return False

    async def _handle_h2_request(
        self,
        request: Request,
        request_service: HttpService,
        source_ip: str,
        listener_port: int,
        client_alpn: str | None,
        log: "structlog.stdlib.BoundLogger",  # noqa: F821
    ) -> Response:
        """Ejecuta un stream HTTP/2 y devuelve la respuesta al servidor h2."""
        flow_id = self._store.next_id()
        return await self._execute(
            request,
            request_service,
            flow_id=flow_id,
            source_ip=source_ip,
            listener_port=listener_port,
            client_alpn=client_alpn,
            log=log,
        )

    async def _execute(
        self,
        request: Request,
        request_service: HttpService,
        *,
        flow_id: int,
        source_ip: str,
        listener_port: int,
        client_alpn: str | None,
        log: "structlog.stdlib.BoundLogger",  # noqa: F821
        abort_event: asyncio.Event | None = None,
    ) -> Response:
        """Intercepta, reenvía, registra el ``Flow`` y devuelve la respuesta.

        Es el pipeline común para HTTP/1.1 y HTTP/2. Los errores de upstream se
        registran como flujo sin respuesta y se propagan al transporte
        (``_send_error`` en h1, 502 sintético en h2).
        """
        timing = Timing.start()
        log = log.bind(flow_id=flow_id)

        ctx = InterceptionContext(
            flow_id=flow_id,
            point=InterceptionPoint.REQUEST_RECEIVED,
            service=request_service,
            listener_port=listener_port,
            source_ip=source_ip,
            request_target=request.target,
            client_alpn=client_alpn,
            abort_event=abort_event,
        )
        result = await self._interceptor.on_message(ctx, request)
        if result.action is InterceptionAction.DROP:
            self._record_dropped(
                flow_id=flow_id,
                request=request,
                final_request=request,
                service=request_service,
                listener_port=listener_port,
                source_ip=source_ip,
                timing=timing,
                reason="request_received",
            )
            raise RequestDropped("request_received")
        final_request = result.message if result.message is not None else request
        assert isinstance(final_request, Request)

        ctx = InterceptionContext(
            flow_id=flow_id,
            point=InterceptionPoint.REQUEST_TO_BE_SENT,
            service=request_service,
            listener_port=listener_port,
            source_ip=source_ip,
            request_target=final_request.target,
            client_alpn=client_alpn,
            abort_event=abort_event,
        )
        result = await self._interceptor.on_message(ctx, final_request)
        if result.action is InterceptionAction.DROP:
            self._record_dropped(
                flow_id=flow_id,
                request=request,
                final_request=final_request,
                service=request_service,
                listener_port=listener_port,
                source_ip=source_ip,
                timing=timing,
                reason="request_to_be_sent",
            )
            raise RequestDropped("request_to_be_sent")
        if result.message is not None:
            final_request = result.message
            assert isinstance(final_request, Request)
        final_request, request_modified = self._apply_match_replace(
            ctx.point, final_request
        )
        assert isinstance(final_request, Request)
        edited = final_request is not request

        try:
            upstream = await send_request(
                final_request,
                request_service,
                verify=self._config.verify_upstream,
                timeout=self._config.upstream_timeout,
                alpn=self._config.alpn,
                pool=self._h2_pool,
            )
        except UpstreamError as exc:
            log.warning("upstream_failed", error=str(exc))
            timing = timing.with_completed()
            self._record(
                Flow(
                    id=flow_id,
                    service=request_service,
                    listener_port=listener_port,
                    received_at=timing.sent_at,
                    request=request,
                    final_request=final_request,
                    edited=edited,
                    modified_by_rule=request_modified,
                    timing=timing,
                    source_ip=source_ip,
                )
            )
            raise

        timing = timing.with_first_byte()
        original_response = upstream.response
        dest_ip = upstream.peer_ip

        ctx = InterceptionContext(
            flow_id=flow_id,
            point=InterceptionPoint.RESPONSE_RECEIVED,
            service=request_service,
            listener_port=listener_port,
            source_ip=source_ip,
            request_target=final_request.target,
            dest_ip=dest_ip,
            client_alpn=client_alpn,
            abort_event=abort_event,
        )
        result = await self._interceptor.on_message(ctx, original_response)
        if result.action is InterceptionAction.DROP:
            log.info("response_dropped")
            self._record_dropped(
                flow_id=flow_id,
                request=request,
                final_request=final_request,
                service=request_service,
                listener_port=listener_port,
                source_ip=source_ip,
                timing=timing,
                reason="response_received",
                original_response=original_response,
                dest_ip=dest_ip,
                modified_by_rule=request_modified,
            )
            raise RequestDropped("response_received")
        response = result.message if result.message is not None else original_response
        assert isinstance(response, Response)

        ctx = InterceptionContext(
            flow_id=flow_id,
            point=InterceptionPoint.RESPONSE_TO_BE_SENT,
            service=request_service,
            listener_port=listener_port,
            source_ip=source_ip,
            request_target=final_request.target,
            dest_ip=dest_ip,
            client_alpn=client_alpn,
            abort_event=abort_event,
        )
        result = await self._interceptor.on_message(ctx, response)
        if result.action is InterceptionAction.DROP:
            self._record_dropped(
                flow_id=flow_id,
                request=request,
                final_request=final_request,
                service=request_service,
                listener_port=listener_port,
                source_ip=source_ip,
                timing=timing,
                reason="response_to_be_sent",
                response=response,
                original_response=original_response,
                dest_ip=dest_ip,
                modified_by_rule=request_modified,
            )
            raise RequestDropped("response_to_be_sent")
        if result.message is not None:
            response = result.message
            assert isinstance(response, Response)
        response, response_modified = self._apply_match_replace(
            ctx.point, response
        )
        assert isinstance(response, Response)
        edited = edited or response is not original_response
        timing = timing.with_completed()

        self._record(
            Flow(
                id=flow_id,
                service=request_service,
                listener_port=listener_port,
                received_at=timing.sent_at,
                request=request,
                final_request=final_request,
                response=response,
                original_response=original_response,
                edited=edited,
                modified_by_rule=request_modified or response_modified,
                mime=MimeType.from_content_type(response.header("Content-Type")),
                timing=timing,
                source_ip=source_ip,
                dest_ip=dest_ip,
            )
        )
        log.info(
            "flow_completed",
            method=final_request.method,
            target=final_request.target,
            status=response.status_code,
            mime=MimeType.from_content_type(response.header("Content-Type")).value,
            ttfb_ms=round(timing.ttfb_ms or 0.0, 2),
            total_ms=round(timing.total_ms or 0.0, 2),
            edited=edited,
            truncated=not upstream.complete,
            protocol=response.version,
        )
        return response


async def _send_downstream(
    conn: h11.Connection,
    writer: asyncio.StreamWriter,
    request: Request,
    response: Response,
    *,
    close: bool,
) -> bool:
    """Escribe la respuesta al cliente. Devuelve ``False`` si hay que cerrar."""
    # Normalizamos el framing a Content-Length (tenemos el cuerpo decodificado).
    headers: list[tuple[bytes, bytes]] = []
    for header in response.headers:
        if header.lowercase_name in h11io.HOP_BY_HOP:
            continue
        if header.lowercase_name == "content-length":
            continue
        headers.append((header.name.encode("latin-1"), header.value.encode("latin-1")))
    headers.append((b"Content-Length", str(len(response.body)).encode("ascii")))
    if close:
        headers.append((b"Connection", b"close"))

    writer.write(
        conn.send(
            h11.Response(
                status_code=response.status_code,
                reason=response.reason.encode("latin-1") if response.reason else None,
                headers=headers,
            )
        )
    )
    # Sin body en HEAD, 1xx, 204 y 304 (h11 los valida; lo comprobamos antes).
    bodyless = (
        request.method.upper() == "HEAD"
        or response.status_code < 200
        or response.status_code in (204, 304)
    )
    if not bodyless and response.body:
        writer.write(conn.send(h11.Data(data=response.body)))
    writer.write(conn.send(h11.EndOfMessage()))
    await writer.drain()
    if close:
        return False
    # h11 exige reiniciar la máquina entre ciclos keep-alive; sin esto, la
    # siguiente petición devolvería PAUSED y se cerraría la conexión.
    if conn.our_state is h11.DONE and conn.their_state is h11.DONE:
        conn.start_next_cycle()
        return True
    return False


async def _send_error(
    conn: h11.Connection,
    writer: asyncio.StreamWriter,
    status: int,
    message: str,
    *,
    close: bool = True,
) -> bool:
    """Respuesta de error sintética (400/502) manteniendo el framing correcto."""
    body = message.encode("utf-8") + b"\n"
    reason = {400: b"Bad Request", 502: b"Bad Gateway"}.get(status, b"Error")
    try:
        writer.write(
            conn.send(
                h11.Response(
                    status_code=status,
                    reason=reason,
                    headers=[
                        (b"Content-Type", b"text/plain; charset=utf-8"),
                        (b"Content-Length", str(len(body)).encode("ascii")),
                        (b"Connection", b"close"),
                    ],
                )
            )
        )
        writer.write(conn.send(h11.Data(data=body)))
        writer.write(conn.send(h11.EndOfMessage()))
        await writer.drain()
    except (h11.LocalProtocolError, ConnectionError, OSError):
        return False
    return not close


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await writer.wait_closed()
    except (ConnectionError, OSError):
        pass


async def _watch_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    abort_event: asyncio.Event,
) -> None:
    """Marca ``abort_event`` si el cliente cierra la conexión.

    Se usa mientras una petición HTTP/1.1 está pausada en un breakpoint para
    abortarla como DROP en cuanto el navegador se desconecta.
    """
    while not abort_event.is_set():
        if (
            reader.at_eof()
            or reader.exception() is not None
            or writer.is_closing()
        ):
            abort_event.set()
            return
        try:
            await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            return
