"""Los 4 puntos de intercepción del Proxy (Plan.md §3.2, §3.5).

1. ``REQUEST_RECEIVED`` — petición recibida del cliente.
2. ``REQUEST_TO_BE_SENT`` — petición a enviar al origen (tras reglas/edición).
3. ``RESPONSE_RECEIVED`` — respuesta recibida del origen.
4. ``RESPONSE_TO_BE_SENT`` — respuesta a enviar al cliente.

Cada punto recibe el mensaje y devuelve una **acción** (seguir reglas,
interceptar, no interceptar, descartar) y, opcionalmente, una versión editada.
El mensaje devuelto es un objeto **nuevo**; el original se conserva en el
``Flow``. En F1 la política es "seguir reglas" + log estructurado: la pausa y
la edición manual llegarán con la UI (F5), pero el contrato ya está fijado.
"""

from __future__ import annotations

import asyncio
import base64
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol

from core.logging import get_logger
from core.model import HttpService, Message, Request, Response
from core.scope import Scope

_log = get_logger("prox0x.proxy.intercept")

_OPCODE_NAMES = {
    0x0: "continuation",
    0x1: "text",
    0x2: "binary",
    0x8: "close",
    0x9: "ping",
    0xA: "pong",
}


class InterceptionPoint(Enum):
    """Los cuatro puntos, en orden de ejecución."""

    REQUEST_RECEIVED = "request_received"
    REQUEST_TO_BE_SENT = "request_to_be_sent"
    RESPONSE_RECEIVED = "response_received"
    RESPONSE_TO_BE_SENT = "response_to_be_sent"
    WEBSOCKET_FRAME = "websocket_frame"


class InterceptionAction(Enum):
    """Acciones posibles en un punto de intercepción."""

    CONTINUE = "continue"  # seguir con las reglas
    INTERCEPT = "intercept"  # pausar y esperar al usuario (F5)
    DO_NOT_INTERCEPT = "do_not_intercept"  # pasar sin aplicar más reglas
    DROP = "drop"  # descartar el mensaje


@dataclass(frozen=True, slots=True)
class InterceptionContext:
    """Metadatos del mensaje interceptado."""

    flow_id: int
    point: InterceptionPoint
    service: HttpService
    listener_port: int
    source_ip: str
    dest_ip: str = ""
    client_alpn: str | None = None
    request_target: str = ""
    abort_event: asyncio.Event | None = None


@dataclass(frozen=True, slots=True)
class InterceptionResult:
    """Decisión de un interceptor: acción + versión final del mensaje."""

    action: InterceptionAction
    message: Message | None = None  # None = sin cambios
    payload: bytes | None = None  # frame WS editado (None = sin cambios)


class Interceptor(Protocol):
    """Contrato de un interceptor (ahora log-only; luego pausa/edición)."""

    async def on_message(self, ctx: InterceptionContext, message: Message) -> InterceptionResult: ...


class LoggingInterceptor:
    """Interceptor por defecto: registra el flujo en los 4 puntos y continúa."""

    def __init__(self) -> None:
        self._log = _log

    async def on_message(self, ctx: InterceptionContext, message: Message) -> InterceptionResult:
        log = self._log.bind(
            flow_id=ctx.flow_id,
            point=ctx.point.value,
            service=str(ctx.service),
            listener=ctx.listener_port,
        )
        if isinstance(message, Request):
            log.info(
                "interception",
                kind="request",
                method=message.method,
                target=message.target,
                headers=len(message.headers),
                body_bytes=len(message.body),
            )
        elif isinstance(message, Response):
            log.info(
                "interception",
                kind="response",
                status=message.status_code,
                reason=message.reason,
                headers=len(message.headers),
                body_bytes=len(message.body),
            )
        # INTERCEPT está reservado para la UI (F5): hasta entonces se trata como
        # CONTINUE para no romper el flujo.
        return InterceptionResult(action=InterceptionAction.CONTINUE)


@dataclass(slots=True)
class PendingBreakpoint:
    """Mensaje pausado esperando una decisión (forward/drop)."""

    id: str
    flow_id: int
    point: InterceptionPoint
    message: Message | None
    service: HttpService
    listener_port: int
    source_ip: str
    dest_ip: str
    client_alpn: str | None
    frame_payload: bytes | None = None
    frame_opcode: int | None = None
    frame_direction: str = ""
    frame_fin: bool = True
    frame_masked: bool = False
    event: asyncio.Event = field(default_factory=asyncio.Event)
    result: InterceptionResult | None = None
    waiter: asyncio.Task[object] | None = None
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @property
    def is_frame(self) -> bool:
        return self.frame_opcode is not None

    @property
    def kind(self) -> str:
        if self.is_frame:
            return "ws_frame"
        if isinstance(self.message, Request):
            return "request"
        if isinstance(self.message, Response):
            return "response"
        return "message"

    def metadata(self) -> dict:
        if self.is_frame:
            payload = self.frame_payload or b""
            return {
                "id": self.id,
                "flow_id": self.flow_id,
                "point": self.point.value,
                "kind": "ws_frame",
                "service": str(self.service),
                "listener_port": self.listener_port,
                "source_ip": self.source_ip,
                "dest_ip": self.dest_ip,
                "created_at": self.created_at.isoformat(),
                "size": len(payload),
                "opcode": self.frame_opcode,
                "opcode_name": _OPCODE_NAMES.get(
                    self.frame_opcode or 0, "unknown"
                ),
                "direction": self.frame_direction,
                "fin": self.frame_fin,
            }
        message = self.message
        raw = getattr(message, "raw", b"") if message is not None else b""
        record: dict = {
            "id": self.id,
            "flow_id": self.flow_id,
            "point": self.point.value,
            "kind": self.kind,
            "service": str(self.service),
            "listener_port": self.listener_port,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "created_at": self.created_at.isoformat(),
            "size": len(raw),
        }
        if isinstance(message, Request):
            record.update(method=message.method, target=message.target)
        elif isinstance(message, Response):
            record.update(status=message.status_code, reason=message.reason)
        return record


def message_record(message: Message | None) -> dict:
    """Serializa un mensaje para la UI.

    Un breakpoint puede llegar sin mensaje (o con un objeto parcial) por una
    carrera durante el cierre de un proyecto o de un stream. La frontera con
    el frontend siempre devuelve un objeto con ``raw`` y ``headers`` válidos:
    un mensaje vacío se representa como ``raw: ""``, nunca como ``null``.
    """
    if message is None:
        return {
            "kind": "message",
            "raw": "",
            "version": "",
            "headers": [],
        }
    raw = getattr(message, "raw", b"") or b""
    headers = getattr(message, "headers", ()) or ()
    record: dict = {
        "kind": "message",
        "raw": base64.b64encode(raw).decode("ascii"),
        "version": getattr(message, "version", "") or "",
        "headers": [
            {"name": header.name, "value": header.value} for header in headers
        ],
    }
    if isinstance(message, Request):
        record.update(kind="request", method=message.method, target=message.target)
    elif isinstance(message, Response):
        record.update(
            kind="response", status=message.status_code, reason=message.reason
        )
    return record


def frame_record(breakpoint: PendingBreakpoint) -> dict:
    payload = breakpoint.frame_payload or b""
    return {
        "payload": base64.b64encode(payload).decode("ascii"),
        "size": len(payload),
        "opcode": breakpoint.frame_opcode or 0,
        "opcode_name": _OPCODE_NAMES.get(breakpoint.frame_opcode or 0, "unknown"),
        "direction": breakpoint.frame_direction,
        "fin": breakpoint.frame_fin,
        "masked": breakpoint.frame_masked,
    }


def breakpoint_record(breakpoint: PendingBreakpoint) -> dict:
    record = breakpoint.metadata()
    if breakpoint.is_frame:
        record["message"] = message_record(None)
        record["frame"] = frame_record(breakpoint)
    else:
        record["message"] = message_record(breakpoint.message)
    return record


class BreakpointManager:
    """Cola de breakpoints y resolución de sus ``asyncio.Event``."""

    def __init__(
        self,
        *,
        enabled: bool = False,
        points: set[InterceptionPoint] | None = None,
        timeout: float = 300.0,
        max_pending: int = 100,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout debe ser > 0")
        if max_pending < 1:
            raise ValueError("max_pending debe ser >= 1")
        self.enabled = enabled
        self.points = set(points or {InterceptionPoint.REQUEST_TO_BE_SENT})
        self.timeout = timeout
        self.max_pending = max_pending
        self.pending: dict[str, PendingBreakpoint] = {}
        self._subscribers: set[asyncio.Queue[dict]] = set()
        self._log = get_logger("prox0x.proxy.breakpoints")

    def should_intercept(self, point: InterceptionPoint) -> bool:
        return self.enabled and point in self.points

    def register(
        self, ctx: InterceptionContext, message: Message
    ) -> PendingBreakpoint | None:
        if not self.should_intercept(ctx.point):
            return None
        if len(self.pending) >= self.max_pending:
            self._log.warning(
                "breakpoint_queue_full",
                flow_id=ctx.flow_id,
                point=ctx.point.value,
            )
            return None
        breakpoint = PendingBreakpoint(
            id=uuid.uuid4().hex,
            flow_id=ctx.flow_id,
            point=ctx.point,
            message=message,
            service=ctx.service,
            listener_port=ctx.listener_port,
            source_ip=ctx.source_ip,
            dest_ip=ctx.dest_ip,
            client_alpn=ctx.client_alpn,
        )
        self.pending[breakpoint.id] = breakpoint
        self._log.info(
            "breakpoint_paused",
            id=breakpoint.id,
            flow_id=ctx.flow_id,
            point=ctx.point.value,
        )
        self._emit({"type": "breakpoint", "breakpoint": breakpoint_record(breakpoint)})
        return breakpoint

    def register_frame(
        self,
        *,
        flow_id: int,
        direction: str,
        opcode: int,
        fin: bool,
        masked: bool,
        payload: bytes,
        service: HttpService,
        listener_port: int,
        source_ip: str,
        dest_ip: str = "",
        client_alpn: str | None = None,
    ) -> PendingBreakpoint | None:
        """Pausa un frame WS de datos si Intercept está activo."""
        if not self.enabled:
            return None
        if len(self.pending) >= self.max_pending:
            self._log.warning(
                "breakpoint_queue_full",
                flow_id=flow_id,
                point=InterceptionPoint.WEBSOCKET_FRAME.value,
            )
            return None
        breakpoint = PendingBreakpoint(
            id=uuid.uuid4().hex,
            flow_id=flow_id,
            point=InterceptionPoint.WEBSOCKET_FRAME,
            message=None,
            service=service,
            listener_port=listener_port,
            source_ip=source_ip,
            dest_ip=dest_ip,
            client_alpn=client_alpn,
            frame_payload=payload,
            frame_opcode=opcode,
            frame_direction=direction,
            frame_fin=fin,
            frame_masked=masked,
        )
        self.pending[breakpoint.id] = breakpoint
        self._log.info(
            "breakpoint_paused",
            id=breakpoint.id,
            flow_id=flow_id,
            point=InterceptionPoint.WEBSOCKET_FRAME.value,
            opcode=opcode,
            size=len(payload),
        )
        self._emit({"type": "breakpoint", "breakpoint": breakpoint_record(breakpoint)})
        return breakpoint

    async def wait(
        self,
        breakpoint: PendingBreakpoint,
        abort_event: asyncio.Event | None = None,
    ) -> InterceptionResult:
        breakpoint.waiter = asyncio.current_task()
        event_task = asyncio.create_task(breakpoint.event.wait())
        abort_task = (
            asyncio.create_task(abort_event.wait())
            if abort_event is not None
            else None
        )
        tasks = {event_task}
        if abort_task is not None:
            tasks.add(abort_task)
        try:
            done, _pending = await asyncio.wait(
                tasks,
                timeout=self.timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if (
                abort_task is not None
                and abort_task in done
                and breakpoint.result is None
            ):
                breakpoint.result = InterceptionResult(InterceptionAction.DROP)
                self._log.info(
                    "breakpoint_client_disconnected",
                    id=breakpoint.id,
                    flow_id=breakpoint.flow_id,
                )
                self._emit(
                    {
                        "type": "resolved",
                        "id": breakpoint.id,
                        "action": "client_disconnected",
                    }
                )
                return breakpoint.result
            if not done:
                breakpoint.result = InterceptionResult(InterceptionAction.CONTINUE)
                self._log.warning(
                    "breakpoint_timeout",
                    id=breakpoint.id,
                    flow_id=breakpoint.flow_id,
                )
                self._emit(
                    {
                        "type": "resolved",
                        "id": breakpoint.id,
                        "action": "timeout",
                    }
                )
            return breakpoint.result or InterceptionResult(
                InterceptionAction.CONTINUE
            )
        except asyncio.CancelledError:
            # El cliente HTTP/2 reseteó el stream o cerró la conexión.
            if breakpoint.result is None:
                breakpoint.result = InterceptionResult(InterceptionAction.DROP)
                self._emit(
                    {
                        "type": "resolved",
                        "id": breakpoint.id,
                        "action": "client_disconnected",
                    }
                )
            self._log.info(
                "breakpoint_cancelled",
                id=breakpoint.id,
                flow_id=breakpoint.flow_id,
            )
            raise
        finally:
            breakpoint.waiter = None
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    def finish(self, breakpoint: PendingBreakpoint) -> None:
        breakpoint.waiter = None
        self.pending.pop(breakpoint.id, None)

    def cancel_all(
        self,
        *,
        action: InterceptionAction = InterceptionAction.DROP,
        reason: str = "cancelled",
        cancel_waiters: bool = False,
    ) -> int:
        """Resuelve y limpia todos los breakpoints pendientes.

        Con ``cancel_waiters=True`` también cancela las tareas que están
        esperando (útil al cambiar de proyecto); así no escriben flujos
        tardíos en la base de datos del proyecto nuevo.
        """
        pending = list(self.pending.values())
        for breakpoint in pending:
            was_pending = breakpoint.result is None
            if was_pending:
                breakpoint.result = InterceptionResult(action)
            breakpoint.event.set()
            if was_pending:
                self._emit(
                    {
                        "type": "resolved",
                        "id": breakpoint.id,
                        "action": reason,
                    }
                )
            if (
                cancel_waiters
                and breakpoint.waiter is not None
                and not breakpoint.waiter.done()
            ):
                breakpoint.waiter.cancel()
        self.pending.clear()
        return len(pending)

    def resolve(
        self,
        breakpoint_id: str,
        action: InterceptionAction,
        message: Message | None = None,
        payload: bytes | None = None,
    ) -> PendingBreakpoint:
        breakpoint = self.pending.get(breakpoint_id)
        if breakpoint is None:
            raise KeyError(f"breakpoint inexistente: {breakpoint_id}")
        if breakpoint.result is not None:
            raise ValueError(f"breakpoint ya resuelto: {breakpoint_id}")
        breakpoint.result = InterceptionResult(action, message, payload)
        breakpoint.event.set()
        action_name = "forward" if action is InterceptionAction.CONTINUE else "drop"
        self._emit(
            {
                "type": "resolved",
                "id": breakpoint.id,
                "action": action_name,
            }
        )
        self._log.info(
            "breakpoint_resolved",
            id=breakpoint.id,
            flow_id=breakpoint.flow_id,
            action=action.value,
        )
        return breakpoint

    def forward(
        self,
        breakpoint_id: str,
        message: Message | None = None,
        payload: bytes | None = None,
    ) -> PendingBreakpoint:
        return self.resolve(
            breakpoint_id,
            InterceptionAction.CONTINUE,
            message,
            payload,
        )

    def drop(self, breakpoint_id: str) -> PendingBreakpoint:
        return self.resolve(breakpoint_id, InterceptionAction.DROP)

    def toggle(
        self,
        *,
        enabled: bool | None = None,
        points: set[InterceptionPoint] | None = None,
    ) -> dict:
        if enabled is not None:
            self.enabled = enabled
        if points is not None:
            self.points = set(points)
        self._log.info(
            "breakpoints_toggled",
            enabled=self.enabled,
            points=sorted(point.value for point in self.points),
        )
        self._emit(self.status_event())
        return self.status()

    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "points": sorted(point.value for point in self.points),
            "pending": len(self.pending),
            "timeout_s": self.timeout,
            "max_pending": self.max_pending,
        }

    def status_event(self) -> dict:
        status = self.status()
        return {"type": "status", **status}

    def subscribe(self, maxsize: int = 200) -> asyncio.Queue[dict]:
        queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=maxsize)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict]) -> None:
        self._subscribers.discard(queue)

    def _emit(self, event: dict) -> None:
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # La UI va lenta: descarta el evento más antiguo antes que
                # bloquear el camino de red.
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    pass

    def snapshot(self) -> list[dict]:
        return [
            breakpoint_record(breakpoint)
            for breakpoint in self.pending.values()
            if breakpoint.result is None
        ]

    def get(self, breakpoint_id: str) -> PendingBreakpoint | None:
        return self.pending.get(breakpoint_id)

    def close(self) -> None:
        """Libera todas las pausas con CONTINUE (parada ordenada del Proxy)."""
        self.cancel_all(
            action=InterceptionAction.CONTINUE,
            reason="close",
        )


class InteractiveInterceptor:
    """Interceptor que pausa en los puntos configurados del ``BreakpointManager``."""

    def __init__(
        self,
        manager: BreakpointManager,
        *,
        delegate: Interceptor | None = None,
        scope: Scope | None = None,
    ) -> None:
        self.manager = manager
        self.delegate = delegate or LoggingInterceptor()
        self.scope = scope

    def in_scope(self, ctx: InterceptionContext, message: Message) -> bool:
        """Indica si el mensaje debe poder pausarse según el Alcance.

        Sin reglas configuradas el comportamiento histórico se conserva: todo
        el tráfico se intercepta. Con reglas, solo se pausa lo que coincide
        con el Alcance; el resto pasa de largo como si Intercept estuviera
        apagado para esa petición.
        """
        scope = self.scope
        if scope is None or not scope.has_rules:
            return True
        target = (
            message.target
            if isinstance(message, Request)
            else ctx.request_target
        )
        if not target:
            # Sin URL no se puede afirmar que esté dentro del Alcance.
            return False
        return scope.matches(ctx.service, target)

    async def on_message(
        self, ctx: InterceptionContext, message: Message
    ) -> InterceptionResult:
        if not self.manager.should_intercept(ctx.point):
            return await self.delegate.on_message(ctx, message)
        if not self.in_scope(ctx, message):
            _log.info(
                "interception_out_of_scope",
                flow_id=ctx.flow_id,
                point=ctx.point.value,
                service=str(ctx.service),
                target=ctx.request_target,
            )
            return await self.delegate.on_message(ctx, message)

        breakpoint = self.manager.register(ctx, message)
        if breakpoint is None:
            return await self.delegate.on_message(ctx, message)

        try:
            return await self.manager.wait(breakpoint, ctx.abort_event)
        finally:
            self.manager.finish(breakpoint)
