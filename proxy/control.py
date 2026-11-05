"""Control plane local del Proxy para breakpoints (socket Unix, JSON-lines).

El Proxy y la API son procesos distintos; este socket evita acoplarlos. Cada
petición abre una conexión, envía una línea JSON y recibe una respuesta. El
socket se crea con permisos ``0600`` y no sale de la máquina.
"""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Awaitable, Callable
import json
import os
import re
from pathlib import Path

from core.logging import get_logger
from core.match_replace import MatchReplace, MatchReplaceError
from core.model import Message, Request, Response
from core.net.wire import parse_request, parse_response
from core.scope import Scope, ScopeError

from .intercept import (
    BreakpointManager,
    InterceptionAction,
    InterceptionPoint,
    breakpoint_record,
)

_log = get_logger("prox0x.proxy.control")

_MAX_LINE = 16 * 1024 * 1024


class ControlCommandError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _breakpoint_detail(breakpoint) -> dict:
    return breakpoint_record(breakpoint)


def _parse_points(raw: object) -> set[InterceptionPoint]:
    if not isinstance(raw, list):
        raise ControlCommandError(400, "points debe ser una lista")
    points: set[InterceptionPoint] = set()
    for value in raw:
        try:
            points.add(InterceptionPoint(str(value)))
        except ValueError as exc:
            raise ControlCommandError(400, f"punto desconocido: {value!r}") from exc
    if not points:
        raise ControlCommandError(400, "points no puede estar vacío")
    return points


def _parse_frame_payload(value: object) -> bytes | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ControlCommandError(400, "frame_payload debe ser string")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ControlCommandError(400, "frame_payload inválido") from exc


def _parse_forward_message(breakpoint, raw_b64: object) -> Message | None:
    if raw_b64 is None:
        return None
    if not isinstance(raw_b64, str):
        raise ControlCommandError(400, "raw_b64 debe ser string")
    try:
        raw = base64.b64decode(raw_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise ControlCommandError(400, "raw_b64 inválido") from exc
    try:
        if isinstance(breakpoint.message, Request):
            message: Message = parse_request(raw)
        elif isinstance(breakpoint.message, Response):
            message = parse_response(raw)
        else:
            raise ControlCommandError(400, "mensaje no soportado")
    except ValueError as exc:
        raise ControlCommandError(400, f"mensaje inválido: {exc}") from exc
    return message


async def dispatch(
    manager: BreakpointManager,
    request: dict,
    scope: Scope | None = None,
    match_replace: MatchReplace | None = None,
    on_project_load: Callable[[dict], dict] | None = None,
    on_scope_change: Callable[[Scope], Awaitable[None]] | None = None,
) -> dict:
    command = request.get("command")
    if command == "project_load":
        if on_project_load is None:
            raise ControlCommandError(503, "cambio de proyecto no disponible")
        try:
            result = on_project_load(request)
        except (ValueError, OSError, ScopeError, MatchReplaceError) as exc:
            raise ControlCommandError(400, str(exc)) from exc
        if on_scope_change is not None and scope is not None:
            await on_scope_change(scope)
        return {"ok": True, **result}
    if command == "match_replace_get":
        if match_replace is None:
            raise ControlCommandError(503, "match & replace no disponible")
        return {"ok": True, "rules": match_replace.serialize()}
    if command == "match_replace_set":
        if match_replace is None:
            raise ControlCommandError(503, "match & replace no disponible")
        rules = request.get("rules", [])
        if not isinstance(rules, list):
            raise ControlCommandError(400, "rules debe ser una lista")
        try:
            serialized = match_replace.set_rules(rules)
        except MatchReplaceError as exc:
            raise ControlCommandError(400, str(exc)) from exc
        return {"ok": True, "rules": serialized}
    if command == "scope_get":
        if scope is None:
            raise ControlCommandError(503, "scope no disponible")
        return {"ok": True, "scope": scope.serialize()}
    if command == "scope_set":
        if scope is None:
            raise ControlCommandError(503, "scope no disponible")
        include = request.get("include", [])
        exclude = request.get("exclude", [])
        if not isinstance(include, list) or not isinstance(exclude, list):
            raise ControlCommandError(400, "include/exclude deben ser listas")
        if not all(isinstance(item, str) for item in include + exclude):
            raise ControlCommandError(400, "las reglas deben ser strings")
        try:
            scope.set_rules(include, exclude)
        except ScopeError as exc:
            raise ControlCommandError(400, str(exc)) from exc
        if on_scope_change is not None:
            await on_scope_change(scope)
        return {"ok": True, "scope": scope.serialize()}
    if command == "scope_add":
        if scope is None:
            raise ControlCommandError(503, "scope no disponible")
        host = request.get("host")
        if not isinstance(host, str):
            raise ControlCommandError(400, "host debe ser string")
        host = host.strip()
        if not host or any(char.isspace() for char in host):
            raise ControlCommandError(400, "host inválido")
        rule = f".*{re.escape(host)}.*"
        include = list(scope.include)
        added = rule not in include
        if added:
            include.append(rule)
        try:
            scope.set_rules(include, scope.exclude)
        except ScopeError as exc:
            raise ControlCommandError(400, str(exc)) from exc
        if on_scope_change is not None:
            await on_scope_change(scope)
        return {
            "ok": True,
            "scope": scope.serialize(),
            "rule": rule,
            "added": added,
        }
    if command == "status":
        return {"ok": True, "status": manager.status()}
    if command == "toggle":
        enabled = request.get("enabled")
        if enabled is not None and not isinstance(enabled, bool):
            raise ControlCommandError(400, "enabled debe ser booleano")
        points = (
            _parse_points(request["points"]) if "points" in request else None
        )
        return {
            "ok": True,
            "status": manager.toggle(enabled=enabled, points=points),
        }
    if command == "pending":
        return {"ok": True, "pending": manager.snapshot()}
    if command == "get":
        breakpoint_id = str(request.get("id", ""))
        breakpoint = manager.get(breakpoint_id)
        if breakpoint is None:
            raise ControlCommandError(404, f"breakpoint inexistente: {breakpoint_id}")
        return {"ok": True, "breakpoint": _breakpoint_detail(breakpoint)}
    if command in ("forward", "drop"):
        breakpoint_id = str(request.get("id", ""))
        breakpoint = manager.get(breakpoint_id)
        if breakpoint is None:
            raise ControlCommandError(404, f"breakpoint inexistente: {breakpoint_id}")
        if breakpoint.result is not None:
            raise ControlCommandError(409, f"breakpoint ya resuelto: {breakpoint_id}")
        if command == "forward":
            if breakpoint.is_frame:
                payload = _parse_frame_payload(request.get("frame_payload"))
                manager.resolve(
                    breakpoint_id,
                    InterceptionAction.CONTINUE,
                    payload=payload,
                )
            else:
                message = _parse_forward_message(
                    breakpoint, request.get("raw_b64")
                )
                manager.resolve(
                    breakpoint_id, InterceptionAction.CONTINUE, message
                )
        else:
            manager.resolve(breakpoint_id, InterceptionAction.DROP)
        return {"ok": True, "id": breakpoint_id, "action": command}
    raise ControlCommandError(400, f"comando desconocido: {command!r}")


class ControlServer:
    """Servidor Unix que expone el ``BreakpointManager`` y el ``Scope`` a la API."""

    def __init__(
        self,
        manager: BreakpointManager,
        path: Path,
        *,
        scope: Scope | None = None,
        match_replace: MatchReplace | None = None,
        on_project_load: Callable[[dict], dict] | None = None,
        on_scope_change: Callable[[Scope], Awaitable[None]] | None = None,
    ) -> None:
        self.manager = manager
        self.path = path
        self.scope = scope
        self.match_replace = match_replace
        self.on_project_load = on_project_load
        self.on_scope_change = on_scope_change
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        self._server = await asyncio.start_unix_server(
            self._handle, path=str(self.path), limit=_MAX_LINE
        )
        os.chmod(self.path, 0o600)
        _log.info("control_socket_listening", path=str(self.path))

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            line = await reader.readline()
            if not line:
                return
            try:
                request = json.loads(line)
            except json.JSONDecodeError as exc:
                response = {
                    "ok": False,
                    "status": 400,
                    "detail": f"JSON inválido: {exc}",
                }
            else:
                if request.get("command") == "subscribe":
                    await self._stream_events(reader, writer)
                    return
                try:
                    response = await dispatch(
                        self.manager,
                        request,
                        self.scope,
                        self.match_replace,
                        self.on_project_load,
                        on_scope_change=self.on_scope_change,
                    )
                except ControlCommandError as exc:
                    response = {
                        "ok": False,
                        "status": exc.status,
                        "detail": exc.detail,
                    }
                except Exception as exc:
                    _log.exception("control_dispatch_failed")
                    response = {
                        "ok": False,
                        "status": 500,
                        "detail": str(exc),
                    }
            writer.write(json.dumps(response, ensure_ascii=True).encode() + b"\n")
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except asyncio.LimitOverrunError:
            _log.warning("control_line_too_long")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass

    async def _stream_events(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        queue = self.manager.subscribe()
        try:
            writer.write(b'{"ok": true}\n')
            writer.write(
                json.dumps(self.manager.status_event(), ensure_ascii=True).encode()
                + b"\n"
            )
            await writer.drain()

            async def send_events() -> None:
                while True:
                    event = await queue.get()
                    writer.write(
                        json.dumps(event, ensure_ascii=True).encode() + b"\n"
                    )
                    await writer.drain()

            async def wait_disconnect() -> None:
                # La API cierra el socket cuando la UI se desconecta.
                await reader.read(1)

            tasks = {
                asyncio.create_task(send_events()),
                asyncio.create_task(wait_disconnect()),
            }
            _done, pending = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        except (ConnectionError, OSError, asyncio.CancelledError):
            pass
        finally:
            self.manager.unsubscribe(queue)
