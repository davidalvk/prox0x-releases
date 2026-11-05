"""Cliente del control plane Unix del Proxy (para FastAPI)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any


class ControlError(Exception):
    def __init__(self, detail: str, *, status: int = 502) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status = status


class ControlUnavailable(ControlError):
    def __init__(self, detail: str) -> None:
        super().__init__(detail, status=503)


class ControlResponseError(ControlError):
    pass


class ControlClient:
    """Una petición por conexión; suficiente para forward/drop/toggle."""

    def __init__(self, path: Path, *, timeout: float = 10.0) -> None:
        self.path = path
        self.timeout = timeout

    async def request(self, command: str, **payload: Any) -> dict[str, Any]:
        body = {"command": command, **payload}
        writer: asyncio.StreamWriter | None = None
        try:
            async with asyncio.timeout(self.timeout):
                reader, writer = await asyncio.open_unix_connection(
                    str(self.path), limit=16 * 1024 * 1024
                )
                writer.write(json.dumps(body, ensure_ascii=True).encode() + b"\n")
                await writer.drain()
                line = await reader.readline()
        except (FileNotFoundError, ConnectionRefusedError, OSError, TimeoutError) as exc:
            raise ControlUnavailable(
                f"control plane no disponible en {self.path}: {exc}"
            ) from exc
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, ConnectionError):
                    pass

        if not line:
            raise ControlUnavailable("el control plane cerró sin responder")
        try:
            response = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ControlError(f"respuesta de control inválida: {exc}") from exc
        if not response.get("ok"):
            raise ControlResponseError(
                str(response.get("detail") or "error de control"),
                status=int(response.get("status") or 502),
            )
        return response

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        """Abre un stream de eventos del control plane (breakpoint/resolved/status)."""
        writer: asyncio.StreamWriter | None = None
        try:
            async with asyncio.timeout(self.timeout):
                reader, writer = await asyncio.open_unix_connection(
                    str(self.path), limit=16 * 1024 * 1024
                )
                writer.write(b'{"command": "subscribe"}\n')
                await writer.drain()
                ack_line = await reader.readline()
        except (FileNotFoundError, ConnectionRefusedError, OSError, TimeoutError) as exc:
            if writer is not None:
                writer.close()
            raise ControlUnavailable(
                f"control plane no disponible en {self.path}: {exc}"
            ) from exc

        try:
            if not ack_line:
                raise ControlUnavailable("el control plane cerró la suscripción")
            ack = json.loads(ack_line)
            if not ack.get("ok"):
                raise ControlError(str(ack.get("detail") or "suscripción rechazada"))
            while True:
                line = await reader.readline()
                if not line:
                    return
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(event, dict):
                    yield event
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, ConnectionError):
                    pass
