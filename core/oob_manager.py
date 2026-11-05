"""Gestor Out-of-Band local y online (Interactsh)."""

from __future__ import annotations

import asyncio
import ssl
import uuid
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from typing import Any, Literal

import aiohttp

from core.interactsh_client import (
    DEFAULT_INTERACTSH_SERVERS,
    InteractshClient,
    InteractshInteraction,
)
from core.logging import get_logger
from core.net.tls import verified_ssl_context

OOBMode = Literal["local", "online"]
OOB_KEY = "oob_mode"
_MAX_BODY = 1024 * 1024

_log = get_logger("prox0x.oob")


class OOBError(RuntimeError):
    pass


class OOBManager:
    """Servidor local en 127.0.0.1:9999 y cliente Interactsh en modo online."""

    def __init__(
        self,
        store_provider: Callable[[], Any],
        *,
        local_port: int = 9999,
        poll_interval: float = 2.0,
        interactsh_servers: Sequence[str] | None = None,
    ) -> None:
        self._store_provider = store_provider
        self._local_port = local_port
        self._poll_interval = poll_interval
        self._servers = tuple(interactsh_servers or DEFAULT_INTERACTSH_SERVERS)
        self._mode: OOBMode = "local"
        self._local_server: asyncio.AbstractServer | None = None
        self._client: Any | None = None
        self._poll_task: asyncio.Task[None] | None = None
        self._callback_url = ""
        self._server: str | None = None
        self._error: str | None = None
        self._lock = asyncio.Lock()

    @property
    def mode(self) -> OOBMode:
        return self._mode

    def _store(self) -> Any | None:
        try:
            return self._store_provider()
        except Exception:
            return None

    def _record(self, item: dict) -> None:
        store = self._store()
        if store is None:
            return
        try:
            inserted = store.add_oob_interactions([item])
            if inserted:
                _log.info(
                    "oob_interaction",
                    mode=item.get("mode"),
                    protocol=item.get("protocol"),
                    source=item.get("remote_address"),
                )
        except Exception:
            _log.error("oob_store_failed", exc_info=True)

    async def start(self) -> None:
        store = self._store()
        mode: OOBMode = "local"
        if store is not None:
            stored = store.get_setting(OOB_KEY)
            if stored in ("local", "online"):
                mode = stored
        await self.set_mode(mode, persist=False)

    async def stop(self) -> None:
        async with self._lock:
            await self._stop_current()

    async def _stop_current(self) -> None:
        if self._poll_task is not None:
            self._poll_task.cancel()
            try:
                await asyncio.wait_for(self._poll_task, timeout=3)
            except (asyncio.CancelledError, TimeoutError, Exception):
                pass
            self._poll_task = None
        if self._client is not None:
            try:
                await asyncio.wait_for(self._client.close(), timeout=5)
            except (TimeoutError, Exception):
                _log.debug("oob_close_failed", exc_info=True)
            self._client = None
        if self._local_server is not None:
            self._local_server.close()
            try:
                await asyncio.wait_for(
                    self._local_server.wait_closed(), timeout=3
                )
            except (TimeoutError, Exception):
                _log.debug("oob_local_close_failed", exc_info=True)
            self._local_server = None
        self._callback_url = ""
        self._server = None

    async def set_mode(self, mode: str, *, persist: bool = True) -> dict:
        if mode not in ("local", "online"):
            raise OOBError("modo OOB inválido")
        async with self._lock:
            await self._stop_current()
            self._mode = mode  # type: ignore[assignment]
            self._error = None
            try:
                if mode == "local":
                    await self._start_local()
                else:
                    await self._start_online()
            except Exception as exc:
                self._error = str(exc)
                _log.warning("oob_mode_failed", mode=mode, error=str(exc))
                self._callback_url = ""
            if persist:
                store = self._store()
                if store is not None:
                    store.set_setting(OOB_KEY, mode)
            return self.status()

    async def _start_local(self) -> None:
        self._local_server = await asyncio.start_server(
            self._handle_local, "127.0.0.1", self._local_port
        )
        port = self._local_server.sockets[0].getsockname()[1]
        self._callback_url = f"http://127.0.0.1:{port}"

    async def _start_online(self) -> None:
        errors: list[str] = []
        for server in self._servers:
            _log.info("oob_register_attempt", server=server)
            client = InteractshClient()
            try:
                registered = await client.register(server)
                callback_url = await client.url()
            except Exception as exc:  # noqa: BLE001 - se prueba el siguiente
                _log.error(
                    "oob_register_failed",
                    server=server,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
                errors.append(f"{server}: {exc}")
                try:
                    await client.close()
                except Exception:
                    pass
                continue

            self._client = client
            self._server = registered
            self._callback_url = callback_url
            self._error = None
            _log.info(
                "oob_registered",
                server=registered,
                callback_url=callback_url,
            )
            self._poll_task = asyncio.create_task(
                self._poll_online(client), name="prox0x-oob-poll"
            )
            return
        raise OOBError(
            "No se pudo registrar en ningún servidor Interactsh: "
            + ("; ".join(errors) or "sin servidores disponibles")
        )

    def _interaction_record(
        self, interaction: InteractshInteraction
    ) -> dict[str, Any]:
        timestamp = interaction.timestamp
        created = (
            timestamp.isoformat()
            if isinstance(timestamp, datetime)
            else datetime.now(timezone.utc).isoformat()
        )
        return {
            "mode": "online",
            "protocol": interaction.protocol,
            "unique_id": interaction.unique_id,
            "full_id": interaction.full_id,
            "remote_address": interaction.remote_address,
            "raw_request": interaction.raw_request,
            "raw_response": interaction.raw_response,
            "created_at": created,
        }

    async def _poll_online(self, client: InteractshClient) -> None:
        while True:
            await asyncio.sleep(self._poll_interval)
            _log.info("oob_poll_cycle", server=self._server)
            try:
                interactions = await client.poll()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - se reporta y se reintenta
                self._error = f"poll Interactsh ({self._server}): {exc}"
                _log.error(
                    "oob_poll_failed",
                    server=self._server,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
                continue

            if self._error is not None and self._error.startswith("poll Interactsh"):
                self._error = None
            if interactions:
                _log.info(
                    "oob_poll_interactions",
                    server=self._server,
                    count=len(interactions),
                )
            for interaction in interactions:
                self._record(self._interaction_record(interaction))

    def _interaction_matches(self, marker: str) -> bool:
        store = self._store()
        if store is None:
            return False
        for item in store.recent_oob_interactions(50):
            haystack = " ".join(
                str(item.get(key) or "")
                for key in ("full_id", "raw_request", "raw_response")
            )
            if marker in haystack:
                return True
        return False

    async def test_connectivity(self, timeout: float = 20.0) -> dict[str, Any]:
        """Envía un callback real y espera a que aparezca por polling."""
        client = self._client
        if self._mode != "online" or client is None:
            raise OOBError("cambia a modo online antes de probar conectividad")
        marker = f"prox0x-check-{uuid.uuid4().hex[:12]}"
        try:
            callback_url = await client.url()
        except Exception as exc:  # noqa: BLE001
            return {
                "ok": False,
                "server": self._server,
                "callback_url": "",
                "detail": f"No se pudo generar la URL de prueba: {exc}",
            }
        test_url = f"{callback_url}/{marker}?ts={uuid.uuid4().hex[:8]}"
        _log.info("oob_connectivity_request", url=test_url, server=self._server)

        status_code: int | None = None
        try:
            connector = aiohttp.TCPConnector(ssl=verified_ssl_context())
            async with aiohttp.ClientSession(
                headers={"User-Agent": "prox0x-connectivity/1.0"},
                connector=connector,
            ) as session:
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    status_code = response.status
                    await response.read()
        except Exception as exc:  # noqa: BLE001
            _log.error(
                "oob_connectivity_send_failed",
                url=test_url,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return {
                "ok": False,
                "server": self._server,
                "callback_url": test_url,
                "detail": f"No se pudo enviar el callback: {exc}",
            }

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        last_error: str | None = None
        while loop.time() < deadline:
            if self._interaction_matches(marker):
                self._error = None
                _log.info(
                    "oob_connectivity_ok",
                    url=test_url,
                    server=self._server,
                )
                return {
                    "ok": True,
                    "server": self._server,
                    "callback_url": test_url,
                    "detail": "Callback recibido y descifrado correctamente",
                    "status_code": status_code,
                }
            try:
                interactions = await client.poll()
                for interaction in interactions:
                    self._record(self._interaction_record(interaction))
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
                _log.error(
                    "oob_connectivity_poll_failed",
                    server=self._server,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
            if self._interaction_matches(marker):
                self._error = None
                return {
                    "ok": True,
                    "server": self._server,
                    "callback_url": test_url,
                    "detail": "Callback recibido y descifrado correctamente",
                    "status_code": status_code,
                }
            await asyncio.sleep(1.0)

        detail = (
            f"El callback respondió HTTP {status_code}, pero no apareció en "
            "el servidor de interacciones."
        )
        if last_error:
            detail += f" Último error de polling: {last_error}"
        _log.error(
            "oob_connectivity_timeout",
            server=self._server,
            url=test_url,
            error=detail,
        )
        return {
            "ok": False,
            "server": self._server,
            "callback_url": test_url,
            "detail": detail,
            "status_code": status_code,
        }

    async def _handle_local(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            try:
                head = await asyncio.wait_for(
                    reader.readuntil(b"\r\n\r\n"), timeout=5
                )
            except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                return
            lines = head[:-4].split(b"\r\n")
            start_line = lines[0].decode("latin-1", errors="replace")
            headers: dict[str, str] = {}
            for line in lines[1:]:
                name, separator, value = line.partition(b":")
                if separator:
                    headers[name.decode("latin-1").lower()] = value.decode(
                        "latin-1"
                    ).strip()
            length = min(
                int(headers.get("content-length", "0") or "0"),
                _MAX_BODY,
            )
            body = await reader.readexactly(length) if length else b""
            raw = (head + body).decode("latin-1", errors="replace")
            peer = writer.get_extra_info("peername")
            remote = peer[0] if peer else ""
            path = start_line.split(" ")[1] if " " in start_line else "/"
            self._record(
                {
                    "mode": "local",
                    "protocol": "http",
                    "unique_id": uuid.uuid4().hex[:12],
                    "full_id": path[:300],
                    "remote_address": remote,
                    "raw_request": raw[:16_384],
                    "raw_response": "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: 2\r\n"
                b"Connection: close\r\n\r\nok"
            )
            await writer.drain()
        except (ConnectionError, OSError, ssl.SSLError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError, ssl.SSLError):
                pass

    def status(self) -> dict:
        store = self._store()
        interactions = (
            len(store.recent_oob_interactions(1)) if store is not None else 0
        )
        return {
            "mode": self._mode,
            "callback_url": self._callback_url,
            "running": bool(self._callback_url),
            "error": self._error,
            "server": self._server,
            "local_port": self._local_port,
            "last_interactions": interactions,
        }
