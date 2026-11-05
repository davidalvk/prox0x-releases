"""Arranque unificado del binario: Proxy + API/UI en un solo proceso.

El binario de PyInstaller no necesita procesos externos:

- El Proxy corre en un hilo con su propio event loop.
- Uvicorn sirve FastAPI + la UI React en ``127.0.0.1:8000``.
- El control de breakpoints/Scope/Match & Replace se hace **in-process**
  (sin socket Unix), por lo que funciona también en Windows.
- ``Ctrl+C`` detiene ambos servicios de forma ordenada.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import typer
import uvicorn

from api.control import ControlResponseError, ControlUnavailable
from api.main import create_app, ui_dist_directory
from core.ca import CaError, CaPassphraseError, CertificateAuthority
from core.config import (
    DEFAULT_FLOW_BUFFER,
    DEFAULT_HOST,
    DEFAULT_PORT,
    ENV_CA_PASSPHRASE,
    default_ca_dir,
    default_db_file,
    default_flows_file,
    default_match_replace_file,
    default_scope_file,
    default_state_dir,
    default_temporal_dir,
)
from core.store import FlowStore
from proxy import ProxyConfig, ProxyServer
from proxy.control import ControlCommandError, dispatch

DEFAULT_API_PORT = 8000


# ---------------------------------------------------------------- navegador
def _browser_environment() -> dict[str, str]:
    """Copia el entorno sin las rutas de librerías inyectadas por PyInstaller.

    PyInstaller añade directorios ``_MEI...`` a ``LD_LIBRARY_PATH``; al abrir
    xdg-open/kde-open con ese entorno, el lanzador del sistema carga el OpenSSL
    empaquetado y falla con símbolos incompatibles.
    """
    env = os.environ.copy()
    for name in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        value = env.get(name)
        if not value:
            continue
        paths = [
            path
            for path in value.split(os.pathsep)
            if path and "_MEI" not in path
        ]
        if paths:
            env[name] = os.pathsep.join(paths)
        else:
            env.pop(name, None)
    return env


def _try_open(command: list[str], env: dict[str, str]) -> bool:
    try:
        process = subprocess.Popen(
            command,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except (OSError, ValueError):
        return False
    try:
        return process.wait(timeout=3) == 0
    except subprocess.TimeoutExpired:
        # El navegador puede seguir abierto; el lanzador ya hizo su trabajo.
        return True


def _open_browser(url: str) -> bool:
    """Abre ``url`` con un lanzador del sistema usando un entorno limpio."""
    env = _browser_environment()

    if os.name == "nt":
        try:
            os.startfile(url)  # type: ignore[attr-defined]
            return True
        except (OSError, AttributeError):
            return _try_open(["cmd", "/c", "start", "", url], env)

    if sys.platform == "darwin":
        return _try_open(["open", url], env)

    wsl = False
    try:
        wsl = "microsoft" in Path("/proc/version").read_text(
            encoding="utf-8", errors="ignore"
        ).lower()
    except OSError:
        pass

    candidates: list[list[str]] = []
    if wsl:
        candidates.append(["wslview", url])
        candidates.append(["cmd.exe", "/c", "start", "", url])
    candidates.extend(
        [
            ["xdg-open", url],
            ["kde-open", url],
            ["gnome-open", url],
            ["gio", "open", url],
            ["sensible-browser", url],
            ["x-www-browser", url],
        ]
    )
    for command in candidates:
        if shutil.which(command[0]) is None:
            continue
        if _try_open(command, env):
            return True
    return False


# --------------------------------------------------------------------- CA
def _passphrase_path(ca_dir: Path) -> Path:
    return ca_dir / "passphrase"


def _write_passphrase(ca_dir: Path, passphrase: str) -> None:
    """Guarda la frase de paso con permisos 0600 para el siguiente arranque."""
    ca_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(ca_dir, 0o700)
    except OSError:
        pass
    path = _passphrase_path(ca_dir)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(passphrase + "\n")
    finally:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def _resolve_passphrase(explicit: str | None, ca_dir: Path) -> str:
    """Frase de paso: opción > entorno > archivo local > generación automática."""
    if explicit:
        return explicit

    from_env = os.environ.get(ENV_CA_PASSPHRASE)
    if from_env:
        return from_env

    path = _passphrase_path(ca_dir)
    if path.is_file():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return value

    if CertificateAuthority.exists(ca_dir):
        raise RuntimeError(
            "La CA ya existe en "
            f"{ca_dir}, pero no se encontró su frase de paso. "
            f"Define {ENV_CA_PASSPHRASE} o usa --passphrase."
        )

    # Primera ejecución: el binario genera y guarda una frase de paso propia.
    return secrets.token_hex(32)


# -------------------------------------------------------------------- proxy
class _ProxyThread(threading.Thread):
    """Hilo con event loop propio que sirve el Proxy hasta que se detiene."""

    def __init__(self, server: ProxyServer) -> None:
        super().__init__(name="prox0x-proxy", daemon=True)
        self.server = server
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.error: BaseException | None = None

    def run(self) -> None:  # noqa: D401 - contrato de Thread
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self.server.start())
        except BaseException as exc:  # noqa: BLE001 - se comunica al hilo principal
            self.error = exc
            self.ready.set()
            try:
                self.loop.run_until_complete(self.server.stop())
            except Exception:
                pass
            finally:
                self.loop.close()
            return

        self.ready.set()
        try:
            self.loop.run_forever()
        finally:
            try:
                self.loop.run_until_complete(self.server.stop())
            except Exception:
                pass
            finally:
                self.loop.close()

    def wait_ready(self, timeout: float = 20.0) -> None:
        if not self.ready.wait(timeout):
            raise RuntimeError("el Proxy no arrancó a tiempo")
        if self.error is not None:
            raise RuntimeError(f"no se pudo arrancar el Proxy: {self.error}")

    def stop(self) -> None:
        if self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.join(timeout=10)


# ------------------------------------------------------- control in-process
class InProcessControl:
    """Implementa la interfaz de ``ControlClient`` sin socket Unix.

    Los comandos se ejecutan en el event loop del Proxy para que
    ``BreakpointManager.resolve``/``Event.set`` ocurran en el hilo correcto.
    Las suscripciones hacen *polling* del estado; así no hay colas asyncio
    compartidas entre hilos y funciona igual en Linux, macOS y Windows.
    """

    def __init__(self, server: ProxyServer, loop: asyncio.AbstractEventLoop) -> None:
        self._server = server
        self._loop = loop

    async def _call(self, factory):
        if not self._loop.is_running():
            raise ControlUnavailable("el Proxy todavía no está en marcha")
        try:
            future = asyncio.run_coroutine_threadsafe(factory(), self._loop)
            return await asyncio.wrap_future(future)
        except ControlCommandError as exc:
            raise ControlResponseError(exc.detail, status=exc.status) from exc
        except RuntimeError as exc:
            raise ControlUnavailable(f"control local no disponible: {exc}") from exc

    async def request(self, command: str, **payload: Any) -> dict[str, Any]:
        async def run() -> dict[str, Any]:
            manager = self._server.breakpoints
            if manager is None:
                raise ControlUnavailable("breakpoints no disponibles")
            return await dispatch(
                manager,
                {"command": command, **payload},
                self._server.scope,
                self._server.match_replace,
                self._server._handle_project_load,
            )

        return await self._call(run)

    async def _snapshot(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        async def read():
            manager = self._server.breakpoints
            if manager is None:
                raise ControlUnavailable("breakpoints no disponibles")
            return manager.status(), manager.snapshot()

        return await self._call(read)

    async def subscribe(self):
        last_status: dict[str, Any] | None = None
        seen: dict[str, dict[str, Any]] = {}

        while True:
            status, pending = await self._snapshot()
            if status != last_status:
                yield {"type": "status", **status}
                last_status = status

            current: dict[str, dict[str, Any]] = {}
            for item in pending:
                key = str(item.get("id"))
                current[key] = item
                if seen.get(key) != item:
                    yield {"type": "breakpoint", "breakpoint": item}

            for key in list(seen):
                if key not in current:
                    yield {"type": "resolved", "id": key, "action": "unknown"}

            seen = current
            await asyncio.sleep(0.25)


# ------------------------------------------------------------------- start
def start_command(
    host: str = typer.Option(
        DEFAULT_HOST,
        "--host",
        help="Interfaz de escucha del Proxy (por seguridad, solo loopback)",
    ),
    proxy_port: int = typer.Option(
        DEFAULT_PORT, "--proxy-port", help="Puerto del Proxy"
    ),
    api_port: int = typer.Option(
        DEFAULT_API_PORT, "--api-port", help="Puerto de la UI/API"
    ),
    passphrase: str = typer.Option(
        None,
        "--passphrase",
        help=f"Frase de paso de la CA (o ${ENV_CA_PASSPHRASE})",
    ),
    insecure: bool = typer.Option(
        False,
        "--insecure",
        help="No verificar el certificado del origen (upstream)",
    ),
    no_browser: bool = typer.Option(
        False, "--no-browser", help="No abrir el navegador automáticamente"
    ),
) -> None:
    """Arranca Proxy + API/UI en un solo proceso y abre el navegador."""
    if api_port == proxy_port:
        raise typer.BadParameter("api-port y proxy-port deben ser distintos")
    if host not in ("127.0.0.1", "localhost", "::1"):
        typer.echo(
            f"⚠️  El Proxy escuchará en {host}: cualquier vecino de red podrá "
            "usarlo como open relay.",
            err=True,
        )
    if ui_dist_directory() is None:
        typer.echo(
            "Aviso: no hay UI compilada. En el repositorio ejecuta "
            "`cd ui && npm run build` o usa el binario de Release.",
            err=True,
        )

    ca_dir = default_ca_dir()
    try:
        ca_passphrase = _resolve_passphrase(passphrase, ca_dir)
        if CertificateAuthority.exists(ca_dir):
            ca = CertificateAuthority.load(ca_dir, ca_passphrase)
        else:
            typer.echo(f"No hay CA en {ca_dir}; generándola automáticamente…")
            ca = CertificateAuthority.init(ca_dir, ca_passphrase)
        _write_passphrase(ca_dir, ca_passphrase)
    except (RuntimeError, CaError, CaPassphraseError, ValueError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if ca.is_expired:
        typer.echo(
            "⚠️  La CA está caducada; regenera con `prox0x ca init --force`.",
            err=True,
        )

    # Temporal es efímero, igual que en start.sh.
    shutil.rmtree(default_temporal_dir(), ignore_errors=True)

    config = ProxyConfig(
        host=host,
        port=proxy_port,
        verify_upstream=not insecure,
        flows_file=default_flows_file(),
        db_file=default_db_file(),
        control_socket=None,
        embedded_control=True,
        scope_file=default_scope_file(),
        match_replace_file=default_match_replace_file(),
    )
    store = FlowStore(maxsize=DEFAULT_FLOW_BUFFER)
    proxy = ProxyServer(ca, store, config=config)

    stop_event = threading.Event()
    debug_signals = os.environ.get("PROX0X_DEBUG_SIGNALS") == "1"

    def _request_stop(_signum: int, _frame: object) -> None:
        stop_event.set()

    if debug_signals:
        typer.echo(
            "DEBUG signals antes: "
            f"thread={threading.current_thread().name} "
            f"main={threading.current_thread() is threading.main_thread()} "
            f"sigint={signal.getsignal(signal.SIGINT)!r}",
            err=True,
        )

    if threading.current_thread() is threading.main_thread():
        handled = [signal.SIGINT, signal.SIGTERM]
        if hasattr(signal, "SIGBREAK"):
            handled.append(signal.SIGBREAK)  # type: ignore[attr-defined]
        for sig in handled:
            try:
                signal.signal(sig, _request_stop)
            except (ValueError, OSError) as exc:
                if debug_signals:
                    typer.echo(
                        f"DEBUG signal {sig} no instalada: {exc}", err=True
                    )

    if debug_signals:
        typer.echo(
            f"DEBUG signals después: sigint={signal.getsignal(signal.SIGINT)!r}",
            err=True,
        )

    proxy_thread = _ProxyThread(proxy)
    proxy_thread.start()
    typer.echo("Arrancando Proxy…")
    try:
        proxy_thread.wait_ready()
    except RuntimeError as exc:
        proxy_thread.stop()
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    control = InProcessControl(proxy, proxy_thread.loop)
    app = create_app(
        control=control,
        allowed_ws_origins={
            f"http://127.0.0.1:{api_port}",
            f"http://localhost:{api_port}",
        },
    )
    uvicorn_config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=api_port,
        log_level="info",
        loop="asyncio",
        http="h11",
        ws="auto",
        lifespan="on",
        access_log=False,
    )
    api_server = uvicorn.Server(uvicorn_config)
    # Uvicorn no puede instalar signal handlers fuera del hilo principal.
    api_server.install_signal_handlers = lambda: None  # type: ignore[method-assign]

    api_thread = threading.Thread(
        target=api_server.run, name="prox0x-api", daemon=True
    )
    api_thread.start()
    typer.echo("Arrancando API/UI…")

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if api_server.started:
            break
        if not api_thread.is_alive():
            break
        time.sleep(0.1)

    if not api_server.started:
        api_server.should_exit = True
        api_thread.join(timeout=5)
        proxy_thread.stop()
        typer.echo(
            f"Error: la API/UI no pudo arrancar en 127.0.0.1:{api_port}. "
            "Revisa si el puerto está ocupado.",
            err=True,
        )
        raise typer.Exit(code=1)

    url = f"http://127.0.0.1:{api_port}"
    typer.echo(
        "\nprox0x listo:\n"
        f"  UI/API: {url}\n"
        f"  Proxy:  http://{host}:{proxy.port}\n"
        f"  Datos:  {default_state_dir()}\n"
        "  Ctrl+C para detener.\n"
    )

    if not no_browser and os.environ.get("PROX0X_NO_BROWSER") != "1":
        if not _open_browser(url):
            typer.echo(
                "No se pudo abrir el navegador automáticamente. "
                f"Por favor, abre manualmente {url}"
            )

    exit_code = 0
    try:
        while not stop_event.is_set():
            if not proxy_thread.is_alive():
                if proxy_thread.error is not None:
                    typer.echo(
                        f"El Proxy se detuvo: {proxy_thread.error}", err=True
                    )
                    exit_code = 1
                break
            if not api_thread.is_alive():
                typer.echo("La API/UI se detuvo.", err=True)
                exit_code = 1
                break
            stop_event.wait(0.5)
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        if stop_event.is_set():
            typer.echo("\nDeteniendo prox0x…")
        api_server.should_exit = True
        api_thread.join(timeout=10)
        proxy_thread.stop()

    if exit_code:
        raise typer.Exit(code=exit_code)
