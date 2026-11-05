"""Motor de ejecución concurrente (Plan.md §4.4 y §7.2).

Un solo lugar para enviar peticiones: Repeater e Intruder comparten semántica
de concurrencia, tiempos, reintentos y cancelación. El motor **no** sabe qué
producto lo usa ni genera peticiones: recibe ``Request`` ya construidas.

Garantías de F2:

- ``Attempt.index`` es el índice de entrada y **nunca** se reordena.
- La concurrencia se limita con ``Semaphore``; el *throttle* espacia los
  lanzamientos sin ocupar el semáforo mientras se espera.
- Los reintentos solo cubren fallos de transporte/timeout, nunca respuestas
  HTTP (un 500 es una respuesta válida).
- La cancelación cooperativa (``asyncio.Event``) deja los intentos no
  iniciados como ``CANCELLED`` sin romper los que ya están en vuelo.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from urllib.parse import urljoin, urlsplit

from core.logging import get_logger
from core.model import Header, HttpService, Request, Response, Timing
from core.net.h2client import H2Pool

from .client import send_once
from .errors import EngineTimeout, ProtocolError, TransportError
from .options import ExecutionStats, RedirectMode, RequestOptions

_log = get_logger("prox0x.engine")

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class AttemptStatus(StrEnum):
    """Resultado de un intento (Plan.md §7.3, ``RequestStatus``)."""

    RESPONDED = "responded"
    TIMED_OUT = "timed_out"
    CONNECTION_FAILED = "connection_failed"
    PROTOCOL_ERROR = "protocol_error"
    CANCELLED = "cancelled"
    DROPPED = "dropped"  # reservado para el Intruder (F3)


@dataclass(frozen=True, slots=True, kw_only=True)
class Attempt:
    """Un envío concreto, identificado por su índice de lanzamiento."""

    index: int
    label: str = ""
    status: AttemptStatus = AttemptStatus.RESPONDED
    request: Request | None = None
    response: Response | None = None
    timing: Timing | None = None
    latency_ms: float = 0.0  # extremo a extremo (incluye conexión/TLS)
    peer_ip: str = ""
    redirects: tuple[str, ...] = ()
    retries: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is AttemptStatus.RESPONDED

    @property
    def status_code(self) -> int | None:
        return self.response.status_code if self.response is not None else None

    @property
    def request_bytes(self) -> int:
        return len(self.request.to_bytes()) if self.request is not None else 0

    @property
    def response_bytes(self) -> int:
        return len(self.response.to_bytes()) if self.response is not None else 0

    @property
    def ttfb_ms(self) -> float | None:
        return self.timing.ttfb_ms if self.timing is not None else None

    @property
    def total_ms(self) -> float | None:
        return self.timing.total_ms if self.timing is not None else None


def _wire_request(
    *, method: str, target: str, version: str, headers: tuple[Header, ...], body: bytes
) -> Request:
    """Construye un ``Request`` con ``raw``/``body_offset`` coherentes."""
    head = (
        f"{method} {target} {version}\r\n".encode("latin-1")
        + b"".join(header.to_bytes() for header in headers)
        + b"\r\n"
    )
    return Request(
        raw=head + body,
        headers=headers,
        body=body,
        body_offset=len(head),
        version=version,
        method=method,
        target=target,
    )


def _base_url(request: Request, service: HttpService) -> str:
    if request.target.startswith(("http://", "https://")):
        return request.target
    scheme = "https" if service.secure else "http"
    return f"{scheme}://{service.authority}{request.target}"


def build_redirect(
    request: Request, service: HttpService, response: Response
) -> tuple[Request, HttpService] | None:
    """Siguiente petición de una redirección, o ``None`` si no es seguible."""
    location = response.header("Location")
    if not location:
        return None
    parts = urlsplit(urljoin(_base_url(request, service), location))
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None

    secure = parts.scheme == "https"
    port = parts.port or (443 if secure else 80)
    same_host = parts.hostname.lower() == service.host.lower()
    new_service = HttpService(
        host=parts.hostname,
        port=port,
        secure=secure,
        sni=service.sni if same_host else None,
    )
    target = parts.path or "/"
    if parts.query:
        target += f"?{parts.query}"

    method = request.method
    body = request.body
    headers = [
        header
        for header in request.headers
        if header.lowercase_name not in {"host", "content-length", "transfer-encoding"}
    ]
    if response.status_code in (301, 302, 303) and method.upper() not in ("GET", "HEAD"):
        # Cambio a GET: se descarta el cuerpo y su metainformación.
        method = "GET"
        body = b""
        headers = [h for h in headers if h.lowercase_name != "content-type"]
    if not same_host:
        # No filtrar credenciales a otro host (buena práctica de redirecciones).
        headers = [h for h in headers if h.lowercase_name != "authorization"]
    headers.append(Header("Host", new_service.authority))

    new_request = _wire_request(
        method=method,
        target=target,
        version=request.version,
        headers=tuple(headers),
        body=body,
    )
    return (
        Request(
            raw=new_request.raw,
            headers=new_request.headers,
            body=new_request.body,
            body_offset=new_request.body_offset,
            version=new_request.version,
            method=new_request.method,
            target=new_request.target,
            http_service=new_service,
        ),
        new_service,
    )


class RequestEngine:
    """Ejecutor de peticiones HTTP/1.1 con orden estable de resultados."""

    def __init__(
        self,
        *,
        default_options: RequestOptions | None = None,
        max_concurrency: int = 8,
        auth_refresh: Callable[[Request, Response], Awaitable[Request | None]]
        | None = None,
    ) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency debe ser >= 1")
        self._default_options = default_options or RequestOptions()
        self._max_concurrency = max_concurrency
        self._auth_refresh = auth_refresh
        self._h2_pool = H2Pool()
        self._cancel = asyncio.Event()
        self._stats = ExecutionStats()
        self._started_at: float | None = None
        self._warned_connections: set[str] = set()

    # ------------------------------------------------------------------ estado

    @property
    def max_concurrency(self) -> int:
        return self._max_concurrency

    @property
    def stats(self) -> ExecutionStats:
        return self._stats

    def reset_stats(self) -> None:
        self._stats = ExecutionStats()
        self._started_at = None

    def cancel(self) -> None:
        """Solicita cancelar los envíos aún no iniciados (cooperativo)."""
        self._cancel.set()

    def reset_cancel(self) -> None:
        self._cancel.clear()

    async def aclose(self) -> None:
        """Cierra las conexiones HTTP/2 del pool (los sockets h1 son efímeros)."""
        await self._h2_pool.aclose()

    # ------------------------------------------------------------------ envío

    async def send(
        self,
        request: Request,
        service: HttpService,
        *,
        options: RequestOptions | None = None,
        label: str = "",
    ) -> Attempt:
        """Envía una petición y devuelve su ``Attempt`` (índice 0)."""
        opts = options or self._default_options
        self._note_connection_id(opts)
        return await self._run(0, request, service, opts, label, cancel=None)

    async def send_requests(
        self,
        requests: Sequence[Request],
        services: HttpService | Sequence[HttpService],
        *,
        options: RequestOptions | Sequence[RequestOptions] | None = None,
        concurrency: int | None = None,
        labels: Sequence[str] | None = None,
        cancel: asyncio.Event | None = None,
    ) -> list[Attempt]:
        """Envía N peticiones y devuelve los intentos **en orden de entrada**.

        ``concurrency`` limita los envíos simultáneos (por defecto el máximo del
        motor). ``cancel`` permite abortar los que aún no han empezado.
        """
        pending = list(requests)
        if not pending:
            return []

        if isinstance(services, HttpService):
            service_list = [services] * len(pending)
        else:
            service_list = list(services)
            if len(service_list) != len(pending):
                raise ValueError("services debe tener la misma longitud que requests")

        if options is None:
            option_list = [self._default_options] * len(pending)
        elif isinstance(options, RequestOptions):
            option_list = [options] * len(pending)
        else:
            option_list = list(options)
            if len(option_list) != len(pending):
                raise ValueError("options debe tener la misma longitud que requests")

        label_list = list(labels) if labels is not None else [""] * len(pending)
        if len(label_list) != len(pending):
            raise ValueError("labels debe tener la misma longitud que requests")

        limit = self._max_concurrency if concurrency is None else concurrency
        if limit < 1:
            raise ValueError("concurrency debe ser >= 1")
        limit = min(limit, len(pending))

        for opts in option_list:
            self._note_connection_id(opts)

        semaphore = asyncio.Semaphore(limit)
        gate = asyncio.Lock()
        next_start = 0.0

        async def one(index: int) -> Attempt:
            nonlocal next_start
            async with semaphore:
                opts = option_list[index]
                if opts.throttle_s > 0:
                    async with gate:
                        loop = asyncio.get_running_loop()
                        now = loop.time()
                        delay = next_start - now
                        next_start = max(now, next_start) + opts.throttle_s
                    if delay > 0:
                        await asyncio.sleep(delay)
                return await self._run(
                    index,
                    pending[index],
                    service_list[index],
                    opts,
                    label_list[index],
                    cancel=cancel,
                )

        async with asyncio.TaskGroup() as group:
            tasks = [group.create_task(one(index)) for index in range(len(pending))]

        return sorted((task.result() for task in tasks), key=lambda attempt: attempt.index)

    # ---------------------------------------------------------------- interno

    async def _run(
        self,
        index: int,
        request: Request,
        service: HttpService,
        options: RequestOptions,
        label: str,
        *,
        cancel: asyncio.Event | None,
    ) -> Attempt:
        self._begin()
        started = time.perf_counter()
        current_request = request
        current_service = service
        original_service = service
        redirects: list[str] = []
        retries = 0
        auth_retried = False
        status = AttemptStatus.CONNECTION_FAILED
        response: Response | None = None
        timing: Timing | None = None
        peer_ip = ""
        error: str | None = None

        try:
            while True:
                if self._is_cancelled(cancel):
                    status = AttemptStatus.CANCELLED
                    error = "cancelado antes del envío"
                    break
                try:
                    result = await send_once(
                        current_request,
                        current_service,
                        options=options,
                        h2_pool=self._h2_pool,
                    )
                except EngineTimeout as exc:
                    if retries < options.max_retries:
                        retries += 1
                        await asyncio.sleep(
                            options.retry_backoff_s * (2 ** (retries - 1))
                        )
                        continue
                    status = AttemptStatus.TIMED_OUT
                    error = str(exc)
                    break
                except TransportError as exc:
                    if retries < options.max_retries:
                        retries += 1
                        await asyncio.sleep(
                            options.retry_backoff_s * (2 ** (retries - 1))
                        )
                        continue
                    status = AttemptStatus.CONNECTION_FAILED
                    error = str(exc)
                    break
                except ProtocolError as exc:
                    status = AttemptStatus.PROTOCOL_ERROR
                    error = str(exc)
                    break
                except Exception as exc:  # noqa: BLE001 - un fallo no debe tumbar el lote
                    _log.exception("engine_unexpected_error", index=index)
                    status = AttemptStatus.CONNECTION_FAILED
                    error = f"error inesperado: {exc}"
                    break

                if (
                    result.response.status_code in (401, 403)
                    and self._auth_refresh is not None
                    and not auth_retried
                ):
                    try:
                        refreshed = await self._auth_refresh(
                            current_request, result.response
                        )
                    except Exception:
                        _log.exception("auth_refresh_failed", index=index)
                        refreshed = None
                    if refreshed is not None:
                        current_request = refreshed
                        auth_retried = True
                        continue

                if (
                    result.response.status_code in _REDIRECT_STATUSES
                    and options.redirect is not RedirectMode.NEVER
                ):
                    nxt = build_redirect(
                        current_request, current_service, result.response
                    )
                    if nxt is not None:
                        next_request, next_service = nxt
                        if self._follows(
                            options.redirect, original_service, next_service
                        ):
                            if len(redirects) < options.max_redirects:
                                current_request, current_service = next_request, next_service
                                redirects.append(
                                    _base_url(current_request, current_service)
                                )
                                continue
                            _log.warning(
                                "redirect_limit",
                                index=index,
                                max_redirects=options.max_redirects,
                            )

                response = result.response
                timing = result.timing
                peer_ip = result.peer_ip
                status = AttemptStatus.RESPONDED
                break
        except asyncio.CancelledError:
            status = AttemptStatus.CANCELLED
            error = "tarea cancelada"
            raise
        finally:
            self._end(status)

        return Attempt(
            index=index,
            label=label,
            status=status,
            request=current_request,
            response=response,
            timing=timing,
            latency_ms=(time.perf_counter() - started) * 1000,
            peer_ip=peer_ip,
            redirects=tuple(redirects),
            retries=retries,
            error=error,
        )

    def _is_cancelled(self, cancel: asyncio.Event | None) -> bool:
        return self._cancel.is_set() or (cancel is not None and cancel.is_set())

    @staticmethod
    def _follows(
        mode: RedirectMode, original: HttpService, target: HttpService
    ) -> bool:
        if mode is RedirectMode.NEVER:
            return False
        if mode is RedirectMode.ALWAYS:
            return True
        if mode is RedirectMode.SAME_HOST:
            return original.host.lower() == target.host.lower()
        return False

    def _note_connection_id(self, options: RequestOptions) -> None:
        connection_id = options.connection_id
        if not connection_id or connection_id in self._warned_connections:
            return
        self._warned_connections.add(connection_id)
        _log.warning(
            "connection_id_ignored",
            connection_id=connection_id,
            detail="F2 abre una conexión nueva por envío; el pool llega en F3/F4",
        )

    def _begin(self) -> None:
        now = time.perf_counter()
        if self._started_at is None:
            self._started_at = now
        stats = self._stats
        self._stats = replace(
            stats,
            requested=stats.requested + 1,
            in_flight=stats.in_flight + 1,
        )

    def _end(self, status: AttemptStatus) -> None:
        stats = self._stats
        elapsed = 0.0
        if self._started_at is not None:
            elapsed = (time.perf_counter() - self._started_at) * 1000
        self._stats = replace(
            stats,
            completed=stats.completed + (1 if status is AttemptStatus.RESPONDED else 0),
            failed=stats.failed
            + (
                1
                if status
                in {
                    AttemptStatus.TIMED_OUT,
                    AttemptStatus.CONNECTION_FAILED,
                    AttemptStatus.PROTOCOL_ERROR,
                }
                else 0
            ),
            cancelled=stats.cancelled + (1 if status is AttemptStatus.CANCELLED else 0),
            in_flight=max(0, stats.in_flight - 1),
            elapsed_ms=elapsed,
        )
