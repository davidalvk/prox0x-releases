"""Opciones de ejecución del motor (Plan.md §4.3, ``RequestOptions``).

Son agnósticas de producto: Repeater e Intruder las rellenan y el motor las
aplica. ``http_mode`` selecciona HTTP/1.1, HTTP/2 o AUTO; ``IN_SCOPE`` sigue
reservado a F5 (necesita el motor de scope).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class HttpMode(StrEnum):
    """Modo de protocolo solicitado para el envío."""

    AUTO = "auto"
    HTTP_1 = "http/1.1"
    HTTP_2 = "http/2"
    HTTP_2_IGNORE_ALPN = "http/2-ignore-alpn"


class RedirectMode(StrEnum):
    """Política de seguimiento de redirecciones (Plan.md §4.2)."""

    NEVER = "never"
    ALWAYS = "always"
    SAME_HOST = "same-host"
    IN_SCOPE = "in-scope"


@dataclass(frozen=True, slots=True, kw_only=True)
class RequestOptions:
    """Opciones de un envío del motor HTTP (Plan.md §4.3).

    ``connection_id`` se acepta por compatibilidad pero en F2 no hay pool: cada
    envío abre una conexión nueva y el motor avisa una vez por id.
    """

    http_mode: HttpMode = HttpMode.AUTO
    connection_id: str | None = None
    verify_upstream: bool = True
    redirect: RedirectMode = RedirectMode.NEVER
    sni: str | None = None
    timeout_ms: float = 60_000.0
    max_redirects: int = 10
    max_retries: int = 0
    retry_backoff_ms: float = 250.0
    throttle_ms: float = 0.0

    def __post_init__(self) -> None:
        if self.redirect is RedirectMode.IN_SCOPE:
            raise NotImplementedError("el modo de redirección IN_SCOPE llega con el scope (F5)")
        if self.timeout_ms <= 0:
            raise ValueError("timeout_ms debe ser > 0")
        if self.max_redirects < 0:
            raise ValueError("max_redirects no puede ser negativo")
        if self.max_retries < 0:
            raise ValueError("max_retries no puede ser negativo")
        if self.retry_backoff_ms < 0:
            raise ValueError("retry_backoff_ms no puede ser negativo")
        if self.throttle_ms < 0:
            raise ValueError("throttle_ms no puede ser negativo")
        if self.sni is not None and not self.sni.strip():
            raise ValueError("sni no puede ser una cadena vacía (usa None)")

    @property
    def timeout_s(self) -> float:
        return self.timeout_ms / 1000.0

    @property
    def throttle_s(self) -> float:
        return self.throttle_ms / 1000.0

    @property
    def retry_backoff_s(self) -> float:
        return self.retry_backoff_ms / 1000.0


@dataclass(frozen=True, slots=True)
class ExecutionStats:
    """Contadores del motor (Plan.md §5.3, ``ExecutionStats``).

    ``failed`` agrupa timeouts, fallos de conexión y de protocolo; ``cancelled``
    se contabiliza aparte para no confundir cancelación con error de red.
    """

    requested: int = 0
    completed: int = 0
    failed: int = 0
    cancelled: int = 0
    in_flight: int = 0
    elapsed_ms: float = 0.0
