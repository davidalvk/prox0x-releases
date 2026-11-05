"""Servicio HTTP de destino: host, puerto, esquema y SNI (Plan.md §7.3)."""

from __future__ import annotations

from dataclasses import dataclass

_DEFAULT_PORTS = {False: 80, True: 443}


@dataclass(frozen=True, slots=True)
class HttpService:
    """Destino de una conexión.

    ``sni`` permite forzar un nombre distinto del host de conexión (útil contra
    virtual hosting y en Repeater); si es ``None``, se usa ``host``.
    """

    host: str
    port: int
    secure: bool
    sni: str | None = None

    def __post_init__(self) -> None:
        if not self.host or not self.host.strip():
            raise ValueError("host no puede estar vacío")
        if not 0 < self.port < 65_536:
            raise ValueError(f"puerto fuera de rango: {self.port}")
        if self.sni is not None and not self.sni.strip():
            raise ValueError("sni no puede ser una cadena vacía (usa None)")

    @property
    def authority(self) -> str:
        """``host`` sin el puerto por defecto del esquema (`host:puerto` si no es el habitual)."""
        if self.port == _DEFAULT_PORTS[self.secure]:
            return self.host
        return f"{self.host}:{self.port}"

    @property
    def effective_sni(self) -> str:
        """Nombre que se presenta en el handshake TLS saliente."""
        return self.sni if self.sni is not None else self.host

    def __str__(self) -> str:
        scheme = "https" if self.secure else "http"
        return f"{scheme}://{self.authority}"
