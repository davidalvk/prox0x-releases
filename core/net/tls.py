"""Contexto TLS de cliente compartido por HTTP/1.1 y HTTP/2."""

from __future__ import annotations

import ssl

import certifi

from core.model import HttpService


def verified_ssl_context() -> ssl.SSLContext:
    """Contexto cliente con el bundle portable de certifi.

    PyInstaller no incluye por sí solo las CA del sistema operativo; usar
    ``certifi.where()`` garantiza que el binario encuentre un trust store
    incluso en un entorno limpio.
    """
    return ssl.create_default_context(cafile=certifi.where())


def client_context(
    service: HttpService, verify: bool, alpn: tuple[str, ...]
) -> ssl.SSLContext | None:
    """Contexto TLS de cliente, o ``None`` para HTTP plano."""
    if not service.secure:
        return None
    context = verified_ssl_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(list(alpn))
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context
