"""Errores del motor de ejecución.

La jerarquía separa **transporte** (reintentable) de **protocolo** (no
reintentable) y de **configuración** (error del llamante). El motor traduce
cada uno a un ``AttemptStatus`` distinto para que Repeater/Intruder puedan
decidir sin inspeccionar excepciones.
"""

from __future__ import annotations


class EngineError(Exception):
    """Error base del motor."""


class TransportError(EngineError):
    """Fallo de red/TLS: conexión rechazada, reset, DNS, etc."""


class EngineTimeout(TransportError):
    """El origen no respondió dentro del ``timeout_ms``."""


class ProtocolError(EngineError):
    """El peer violó HTTP/1.1 (respuesta malformada, cierre a mitad, etc.)."""


class ConfigurationError(EngineError, ValueError):
    """Opción inválida o no soportada todavía."""
