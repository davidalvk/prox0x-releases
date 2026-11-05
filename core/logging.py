"""Configuración global de logging estructurado con ``structlog``.

Los logs van a consola con renderizador development-friendly. En F5 se podrá
cambiar a JSON y añadir correlación por ``flow_id`` en el contexto.
"""

from __future__ import annotations

import logging

import structlog

_ASYNCIO_TLS_EOF_NOISE = "returning true from eof_received() has no effect when using ssl"


class _AsyncioTlsNoiseFilter(logging.Filter):
    """Silencia un aviso benigno y muy ruidoso de asyncio al cerrar túneles TLS.

    Cuando el cliente cierra un túnel con close_notify limpio,
    ``StreamReaderProtocol.eof_received()`` devuelve ``True`` (hay un writer
    vivo) y asyncio lo avisa **en cada cierre**. Es inocuo y satura la salida
    del proxy durante la navegación normal.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        return record.getMessage() != _ASYNCIO_TLS_EOF_NOISE


def configure_logging(level: str | int = "INFO") -> None:
    """Configura ``structlog`` para imprimir eventos estructurados por consola."""
    if isinstance(level, str):
        level = logging.getLevelName(level.upper())

    logging.getLogger("asyncio").addFilter(_AsyncioTlsNoiseFilter())

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str, **initial_fields: object) -> structlog.stdlib.BoundLogger:
    """Devuelve un logger estructurado con el nombre del módulo."""
    return structlog.get_logger(name).bind(**initial_fields)
