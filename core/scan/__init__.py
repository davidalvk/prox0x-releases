"""Primitivas del Escáner Activo (Fase 0).

El paquete separa dos responsabilidades:

- ``points``: descubrir puntos de inyección y aplicar payloads preservando el
  resto de la petición (query, form, JSON anidado, cookies y cabeceras).
- ``detection``: firmas, contextos XSS y reglas de evidencia.

``core.active_scanner`` sigue siendo la fachada pública que usa la API.
"""

from .crawler import (
    CrawlPage,
    CrawlResult,
    Crawler,
    CrawlerConfig,
    FormField,
    FormInfo,
    extract_js_urls,
    normalize_url,
)
from .points import (
    PointProbe,
    ScanConfig,
    ScanJob,
    ScanParam,
    apply_payload,
    discover_points,
    is_valid_header_value,
)

__all__ = [
    "CrawlPage",
    "CrawlResult",
    "Crawler",
    "CrawlerConfig",
    "FormField",
    "FormInfo",
    "PointProbe",
    "ScanConfig",
    "ScanJob",
    "ScanParam",
    "apply_payload",
    "discover_points",
    "extract_js_urls",
    "is_valid_header_value",
    "normalize_url",
]
