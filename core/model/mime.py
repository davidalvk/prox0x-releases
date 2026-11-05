"""Tipos MIME detectados en el historial (Plan.md §3.3).

La detección vive en el modelo, no en la UI, para que el filtrado sea eficiente
y consistente entre módulos (Plan.md §3.5).
"""

from __future__ import annotations

from enum import Enum


class MimeType(Enum):
    """MIME del historial. ``NONE`` = desconocido / no detectado."""

    NONE = ""
    PLAIN_TEXT = "text/plain"
    HTML = "text/html"
    JAVASCRIPT = "text/javascript"
    CSS = "text/css"
    CSV = "text/csv"
    SSE = "text/event-stream"
    JSON = "application/json"
    XML = "application/xml"
    YAML = "application/yaml"
    FORM = "application/x-www-form-urlencoded"
    MULTIPART = "multipart/form-data"
    PDF = "application/pdf"
    ZIP = "application/zip"
    GZIP = "application/gzip"
    BINARY = "application/octet-stream"
    PNG = "image/png"
    JPEG = "image/jpeg"
    GIF = "image/gif"
    SVG = "image/svg+xml"
    ICO = "image/x-icon"
    WOFF = "font/woff"
    WOFF2 = "font/woff2"

    @classmethod
    def from_content_type(cls, content_type: str | None) -> "MimeType":
        """Detecta el MIME a partir de una cabecera ``Content-Type``.

        Ignora parámetros (`; charset=utf-8`), normaliza a minúsculas y cubre
        los sufijos registrados `+json` / `+xml` (p. ej. `application/vnd.api+json`).
        """
        if not content_type:
            return cls.NONE
        essence = content_type.split(";", 1)[0].strip().lower()
        if not essence:
            return cls.NONE
        exact = {m.value: m for m in cls if m.value}
        if essence in exact:
            return exact[essence]
        if essence.endswith("+json"):
            return cls.JSON
        if essence.endswith("+xml"):
            return cls.XML
        return cls.NONE
