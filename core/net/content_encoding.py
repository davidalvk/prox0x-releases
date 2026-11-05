"""Descompresión de cuerpos HTTP para la representación que ve la UI.

El Proxy conserva siempre los bytes originales (``raw``) para reenviarlos al
navegador. Este módulo solo produce una *vista* descomprimida que la API entrega
a la interfaz, de modo que un ``Content-Encoding: gzip`` no aparezca como
contenido binario ilegible.

Soporta ``gzip``/``x-gzip``, ``deflate`` (zlib y raw) y ``br`` (si el paquete
``brotli`` está instalado). Los cuerpos que superan ``MAX_DECODED_BYTES`` se
descartan para evitar *gzip bombs* en la UI.
"""

from __future__ import annotations

import zlib

MAX_DECODED_BYTES = 32 * 1024 * 1024

_SUPPORTED = frozenset({"gzip", "x-gzip", "deflate", "br"})
_IGNORED = frozenset({"identity"})


class ContentDecodingError(ValueError):
    """El cuerpo no se puede descomprimir con la codificación indicada."""


def content_encoding_tokens(value: str | None) -> tuple[str, ...]:
    """Tokens de ``Content-Encoding`` en orden de aplicación (sin ``identity``)."""
    if not value:
        return ()
    tokens = [token.strip().lower() for token in value.split(",")]
    return tuple(token for token in tokens if token and token not in _IGNORED)


def decode_content(
    body: bytes,
    content_encoding: str | None,
    *,
    max_bytes: int = MAX_DECODED_BYTES,
) -> bytes | None:
    """Devuelve el cuerpo descomprimido o ``None`` si no hay nada que hacer.

    Lanza ``ContentDecodingError`` si la codificación no está soportada o el
    cuerpo no es válido para ella. Las codificaciones se aplican en orden, por
    lo que se deshacen en orden inverso (RFC 9110 §8.4).
    """
    tokens = content_encoding_tokens(content_encoding)
    if not body or not tokens:
        return None
    data = body
    for token in reversed(tokens):
        data = _decode_one(data, token, max_bytes)
    return data


def is_decodable(body: bytes, content_encoding: str | None) -> bool:
    """``True`` si ``body`` es realmente válido para ``content_encoding``."""
    try:
        return decode_content(body, content_encoding) is not None
    except ContentDecodingError:
        return False


def _decode_one(data: bytes, token: str, max_bytes: int) -> bytes:
    if token not in _SUPPORTED:
        raise ContentDecodingError(f"codificación no soportada: {token!r}")

    if token in ("gzip", "x-gzip"):
        return _inflate(data, 16 + zlib.MAX_WBITS, max_bytes, token)

    if token == "deflate":
        errors: list[Exception] = []
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                return _inflate(data, wbits, max_bytes, token)
            except ContentDecodingError as exc:
                errors.append(exc)
        raise ContentDecodingError(
            f"cuerpo deflate inválido: {errors[-1] if errors else 'sin detalle'}"
        )

    # Brotli: dependencia opcional para no obligar a compilarla en instalaciones
    # mínimas. Si no está, la UI simplemente muestra los bytes originales.
    try:
        import brotli
    except ImportError as exc:  # pragma: no cover - depende del entorno
        raise ContentDecodingError("brotli no está instalado") from exc

    try:
        decoded = brotli.decompress(data)
    except Exception as exc:  # brotli.error no siempre expone una base común
        raise ContentDecodingError(f"cuerpo brotli inválido: {exc}") from exc
    if len(decoded) > max_bytes:
        raise ContentDecodingError(
            f"cuerpo descomprimido excede el límite de {max_bytes} bytes"
        )
    return decoded


def _inflate(data: bytes, wbits: int, max_bytes: int, label: str) -> bytes:
    decompressor = zlib.decompressobj(wbits)
    try:
        output = decompressor.decompress(data, max_bytes + 1)
        if len(output) > max_bytes or decompressor.unconsumed_tail:
            raise ContentDecodingError(
                f"cuerpo descomprimido excede el límite de {max_bytes} bytes"
            )
        output += decompressor.flush()
    except zlib.error as exc:
        raise ContentDecodingError(f"cuerpo {label} inválido: {exc}") from exc
    if len(output) > max_bytes:
        raise ContentDecodingError(
            f"cuerpo descomprimido excede el límite de {max_bytes} bytes"
        )
    if not decompressor.eof:
        raise ContentDecodingError(f"cuerpo {label} incompleto")
    return output
