"""Parser/serializador de peticiones en texto (wire) para herramientas manuales.

El Proxy parsea con ``h11``; Repeater e Intruder, en cambio, reciben texto que
el usuario edita o genera. Este módulo convierte esos bytes en un ``Request``
inmutable conservando el cuerpo tal cual y normalizando solo las cabeceras.
"""

from __future__ import annotations

from core.model import Header, Request, Response

from .content_encoding import is_decodable


def split_head_body(raw: bytes) -> tuple[bytes, bytes]:
    """Separa cabeceras y cuerpo aceptando CRLF o LF como separador."""
    for separator in (b"\r\n\r\n", b"\n\n"):
        if separator in raw:
            head, _, body = raw.partition(separator)
            return head, body
    return raw, b""


def normalize_head(head: bytes) -> bytes:
    """Unifica los fines de línea de la zona de cabeceras (no toca el cuerpo)."""
    return head.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def parse_request(raw: bytes) -> Request:
    """Convierte una petición en texto (CRLF o LF) en un ``Request`` inmutable.

    Normaliza solo la zona de cabeceras (fin de línea y espacios tras ``:``);
    el cuerpo se conserva byte a byte.
    """
    if not raw.strip():
        raise ValueError("la petición está vacía")

    head, body = split_head_body(raw)
    lines = normalize_head(head).split(b"\n")
    start = lines[0].strip()
    parts = start.split(b" ", 2)
    if len(parts) != 3:
        raise ValueError(
            "línea de inicio inválida; se esperaba 'MÉTODO TARGET VERSIÓN'"
        )
    method, target, version = (part.decode("latin-1") for part in parts)
    if not method or not target or not version:
        raise ValueError("línea de inicio incompleta")

    headers: list[Header] = []
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        name, separator, value = line.partition(b":")
        if not separator:
            raise ValueError(f"cabecera sin ':' → {line!r}")
        headers.append(
            Header(
                name.decode("latin-1").strip(),
                value.decode("latin-1").strip(),
            )
        )

    # Si el usuario editó una petición que la UI mostró descomprimida, el cuerpo
    # ya no está comprimido: mantener ``Content-Encoding`` haría que el origen
    # intentara descomprimir texto plano y devolviera un error.
    encoding = next(
        (header.value for header in headers if header.lowercase_name == "content-encoding"),
        None,
    )
    if encoding and (not body or not is_decodable(body, encoding)):
        headers = [
            header for header in headers if header.lowercase_name != "content-encoding"
        ]
        headers = [
            Header("Content-Length", str(len(body)))
            if header.lowercase_name == "content-length"
            else header
            for header in headers
        ]

    start_line = f"{method} {target} {version}\r\n".encode("latin-1")
    head_bytes = (
        start_line + b"".join(header.to_bytes() for header in headers) + b"\r\n"
    )
    return Request(
        raw=head_bytes + body,
        headers=tuple(headers),
        body=body,
        body_offset=len(head_bytes),
        version=version,
        method=method,
        target=target,
    )


def parse_response(raw: bytes) -> Response:
    """Convierte una respuesta en texto (CRLF o LF) en un ``Response`` inmutable."""
    if not raw.strip():
        raise ValueError("la respuesta está vacía")

    head, body = split_head_body(raw)
    lines = normalize_head(head).split(b"\n")
    start = lines[0].strip()
    parts = start.split(b" ", 2)
    if len(parts) < 2:
        raise ValueError("línea de estado inválida")
    version = parts[0].decode("latin-1")
    try:
        status = int(parts[1])
    except ValueError as exc:
        raise ValueError(f"código de estado inválido: {parts[1]!r}") from exc
    reason = parts[2].decode("latin-1") if len(parts) > 2 else ""

    headers: list[Header] = []
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        name, separator, value = line.partition(b":")
        if not separator:
            raise ValueError(f"cabecera sin ':' → {line!r}")
        headers.append(
            Header(
                name.decode("latin-1").strip(),
                value.decode("latin-1").strip(),
            )
        )

    start_line = f"{version} {status} {reason}".rstrip().encode("latin-1") + b"\r\n"
    head_bytes = (
        start_line + b"".join(header.to_bytes() for header in headers) + b"\r\n"
    )
    return Response(
        raw=head_bytes + body,
        headers=tuple(headers),
        body=body,
        body_offset=len(head_bytes),
        version=version,
        status_code=status,
        reason=reason,
    )
