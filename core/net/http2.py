"""Traducción entre HTTP/2 y el modelo interno (Plan.md §3.4.3).

Reglas clave:

- Los pseudo-headers (``:method``, ``:path``, ``:scheme``, ``:authority``) no
  forman parte de ``headers``: se traducen a ``Request.method/target`` y a la
  cabecera ``Host`` del modelo.
- ``Connection``, ``Keep-Alive``, ``TE``, ``Transfer-Encoding``, ``Upgrade`` y
  las cabeceras nominadas en ``Connection`` son ilegales en HTTP/2 y se filtran.
- La versión del modelo es ``"HTTP/2"``.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from core.model import Header, HttpService, Request, Response

PSEUDO_HEADERS = frozenset(
    {b":method", b":path", b":scheme", b":authority", b":status"}
)
FORBIDDEN_HEADERS = frozenset(
    {
        b"connection",
        b"keep-alive",
        b"proxy-connection",
        b"proxy-authenticate",
        b"proxy-authorization",
        b"te",
        b"trailer",
        b"transfer-encoding",
        b"upgrade",
    }
)


def _connection_tokens(headers: Iterable[tuple[bytes, bytes]]) -> set[bytes]:
    tokens: set[bytes] = set()
    for name, value in headers:
        if name.lower() == b"connection":
            for token in value.split(b","):
                token = token.strip().lower()
                if token:
                    tokens.add(token)
    return tokens


def filter_h2_headers(
    headers: Iterable[tuple[bytes, bytes]],
) -> list[tuple[bytes, bytes]]:
    """Quita pseudo-headers y cabeceras ilegales en HTTP/2."""
    source = list(headers)
    nominated = _connection_tokens(source)
    filtered: list[tuple[bytes, bytes]] = []
    for name, value in source:
        lowered = name.lower()
        if lowered in PSEUDO_HEADERS:
            continue
        if lowered in FORBIDDEN_HEADERS:
            continue
        if lowered in nominated:
            continue
        filtered.append((lowered, value))
    return filtered


def origin_path(request: Request) -> bytes:
    if request.target == "*":
        return b"*"
    path = request.path or "/"
    query = request.query
    return (f"{path}?{query}" if query else path).encode("latin-1")


def h2_request_headers(
    request: Request, service: HttpService
) -> list[tuple[bytes, bytes]]:
    """Cabeceras de una ``Request`` para enviarla por HTTP/2."""
    headers: list[tuple[bytes, bytes]] = [
        (b":method", request.method.encode("latin-1")),
        (b":scheme", b"https" if service.secure else b"http"),
        (b":authority", service.authority.encode("latin-1")),
        (b":path", origin_path(request)),
    ]
    regular: list[tuple[bytes, bytes]] = []
    for header in request.headers:
        lowered = header.lowercase_name.encode("latin-1")
        if lowered in {b"host", b"content-length"}:
            continue
        regular.append((lowered, header.value.encode("latin-1")))
    if request.body or request.has_header("Content-Length") or request.is_chunked:
        regular.append((b"content-length", str(len(request.body)).encode("ascii")))
    return headers + filter_h2_headers(regular)


def request_from_h2(
    headers: Sequence[tuple[bytes, bytes]],
    body: bytes,
    service: HttpService,
) -> Request:
    """Convierte headers/body de un stream HTTP/2 en una ``Request`` inmutable."""
    pseudo: dict[bytes, bytes] = {}
    regular: list[Header] = []
    for name, value in headers:
        lowered = name.lower()
        if lowered in PSEUDO_HEADERS:
            pseudo[lowered] = value
        elif lowered in FORBIDDEN_HEADERS:
            continue
        else:
            regular.append(
                Header(lowered.decode("latin-1"), value.decode("latin-1"))
            )

    method = pseudo.get(b":method", b"GET").decode("latin-1")
    target = pseudo.get(b":path", b"/").decode("latin-1")
    if b":authority" in pseudo:
        host_value = pseudo[b":authority"].decode("latin-1")
        regular = [header for header in regular if header.lowercase_name != "host"]
        regular.append(Header("Host", host_value))

    start_line = f"{method} {target} HTTP/2\r\n".encode("latin-1")
    head = start_line + b"".join(header.to_bytes() for header in regular) + b"\r\n"
    return Request(
        raw=head + body,
        headers=tuple(regular),
        body=body,
        body_offset=len(head),
        version="HTTP/2",
        method=method,
        target=target,
        http_service=service,
    )


def response_from_h2(
    headers: Sequence[tuple[bytes, bytes]], body: bytes
) -> Response:
    """Convierte headers/body de una respuesta HTTP/2 en ``Response``."""
    status = 200
    regular: list[Header] = []
    for name, value in headers:
        lowered = name.lower()
        if lowered == b":status":
            status = int(value.decode("ascii"))
        elif lowered in FORBIDDEN_HEADERS or lowered in PSEUDO_HEADERS:
            continue
        else:
            regular.append(
                Header(lowered.decode("latin-1"), value.decode("latin-1"))
            )

    start_line = f"HTTP/2 {status}\r\n".encode("ascii")
    head = start_line + b"".join(header.to_bytes() for header in regular) + b"\r\n"
    return Response(
        raw=head + body,
        headers=tuple(regular),
        body=body,
        body_offset=len(head),
        version="HTTP/2",
        status_code=status,
        reason="",
    )


def h2_response_headers(
    response: Response, *, request_method: str
) -> tuple[list[tuple[bytes, bytes]], bool]:
    """Cabeceras para responder por HTTP/2 y si el stream no lleva cuerpo."""
    headers: list[tuple[bytes, bytes]] = [
        (b":status", str(response.status_code).encode("ascii"))
    ]
    for header in response.headers:
        lowered = header.lowercase_name.encode("latin-1")
        if lowered in FORBIDDEN_HEADERS or lowered == b"content-length":
            continue
        headers.append((lowered, header.value.encode("latin-1")))

    bodyless = (
        request_method.upper() == "HEAD"
        or response.status_code < 200
        or response.status_code in (204, 304)
    )
    if (not bodyless or request_method.upper() == "HEAD") and (
        response.body or response.has_header("Content-Length")
    ):
        headers.append((b"content-length", str(len(response.body)).encode("ascii")))
    return headers, bodyless
