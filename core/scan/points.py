"""Descubrimiento y mutación de puntos de inyección (Fase 0).

Cubre query, formularios urlencoded, JSON anidado, cookies y las cabeceras
comunes que utilizan escáneres comerciales (``User-Agent``, ``Referer`` y
``X-Forwarded-For``). El diseño es inmutable: cada payload devuelve un
``Request`` nuevo y conserva el resto de parámetros/cabeceras.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from core.model import Request

# Cabeceras que no deben recibir payloads: o son estructurales, o ya se
# atacan por otra vía (Cookie), o romperían la petición.
_EXCLUDED_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "content-type",
        "cookie",
        "connection",
        "transfer-encoding",
        "accept-encoding",
        "expect",
    }
)

_HEADER_DEFAULTS: dict[str, str] = {
    "user-agent": "prox0x-scanner/1.0",
    "referer": "http://prox0x.invalid/",
    "x-forwarded-for": "127.0.0.1",
}


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Límites y switches del escáner activo.

    Los defaults reproducen el comportamiento histórico (concurrencia 5,
    throttle 50 ms) y añaden los nuevos puntos de inyección.
    """

    include_query: bool = True
    include_form: bool = True
    include_json: bool = True
    include_cookies: bool = True
    include_headers: bool = True

    header_names: tuple[str, ...] = (
        "User-Agent",
        "Referer",
        "X-Forwarded-For",
    )

    max_params: int = 32
    max_requests: int = 240
    concurrency: int = 5
    throttle_ms: float = 50.0
    intensity: str = "medium"

    canary_prefix: str = "xss_canary"
    time_based_threshold_ms: float = 4_000.0
    time_based_baseline_ms: float = 1_500.0

    def __post_init__(self) -> None:
        if self.max_params < 0:
            raise ValueError("max_params no puede ser negativo")
        if self.max_requests < 0:
            raise ValueError("max_requests no puede ser negativo")
        if self.concurrency < 1:
            raise ValueError("concurrency debe ser >= 1")
        if self.throttle_ms < 0:
            raise ValueError("throttle_ms no puede ser negativo")
        if self.intensity not in ("low", "medium", "high"):
            raise ValueError("intensity debe ser low, medium o high")
        if self.time_based_threshold_ms <= 0:
            raise ValueError("time_based_threshold_ms debe ser > 0")
        if self.time_based_baseline_ms < 0:
            raise ValueError("time_based_baseline_ms no puede ser negativo")


# Presupuesto por flujo y agresividad de red según la intensidad. ``high``
# necesita cubrir varias decenas de puntos con todos los payloads; ``low``
# mantiene el escaneo rápido y discreto.
_INTENSITY_PRESETS: dict[str, dict[str, float | int]] = {
    "low": {
        "max_requests": 1_200,
        "concurrency": 4,
        "throttle_ms": 60.0,
    },
    "medium": {
        "max_requests": 3_500,
        "concurrency": 6,
        "throttle_ms": 40.0,
    },
    "high": {
        "max_requests": 6_000,
        "concurrency": 8,
        "throttle_ms": 25.0,
    },
}


def config_for_intensity(
    intensity: str,
    **overrides: object,
) -> ScanConfig:
    """Devuelve un ``ScanConfig`` con los límites del nivel solicitado.

    Los overrides permiten ajustar casos concretos (tests, escaneos de un solo
    flujo) sin duplicar la política de intensidad en la API.
    """

    if intensity not in _INTENSITY_PRESETS:
        raise ValueError("intensity debe ser low, medium o high")
    values: dict[str, object] = {
        "max_params": 32,
        **_INTENSITY_PRESETS[intensity],
        "intensity": intensity,
    }
    values.update(overrides)
    return ScanConfig(**values)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class ScanParam:
    """Punto de inyección localizado."""

    location: str  # url | form | json | cookie | header
    name: str
    index: int
    value: str
    json_path: tuple[str | int, ...] = ()


@dataclass(frozen=True, slots=True)
class ScanJob:
    """Payload concreto que se enviará sobre un punto."""

    request: Request
    param: ScanParam
    attack: str  # xss | sqli | command | traversal
    payload: str
    context: str = ""
    canary: str = ""
    technique: str = ""
    pair_id: str = ""


@dataclass(frozen=True, slots=True)
class PointProbe:
    """Resultado de la petición de control (canary + baseline SQLi)."""

    param: ScanParam
    canary: str
    response_body: str | None
    sql_markers: frozenset[str]
    xss_contexts: tuple[str, ...]
    baseline_length: int = 0
    baseline_status: int = 0
    baseline_elapsed_ms: float | None = None


def is_valid_header_value(value: str) -> bool:
    """Indica si ``value`` puede viajar como valor de cabecera HTTP/1.1.

    h11 rechaza espacios al principio/final, CR/LF y caracteres fuera de
    latin-1. Filtrar antes de construir el job evita errores de protocolo y
    peticiones que no llevan realmente el payload.
    """

    if value != value.strip():
        return False
    if any(char in value for char in "\r\n\0"):
        return False
    try:
        value.encode("latin-1")
    except UnicodeEncodeError:
        return False
    return True


def _content_type(request: Request) -> str:
    return (request.header("Content-Type") or "").split(";", 1)[0].strip().lower()


def _decode_body(body: bytes) -> str:
    return body[: 1024 * 1024].decode("utf-8", errors="replace")


def _is_json(content_type: str) -> bool:
    return content_type == "application/json" or content_type.endswith("+json")


def _iter_json(
    node: object,
    path: tuple[str | int, ...],
    name: str,
    out: list[ScanParam],
    limit: int,
) -> None:
    if len(out) >= limit:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            child_name = f"{name}.{key}" if name else str(key)
            _iter_json(value, path + (key,), child_name, out, limit)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            child_name = f"{name}[{index}]"
            _iter_json(value, path + (index,), child_name, out, limit)
    else:
        value = node if isinstance(node, str) else json.dumps(
            node, ensure_ascii=False
        )
        out.append(
            ScanParam(
                location="json",
                name=name or "$",
                index=len(out),
                value=str(value),
                json_path=path,
            )
        )


def _json_points(request: Request, limit: int) -> list[ScanParam]:
    if not request.body or not _is_json(_content_type(request)):
        return []
    try:
        data = json.loads(_decode_body(request.body))
    except ValueError:
        return []
    points: list[ScanParam] = []
    _iter_json(data, (), "", points, limit)
    return points


def _cookie_points(request: Request) -> list[ScanParam]:
    raw = request.header("Cookie")
    if not raw:
        return []
    points: list[ScanParam] = []
    for index, part in enumerate(raw.split(";")):
        name, sep, value = part.partition("=")
        if sep and name.strip():
            points.append(
                ScanParam(
                    location="cookie",
                    name=name.strip(),
                    index=index,
                    value=value.strip(),
                )
            )
    return points


def _header_points(request: Request, names: tuple[str, ...]) -> list[ScanParam]:
    existing = {header.lowercase_name: header for header in request.headers}
    points: list[ScanParam] = []
    for index, name in enumerate(names):
        lower = name.lower()
        if lower in _EXCLUDED_HEADERS:
            continue
        header = existing.get(lower)
        points.append(
            ScanParam(
                location="header",
                name=header.name if header is not None else name,
                index=index,
                value=header.value if header is not None else _HEADER_DEFAULTS.get(lower, ""),
            )
        )
    return points


def discover_points(request: Request, config: ScanConfig) -> list[ScanParam]:
    """Devuelve los puntos de inyección soportados, sin duplicados."""

    params: list[ScanParam] = []

    if config.include_query:
        parts = urlsplit(request.target)
        for index, (name, value) in enumerate(
            parse_qsl(parts.query, keep_blank_values=True)
        ):
            params.append(ScanParam("url", name, index, value))

    content_type = _content_type(request)
    if config.include_form and content_type == "application/x-www-form-urlencoded" and request.body:
        for index, (name, value) in enumerate(
            parse_qsl(_decode_body(request.body), keep_blank_values=True)
        ):
            params.append(ScanParam("form", name, index, value))

    if config.include_json:
        params.extend(_json_points(request, config.max_params))

    if config.include_cookies:
        params.extend(_cookie_points(request))

    if config.include_headers:
        params.extend(_header_points(request, config.header_names))

    seen: set[tuple[str, str, int, tuple[str | int, ...]]] = set()
    unique: list[ScanParam] = []
    for param in params:
        key = (param.location, param.name, param.index, param.json_path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(param)
    return unique[: config.max_params]


def _set_json_path(node: object, path: tuple[str | int, ...], payload: str) -> bool:
    if not path:
        return False
    current = node
    for key in path[:-1]:
        if isinstance(current, dict) and key in current:
            current = current[key]
        elif isinstance(current, list) and isinstance(key, int) and 0 <= key < len(current):
            current = current[key]
        else:
            return False
    last = path[-1]
    if isinstance(current, dict) and last in current:
        current[last] = payload
        return True
    if isinstance(current, list) and isinstance(last, int) and 0 <= last < len(current):
        current[last] = payload
        return True
    return False


def _set_query(request: Request, param: ScanParam, payload: str) -> Request:
    parts = urlsplit(request.target)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if param.index >= len(pairs):
        return request
    pairs[param.index] = (param.name, payload)
    target = urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment)
    )
    return request.with_target(target)


def _set_form(request: Request, param: ScanParam, payload: str) -> Request:
    pairs = parse_qsl(_decode_body(request.body), keep_blank_values=True)
    if param.index >= len(pairs):
        return request
    pairs[param.index] = (param.name, payload)
    return request.with_body(urlencode(pairs).encode("utf-8"))


def _set_json(request: Request, param: ScanParam, payload: str) -> Request:
    try:
        data = json.loads(_decode_body(request.body))
    except ValueError:
        return request
    if not _set_json_path(data, param.json_path, payload):
        return request
    body = json.dumps(data, ensure_ascii=False).encode("utf-8")
    return request.with_body(body)


def _set_cookie(request: Request, param: ScanParam, payload: str) -> Request:
    raw = request.header("Cookie")
    if not raw:
        return request
    segments = raw.split(";")
    if param.index >= len(segments):
        return request
    # ``;`` separa cookies, así que el valor lógico se envía URL-encoded. Si el
    # servidor lo decodifica, el reflejo contiene el payload original.
    encoded = quote(payload, safe="")
    segments[param.index] = f"{param.name}={encoded}"
    value = "; ".join(segment.strip() for segment in segments)
    return request.with_header("Cookie", value)


def apply_payload(request: Request, param: ScanParam, payload: str) -> Request:
    """Copia la petición sustituyendo solo el punto indicado."""

    if param.location == "url":
        return _set_query(request, param, payload)
    if param.location == "form":
        return _set_form(request, param, payload)
    if param.location == "json":
        return _set_json(request, param, payload)
    if param.location == "cookie":
        return _set_cookie(request, param, payload)
    if param.location == "header":
        return request.with_header(param.name, payload)
    return request
