"""Plantilla de ataque: bytes + posiciones de inserción (Plan.md §5.3).

La plantilla **no** usa marcadores textuales en tiempo de ataque: guarda el
mensaje base y los offsets semiabiertos ``[start, end)`` de cada posición. Un
payload puede contener cualquier byte (incluido el marcador) sin ambigüedad.

La sustitución se aplica **de derecha a izquierda** para que los offsets de las
posiciones anteriores sigan siendo válidos aunque cambie la longitud.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import combinations
from urllib.parse import unquote_plus

from core.model import ParamType, Request
from core.net.wire import parse_request, split_head_body

_JSON_STRING = re.compile(rb'"((?:[^"\\]|\\.)*)"')


@dataclass(frozen=True, slots=True)
class InsertionPoint:
    """Una posición de inserción dentro de la plantilla."""

    index: int
    start: int
    end: int
    base_value: bytes
    name: str = ""
    param_type: ParamType | None = None

    def __post_init__(self) -> None:
        if self.index < 0:
            raise ValueError(f"índice de posición negativo: {self.index}")
        if self.start < 0:
            raise ValueError(f"start negativo: {self.start}")
        if self.end < self.start:
            raise ValueError(f"end ({self.end}) < start ({self.start})")

    @property
    def length(self) -> int:
        return self.end - self.start

    def overlaps(self, other: "InsertionPoint") -> bool:
        return self.start < other.end and other.start < self.end


@dataclass(frozen=True, slots=True)
class RequestTemplate:
    """Mensaje base + posiciones; el motor de ataque solo necesita esto."""

    base: bytes
    points: tuple[InsertionPoint, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.base, bytes):
            raise TypeError("base debe ser bytes")
        if not isinstance(self.points, tuple):
            raise TypeError("points debe ser una tupla")
        expected = tuple(range(len(self.points)))
        if tuple(point.index for point in self.points) != expected:
            raise ValueError("los índices de las posiciones deben ser 0..N-1")
        for point in self.points:
            if not 0 <= point.start <= point.end <= len(self.base):
                raise ValueError(
                    f"posición {point.index} fuera de la plantilla "
                    f"({point.start}..{point.end} de {len(self.base)} bytes)"
                )
            if self.base[point.start : point.end] != point.base_value:
                raise ValueError(
                    f"base_value de la posición {point.index} no coincide con la plantilla"
                )
        for left, right in combinations(self.points, 2):
            if left.overlaps(right):
                raise ValueError(
                    f"posiciones solapadas: {left.index} y {right.index}"
                )

    # ------------------------------------------------------------ propiedades

    @property
    def offsets(self) -> tuple[tuple[int, int], ...]:
        return tuple((point.start, point.end) for point in self.points)

    @property
    def position_count(self) -> int:
        return len(self.points)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(point.name for point in self.points)

    def subset(self, indices: Sequence[int]) -> "RequestTemplate":
        """Nueva plantilla con solo las posiciones indicadas (reindexadas)."""
        chosen: list[InsertionPoint] = []
        seen: set[int] = set()
        for index in indices:
            if not 0 <= index < len(self.points):
                raise ValueError(
                    f"posición {index} fuera de rango (0..{len(self.points) - 1})"
                )
            if index in seen:
                continue
            seen.add(index)
            chosen.append(self.points[index])
        if not chosen:
            raise ValueError("la selección de posiciones está vacía")
        points = tuple(
            InsertionPoint(
                index=new_index,
                start=point.start,
                end=point.end,
                base_value=point.base_value,
                name=point.name,
                param_type=point.param_type,
            )
            for new_index, point in enumerate(chosen)
        )
        return RequestTemplate(base=self.base, points=points)

    # -------------------------------------------------------------- construcción

    @classmethod
    def from_request(
        cls,
        request: Request,
        offsets: Sequence[tuple[int, int]],
        *,
        names: Sequence[str] | None = None,
        types: Sequence[ParamType | None] | None = None,
    ) -> "RequestTemplate":
        """Construye una plantilla a partir de offsets sobre ``request.to_bytes()``."""
        if request.is_chunked:
            raise ValueError(
                "los cuerpos chunked no son soportados por el Intruder (F3); "
                "normaliza el cuerpo antes de atacar"
            )
        base = request.to_bytes()
        name_list = list(names) if names is not None else [
            f"pos{index}" for index in range(len(offsets))
        ]
        type_list = list(types) if types is not None else [None] * len(offsets)
        if len(name_list) != len(offsets) or len(type_list) != len(offsets):
            raise ValueError("names/types deben tener la misma longitud que offsets")

        points: list[InsertionPoint] = []
        for index, (start, end) in enumerate(offsets):
            if not 0 <= start <= end <= len(base):
                raise ValueError(f"offset {index} fuera de la petición")
            points.append(
                InsertionPoint(
                    index=index,
                    start=start,
                    end=end,
                    base_value=base[start:end],
                    name=name_list[index],
                    param_type=type_list[index],
                )
            )
        return cls(base=base, points=tuple(points))

    from_offsets = from_request

    @classmethod
    def from_markers(
        cls, request: Request, *, marker: str = "§"
    ) -> "RequestTemplate":
        """Extrae posiciones delimitadas por ``marker`` y las elimina del base.

        Ejemplo: ``GET /?q=§prox0x§ HTTP/1.1`` deja la posición sobre ``prox0x``.
        """
        marker_bytes = marker.encode("utf-8")
        if not marker_bytes:
            raise ValueError("el marcador no puede estar vacío")
        raw = request.to_bytes()
        # El wire puede mezclar latin-1 (línea de inicio/cabeceras) y UTF-8
        # (cuerpo editado en la UI). Acepta ambos marcadores en el mismo texto.
        variants = [marker_bytes]
        try:
            latin = marker.encode("latin-1")
        except UnicodeEncodeError:
            latin = None
        if latin and latin not in variants:
            variants.append(latin)
        variants = sorted(set(variants), key=len, reverse=True)
        out = bytearray()
        ranges: list[tuple[int, int]] = []
        inside = False
        start = 0
        index = 0
        while index < len(raw):
            matched = next(
                (
                    candidate
                    for candidate in variants
                    if raw.startswith(candidate, index)
                ),
                None,
            )
            if matched is not None:
                if not inside:
                    start = len(out)
                    inside = True
                else:
                    ranges.append((start, len(out)))
                    inside = False
                index += len(matched)
                continue
            out.append(raw[index])
            index += 1
        if inside:
            raise ValueError("marcador de apertura sin cierre")
        if not ranges:
            raise ValueError(f"no hay posiciones delimitadas por {marker!r}")

        points = tuple(
            InsertionPoint(
                index=position,
                start=range_start,
                end=range_end,
                base_value=bytes(out[range_start:range_end]),
                name=f"pos{position}",
            )
            for position, (range_start, range_end) in enumerate(ranges)
        )
        return cls(base=bytes(out), points=points)

    @classmethod
    def auto(
        cls,
        request: Request,
        *,
        names: Sequence[str] | None = None,
    ) -> "RequestTemplate":
        """Detecta posiciones en URL, body urlencoded, cookies y JSON.

        ``names`` filtra por nombre de parámetro (útil para
        ``--position user``). Si no se detecta ninguna posición, falla con un
        mensaje explícito para que el usuario marque posiciones a mano.
        """
        if request.is_chunked:
            raise ValueError(
                "los cuerpos chunked no son soportados por el Intruder (F3)"
            )
        base = request.to_bytes()
        head, body = split_head_body(base)
        body_offset = len(base) - len(body)

        ranges: list[tuple[int, int, str, ParamType | None]] = []
        ranges.extend(_url_ranges(base, request))
        ranges.extend(_body_ranges(body, body_offset, request))
        ranges.extend(_cookie_ranges(head))
        ranges.extend(_json_ranges(body, body_offset, request))

        if names is not None:
            wanted = set(names)
            ranges = [item for item in ranges if item[2] in wanted]
        if not ranges:
            raise ValueError(
                "no se encontraron posiciones; usa --position o marca la "
                "petición con §valor§"
            )

        ranges.sort(key=lambda item: item[0])
        points = tuple(
            InsertionPoint(
                index=index,
                start=start,
                end=end,
                base_value=base[start:end],
                name=name,
                param_type=param_type,
            )
            for index, (start, end, name, param_type) in enumerate(ranges)
        )
        return cls(base=base, points=points)

    # ------------------------------------------------------------------ build

    def build_bytes(self, values: Mapping[int, bytes]) -> bytes:
        """Sustituye las posiciones indicadas y devuelve los bytes resultantes."""
        known = {point.index for point in self.points}
        unknown = set(values) - known
        if unknown:
            raise ValueError(f"posiciones desconocidas: {sorted(unknown)}")

        data = self.base
        # De derecha a izquierda: los offsets anteriores no se desplazan.
        for point in sorted(self.points, key=lambda item: item.start, reverse=True):
            if point.index not in values:
                continue
            payload = values[point.index]
            if not isinstance(payload, bytes):
                raise TypeError("los payloads deben ser bytes")
            data = data[: point.start] + payload + data[point.end :]
        return data

    def build_request(self, values: Mapping[int, bytes]) -> Request:
        """Construye la ``Request`` final, recalculando ``Content-Length``."""
        parsed = parse_request(self.build_bytes(values))
        if parsed.body or parsed.has_header("Content-Length") or parsed.is_chunked:
            # El cuerpo cambió de tamaño: recalcula el framing del mensaje.
            parsed = parsed.with_body(parsed.body)
        return parsed


# --------------------------------------------------------------- auto-detección


def _segments(data: bytes, separator: bytes = b"&"):
    """Segmentos y su offset dentro de ``data``."""
    offset = 0
    for segment in data.split(separator):
        yield offset, segment
        offset += len(segment) + len(separator)


def _url_ranges(
    base: bytes, request: Request
) -> list[tuple[int, int, str, ParamType | None]]:
    line_end = base.find(b"\r\n")
    if line_end == -1:
        line_end = len(base)
    first_line = base[:line_end]
    prefix = request.method.encode("latin-1") + b" "
    if not first_line.startswith(prefix):
        return []
    target_end = first_line.rfind(b" ")
    if target_end <= len(prefix):
        return []
    target = first_line[len(prefix) : target_end]
    target_offset = len(prefix)
    question = target.find(b"?")
    if question == -1:
        return []
    query = target[question + 1 :]
    query_offset = target_offset + question + 1

    ranges: list[tuple[int, int, str, ParamType | None]] = []
    for segment_offset, segment in _segments(query):
        name_raw, separator, value_raw = segment.partition(b"=")
        if not separator:
            continue
        start = query_offset + segment_offset + len(name_raw) + 1
        end = start + len(value_raw)
        ranges.append(
            (
                start,
                end,
                unquote_plus(name_raw.decode("latin-1")),
                ParamType.URL,
            )
        )
    return ranges


def _body_ranges(
    body: bytes, body_offset: int, request: Request
) -> list[tuple[int, int, str, ParamType | None]]:
    content_type = (request.header("Content-Type") or "").lower()
    if not body or "application/x-www-form-urlencoded" not in content_type:
        return []
    ranges: list[tuple[int, int, str, ParamType | None]] = []
    for segment_offset, segment in _segments(body):
        name_raw, separator, value_raw = segment.partition(b"=")
        if not separator:
            continue
        start = body_offset + segment_offset + len(name_raw) + 1
        end = start + len(value_raw)
        ranges.append(
            (
                start,
                end,
                unquote_plus(name_raw.decode("latin-1")),
                ParamType.BODY,
            )
        )
    return ranges


def _cookie_ranges(head: bytes) -> list[tuple[int, int, str, ParamType | None]]:
    ranges: list[tuple[int, int, str, ParamType | None]] = []
    line_offset = 0
    for line in head.split(b"\r\n"):
        name, separator, value = line.partition(b":")
        if separator and name.strip().lower() == b"cookie":
            stripped = value.lstrip()
            value_offset = line_offset + len(name) + 1 + (len(value) - len(stripped))
            for segment_offset, segment in _segments(stripped, b";"):
                cookie_name, cookie_sep, cookie_value = segment.partition(b"=")
                if not cookie_sep:
                    continue
                leading = len(cookie_value) - len(cookie_value.lstrip())
                value_bytes = cookie_value.strip()
                start = (
                    value_offset
                    + segment_offset
                    + len(cookie_name)
                    + 1
                    + leading
                )
                ranges.append(
                    (
                        start,
                        start + len(value_bytes),
                        cookie_name.strip().decode("latin-1"),
                        ParamType.COOKIE,
                    )
                )
        line_offset += len(line) + 2  # CRLF
    return ranges


def _json_ranges(
    body: bytes, body_offset: int, request: Request
) -> list[tuple[int, int, str, ParamType | None]]:
    content_type = (request.header("Content-Type") or "").lower()
    if not body or "json" not in content_type:
        return []

    ranges: list[tuple[int, int, str, ParamType | None]] = []
    for match in _JSON_STRING.finditer(body):
        after = body[match.end() :].lstrip()
        if after.startswith(b":"):
            continue  # es una clave, no un valor
        start = body_offset + match.start(1)
        end = body_offset + match.end(1)
        ranges.append((start, end, f"json[{len(ranges)}]", ParamType.JSON))
    return ranges
