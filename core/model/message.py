"""Mensaje HTTP inmutable: base de ``Request`` y ``Response`` (Plan.md §7.3).

Invariante central (Plan.md §7.5.1, byte-fidelidad): ``raw`` guarda los bytes
exactos y ``body_offset`` el offset del cuerpo dentro de ``raw``. Toda edición
(``with_header`` / ``with_body``) genera un **objeto nuevo** con ``raw``
recalculado; este permanece intacto como `original`.

Cuerpo y *chunked* (Plan.md §3.4.2): ``body`` guarda el cuerpo **decodificado**
para mostrar/editar; si el mensaje tiene ``Transfer-Encoding: chunked``, al
serializar se vuelve a *encuadrar* en trozos. El crudo original se conserva en
``raw``.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Self
from urllib.parse import urlsplit

from .annotations import Annotations
from .headers import Header
from .params import (
    Param,
    ParamType,
    parse_body_params,
    parse_cookie_params,
    parse_json_params,
    parse_query_params,
    parse_set_cookie_params,
)
from .service import HttpService

_CHUNK_SIZE = 8_192
_HTTP_VERSIONS = frozenset({"HTTP/1.0", "HTTP/1.1", "HTTP/2"})


@dataclass(frozen=True, slots=True)
class Range:
    """Rango semiabierto ``[start, end)`` sobre los bytes de un mensaje.

    Es la base de ``markers`` (resaltados) y de las posiciones de Intruder
    (Plan.md §5.3).
    """

    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start < 0:
            raise ValueError(f"start negativo: {self.start}")
        if self.end < self.start:
            raise ValueError(f"end ({self.end}) < start ({self.start})")

    @property
    def length(self) -> int:
        return self.end - self.start

    def contains(self, offset: int) -> bool:
        return self.start <= offset < self.end

    def overlaps(self, other: "Range") -> bool:
        return self.start < other.end and other.start < self.end


def _head_bytes(headers: tuple[Header, ...]) -> bytes:
    """Cabeceras serializadas + línea en blanco separadora."""
    return b"".join(header.to_bytes() for header in headers) + b"\r\n"


def _is_chunked(headers: tuple[Header, ...]) -> bool:
    for header in headers:
        if header.lowercase_name == "transfer-encoding" and "chunked" in header.value.lower():
            return True
    return False


def _frame_chunked(body: bytes) -> bytes:
    """Encuadra un cuerpo decodificado en formato *chunked* (RFC 9112 §7.1)."""
    if not body:
        return b"0\r\n\r\n"
    out = bytearray()
    offset = 0
    length = len(body)
    while offset < length:
        block = body[offset : offset + _CHUNK_SIZE]
        out += f"{len(block):x}\r\n".encode("ascii")
        out += block + b"\r\n"
        offset += _CHUNK_SIZE
    out += b"0\r\n\r\n"
    return bytes(out)


def _with_content_length(headers: tuple[Header, ...], length: int) -> tuple[Header, ...]:
    """Sustituye ``Content-Length`` (primera aparición) y elimina duplicados."""
    replacement = Header("Content-Length", str(length))
    out: list[Header] = []
    replaced = False
    for header in headers:
        if header.lowercase_name == "content-length":
            if not replaced:
                out.append(replacement)
                replaced = True
        else:
            out.append(header)
    if not replaced:
        out.append(replacement)
    return tuple(out)


def serialize_head(headers: tuple[Header, ...]) -> bytes:
    """Cabeceras + línea en blanco, listas para la red (sin línea de inicio)."""
    return _head_bytes(headers)


def serialize_body(headers: tuple[Header, ...], body: bytes) -> bytes:
    """Cuerpo listo para la red: re-chunkea si el mensaje lo pide (§3.4.2)."""
    return _frame_chunked(body) if _is_chunked(headers) else body


@dataclass(frozen=True, slots=True, kw_only=True)
class Message:
    """Mensaje HTTP genérico (petición o respuesta) inmutable.

    Campos del contrato (Plan.md §7.3). Se construye por keyword (``kw_only``)
    para que la posición de 7+ campos no sea una fuente de errores.
    """

    raw: bytes
    headers: tuple[Header, ...]
    body: bytes
    body_offset: int
    version: str  # "HTTP/1.0" | "HTTP/1.1" | "HTTP/2"
    markers: tuple[Range, ...] = ()
    annotations: Annotations = Annotations()

    def __post_init__(self) -> None:
        if not isinstance(self.raw, bytes) or not isinstance(self.body, bytes):
            raise TypeError("raw y body deben ser bytes")
        if not isinstance(self.headers, tuple):
            raise TypeError("headers debe ser una tupla (el orden es el contrato)")
        if not isinstance(self.markers, tuple):
            raise TypeError("markers debe ser una tupla")
        if self.version not in _HTTP_VERSIONS:
            raise ValueError(f"versión HTTP no soportada: {self.version!r}")
        if not 0 <= self.body_offset <= len(self.raw):
            raise ValueError(f"body_offset {self.body_offset} fuera del raw ({len(self.raw)} bytes)")

    # ------------------------------------------------------------------ consultas

    def header(self, name: str) -> str | None:
        """Valor de la primera cabecera con ese nombre (sin distinguir caja)."""
        wanted = name.lower()
        for header in self.headers:
            if header.lowercase_name == wanted:
                return header.value
        return None

    def has_header(self, name: str) -> bool:
        return self.header(name) is not None

    @property
    def is_chunked(self) -> bool:
        return _is_chunked(self.headers)

    def _start_line(self) -> bytes:
        """Línea de inicio del mensaje en la red (vacía en la clase base)."""
        return b""

    def to_bytes(self) -> bytes:
        """Serializa el mensaje completo (línea de inicio + cabeceras + cuerpo)."""
        body = _frame_chunked(self.body) if self.is_chunked else self.body
        return self._start_line() + _head_bytes(self.headers) + body

    # --------------------------------------------------------------- mutaciones

    def with_header(self, name: str, value: str) -> "Message":
        """Copia con la cabecera ``name`` puesta a ``value``.

        - Si ya existe (sin distinguir caja), sustituye el valor **en su
          posición** y elimina duplicados posteriores con ese nombre.
        - Si no existe, la añade al final.
        - ``raw`` y ``body_offset`` se recalculan.
        """
        wanted = name.lower()
        replacement = Header(name, value)
        out: list[Header] = []
        replaced = False
        for header in self.headers:
            if header.lowercase_name == wanted:
                if not replaced:
                    out.append(replacement)
                    replaced = True
            else:
                out.append(header)
        if not replaced:
            out.append(replacement)
        return self._rebuild(headers=tuple(out))

    def without_header(self, name: str) -> "Message":
        """Copia sin la cabecera ``name`` (elimina todas sus apariciones).

        ``raw`` y ``body_offset`` se recalculan; el cuerpo no cambia.
        """
        wanted = name.lower()
        headers = tuple(
            header for header in self.headers if header.lowercase_name != wanted
        )
        if len(headers) == len(self.headers):
            return self
        return self._rebuild(headers=headers)

    def with_body(self, body: bytes) -> "Message":
        """Copia con un cuerpo nuevo y ``Content-Length`` recalculado.

        - Con ``Transfer-Encoding: chunked`` **no** se toca ``Content-Length``:
          el cuerpo se re-*chunkea* al serializar (Plan.md §7.5.3).
        - El llamante debe evitar esto en mensajes sin cuerpo real
          (respuestas a ``HEAD``, 1xx/204/304), donde añadir cabeceras de
          cuerpo sería incorrecto.
        """
        if self.is_chunked:
            return self._rebuild(body=body)
        return self._rebuild(body=body, headers=_with_content_length(self.headers, len(body)))

    def _rebuild(
        self,
        *,
        headers: tuple[Header, ...] | None = None,
        body: bytes | None = None,
    ) -> Self:
        """Construye una copia coherente con ``raw`` y ``body_offset`` recalculados.

        Funciona también para subclases: ``dataclasses.replace`` conserva los
        campos propios de ``Request`` / ``Response``.
        """
        new_headers = self.headers if headers is None else headers
        new_body = self.body if body is None else body
        head = self._start_line() + _head_bytes(new_headers)
        wire_body = _frame_chunked(new_body) if _is_chunked(new_headers) else new_body
        return replace(
            self,
            headers=new_headers,
            body=new_body,
            raw=head + wire_body,
            body_offset=len(head),
        )

    # -------------------------------------------------------------- parámetros

    def _url_params(self) -> tuple[Param, ...]:
        """Parámetros de URL (solo ``Request``)."""
        return ()

    def _cookie_params(self) -> tuple[Param, ...]:
        """Parámetros de cookie del mensaje."""
        return ()

    def params(self, type: ParamType | None = None) -> tuple[Param, ...]:
        """Parámetros del mensaje, opcionalmente de un tipo concreto.

        Con ``type=None`` devuelve todos los tipos soportados. ``XML``,
        ``XML_ATTRIBUTE`` y ``MULTIPART_ATTRIBUTE`` están pendientes de F3.
        """
        unsupported = (
            ParamType.XML,
            ParamType.XML_ATTRIBUTE,
            ParamType.MULTIPART_ATTRIBUTE,
        )
        if type in unsupported:
            raise NotImplementedError(f"parseo de {type.value} pendiente de F3 (Intruder)")

        collected: list[Param] = []
        if type is None or type is ParamType.URL:
            collected += self._url_params()
        if type is None or type is ParamType.BODY:
            collected += parse_body_params(self.body, self.header("Content-Type"))
        if type is None or type is ParamType.COOKIE:
            collected += self._cookie_params()
        if type is None or type is ParamType.JSON:
            collected += parse_json_params(self.body)
        return tuple(collected)

    def param(self, name: str, type: ParamType) -> Param | None:
        """Primer parámetro con ese nombre y tipo, o ``None``."""
        for param in self.params(type):
            if param.name == name:
                return param
        return None


@dataclass(frozen=True, slots=True, kw_only=True)
class Request(Message):
    """Petición HTTP.

    ``target`` es el request-target tal cual llegó (forma de origen `/a?b=1`,
    forma absoluta `http://host/a` para proxy, o forma de autoridad `host:443`
    para ``CONNECT``).
    """

    method: str
    target: str
    http_service: HttpService | None = None

    def __post_init__(self) -> None:
        Message.__post_init__(self)
        if not self.method or not self.method.strip():
            raise ValueError("method no puede estar vacío")
        if not self.target or not self.target.strip():
            raise ValueError("target no puede estar vacío")

    @property
    def path(self) -> str:
        """Path del request-target (vacío para ``CONNECT``, que es authority-form)."""
        if self.method.upper() == "CONNECT":
            return ""
        return urlsplit(self.target).path

    @property
    def query(self) -> str:
        """Query del request-target sin el signo ``?``."""
        if self.method.upper() == "CONNECT":
            return ""
        return urlsplit(self.target).query

    def _url_params(self) -> tuple[Param, ...]:
        return parse_query_params(self.target)

    def _start_line(self) -> bytes:
        return f"{self.method} {self.target} {self.version}\r\n".encode("latin-1")

    def with_target(self, target: str) -> "Request":
        """Copia con otro request-target y ``raw`` recalculado."""
        return replace(self, target=target)._rebuild()

    def with_method(self, method: str) -> "Request":
        """Copia con otro método HTTP y ``raw`` recalculado."""
        return replace(self, method=method)._rebuild()

    def _cookie_params(self) -> tuple[Param, ...]:
        return parse_cookie_params(self.header("Cookie"))


@dataclass(frozen=True, slots=True, kw_only=True)
class Response(Message):
    """Respuesta HTTP."""

    status_code: int
    reason: str = ""

    def __post_init__(self) -> None:
        Message.__post_init__(self)
        if not 100 <= self.status_code <= 599:
            raise ValueError(f"código de estado fuera de rango: {self.status_code}")

    @property
    def status_line(self) -> str:
        """Línea de estado completa (`HTTP/1.1 200 OK`)."""
        return f"{self.version} {self.status_code} {self.reason}".rstrip()

    def _start_line(self) -> bytes:
        return (self.status_line + "\r\n").encode("latin-1")

    def _cookie_params(self) -> tuple[Param, ...]:
        values = [h.value for h in self.headers if h.lowercase_name == "set-cookie"]
        return parse_set_cookie_params(values)
