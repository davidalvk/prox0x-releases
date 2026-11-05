"""Parseo de parámetros consciente del formato (Plan.md §3.3).

Los parámetros se parsean por tipo (URL, BODY, COOKIE, JSON…), no con una sola
heurística: es el requisito para que Intruder genere posiciones con sentido
(Plan.md §5.2) y para que el Repeater permita editar por parámetro.

Pendiente (F3, junto al Intruder): ``XML``, ``XML_ATTRIBUTE`` y
``MULTIPART_ATTRIBUTE``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Iterable
from urllib.parse import parse_qsl

# Guardia DoS: una URL o body no debe tener un número ilimitado de campos.
_MAX_FIELDS = 10_000


class ParamType(Enum):
    """Tipos de parámetro soportados por el parser HTTP (Plan.md §3.3)."""

    URL = "URL"
    BODY = "BODY"
    COOKIE = "COOKIE"
    XML = "XML"
    XML_ATTRIBUTE = "XML_ATTRIBUTE"
    MULTIPART_ATTRIBUTE = "MULTIPART_ATTRIBUTE"
    JSON = "JSON"


@dataclass(frozen=True, slots=True)
class Param:
    """Parámetro de un mensaje HTTP."""

    name: str
    value: str
    type: ParamType


def _decode(body: bytes) -> str:
    """UTF-8 con fallback latin-1: los cuerpos arbitrarios no deben romper el parseo."""
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return body.decode("latin-1")


def _urlencoded(text: str, type: ParamType) -> tuple[Param, ...]:
    try:
        pairs = parse_qsl(text, keep_blank_values=True, max_num_fields=_MAX_FIELDS)
    except ValueError:
        # Demasiados campos: mejor no parametrizar que tumbar el flujo.
        return ()
    return tuple(Param(name=name, value=value, type=type) for name, value in pairs)


def parse_query_params(target: str) -> tuple[Param, ...]:
    """Parámetros de la query del request-target (forma absoluta o de origen)."""
    if "?" not in target:
        return ()
    # El request-target no debería llevar fragment; si llega, se ignora (RFC 9112).
    query = target.split("?", 1)[1].split("#", 1)[0]
    return _urlencoded(query, ParamType.URL)


def parse_body_params(body: bytes, content_type: str | None) -> tuple[Param, ...]:
    """Parámetros del body si es ``application/x-www-form-urlencoded``."""
    if not body or not content_type:
        return ()
    if "application/x-www-form-urlencoded" not in content_type.lower():
        return ()
    return _urlencoded(_decode(body), ParamType.BODY)


def parse_cookie_params(cookie_header: str | None) -> tuple[Param, ...]:
    """Cookies de la cabecera ``Cookie`` de una petición (`a=1; b=2`)."""
    if not cookie_header:
        return ()
    out: list[Param] = []
    for chunk in cookie_header.split(";"):
        name, sep, value = chunk.partition("=")
        if sep:
            out.append(Param(name=name.strip(), value=value.strip(), type=ParamType.COOKIE))
    return tuple(out)


def parse_set_cookie_params(values: Iterable[str]) -> tuple[Param, ...]:
    """Cookies de las cabeceras ``Set-Cookie`` de una respuesta (solo `nombre=valor`)."""
    out: list[Param] = []
    for raw in values:
        # Los atributos (Path, HttpOnly…) van tras el primer ';'; no son parámetros.
        first_pair = raw.split(";", 1)[0]
        name, sep, value = first_pair.partition("=")
        if sep:
            out.append(Param(name=name.strip(), value=value.strip(), type=ParamType.COOKIE))
    return tuple(out)


def parse_json_params(body: bytes) -> tuple[Param, ...]:
    """Parámetros de un body JSON con ruta punteada (`user.roles[0]`)."""
    if not body:
        return ()
    try:
        data = json.loads(_decode(body))
    except ValueError:
        return ()
    out: list[Param] = []
    _walk_json(data, "", out)
    return tuple(out)


def _walk_json(node: object, path: str, out: list[Param]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}" if path else str(key)
            _walk_json(value, child, out)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _walk_json(value, f"{path}[{index}]", out)
    else:
        # Los escalares conservan su representación JSON salvo las cadenas.
        value = node if isinstance(node, str) else json.dumps(node)
        out.append(Param(name=path, value=value, type=ParamType.JSON))
