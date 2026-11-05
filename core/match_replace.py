"""Motor de Match & Replace (Plan.md §F11).

Las reglas se aplican **después** de la edición manual en el punto
``*_TO_BE_SENT`` del Proxy, de modo que el usuario ve el mensaje original en el
breakpoint y las reglas transforman la versión final enviada al origen/cliente.

Cada regla tiene:

- ``target``: ``request`` o ``response``.
- ``match``: texto exacto o expresión regular (``regex=True``).
- ``replace``: texto de sustitución (admite grupos ``\\1`` en regex).
- ``location``: ``headers`` (solo campos de cabecera), ``body`` o ``all``.
- ``enabled``: permite desactivarla sin borrarla.

La política se persiste en JSON y se comparte Proxy/API mediante el control
plane Unix, igual que el Scope.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable, Mapping, cast
from typing import Literal

from core.model import Message, Request, Response, serialize_body
from core.net.wire import parse_request, parse_response

Target = Literal["request", "response"]
Location = Literal["headers", "body", "all"]

MAX_REGEX_BYTES = 1_048_576  # 1 MiB: evita ReDoS en cuerpos grandes


class MatchReplaceError(ValueError):
    """Regla inválida, regex mal formada o mensaje no reconstruible."""


@dataclass(frozen=True, slots=True)
class MatchReplaceRule:
    """Una regla de sustitución automática."""

    id: str
    target: Target
    match: str
    replace: str = ""
    location: Location = "all"
    regex: bool = False
    enabled: bool = True

    def __post_init__(self) -> None:
        if self.target not in ("request", "response"):
            raise MatchReplaceError(f"target inválido: {self.target!r}")
        if self.location not in ("headers", "body", "all"):
            raise MatchReplaceError(f"location inválida: {self.location!r}")
        if not self.match:
            raise MatchReplaceError("match no puede estar vacío")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "target": self.target,
            "match": self.match,
            "replace": self.replace,
            "location": self.location,
            "regex": self.regex,
            "enabled": self.enabled,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "MatchReplaceRule":
        if not isinstance(data, Mapping):
            raise MatchReplaceError("cada regla debe ser un objeto JSON")
        target = str(data.get("target", "request"))
        location = str(data.get("location", "all"))
        return cls(
            id=str(data.get("id") or ""),
            target=cast(Target, target),
            match=str(data.get("match") or ""),
            replace=str(data.get("replace") or ""),
            location=cast(Location, location),
            regex=bool(data.get("regex", False)),
            enabled=bool(data.get("enabled", True)),
        )


def _split_message(raw: bytes) -> tuple[bytes, bytes, bytes]:
    """Devuelve (head con separador, body, separador) preservando el original."""
    for separator in (b"\r\n\r\n", b"\n\n"):
        index = raw.find(separator)
        if index >= 0:
            return raw[: index + len(separator)], raw[index + len(separator) :], separator
    return raw, b"", b""


def _replace_header_block(head: bytes, replace_bytes) -> bytes:
    """Aplica la sustitución a las cabeceras, dejando intacta la start line."""
    newline = head.find(b"\n")
    if newline < 0:
        return head
    return head[: newline + 1] + replace_bytes(head[newline + 1 :])


class MatchReplace:
    """Colección ordenada de reglas y aplicación sobre mensajes inmutables."""

    def __init__(
        self,
        rules: Iterable[MatchReplaceRule | Mapping[str, object]] = (),
        *,
        path: Path | None = None,
    ) -> None:
        self.path = path
        self._rules: tuple[MatchReplaceRule, ...] = ()
        self._patterns: dict[str, re.Pattern[bytes]] = {}
        self.set_rules(rules, save=False)

    @classmethod
    def from_file(cls, path: Path) -> "MatchReplace":
        if not path.is_file():
            return cls(path=path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise MatchReplaceError(f"no se pudo leer {path}: {exc}") from exc
        raw_rules = data.get("rules", []) if isinstance(data, dict) else data
        if not isinstance(raw_rules, list):
            raise MatchReplaceError("el fichero de reglas debe contener una lista")
        engine = cls(path=path)
        engine.set_rules(raw_rules, save=False)
        return engine

    # ------------------------------------------------------------------ reglas

    @property
    def rules(self) -> tuple[MatchReplaceRule, ...]:
        return self._rules

    def set_rules(
        self,
        rules: Iterable[MatchReplaceRule | Mapping[str, object]],
        *,
        save: bool = True,
    ) -> list[dict[str, object]]:
        normalized: list[MatchReplaceRule] = []
        patterns: dict[str, re.Pattern[bytes]] = {}
        seen: set[str] = set()

        for item in rules:
            rule = item if isinstance(item, MatchReplaceRule) else MatchReplaceRule.from_mapping(item)
            if not rule.id:
                rule = replace(rule, id=uuid.uuid4().hex[:12])
            if rule.id in seen:
                raise MatchReplaceError(f"id de regla duplicado: {rule.id!r}")
            seen.add(rule.id)
            if rule.regex:
                try:
                    patterns[rule.id] = re.compile(rule.match.encode("utf-8"))
                except re.error as exc:
                    raise MatchReplaceError(
                        f"regex inválida {rule.match!r}: {exc}"
                    ) from exc
            normalized.append(rule)

        self._rules = tuple(normalized)
        self._patterns = patterns
        if save and self.path is not None:
            self.save()
        return self.serialize()

    def save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"rules": self.serialize()}
        self.path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def serialize(self) -> list[dict[str, object]]:
        return [rule.to_dict() for rule in self._rules]

    def load_file(self, path: Path) -> list[dict[str, object]]:
        """Cambia el fichero de persistencia y recarga sus reglas en caliente."""
        self.path = path
        if not path.is_file():
            return self.set_rules([], save=True)
        loaded = self.from_file(path)
        return self.set_rules(loaded.rules, save=False)

    def toggle(self, rule_id: str, enabled: bool) -> list[dict[str, object]]:
        updated = tuple(
            replace(rule, enabled=enabled) if rule.id == rule_id else rule
            for rule in self._rules
        )
        if not any(rule.id == rule_id for rule in self._rules):
            raise MatchReplaceError(f"regla inexistente: {rule_id}")
        self._rules = updated
        self.save()
        return self.serialize()

    def delete(self, rule_id: str) -> list[dict[str, object]]:
        if not any(rule.id == rule_id for rule in self._rules):
            raise MatchReplaceError(f"regla inexistente: {rule_id}")
        self._rules = tuple(rule for rule in self._rules if rule.id != rule_id)
        self._patterns.pop(rule_id, None)
        self.save()
        return self.serialize()

    # --------------------------------------------------------------- aplicación

    def apply(self, message: Message) -> Message:
        if isinstance(message, Request):
            target: Target = "request"
        elif isinstance(message, Response):
            target = "response"
        else:
            raise MatchReplaceError("mensaje no soportado")

        applicable = [
            rule
            for rule in self._rules
            if rule.enabled and rule.target == target
        ]
        if not applicable:
            return message

        current = message
        for rule in applicable:
            current = self._apply_rule(current, rule)
        return current

    def apply_request(self, request: Request) -> Request:
        return cast(Request, self.apply(request))

    def apply_response(self, response: Response) -> Response:
        return cast(Response, self.apply(response))

    def _replacement(self, rule: MatchReplaceRule, data: bytes) -> bytes:
        try:
            replacement = rule.replace.encode("utf-8")
            if rule.regex:
                return self._patterns[rule.id].sub(replacement, data)
            return data.replace(rule.match.encode("utf-8"), replacement)
        except re.error as exc:
            raise MatchReplaceError(f"reemplazo inválido: {exc}") from exc

    def _rebuild(self, source: Message, parsed: Message) -> Message:
        """Reconstruye tras editar cabeceras conservando el body original."""
        head = parsed.to_bytes()[: parsed.body_offset]
        wire_body = serialize_body(parsed.headers, source.body)
        return replace(
            source,
            raw=head + wire_body,
            headers=parsed.headers,
            body=source.body,
            body_offset=parsed.body_offset,
        )

    def _apply_rule(self, message: Message, rule: MatchReplaceRule) -> Message:
        if rule.location == "body":
            if rule.regex and len(message.body) > MAX_REGEX_BYTES:
                return message
            new_body = self._replacement(rule, message.body)
            return message if new_body == message.body else message.with_body(new_body)

        head, body, _ = _split_message(message.raw)

        if rule.location == "headers":
            new_head = _replace_header_block(
                head, lambda data: self._replacement(rule, data)
            )
            if new_head == head:
                return message
            try:
                parsed = (
                    parse_request(new_head)
                    if isinstance(message, Request)
                    else parse_response(new_head)
                )
            except ValueError as exc:
                raise MatchReplaceError(
                    f"las cabeceras resultantes no son HTTP válido: {exc}"
                ) from exc
            return self._rebuild(message, parsed)

        # location == "all": se aplica al mensaje completo, pero con el body
        # decodificado para no tocar el encuadre chunked.
        if rule.regex and len(head) + len(body) > MAX_REGEX_BYTES:
            return message
        new_wire = self._replacement(rule, head + body)
        if new_wire == head + body:
            return message
        try:
            parsed = (
                parse_request(new_wire)
                if isinstance(message, Request)
                else parse_response(new_wire)
            )
        except ValueError as exc:
            raise MatchReplaceError(
                f"el mensaje resultante no es HTTP válido: {exc}"
            ) from exc
        if parsed.body != body:
            parsed = parsed.with_body(parsed.body)
        return parsed
