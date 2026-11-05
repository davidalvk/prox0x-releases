"""Motor de Scope: decides si una petición pertenece al alcance de la auditoría.

Reglas (una por línea):

- ``.*\\.miobjetivo\\.com`` → inclusión por regex (host o URL).
- ``!.*\\.google\\.com`` → exclusión por regex.

Semántica:
- Sin reglas de inclusión, todo está dentro del scope salvo lo excluido.
- Con inclusiones, debe coincidir al menos una y ninguna exclusión.
- Las regex se aplican al host y a la URL completa, sin distinguir mayúsculas.

La política se guarda en JSON para sobrevivir reinicios del Proxy y se puede
actualizar en caliente vía el control plane Unix.
"""

from __future__ import annotations

from collections import OrderedDict
import json
import re
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

from core.model import HttpService

MAX_CACHE_SIZE = 4_096


class ScopeError(ValueError):
    """Regla inválida o fichero de scope corrupto."""


def _clean_rules(rules: Iterable[str]) -> tuple[list[str], list[str]]:
    includes: list[str] = []
    excludes: list[str] = []
    seen: set[tuple[bool, str]] = set()
    for raw in rules:
        rule = str(raw).strip()
        if not rule or rule.startswith("#"):
            continue
        exclude = rule.startswith("!")
        pattern = rule[1:].strip() if exclude else rule
        if not pattern:
            raise ScopeError("regla vacía")
        key = (exclude, pattern)
        if key in seen:
            continue
        seen.add(key)
        (excludes if exclude else includes).append(pattern)
    return includes, excludes


def _compile(rules: list[str]) -> tuple[re.Pattern[str], ...]:
    compiled: list[re.Pattern[str]] = []
    for rule in rules:
        try:
            compiled.append(re.compile(rule, re.IGNORECASE))
        except re.error as exc:
            raise ScopeError(f"regex inválida {rule!r}: {exc}") from exc
    return tuple(compiled)


class Scope:
    """Política de alcance con reglas de inclusión/exclusión."""

    def __init__(
        self,
        include: Iterable[str] = (),
        exclude: Iterable[str] = (),
        *,
        path: Path | None = None,
    ) -> None:
        self.path = path
        self._cache: OrderedDict[tuple[bool, str, str], bool] = OrderedDict()
        self.set_rules(list(include), list(exclude), save=path is not None)

    @classmethod
    def from_file(cls, path: Path) -> "Scope":
        if not path.is_file():
            return cls(path=path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ScopeError(f"no se pudo leer el scope {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ScopeError("el scope debe ser un objeto JSON")
        return cls(
            include=data.get("include") or [],
            exclude=data.get("exclude") or [],
            path=path,
        )

    # ------------------------------------------------------------------ reglas

    def set_rules(
        self,
        include: Iterable[str],
        exclude: Iterable[str],
        *,
        save: bool = True,
    ) -> None:
        # Acepta también reglas con prefijo ! dentro de include/exclude.
        combined = list(include) + [f"!{item}" for item in exclude]
        includes, excludes = _clean_rules(combined)
        include_re = _compile(includes)
        exclude_re = _compile(excludes)
        self.include = tuple(includes)
        self.exclude = tuple(excludes)
        self._include_re = include_re
        self._exclude_re = exclude_re
        self._cache.clear()
        if save and self.path is not None:
            self.save()

    def save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "include": list(self.include),
            "exclude": list(self.exclude),
        }
        self.path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def serialize(self) -> dict[str, list[str]]:
        return {"include": list(self.include), "exclude": list(self.exclude)}

    @property
    def has_rules(self) -> bool:
        """``True`` si hay alguna inclusión o exclusión configurada."""
        return bool(self.include or self.exclude)

    def load_file(self, path: Path) -> dict[str, list[str]]:
        """Cambia el fichero de persistencia y recarga sus reglas en caliente."""
        self.path = path
        if not path.is_file():
            self.set_rules([], [], save=True)
            return self.serialize()
        loaded = self.from_file(path)
        self.set_rules(loaded.include, loaded.exclude, save=False)
        return self.serialize()

    # --------------------------------------------------------------- evaluación

    def matches(self, service: HttpService, target: str) -> bool:
        key = (service.secure, service.authority, target)
        cached = self._cache.get(key)
        if cached is not None:
            self._cache.move_to_end(key)
            return cached

        scheme = "https" if service.secure else "http"
        if target.startswith(("http://", "https://", "ws://", "wss://")):
            full_url = target
        else:
            full_url = f"{scheme}://{service.authority}{target}"

        host = service.host
        url = full_url
        included = (
            not self._include_re
            or any(pattern.search(url) or pattern.search(host) for pattern in self._include_re)
        )
        excluded = any(
            pattern.search(url) or pattern.search(host) for pattern in self._exclude_re
        )
        result = included and not excluded
        self._cache[key] = result
        while len(self._cache) > MAX_CACHE_SIZE:
            self._cache.popitem(last=False)
        return result
