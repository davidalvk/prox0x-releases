"""Carga de diccionarios de payloads (Plan.md §5.5).

Los ficheros ``.pay`` y ``.txt`` son texto plano con una entrada por línea.
Se leen como **bytes** para no corromper payloads binarios ni depender de la
codificación del diccionario.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from collections.abc import Iterable, Iterator

_BOM = b"\xef\xbb\xbf"


class PayloadSourceError(ValueError):
    """Diccionario ilegible o vacío."""


def load_payloads(
    path: Path,
    *,
    skip_empty: bool = True,
    max_payloads: int | None = None,
) -> tuple[bytes, ...]:
    """Lee un diccionario (``.pay``/``.txt``) y devuelve sus entradas en bytes."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PayloadSourceError(f"no se pudo leer el diccionario {path}: {exc}") from exc

    payloads: list[bytes] = []
    for index, line in enumerate(raw.splitlines()):
        if index == 0 and line.startswith(_BOM):
            line = line[len(_BOM) :]
        if skip_empty and not line.strip():
            continue
        payloads.append(line)
        if max_payloads is not None and len(payloads) >= max_payloads:
            break

    if not payloads:
        raise PayloadSourceError(f"el diccionario {path} no contiene payloads")
    return tuple(payloads)


@dataclass(slots=True)
class PayloadSet:
    """Conjunto de payloads de una posición, con cursor de avance."""

    items: tuple[bytes, ...]
    id: str = "payloads"
    source: str = ""
    cursor: int = field(default=0)

    def __post_init__(self) -> None:
        self.items = tuple(self.items)
        if not self.items:
            raise ValueError(f"el set de payloads {self.id!r} está vacío")
        if self.cursor < 0:
            raise ValueError("el cursor no puede ser negativo")

    @classmethod
    def from_file(
        cls,
        path: Path,
        *,
        id: str | None = None,
        skip_empty: bool = True,
        max_payloads: int | None = None,
    ) -> "PayloadSet":
        payloads = load_payloads(
            path, skip_empty=skip_empty, max_payloads=max_payloads
        )
        return cls(
            items=payloads,
            id=id or path.stem,
            source=str(path),
        )

    @classmethod
    def from_items(
        cls, items: Iterable[bytes | str], *, id: str = "inline"
    ) -> "PayloadSet":
        normalized = tuple(
            item.encode("utf-8") if isinstance(item, str) else bytes(item)
            for item in items
        )
        return cls(items=normalized, id=id, source="inline")

    def __len__(self) -> int:
        return len(self.items)

    def __iter__(self) -> Iterator[bytes]:
        return iter(self.items)

    def __bool__(self) -> bool:
        return bool(self.items)

    @property
    def remaining(self) -> int:
        return max(0, len(self.items) - self.cursor)

    def next(self) -> bytes:
        """Siguiente payload; ``StopIteration`` al agotar el set."""
        if self.cursor >= len(self.items):
            raise StopIteration
        payload = self.items[self.cursor]
        self.cursor += 1
        return payload

    def reset(self) -> None:
        self.cursor = 0


def load_payload_sets(
    paths: Iterable[Path],
    *,
    ids: Iterable[str] | None = None,
    max_payloads: int | None = None,
) -> tuple[PayloadSet, ...]:
    """Carga un set por ruta (pitchfork/cluster bomb)."""
    path_list = list(paths)
    if ids is None:
        return tuple(
            PayloadSet.from_file(path, max_payloads=max_payloads)
            for path in path_list
        )
    id_list = list(ids)
    if len(id_list) != len(path_list):
        raise ValueError("ids debe tener la misma longitud que paths")
    return tuple(
        PayloadSet.from_file(path, id=id_, max_payloads=max_payloads)
        for path, id_ in zip(path_list, id_list)
    )
