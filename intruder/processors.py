"""Procesadores de payloads: cadena ``USE``/``SKIP`` (Plan.md §5.2).

Cada procesador ve el payload **actual** y el **original** (antes de la cadena)
y la posición de inserción. ``SKIP`` descarta la combinación sin abortar el
ataque, que es el mecanismo de filtrado de la cadena de payloads.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from urllib.parse import quote_from_bytes

from .template import InsertionPoint


class ProcessingAction(StrEnum):
    USE = "use"
    SKIP = "skip"


@dataclass(frozen=True, slots=True)
class PayloadData:
    """Entrada de un procesador."""

    current: bytes
    original: bytes
    insertion_point: InsertionPoint | None = None


@dataclass(frozen=True, slots=True)
class ProcessingResult:
    """Salida de un procesador."""

    payload: bytes
    action: ProcessingAction = ProcessingAction.USE

    def __post_init__(self) -> None:
        if not isinstance(self.payload, bytes):
            raise TypeError("payload debe ser bytes")


class PayloadProcessor(Protocol):
    """Interfaz mínima de un procesador."""

    def process(self, data: PayloadData) -> ProcessingResult: ...


@dataclass(frozen=True, slots=True)
class Prefix:
    prefix: bytes

    def process(self, data: PayloadData) -> ProcessingResult:
        return ProcessingResult(self.prefix + data.current)


@dataclass(frozen=True, slots=True)
class Suffix:
    suffix: bytes

    def process(self, data: PayloadData) -> ProcessingResult:
        return ProcessingResult(data.current + self.suffix)


@dataclass(frozen=True, slots=True)
class Replace:
    old: bytes
    new: bytes

    def process(self, data: PayloadData) -> ProcessingResult:
        return ProcessingResult(data.current.replace(self.old, self.new))


@dataclass(frozen=True, slots=True)
class UrlEncode:
    """Percent-encoding estricto (útil para posiciones en URL/body)."""

    safe: str = ""

    def process(self, data: PayloadData) -> ProcessingResult:
        return ProcessingResult(quote_from_bytes(data.current, safe=self.safe).encode("ascii"))


@dataclass(frozen=True, slots=True)
class SkipIf:
    """Descarta el payload si el predicado devuelve ``True``."""

    predicate: Callable[[bytes], bool]

    def process(self, data: PayloadData) -> ProcessingResult:
        if self.predicate(data.current):
            return ProcessingResult(data.current, ProcessingAction.SKIP)
        return ProcessingResult(data.current)


@dataclass(frozen=True, slots=True)
class CallableProcessor:
    """Adaptador para procesadores definidos en tests o extensiones."""

    function: Callable[[PayloadData], ProcessingResult]

    def process(self, data: PayloadData) -> ProcessingResult:
        return self.function(data)


@dataclass(frozen=True, slots=True)
class ProcessorChain:
    """Aplica los procesadores en orden; ``SKIP`` corta la cadena."""

    processors: tuple[PayloadProcessor, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.processors, tuple):
            object.__setattr__(self, "processors", tuple(self.processors))

    def __bool__(self) -> bool:
        return bool(self.processors)

    def apply(
        self,
        payload: bytes,
        *,
        insertion_point: InsertionPoint | None = None,
    ) -> ProcessingResult:
        original = payload
        current = payload
        for processor in self.processors:
            result = processor.process(
                PayloadData(
                    current=current,
                    original=original,
                    insertion_point=insertion_point,
                )
            )
            if result.action is ProcessingAction.SKIP:
                return result
            current = result.payload
        return ProcessingResult(current, ProcessingAction.USE)


def make_chain(processors: Iterable[PayloadProcessor] | None) -> ProcessorChain:
    """Normaliza ``None``/secuencia/``ProcessorChain`` a una cadena."""
    if processors is None:
        return ProcessorChain()
    if isinstance(processors, ProcessorChain):
        return processors
    return ProcessorChain(tuple(processors))
