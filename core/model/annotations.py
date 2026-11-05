"""Anotaciones de análisis sobre un mensaje (Plan.md §3.3).

Notas y color de resaltado viajan con el mensaje, no con la UI: así se
persisten, se exportan y se ven igual en Proxy, Repeater e Intruder
(Plan.md §3.5).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Color(Enum):
    """Colores de resaltado del historial."""

    NONE = "none"
    GRAY = "gray"
    RED = "red"
    ORANGE = "orange"
    YELLOW = "yellow"
    GREEN = "green"
    CYAN = "cyan"
    BLUE = "blue"
    PINK = "pink"
    MAGENTA = "magenta"


@dataclass(frozen=True, slots=True)
class Annotations:
    """Metadatos de análisis asociados a un mensaje."""

    notes: str = ""
    highlight_color: Color = Color.NONE
