"""Tiempos de un intercambio HTTP (Plan.md §3.3, `TimingData`).

Tres marcas: envío, primer byte y fin. El TTFB (`ttfb_ms`) es la métrica clave
para detectar *blind* SQLi y *time-based* (Plan.md §4.4).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class Timing:
    """Marcas de tiempo de una petición/respuesta. Todas tz-aware (UTC)."""

    sent_at: datetime
    first_byte_at: datetime | None = None
    completed_at: datetime | None = None

    def __post_init__(self) -> None:
        for field_name in ("sent_at", "first_byte_at", "completed_at"):
            value = getattr(self, field_name)
            if value is not None and value.tzinfo is None:
                raise ValueError(f"{field_name} debe ser consciente de zona (tz-aware)")

    @classmethod
    def start(cls, now: datetime | None = None) -> "Timing":
        """Timing con la marca de envío = ahora (UTC)."""
        return cls(sent_at=now if now is not None else _now())

    def with_first_byte(self, at: datetime | None = None) -> "Timing":
        return replace(self, first_byte_at=at if at is not None else _now())

    def with_completed(self, at: datetime | None = None) -> "Timing":
        return replace(self, completed_at=at if at is not None else _now())

    @property
    def ttfb_ms(self) -> float | None:
        """Tiempo hasta el primer byte (``None`` si aún no llegó)."""
        if self.first_byte_at is None:
            return None
        return (self.first_byte_at - self.sent_at).total_seconds() * 1000

    @property
    def total_ms(self) -> float | None:
        """Tiempo total del intercambio (``None`` si no terminó)."""
        if self.completed_at is None:
            return None
        return (self.completed_at - self.sent_at).total_seconds() * 1000
