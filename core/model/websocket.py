"""Metadatos de frames WebSocket para el historial (Plan.md §3.4.4).

Solo se guardan dirección, opcode, tamaño y tiempo; el payload no se persiste
en F4 (la edición/intercepción de frames llega después).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class WebSocketDirection(StrEnum):
    CLIENT_TO_SERVER = "client_to_server"
    SERVER_TO_CLIENT = "server_to_client"


_OPCODE_NAMES = {
    0x0: "continuation",
    0x1: "text",
    0x2: "binary",
    0x8: "close",
    0x9: "ping",
    0xA: "pong",
}


@dataclass(frozen=True, slots=True)
class WebSocketFrame:
    """Un frame observado durante el relay."""

    direction: WebSocketDirection
    opcode: int
    size: int
    at: datetime

    def __post_init__(self) -> None:
        if self.size < 0:
            raise ValueError("el tamaño del frame no puede ser negativo")
        if self.at.tzinfo is None:
            raise ValueError("at debe ser consciente de zona (tz-aware)")

    @property
    def opcode_name(self) -> str:
        return _OPCODE_NAMES.get(self.opcode, f"0x{self.opcode:x}")
