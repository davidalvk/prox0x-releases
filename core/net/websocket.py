"""Parser incremental de frames WebSocket (Plan.md §3.4.4).

Solo necesita cabecera y longitud: el relay reenvía los bytes tal cual y este
parser emite metadatos (opcode, tamaño, máscara) sin materializar el payload.
Soporta frames fragmentados y longitudes de 7/16/64 bits.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FrameInfo:
    opcode: int
    size: int
    masked: bool
    fin: bool


@dataclass(frozen=True, slots=True)
class RawFrame:
    """Frame completo: bytes originales, metadatos y payload desenmascarado."""

    raw: bytes
    info: FrameInfo
    payload: bytes


def build_frame(
    opcode: int,
    payload: bytes,
    *,
    fin: bool = True,
    masked: bool = False,
) -> bytes:
    """Construye un frame WebSocket aplicando máscara si hace falta."""
    first = (0x80 if fin else 0) | (opcode & 0x0F)
    length = len(payload)
    if length < 126:
        header = bytes((first, length | (0x80 if masked else 0)))
    elif length < 65_536:
        header = (
            bytes((first, 126 | (0x80 if masked else 0)))
            + length.to_bytes(2, "big")
        )
    else:
        header = (
            bytes((first, 127 | (0x80 if masked else 0)))
            + length.to_bytes(8, "big")
        )
    if not masked:
        return header + payload
    key = os.urandom(4)
    body = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))
    return header + key + body


class RawFrameParser:
    """Acumula bytes y devuelve frames completos listos para interceptar."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[RawFrame]:
        self._buffer += data
        frames: list[RawFrame] = []
        while True:
            frame = self._parse_one()
            if frame is None:
                return frames
            frames.append(frame)

    def _parse_one(self) -> RawFrame | None:
        buffer = self._buffer
        if len(buffer) < 2:
            return None
        first, second = buffer[0], buffer[1]
        fin = bool(first & 0x80)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        offset = 2
        if length == 126:
            if len(buffer) < offset + 2:
                return None
            length = int.from_bytes(buffer[offset : offset + 2], "big")
            offset += 2
        elif length == 127:
            if len(buffer) < offset + 8:
                return None
            length = int.from_bytes(buffer[offset : offset + 8], "big")
            offset += 8

        mask = b""
        if masked:
            if len(buffer) < offset + 4:
                return None
            mask = bytes(buffer[offset : offset + 4])
            offset += 4
        frame_end = offset + length
        if len(buffer) < frame_end:
            return None

        raw_payload = bytes(buffer[offset:frame_end])
        payload = (
            bytes(
                byte ^ mask[index % 4]
                for index, byte in enumerate(raw_payload)
            )
            if masked
            else raw_payload
        )
        raw = bytes(buffer[:frame_end])
        del buffer[:frame_end]
        return RawFrame(
            raw=raw,
            info=FrameInfo(
                opcode=opcode,
                size=length,
                masked=masked,
                fin=fin,
            ),
            payload=payload,
        )


class FrameParser:
    """Acumula bytes y emite un ``FrameInfo`` por frame completo."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._remaining = 0  # bytes de payload pendientes de descartar

    def feed(self, data: bytes) -> list[FrameInfo]:
        self._buffer += data
        frames: list[FrameInfo] = []
        while True:
            if self._remaining:
                take = min(len(self._buffer), self._remaining)
                if take:
                    del self._buffer[:take]
                    self._remaining -= take
                if self._remaining:
                    break
                continue

            parsed = self._parse_header()
            if parsed is None:
                break
            info, header_length, payload_length = parsed
            frames.append(info)
            del self._buffer[:header_length]
            self._remaining = payload_length
            if payload_length == 0:
                self._remaining = 0
        return frames

    def _parse_header(self) -> tuple[FrameInfo, int, int] | None:
        buffer = self._buffer
        if len(buffer) < 2:
            return None
        first, second = buffer[0], buffer[1]
        fin = bool(first & 0x80)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        offset = 2
        if length == 126:
            if len(buffer) < offset + 2:
                return None
            length = int.from_bytes(buffer[offset : offset + 2], "big")
            offset += 2
        elif length == 127:
            if len(buffer) < offset + 8:
                return None
            length = int.from_bytes(buffer[offset : offset + 8], "big")
            offset += 8
        if masked:
            if len(buffer) < offset + 4:
                return None
            offset += 4
        return FrameInfo(opcode=opcode, size=length, masked=masked, fin=fin), offset, length
