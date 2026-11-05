"""Diff de respuestas del Repeater (Plan.md §4.4).

Estrategia:

- Texto: ``difflib.SequenceMatcher`` por líneas con fin de línea unificado
  (CRLF/CR → LF) y opción de ignorar cabeceras (comparar solo el cuerpo).
- Binario: si el cuerpo no es UTF-8 o contiene NUL, se compara byte a byte y
  se muestran *previews* hex.
- > 1 MB: no se materializan líneas; se comparan *hashes* de bloques de 64 KiB
  y se devuelve solo un resumen (evita explotar memoria en respuestas grandes).
"""

from __future__ import annotations

import difflib
import hashlib
from dataclasses import dataclass

from core.model import Response

MAX_DIFF_BYTES = 1_000_000
BLOCK_SIZE = 65_536


@dataclass(frozen=True, slots=True)
class DiffOp:
    """Una operación de diff (``equal``/``insert``/``delete``/``replace``)."""

    kind: str
    old_start: int
    old_end: int
    new_start: int
    new_end: int
    old_lines: tuple[str, ...] = ()
    new_lines: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DiffStats:
    added: int = 0
    removed: int = 0
    changed: int = 0


@dataclass(frozen=True, slots=True)
class DiffResult:
    """Resultado del diff con estadísticas y metadatos de tamaño."""

    ops: tuple[DiffOp, ...] = ()
    stats: DiffStats = DiffStats()
    binary: bool = False
    large: bool = False
    summary: str | None = None
    old_size: int = 0
    new_size: int = 0

    @property
    def has_changes(self) -> bool:
        return (
            self.stats.added > 0
            or self.stats.removed > 0
            or self.stats.changed > 0
        )


# ------------------------------------------------------------------ helpers


def _split_head_body(data: bytes) -> tuple[bytes, bytes]:
    for separator in (b"\r\n\r\n", b"\n\n"):
        if separator in data:
            head, _, body = data.partition(separator)
            return head, body
    return data, b""


def _body_of(data: bytes) -> bytes:
    _, body = _split_head_body(data)
    return body


def _is_binary(body: bytes) -> bool:
    if b"\x00" in body:
        return True
    try:
        body.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _normalize_lines(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")


def _normalize_headers(data: bytes) -> str:
    # Latin-1 nunca falla: las cabeceras HTTP son bytes, no UTF-8 obligatorio.
    return data.decode("latin-1").replace("\r\n", "\n").replace("\r", "\n")


def _preview(data: bytes) -> str:
    if not data:
        return ""
    return f"<{len(data)} bytes: {data[:32].hex()}{'…' if len(data) > 32 else ''}>"


def _text_result(
    old_text: str, new_text: str, *, old_size: int, new_size: int
) -> DiffResult:
    old_lines = old_text.split("\n")
    new_lines = new_text.split("\n")
    matcher = difflib.SequenceMatcher(None, old_lines, new_lines, autojunk=False)

    ops: list[DiffOp] = []
    added = removed = changed = 0
    for kind, i1, i2, j1, j2 in matcher.get_opcodes():
        ops.append(
            DiffOp(
                kind=kind,
                old_start=i1,
                old_end=i2,
                new_start=j1,
                new_end=j2,
                old_lines=tuple(old_lines[i1:i2]),
                new_lines=tuple(new_lines[j1:j2]),
            )
        )
        if kind == "insert":
            added += j2 - j1
        elif kind == "delete":
            removed += i2 - i1
        elif kind == "replace":
            old_count, new_count = i2 - i1, j2 - j1
            changed += min(old_count, new_count)
            removed += max(0, old_count - new_count)
            added += max(0, new_count - old_count)

    return DiffResult(
        ops=tuple(ops),
        stats=DiffStats(added=added, removed=removed, changed=changed),
        old_size=old_size,
        new_size=new_size,
    )


def _binary_result(
    old: bytes, new: bytes, *, old_size: int, new_size: int
) -> DiffResult:
    matcher = difflib.SequenceMatcher(None, old, new, autojunk=False)
    ops: list[DiffOp] = []
    added = removed = changed = 0
    for kind, i1, i2, j1, j2 in matcher.get_opcodes():
        ops.append(
            DiffOp(
                kind=kind,
                old_start=i1,
                old_end=i2,
                new_start=j1,
                new_end=j2,
                old_lines=(_preview(old[i1:i2]),) if i2 > i1 else (),
                new_lines=(_preview(new[j1:j2]),) if j2 > j1 else (),
            )
        )
        if kind == "insert":
            added += j2 - j1
        elif kind == "delete":
            removed += i2 - i1
        elif kind == "replace":
            old_count, new_count = i2 - i1, j2 - j1
            changed += min(old_count, new_count)
            removed += max(0, old_count - new_count)
            added += max(0, new_count - old_count)

    return DiffResult(
        ops=tuple(ops),
        stats=DiffStats(added=added, removed=removed, changed=changed),
        binary=True,
        old_size=old_size,
        new_size=new_size,
    )


def _large_result(
    old: bytes, new: bytes, *, old_size: int, new_size: int
) -> DiffResult:
    def blocks(data: bytes) -> list[bytes]:
        return [
            hashlib.sha256(data[offset : offset + BLOCK_SIZE]).digest()
            for offset in range(0, len(data), BLOCK_SIZE)
        ]

    matcher = difflib.SequenceMatcher(None, blocks(old), blocks(new), autojunk=False)
    added = removed = changed = 0
    for kind, i1, i2, j1, j2 in matcher.get_opcodes():
        if kind == "insert":
            added += j2 - j1
        elif kind == "delete":
            removed += i2 - i1
        elif kind == "replace":
            old_count, new_count = i2 - i1, j2 - j1
            changed += min(old_count, new_count)
            removed += max(0, old_count - new_count)
            added += max(0, new_count - old_count)

    stats = DiffStats(added=added, removed=removed, changed=changed)
    summary = (
        f"{old_size:,} → {new_size:,} bytes; "
        f"{stats.added} bloque(s) añadido(s), {stats.removed} eliminado(s), "
        f"{stats.changed} cambiado(s) (bloques de {BLOCK_SIZE // 1024} KiB)"
    )
    return DiffResult(
        stats=stats,
        binary=True,
        large=True,
        summary=summary,
        old_size=old_size,
        new_size=new_size,
    )


# --------------------------------------------------------------------- API


def diff_bytes(
    old: bytes, new: bytes, *, ignore_headers: bool = False
) -> DiffResult:
    """Diff entre dos mensajes o cuerpos en bytes."""
    old_head, old_body = _split_head_body(old)
    new_head, new_body = _split_head_body(new)
    old_size, new_size = len(old), len(new)

    if ignore_headers:
        left, right = old_body, new_body
        old_text = _normalize_lines(old_body)
        new_text = _normalize_lines(new_body)
    else:
        left, right = old, new
        old_text = _normalize_headers(old_head)
        new_text = _normalize_headers(new_head)
        if old_body:
            old_text += "\n" + _normalize_lines(old_body)
        if new_body:
            new_text += "\n" + _normalize_lines(new_body)

    if max(old_size, new_size) > MAX_DIFF_BYTES:
        return _large_result(left, right, old_size=old_size, new_size=new_size)
    if _is_binary(old_body) or _is_binary(new_body):
        return _binary_result(left, right, old_size=old_size, new_size=new_size)
    return _text_result(old_text, new_text, old_size=old_size, new_size=new_size)


def diff_responses(
    old: Response, new: Response, *, ignore_headers: bool = False
) -> DiffResult:
    """Diff de dos respuestas completas (o solo de sus cuerpos)."""
    return diff_bytes(old.to_bytes(), new.to_bytes(), ignore_headers=ignore_headers)
