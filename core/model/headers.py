"""Cabecera HTTP preservando orden y caja original (Plan.md §3.3)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Header:
    """Cabecera HTTP individual.

    El orden se conserva en el ``tuple[Header, ...]`` del mensaje: es
    significativo para algunos ataques (p. ej. duplicados de ``X-Forwarded-For``).
    """

    name: str
    value: str

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise ValueError("el nombre del header no puede estar vacío")
        if any(ch in self.name for ch in "\r\n: "):
            raise ValueError(f"nombre de header ilegal: {self.name!r}")
        if "\r" in self.value or "\n" in self.value:
            raise ValueError(f"valor de header con CR/LF (inyección): {self.value!r}")

    @property
    def lowercase_name(self) -> str:
        """Nombre en minúsculas para comparaciones (HTTP no distingue caja)."""
        return self.name.lower()

    def to_bytes(self) -> bytes:
        """Serializa la cabecera como bytes HTTP/1.1 (`name: value\\r\\n`)."""
        name = self.name.encode("latin-1", errors="replace")
        value = self.value.encode("latin-1", errors="replace")
        return name + b": " + value + b"\r\n"

    def __str__(self) -> str:
        return f"{self.name}: {self.value}"
