"""Gestor de plantillas Nuclei (Fase 2).

Clona o actualiza el repositorio oficial de plantillas en el directorio de
estado de prox0x. Las operaciones de git se ejecutan en un hilo para no
bloquear el event loop y se serializan con un lock.
"""

from __future__ import annotations

import asyncio
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from core.config import default_state_dir

NUCLEI_TEMPLATES_URL = "https://github.com/projectdiscovery/nuclei-templates.git"
TEMPLATES_DIRNAME = "nuclei"
LICENSE_FILENAME = "LICENSE-NUCLEI.md"
GIT_TIMEOUT_S = 180.0

# Extracción rápida de ``info.tags`` sin parsear YAML completo: recorrer 14k
# plantillas con PyYAML tarda decenas de segundos; con texto <1 s.
_TAG_LINE_RE = re.compile(r"(?m)^\s{2,6}tags:\s*(.+?)\s*$")
_VALID_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

# Claves de primer nivel que identifican el protocolo de una plantilla. La
# detección es textual para no pagar el coste de PyYAML sobre miles de archivos.
_TOP_LEVEL_KEY_RE = re.compile(r"(?m)^([A-Za-z][A-Za-z0-9_-]*):")
HTTP_PROTOCOL_KEYS = frozenset({"http", "requests"})
NON_HTTP_PROTOCOL_KEYS = frozenset(
    {"dns", "network", "file", "headless", "websocket"}
)


def template_top_level_keys(text: str) -> frozenset[str]:
    """Devuelve las claves YAML de primer nivel de una plantilla."""

    return frozenset(
        match.group(1).lower() for match in _TOP_LEVEL_KEY_RE.finditer(text)
    )


def is_http_template_text(text: str) -> bool:
    """Indica si la plantilla es HTTP y no declara otro protocolo.

    Se consideran HTTP tanto ``http`` como la clave histórica ``requests``.
    Cualquier plantilla con ``dns``, ``network``, ``file``, ``headless`` o
    ``websocket`` queda fuera, incluso si también incluye un bloque HTTP.
    """

    keys = template_top_level_keys(text)
    return bool(keys & HTTP_PROTOCOL_KEYS) and not (
        keys & NON_HTTP_PROTOCOL_KEYS
    )


NUCLEI_LICENSE_TEXT = """MIT License

Copyright (c) 2025 ProjectDiscovery, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


@dataclass(frozen=True, slots=True)
class TemplateUpdateResult:
    """Resultado de una actualización del repositorio de plantillas."""

    path: Path
    cloned: bool
    updated: bool
    templates: int
    duration_ms: float
    error: str | None = None


class TemplateManager:
    """Administra ``~/.prox0x/templates/nuclei``."""

    def __init__(
        self,
        path: Path | None = None,
        *,
        repository: str = NUCLEI_TEMPLATES_URL,
        timeout_s: float = GIT_TIMEOUT_S,
    ) -> None:
        self.path = path or default_state_dir() / "templates" / TEMPLATES_DIRNAME
        self.repository = repository
        self.timeout_s = timeout_s
        self._lock = asyncio.Lock()
        self._tags_cache: tuple[str, ...] | None = None

    @property
    def license_path(self) -> Path:
        return self.path / LICENSE_FILENAME

    @property
    def is_cloned(self) -> bool:
        return (self.path / ".git").is_dir()

    async def update(self) -> TemplateUpdateResult:
        """Clona o actualiza el repositorio sin bloquear el event loop."""

        async with self._lock:
            return await asyncio.to_thread(self._update_sync)

    async def tags(self) -> tuple[str, ...]:
        """Devuelve los tags únicos, usando caché hasta la próxima update."""

        if self._tags_cache is not None:
            return self._tags_cache
        async with self._lock:
            if self._tags_cache is None:
                self._tags_cache = await asyncio.to_thread(
                    self._collect_tags_sync
                )
            return self._tags_cache

    def _update_sync(self) -> TemplateUpdateResult:
        started = time.monotonic()
        cloned = False
        updated = False
        error: str | None = None

        self.path.parent.mkdir(parents=True, exist_ok=True)

        try:
            if not self.path.exists() or not any(self.path.iterdir()):
                self.path.mkdir(parents=True, exist_ok=True)
                self._git(
                    [
                        "clone",
                        "--depth",
                        "1",
                        self.repository,
                        str(self.path),
                    ]
                )
                cloned = True
                updated = True
            elif self.is_cloned:
                self._git(["-C", str(self.path), "pull", "--ff-only"])
                updated = True
            else:
                error = (
                    f"{self.path} existe pero no es un repositorio git; "
                    "elimínalo o usa otra ruta"
                )
        except FileNotFoundError:
            error = "git no está instalado o no está en PATH"
        except subprocess.TimeoutExpired:
            error = f"git superó el timeout de {self.timeout_s:.0f}s"
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or "").strip()
            error = f"git falló: {detail or exc}"
        except OSError as exc:
            error = f"no se pudo preparar {self.path}: {exc}"

        # La licencia se mantiene incluso si git falla: documenta el origen
        # de las plantillas que el usuario instale manualmente.
        try:
            self.path.mkdir(parents=True, exist_ok=True)
            self.license_path.write_text(NUCLEI_LICENSE_TEXT, encoding="utf-8")
        except OSError as exc:
            if error is None:
                error = f"no se pudo escribir {self.license_path}: {exc}"

        self._tags_cache = self._collect_tags_sync()
        templates = self._count_templates()
        return TemplateUpdateResult(
            path=self.path,
            cloned=cloned,
            updated=updated,
            templates=templates,
            duration_ms=(time.monotonic() - started) * 1000,
            error=error,
        )

    def _git(self, args: list[str]) -> None:
        subprocess.run(
            ["git", *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=self.timeout_s,
        )

    def _collect_tags_sync(self) -> tuple[str, ...]:
        if not self.path.is_dir():
            return ()
        tags: set[str] = set()
        try:
            files = list(self.path.rglob("*.yaml")) + list(
                self.path.rglob("*.yml")
            )
        except OSError:
            return ()
        for path in files:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not is_http_template_text(text):
                continue
            for match in _TAG_LINE_RE.finditer(text):
                raw = match.group(1).strip()
                if raw.startswith("["):
                    raw = raw.strip("[]")
                for candidate in re.split(r"[,\s]+", raw):
                    tag = candidate.strip().strip("\"'").lower()
                    if _VALID_TAG_RE.match(tag):
                        tags.add(tag)
        return tuple(sorted(tags))

    def _count_templates(self) -> int:
        if not self.path.is_dir():
            return 0
        try:
            return sum(
                1
                for pattern in ("*.yaml", "*.yml")
                for _ in self.path.rglob(pattern)
            )
        except OSError:
            return 0
