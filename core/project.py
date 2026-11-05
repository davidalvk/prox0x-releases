"""Gestor de proyectos multi-entorno de prox0x.

Cada proyecto aísla en su propio subdirectorio (`~/.prox0x/projects/<nombre>/`):

- ``flows.db``: base de datos SQLite WAL de flujos capturados.
- ``scope.json``: reglas de inclusión/exclusión del Scope.
- ``match_replace.json``: reglas automáticas de Match & Replace.
- ``flows.jsonl``: volcado JSONL de diagnóstico.

La CA raíz se mantiene global (`~/.prox0x/ca/`) para no requerir reinstalar
certificados en el navegador al cambiar de objetivo.
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from core.config import (
    default_db_file,
    default_flows_file,
    default_match_replace_file,
    default_projects_dir,
    default_scope_file,
)
from core.match_replace import MatchReplace
from core.scope import Scope
from core.store.sqlite import SQLiteFlowStore

DEFAULT_PROJECT_NAME = "Temporal"
_PROJECT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class ProjectError(ValueError):
    """Error de validación o gestión de proyectos."""


class ProjectNotFoundError(ProjectError):
    """El proyecto solicitado no existe."""


class ProjectExistsError(ProjectError):
    """Ya existe un proyecto con ese nombre."""


def validate_project_name(name: str) -> str:
    """Valida el nombre del proyecto evitando Path Traversal."""
    cleaned = name.strip()
    if not cleaned:
        raise ProjectError("el nombre del proyecto no puede estar vacío")
    if ".." in cleaned or "/" in cleaned or "\\" in cleaned:
        raise ProjectError(f"nombre de proyecto inválido: {name!r}")
    if not _PROJECT_NAME_RE.match(cleaned):
        raise ProjectError(
            "nombre de proyecto inválido: usa solo letras, números, '-', '_' o '.' (1–64 caracteres)"
        )
    return cleaned


def _ensure_secure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except PermissionError:
        pass


@dataclass(frozen=True, slots=True)
class ProjectPaths:
    """Rutas de estado asociadas a un proyecto."""

    name: str
    directory: Path
    db_file: Path
    scope_file: Path
    match_replace_file: Path
    flows_file: Path

    @classmethod
    def for_directory(cls, name: str, directory: Path) -> "ProjectPaths":
        return cls(
            name=name,
            directory=directory,
            db_file=directory / "flows.db",
            scope_file=directory / "scope.json",
            match_replace_file=directory / "match_replace.json",
            flows_file=directory / "flows.jsonl",
        )

    def to_control_payload(self) -> dict[str, str]:
        return {
            "name": self.name,
            "db_file": str(self.db_file),
            "scope_file": str(self.scope_file),
            "match_replace_file": str(self.match_replace_file),
            "flows_file": str(self.flows_file),
        }


class ProjectManager:
    """Crea, lista y activa proyectos en `~/.prox0x/projects/`."""

    def __init__(
        self,
        projects_dir: Path | None = None,
        *,
        default_paths: ProjectPaths | None = None,
    ) -> None:
        self.projects_dir = projects_dir or default_projects_dir()
        _ensure_secure_dir(self.projects_dir)
        temporal_dir = self.projects_dir / DEFAULT_PROJECT_NAME
        _ensure_secure_dir(temporal_dir)
        if default_paths is None:
            default_paths = ProjectPaths(
                name=DEFAULT_PROJECT_NAME,
                directory=temporal_dir,
                db_file=default_db_file(),
                scope_file=default_scope_file(),
                match_replace_file=default_match_replace_file(),
                flows_file=default_flows_file(),
            )
        _ensure_secure_dir(default_paths.directory)
        if not default_paths.db_file.is_file():
            SQLiteFlowStore(default_paths.db_file).close()
        if not default_paths.scope_file.is_file():
            Scope(path=default_paths.scope_file).save()
        if not default_paths.match_replace_file.is_file():
            MatchReplace(path=default_paths.match_replace_file).save()
        self._default_paths = default_paths
        self._current_paths = default_paths

    @property
    def current(self) -> str:
        return self._current_paths.name

    @property
    def current_paths(self) -> ProjectPaths:
        return self._current_paths

    def list_projects(self) -> list[str]:
        """Devuelve la lista ordenada de proyectos disponibles (incluye `Temporal`)."""
        names: set[str] = {DEFAULT_PROJECT_NAME}
        if self.projects_dir.is_dir():
            for entry in self.projects_dir.iterdir():
                if entry.is_dir() and _PROJECT_NAME_RE.match(entry.name):
                    names.add(entry.name)
        others = sorted(name for name in names if name != DEFAULT_PROJECT_NAME)
        return [DEFAULT_PROJECT_NAME, *others]

    def _resolve_dir(self, name: str) -> Path:
        validated = validate_project_name(name)
        base = self.projects_dir.resolve()
        target = (self.projects_dir / validated).resolve()
        if target.parent != base:
            raise ProjectError(f"ruta de proyecto fuera de {self.projects_dir}")
        return target

    def create(self, name: str) -> ProjectPaths:
        """Crea un proyecto nuevo con su propia DB, Scope y Match & Replace vacíos."""
        validated = validate_project_name(name)
        if validated == DEFAULT_PROJECT_NAME:
            raise ProjectExistsError("el proyecto 'Temporal' ya existe")
        directory = self._resolve_dir(validated)
        if directory.exists():
            raise ProjectExistsError(f"el proyecto {validated!r} ya existe")

        _ensure_secure_dir(directory)
        paths = ProjectPaths.for_directory(validated, directory)
        SQLiteFlowStore(paths.db_file).close()
        Scope(path=paths.scope_file).save()
        MatchReplace(path=paths.match_replace_file).save()
        return paths

    def get(self, name: str) -> ProjectPaths:
        """Obtiene las rutas de un proyecto existente."""
        validated = validate_project_name(name)
        if validated == DEFAULT_PROJECT_NAME:
            return self._default_paths
        directory = self._resolve_dir(validated)
        if not directory.is_dir():
            raise ProjectNotFoundError(f"no existe el proyecto {validated!r}")
        return ProjectPaths.for_directory(validated, directory)

    def load(self, name: str) -> ProjectPaths:
        """Activa un proyecto existente y garantiza que sus ficheros están inicializados."""
        paths = self.get(name)
        _ensure_secure_dir(paths.directory)
        if not paths.db_file.is_file():
            SQLiteFlowStore(paths.db_file).close()
        if not paths.scope_file.is_file():
            Scope(path=paths.scope_file).save()
        if not paths.match_replace_file.is_file():
            MatchReplace(path=paths.match_replace_file).save()
        self._current_paths = paths
        return paths

    def delete(self, name: str) -> list[str]:
        """Elimina un proyecto y sus ficheros en disco (salvo `Temporal`)."""
        validated = validate_project_name(name)
        if validated == DEFAULT_PROJECT_NAME:
            raise ProjectError("el proyecto 'Temporal' no se puede eliminar")
        directory = self._resolve_dir(validated)
        if not directory.is_dir():
            raise ProjectNotFoundError(f"no existe el proyecto {validated!r}")
        shutil.rmtree(directory)
        if self._current_paths.name == validated:
            self._current_paths = self._default_paths
        return self.list_projects()
