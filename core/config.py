"""Configuración por defecto y variables de entorno de prox0x.

El listener por defecto escucha **solo** en loopback: un proxy abierto es un
*open relay* (Plan.md §7.5.8).
"""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_FLOW_BUFFER = 5_000
DEFAULT_UPSTREAM_TIMEOUT = 60.0
DEFAULT_CA_COMMON_NAME = "prox0x CA"

# Contraseñas/cadenas de la CA se leen del entorno para uso no interactivo
# (scripts, CI, systemd); la CLI sigue pidiéndolas por prompt si faltan.
ENV_CA_DIR = "PROX0X_CA_DIR"
ENV_CA_PASSPHRASE = "PROX0X_CA_PASSPHRASE"
ENV_STATE_DIR = "PROX0X_STATE_DIR"
ENV_DB_FILE = "PROX0X_DB_FILE"
ENV_CONTROL_SOCKET = "PROX0X_CONTROL_SOCKET"
ENV_SCOPE_FILE = "PROX0X_SCOPE_FILE"
ENV_MATCH_REPLACE_FILE = "PROX0X_MATCH_REPLACE_FILE"
ENV_PROJECTS_DIR = "PROX0X_PROJECTS_DIR"


def default_ca_dir() -> Path:
    """Directorio de la CA: `$PROX0X_CA_DIR` o `~/.prox0x/ca`."""
    override = os.environ.get(ENV_CA_DIR)
    return Path(override) if override else Path.home() / ".prox0x" / "ca"


def default_state_dir() -> Path:
    """Directorio de estado: `$PROX0X_STATE_DIR` o `~/.prox0x`."""
    override = os.environ.get(ENV_STATE_DIR)
    return Path(override) if override else Path.home() / ".prox0x"


def default_projects_dir() -> Path:
    """Directorio de proyectos: `$PROX0X_PROJECTS_DIR` o `<state>/projects`."""
    override = os.environ.get(ENV_PROJECTS_DIR)
    return Path(override) if override else default_state_dir() / "projects"


def default_temporal_dir() -> Path:
    """Directorio del proyecto efímero por defecto: `<projects>/Temporal`."""
    return default_projects_dir() / "Temporal"


def default_flows_file() -> Path:
    """Fichero JSONL de flujos capturados: `<projects>/Temporal/flows.jsonl`."""
    return default_temporal_dir() / "flows.jsonl"


def default_db_file() -> Path:
    """Base SQLite de la API/UI: `$PROX0X_DB_FILE` o `<projects>/Temporal/flows.db`."""
    override = os.environ.get(ENV_DB_FILE)
    return Path(override) if override else default_temporal_dir() / "flows.db"


def default_control_socket() -> Path:
    """Socket de control Proxy/API: `$PROX0X_CONTROL_SOCKET` o `<state>/proxy.sock`."""
    override = os.environ.get(ENV_CONTROL_SOCKET)
    return Path(override) if override else default_state_dir() / "proxy.sock"


def default_scope_file() -> Path:
    """Política de Scope: `$PROX0X_SCOPE_FILE` o `<projects>/Temporal/scope.json`."""
    override = os.environ.get(ENV_SCOPE_FILE)
    return Path(override) if override else default_temporal_dir() / "scope.json"


def default_match_replace_file() -> Path:
    """Reglas Match & Replace: `$PROX0X_MATCH_REPLACE_FILE` o `<projects>/Temporal/match_replace.json`."""
    override = os.environ.get(ENV_MATCH_REPLACE_FILE)
    return Path(override) if override else default_temporal_dir() / "match_replace.json"
