"""Carga de flujos del Proxy para las CLIs (Repeater/Intruder).

Centraliza la lectura del JSONL de ``prox0x flows`` y la reconstrucción de la
petición final. Los comandos traducen ``FlowSourceError`` a su propio error de
uso para mostrar un mensaje sin traza.
"""

from __future__ import annotations

from pathlib import Path

from core.model import HttpService, Request
from core.store import read_records
from repeater import request_from_record


class FlowSourceError(Exception):
    """El fichero o el flujo no son utilizables."""


def load_flow(path: Path, flow_id: int) -> tuple[Request, HttpService, str]:
    """Devuelve ``(request, service, nombre)`` de un flujo capturado."""
    if not path.is_file():
        raise FlowSourceError(
            f"no existe el fichero de flujos {path}. Arranca el proxy y genera "
            "tráfico, o pasa --flows-file."
        )
    records, _malformed = read_records(path)
    record = next((item for item in records if item.get("id") == flow_id), None)
    if record is None:
        raise FlowSourceError(f"no existe el flujo #{flow_id} en {path}")

    service_data = record.get("service") or {}
    try:
        service = HttpService(
            host=str(service_data["host"]),
            port=int(service_data["port"]),
            secure=bool(service_data["secure"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise FlowSourceError(f"el flujo #{flow_id} tiene un servicio inválido") from exc

    try:
        request = request_from_record(record)
    except (ValueError, TypeError) as exc:
        raise FlowSourceError(
            f"la petición del flujo #{flow_id} no es válida: {exc}"
        ) from exc
    return request, service, f"flow #{flow_id}"
