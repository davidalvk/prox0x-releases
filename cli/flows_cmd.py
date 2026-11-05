"""Comando `prox0x flows`: vuelca el historial capturado por el proxy.

Lee el JSONL que el proxy escribe (``~/.prox0x/flows.jsonl`` por defecto) y
muestra una tabla con lo esencial, o el detalle de un flujo con sus mensajes
completos. Es el atajo de diagnóstico de F1 para trabajar sin UI ni navegador;
la consulta rica (filtros, SQLite) llega con la API en F5.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import typer

from core.config import default_flows_file
from core.store import read_records

flows_app = typer.Typer(
    help="Historial de flujos capturados por el proxy (JSONL)",
    no_args_is_help=False,
    invoke_without_command=True,
)

_NO_FILE_HINT = (
    "No hay flujos todavía en {path}.\n"
    "Arranca el proxy (`prox0x proxy start`) y pasa alguna petición; "
    "luego vuelve a ejecutar `prox0x flows`."
)


def _load(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        typer.echo(_NO_FILE_HINT.format(path=path))
        raise typer.Exit(code=0)
    records, malformed = read_records(path)
    if malformed:
        typer.echo(f"Aviso: {malformed} línea(s) ilegible(s) ignoradas.", err=True)
    if not records:
        typer.echo(f"El fichero {path} está vacío.")
        raise typer.Exit(code=0)
    return records


def _local_time(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%H:%M:%S")
    except ValueError:
        return "??:??:??"


def _service(record: dict[str, Any]) -> str:
    service = record.get("service") or {}
    scheme = "https" if service.get("secure") else "http"
    return f"{scheme}://{service.get('host', '?')}:{service.get('port', '?')}"


def _message(record: dict[str, Any], key: str) -> dict[str, Any] | None:
    value = record.get(key)
    return value if isinstance(value, dict) else None


def _truncate(text: str, width: int = 48) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


@flows_app.callback(invoke_without_command=True)
def flows_list(
    ctx: typer.Context,
    limit: int = typer.Option(50, "--limit", "-n", help="Flujos a mostrar (los más recientes)"),
    file: Path = typer.Option(default_flows_file, "--file", "-f", help="Fichero JSONL de flujos"),
    as_json: bool = typer.Option(False, "--json", help="Vuelca los registros JSON crudos"),
) -> None:
    """Tabla resumen de los flujos capturados (más reciente primero)."""
    if ctx.invoked_subcommand is not None:
        return
    records = _load(file)
    if as_json:
        for record in records:
            typer.echo(json.dumps(record, ensure_ascii=True))
        return

    header = f"{'ID':>4}  {'HORA':<8} {'MÉTODO':<7} {'CÓD':>4}  {'SERVICIO':<40} {'MIME':<18} {'TTFB':>8} {'TOTAL':>8}  TARGET"
    typer.echo(header)
    typer.echo("-" * len(header))
    selected = records if limit <= 0 else records[:limit]
    for record in selected[::-1]:
        request = _message(record, "request")
        response = _message(record, "response")
        timing = record.get("timing") or {}
        ttfb = timing.get("ttfb_ms")
        total = timing.get("total_ms")
        edited = "*" if record.get("edited") else " "
        typer.echo(
            f"{record.get('id', '?'):>4}{edited} "
            f"{_local_time(str(record.get('at', ''))):<8} "
            f"{(request or {}).get('method', '-'):<7} "
            f"{(response or {}).get('status', '-'):>4}  "
            f"{_truncate(_service(record), 40):<40} "
            f"{_truncate(str(record.get('mime') or '-'), 18):<18} "
            f"{f'{ttfb:.1f}' if isinstance(ttfb, (int, float)) else '-':>8} "
            f"{f'{total:.1f}' if isinstance(total, (int, float)) else '-':>8}  "
            f"{_truncate(str((request or {}).get('target', '-')))}"
        )
    shown = len(selected)
    typer.echo(f"\n{shown} de {len(records)} flujo(s). Los editados llevan '*'. "
               f"Detalle: `prox0x flows show <id>`.")


def _render_message(title: str, message: dict[str, Any] | None) -> None:
    typer.echo(f"\n── {title} " + "─" * max(0, 60 - len(title)))
    if message is None:
        typer.echo("(sin mensaje)")
        return
    try:
        raw = base64.b64decode(str(message.get("raw", "")), validate=True)
    except (ValueError, TypeError):
        typer.echo("(raw ilegible)")
        return
    head, sep, body = raw.partition(b"\r\n\r\n")
    typer.echo(head.decode("utf-8", errors="replace"))
    if sep:
        typer.echo(f"[cuerpo: {len(body)} bytes]")
        typer.echo(body.decode("utf-8", errors="replace"))


@flows_app.command("show")
def flows_show(
    flow_id: int = typer.Argument(..., help="Id del flujo (ver `prox0x flows`)"),
    file: Path = typer.Option(default_flows_file, "--file", "-f", help="Fichero JSONL de flujos"),
) -> None:
    """Muestra un flujo con sus mensajes completos (request y response)."""
    records = _load(file)
    record = next((item for item in records if item.get("id") == flow_id), None)
    if record is None:
        typer.echo(f"No existe el flujo #{flow_id} en {file}.", err=True)
        raise typer.Exit(code=1)

    timing = record.get("timing") or {}
    typer.echo(f"Flujo #{record.get('id')}  [{_local_time(str(record.get('at', '')))}]")
    typer.echo(f"  servicio:   {_service(record)}")
    typer.echo(f"  cliente:    {record.get('source_ip') or '?'} → {record.get('dest_ip') or '?'}")
    typer.echo(f"  mime:       {record.get('mime') or '-'}")
    typer.echo(f"  ttfb/total: {timing.get('ttfb_ms')} / {timing.get('total_ms')} ms")
    typer.echo(f"  editado:    {'sí' if record.get('edited') else 'no'}")
    _render_message("REQUEST", _message(record, "request"))
    if record.get("edited"):
        _render_message("REQUEST FINAL (tras intercepción)", _message(record, "final_request"))
    _render_message("RESPONSE", _message(record, "response"))

    frames = record.get("websocket_frames") or []
    if frames:
        title = f"WEBSOCKET FRAMES ({len(frames)})"
        typer.echo(f"\n── {title} " + "─" * max(0, 60 - len(title)))
        typer.echo(f"{'DIRECCIÓN':<18} {'OPCODE':<14} {'TAMAÑO':>8}")
        for frame in frames:
            typer.echo(
                f"{str(frame.get('direction', '?')):<18} "
                f"{str(frame.get('name', '?')):<14} "
                f"{frame.get('size', 0):>6} B"
            )
