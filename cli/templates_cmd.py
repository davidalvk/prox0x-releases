"""Comando CLI ``prox0x templates``."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer

from core.scan.template_manager import TemplateManager

templates_app = typer.Typer(
    name="templates",
    help="Gestión de plantillas Nuclei.",
    no_args_is_help=True,
)


@templates_app.command("update")
def update_command(
    path: Path | None = typer.Option(
        None,
        "--path",
        help="Directorio alternativo para las plantillas",
    ),
) -> None:
    """Clona o actualiza el repositorio oficial de plantillas Nuclei."""

    manager = TemplateManager(path)
    result = asyncio.run(manager.update())
    typer.echo(f"Plantillas: {result.path}")
    typer.echo(f"YAML encontrados: {result.templates}")
    typer.echo(
        "Estado: "
        + (
            "clonado"
            if result.cloned
            else "actualizado"
            if result.updated
            else "sin cambios"
        )
    )
    typer.echo(f"Duración: {result.duration_ms:.0f} ms")
    if result.error:
        typer.echo(f"Error: {result.error}", err=True)
        raise typer.Exit(code=1)
