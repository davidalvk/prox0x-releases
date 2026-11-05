"""Punto de entrada de la CLI (`prox0x`), construida con Typer (Plan.md §7.4)."""

from __future__ import annotations

import sys

import typer

from core import __version__
from core.logging import configure_logging
from cli.ca import ca_app
from cli.crawl_cmd import crawl_command
from cli.flows_cmd import flows_app
from cli.intruder_cmd import intruder_app
from cli.proxy_cmd import proxy_app
from cli.repeater_cmd import repeater_app
from cli.start_cmd import start_command
from cli.templates_cmd import templates_app

app = typer.Typer(
    name="prox0x",
    help="prox0x — suite ligera de interceptación y auditoría web para red team.",
    no_args_is_help=True,
)
app.add_typer(ca_app, name="ca")
app.add_typer(flows_app, name="flows")
app.add_typer(intruder_app, name="intruder")
app.add_typer(proxy_app, name="proxy")
app.add_typer(repeater_app, name="repeater")
app.add_typer(templates_app, name="templates")
app.command("crawl", help="Rastrea una URL y descubre endpoints")(crawl_command)
app.command("start", help="Arranca Proxy + API/UI y abre el navegador")(start_command)


@app.callback()
def _root() -> None:
    """Raíz de la CLI. El callback evita que Typer colapse la app en un único comando."""


@app.command()
def version() -> None:
    """Muestra la versión de prox0x."""
    typer.echo(f"prox0x {__version__}")


def main() -> None:
    """Arranca la CLI con el logging estructurado configurado."""
    # Consolas Windows antiguas: evita UnicodeEncodeError con →, ⚠️, etc.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, OSError, ValueError):
            pass

    configure_logging()

    # El binario de PyInstaller debe arrancar la suite al hacer doble clic,
    # sin argumentos. La CLI instalada mantiene la ayuda por defecto.
    if getattr(sys, "frozen", False) and len(sys.argv) == 1:
        sys.argv.append("start")

    app()


if __name__ == "__main__":
    main()
