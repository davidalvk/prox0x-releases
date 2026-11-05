"""Comando CLI para arrancar el proxy interceptador."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer

from core.ca import CaError, CaPassphraseError, CertificateAuthority
from core.config import (
    DEFAULT_FLOW_BUFFER,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_UPSTREAM_TIMEOUT,
    default_ca_dir,
    default_control_socket,
    default_db_file,
    default_flows_file,
    default_match_replace_file,
    default_scope_file,
)
from core.logging import get_logger
from core.store import FlowStore
from proxy import ProxyConfig, ProxyServer
from cli.ca import resolve_passphrase

proxy_app = typer.Typer(help="Proxy interceptador HTTP/1.1 + MITM TLS", no_args_is_help=True)
_log = get_logger("prox0x.cli.proxy")


@proxy_app.command("start")
def proxy_start(
    host: str = typer.Option(DEFAULT_HOST, "--host", help="Interfaz de escucha (cuidado: 0.0.0.0 es un open relay)"),
    port: int = typer.Option(DEFAULT_PORT, "--port", help="Puerto del listener"),
    ca_dir: Path = typer.Option(default_ca_dir, "--ca-dir", help="Directorio de la CA"),
    passphrase: str = typer.Option(None, "--passphrase", help="Frase de paso de la CA"),
    insecure: bool = typer.Option(
        False, "--insecure", help="No verificar el certificado del origen (upstream)"
    ),
    timeout: float = typer.Option(
        DEFAULT_UPSTREAM_TIMEOUT, "--timeout", help="Timeout por petición contra el origen"
    ),
    buffer_size: int = typer.Option(
        DEFAULT_FLOW_BUFFER, "--buffer-size", help="Flujos retenidos en memoria"
    ),
    flows_file: Path = typer.Option(
        default_flows_file,
        "--flows-file",
        help="JSONL de flujos para `prox0x flows` (vacío desactiva el volcado)",
    ),
    db_file: Path = typer.Option(
        default_db_file(),
        "--db-file",
        help="SQLite WAL para la API (vacío desactiva la persistencia)",
    ),
    control_socket: Path = typer.Option(
        default_control_socket(),
        "--control-socket",
        help="Socket Unix del control plane de breakpoints (vacío lo desactiva)",
    ),
    breakpoint_timeout: float = typer.Option(
        300.0,
        "--breakpoint-timeout",
        help="Timeout de un breakpoint sin respuesta (segundos)",
    ),
    scope_file: Path = typer.Option(
        default_scope_file(),
        "--scope-file",
        help="JSON con reglas de Scope (vacío desactiva la persistencia)",
    ),
    match_replace_file: Path = typer.Option(
        default_match_replace_file(),
        "--match-replace-file",
        help="JSON con reglas Match & Replace (vacío desactiva la persistencia)",
    ),
) -> None:
    """Arranca el proxy en `host:port` con los flujos en un buffer circular."""
    if host not in ("127.0.0.1", "localhost", "::1"):
        typer.echo(
            f"⚠️  Vas a escuchar en {host}: cualquier red vecina podrá usar tu proxy "
            "(open relay). Úsalo solo en entornos controlados.",
            err=True,
        )

    passphrase = resolve_passphrase(passphrase, prompt="Frase de paso de la CA")
    try:
        if not CertificateAuthority.exists(ca_dir):
            typer.echo(f"No hay CA en {ca_dir}; generándola automáticamente…")
            ca = CertificateAuthority.init(ca_dir, passphrase)
        else:
            ca = CertificateAuthority.load(ca_dir, passphrase)
    except (CaError, CaPassphraseError, ValueError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if ca.is_expired:
        typer.echo("⚠️  La CA está caducada; regenera con `prox0x ca init --force`.", err=True)

    config = ProxyConfig(
        host=host,
        port=port,
        verify_upstream=not insecure,
        upstream_timeout=timeout,
        flows_file=flows_file if str(flows_file) else None,
        db_file=db_file if str(db_file) else None,
        control_socket=control_socket if str(control_socket) else None,
        breakpoint_timeout=breakpoint_timeout,
        scope_file=scope_file if str(scope_file) else None,
        match_replace_file=(
            match_replace_file if str(match_replace_file) else None
        ),
    )
    store = FlowStore(maxsize=buffer_size)
    server = ProxyServer(ca, store, config=config)

    async def _run() -> None:
        await server.start()
        typer.echo(f"Proxy escuchando en http://{config.host}:{server.port}")
        if config.flows_file:
            typer.echo(f"Flujos: {config.flows_file} (inspecciona con `prox0x flows`)")
        if config.db_file:
            typer.echo(f"SQLite: {config.db_file} (API: `./tmp/prox0x-venv/bin/uvicorn api.main:app --reload`)")
        if config.control_socket:
            typer.echo(f"Control: {config.control_socket} (breakpoints)")
        if config.scope_file:
            typer.echo(f"Scope: {config.scope_file}")
        if config.match_replace_file:
            typer.echo(f"Match & Replace: {config.match_replace_file}")
        typer.echo("Apunta tu navegador a ese proxy y confía en la CA exportada.")
        typer.echo("Ctrl+C para parar.")
        try:
            await server.serve()
        except asyncio.CancelledError:
            pass
        finally:
            await server.stop()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        typer.echo("Proxy parado.")
