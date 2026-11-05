"""Comandos CLI de la CA: init, info, export y purge."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import typer

from core.ca import CaError, CaPassphraseError, CertificateAuthority
from core.config import ENV_CA_PASSPHRASE, default_ca_dir

ca_app = typer.Typer(help="Gestión de la CA de prox0x", no_args_is_help=True)


def resolve_passphrase(explicit: str | None, *, prompt: str) -> str:
    """Frase de paso: opción explícita > variable de entorno > prompt oculto."""
    if explicit:
        return explicit
    from_env = os.environ.get(ENV_CA_PASSPHRASE)
    if from_env:
        return from_env
    return typer.prompt(prompt, hide_input=True)


@ca_app.command("init")
def ca_init(
    ca_dir: Path = typer.Option(default_ca_dir, "--ca-dir", help="Directorio de la CA"),
    passphrase: str = typer.Option(
        None, "--passphrase", help=f"Frase de paso (o ${ENV_CA_PASSPHRASE})"
    ),
    common_name: str = typer.Option("prox0x CA", "--cn", help="CN del certificado"),
    force: bool = typer.Option(False, "--force", help="Regenera aunque ya exista"),
) -> None:
    """Genera la CA autofirmada (ECDSA P-256) y la guarda cifrada con permisos 0600."""
    passphrase = resolve_passphrase(passphrase, prompt="Frase de paso de la CA")
    try:
        ca = CertificateAuthority.init(
            ca_dir, passphrase, common_name=common_name, overwrite=force
        )
    except (CaError, ValueError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"CA creada en {ca.ca_dir}")
    typer.echo(f"  certificado: {ca.cert_path}")
    typer.echo(f"  clave cifrada: {ca.key_path} (0600)")
    typer.echo(f"  huella SHA-256: {ca.fingerprint()}")
    typer.echo("Exporta el certificado con `prox0x ca export` para instalarlo en el navegador.")


@ca_app.command("info")
def ca_info(
    ca_dir: Path = typer.Option(default_ca_dir, "--ca-dir", help="Directorio de la CA"),
    passphrase: str = typer.Option(None, "--passphrase", help=f"Frase de paso (o ${ENV_CA_PASSPHRASE})"),
) -> None:
    """Muestra el estado de la CA instalada."""
    passphrase = resolve_passphrase(passphrase, prompt="Frase de paso de la CA")
    try:
        ca = CertificateAuthority.load(ca_dir, passphrase)
    except (CaError, CaPassphraseError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"subject:    {ca.certificate.subject.rfc4514_string()}")
    typer.echo(f"emisor:     {ca.certificate.issuer.rfc4514_string()}")
    typer.echo(f"serial:     {ca.certificate.serial_number}")
    typer.echo(f"válida hasta: {ca.not_valid_after.isoformat()}{' (CADUCADA)' if ca.is_expired else ''}")
    typer.echo(f"huella SHA-256: {ca.fingerprint()}")


@ca_app.command("export")
def ca_export(
    out: Path = typer.Option(Path("."), "--out", help="Directorio de destino"),
    name: str = typer.Option("prox0x-ca", "--name", help="Prefijo de los ficheros"),
    ca_dir: Path = typer.Option(default_ca_dir, "--ca-dir", help="Directorio de la CA"),
    passphrase: str = typer.Option(None, "--passphrase", help=f"Frase de paso (o ${ENV_CA_PASSPHRASE})"),
    p12_passphrase: str = typer.Option(
        None, "--p12-passphrase", help="Frase de paso del .p12 (por defecto, la de la CA)"
    ),
) -> None:
    """Exporta la CA a `.pem` (para instalar) y `.p12` (cert + clave)."""
    passphrase = resolve_passphrase(passphrase, prompt="Frase de paso de la CA")
    try:
        ca = CertificateAuthority.load(ca_dir, passphrase)
    except (CaError, CaPassphraseError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    out.mkdir(parents=True, exist_ok=True)
    pem_path = ca.export_pem(out / f"{name}.pem")
    try:
        p12_path = ca.export_pkcs12(out / f"{name}.p12", p12_passphrase or passphrase)
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Certificado (para confiar en el navegador): {pem_path}")
    typer.echo(f"PKCS#12 (cert + clave, respaldo):           {p12_path}")
    typer.echo("")
    typer.echo("Instalación:")
    typer.echo(f"  Firefox: Ajustes → Privacidad → Certificados → Verifiers → Importar {pem_path}")
    typer.echo(f"  Chrome/Chromium: importar {pem_path} como autoridad de confianza")
    typer.echo(f"  Linux (system-wide): sudo cp {pem_path} /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust")


@ca_app.command("purge")
def ca_purge(
    ca_dir: Path = typer.Option(default_ca_dir, "--ca-dir", help="Directorio de la CA"),
    yes: bool = typer.Option(False, "--yes", help="Confirma la eliminación"),
) -> None:
    """Elimina la CA y los certificados hoja (rotación, Plan.md §9)."""
    if not yes:
        typer.confirm(f"¿Borrar la CA y las hojas de {ca_dir}?", abort=True)
    if ca_dir.exists():
        shutil.rmtree(ca_dir)
        typer.echo(f"CA eliminada: {ca_dir}")
    else:
        typer.echo(f"No había CA en {ca_dir}")
