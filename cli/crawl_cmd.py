"""Comando CLI ``prox0x crawl`` para probar el rastreador (Fase 1)."""

from __future__ import annotations

import asyncio

import typer

from core.scan.crawler import Crawler, CrawlerConfig


def crawl_command(
    url: str = typer.Argument(..., help="URL semilla, p. ej. http://192.168.0.9:5000/"),
    domain: str = typer.Option(
        None,
        "--domain",
        help="Dominio base para el Scope (por defecto, el host de la URL semilla)",
    ),
    max_urls: int = typer.Option(
        100, "--max-urls", min=0, help="Máximo de URLs a visitar"
    ),
    concurrency: int = typer.Option(
        5, "--concurrency", min=1, max=20, help="Peticiones concurrentes"
    ),
    timeout: float = typer.Option(
        10.0, "--timeout", min=0.1, help="Timeout por petición (segundos)"
    ),
    no_robots: bool = typer.Option(
        False, "--no-robots", help="No leer robots.txt"
    ),
    no_sitemaps: bool = typer.Option(
        False, "--no-sitemaps", help="No leer sitemap.xml"
    ),
    no_javascript: bool = typer.Option(
        False, "--no-javascript", help="No extraer endpoints de JavaScript"
    ),
    insecure: bool = typer.Option(
        False, "--insecure", help="No verificar TLS en el origen"
    ),
    show_urls: bool = typer.Option(
        True, "--urls/--no-urls", help="Imprimir las URLs descubiertas"
    ),
) -> None:
    """Rastrea una URL y muestra endpoints, formularios y errores."""

    config = CrawlerConfig(
        max_urls=max_urls,
        concurrency=concurrency,
        timeout_s=timeout,
        parse_robots=not no_robots,
        parse_sitemaps=not no_sitemaps,
        parse_javascript=not no_javascript,
        verify_tls=not insecure,
    )

    async def _run():
        return await Crawler(url, domain, config=config).crawl()

    try:
        result = asyncio.run(_run())
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(
        f"URLs descubiertas: {len(result.urls)} · visitadas: "
        f"{len(result.visited)} · formularios: {len(result.forms)} · "
        f"errores: {len(result.errors)}"
    )
    if result.robots_url:
        typer.echo(f"robots.txt: {result.robots_url}")
    for sitemap in result.sitemap_urls:
        typer.echo(f"sitemap: {sitemap}")

    if show_urls:
        for discovered in result.urls:
            typer.echo(discovered)

    for form in result.forms:
        fields = ", ".join(field.name for field in form.fields)
        suffix = f" [{fields}]" if fields else ""
        typer.echo(f"FORM {form.method} {form.action}{suffix}")

    for error in result.errors:
        typer.echo(f"ERROR {error}", err=True)
