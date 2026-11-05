"""CLI del Intruder: ataque one-shot con tabla y resumen (F3).

Ejemplo:

    prox0x intruder start --from-flow 3 --mode sniper \\
        --payload-file ~/diccionario.txt --position q --concurrency 10

Las posiciones pueden seleccionarse con ``--position`` (nombre o índice
1-based) o marcando la petición con ``§…§`` (también admite ``--request-file``
para editar el wire directamente). El envío delega en ``RequestEngine``.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import typer

from cli.flow_source import FlowSourceError, load_flow
from core.config import default_flows_file
from core.engine import AttemptStatus, RedirectMode, RequestOptions
from core.model import HttpService, Request
from core.net.wire import parse_request
from intruder import (
    Attack,
    AttackMode,
    AttackResult,
    PayloadSet,
    PayloadProcessor,
    PayloadSourceError,
    Prefix,
    ProcessorChain,
    RequestTemplate,
    SkipIf,
    Suffix,
    UrlEncode,
)

intruder_app = typer.Typer(
    help="Intruder: plantilla, payloads, 4 modos y tabla de resultados",
    no_args_is_help=True,
)

_MODE_ALIASES = {
    "sniper": AttackMode.SNIPER,
    "battering_ram": AttackMode.BATTERING_RAM,
    "battering-ram": AttackMode.BATTERING_RAM,
    "pitchfork": AttackMode.PITCHFORK,
    "cluster_bomb": AttackMode.CLUSTER_BOMB,
    "cluster-bomb": AttackMode.CLUSTER_BOMB,
}
_MARKERS = (b"\xc2\xa7", b"\xa7")  # § en UTF-8 y latin-1


class IntruderCliError(Exception):
    """Error de uso del CLI (se muestra sin traza)."""


# ------------------------------------------------------------------- helpers


def _mode(value: str) -> AttackMode:
    mode = _MODE_ALIASES.get(value.strip().lower())
    if mode is None:
        disponibles = ", ".join(sorted(_MODE_ALIASES))
        raise IntruderCliError(f"modo {value!r} no válido; usa: {disponibles}")
    return mode


def _load_request(
    flows_file: Path, from_flow: int, request_file: Path | None
) -> tuple[Request, HttpService, str]:
    try:
        request, service, name = load_flow(flows_file, from_flow)
    except FlowSourceError as exc:
        raise IntruderCliError(str(exc)) from exc

    if request_file is not None:
        try:
            raw = request_file.read_bytes()
        except OSError as exc:
            raise IntruderCliError(
                f"no se pudo leer la petición {request_file}: {exc}"
            ) from exc
        try:
            request = parse_request(raw)
        except ValueError as exc:
            raise IntruderCliError(
                f"la petición de {request_file} no es válida: {exc}"
            ) from exc
    return request, service, name


def _build_template(request: Request) -> RequestTemplate:
    raw = request.to_bytes()
    try:
        if any(marker in raw for marker in _MARKERS):
            return RequestTemplate.from_markers(request)
        return RequestTemplate.auto(request)
    except ValueError as exc:
        raise IntruderCliError(str(exc)) from exc


def _select_positions(
    template: RequestTemplate, tokens: list[str]
) -> RequestTemplate:
    if not tokens:
        return template
    available = ", ".join(
        f"{point.index + 1}={point.name}" for point in template.points
    )
    indices: list[int] = []
    for token in tokens:
        token = token.strip()
        if not token:
            continue
        if token.isdigit():
            index = int(token) - 1
            if not 0 <= index < template.position_count:
                raise IntruderCliError(
                    f"posición {token} fuera de rango; disponibles: {available}"
                )
            if index not in indices:
                indices.append(index)
        else:
            matches = [
                point.index for point in template.points if point.name == token
            ]
            if not matches:
                raise IntruderCliError(
                    f"no existe la posición {token!r}; disponibles: {available}"
                )
            for index in matches:
                if index not in indices:
                    indices.append(index)
    try:
        return template.subset(indices)
    except ValueError as exc:
        raise IntruderCliError(str(exc)) from exc


def _load_sets(
    paths: list[Path], mode: AttackMode, positions: int
) -> tuple[PayloadSet, ...]:
    if not paths:
        raise IntruderCliError("falta --payload-file (diccionario .pay/.txt)")
    sets: list[PayloadSet] = []
    for path in paths:
        try:
            sets.append(PayloadSet.from_file(path))
        except (PayloadSourceError, ValueError) as exc:
            raise IntruderCliError(str(exc)) from exc

    if mode in (AttackMode.SNIPER, AttackMode.BATTERING_RAM):
        if len(sets) != 1:
            raise IntruderCliError(
                f"{mode.value} usa exactamente un --payload-file"
            )
    elif len(sets) != positions:
        raise IntruderCliError(
            f"{mode.value} necesita un --payload-file por posición "
            f"({positions} posiciones, {len(sets)} diccionarios)"
        )
    return tuple(sets)


def _build_processors(
    *,
    skip: list[str],
    url_encode: bool,
    prefix: str | None,
    suffix: str | None,
) -> ProcessorChain:
    processors: list[PayloadProcessor] = []
    if skip:
        skipped = {item.encode("utf-8") for item in skip}
        processors.append(SkipIf(lambda payload: payload in skipped))
    if url_encode:
        processors.append(UrlEncode())
    if prefix is not None:
        processors.append(Prefix(prefix.encode("utf-8")))
    if suffix is not None:
        processors.append(Suffix(suffix.encode("utf-8")))
    return ProcessorChain(tuple(processors))


# --------------------------------------------------------------- presentación


def _fmt_ms(value: float | None) -> str:
    return "-" if value is None else f"{value:.1f} ms"


def _fmt_bytes(value: int) -> str:
    if value < 1024:
        return f"{value} B"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} KiB"
    return f"{value / (1024 * 1024):.1f} MiB"


def _truncate(text: str, width: int) -> str:
    clean = text.replace("\r", "\\r").replace("\n", "\\n")
    return clean if len(clean) <= width else clean[: width - 1] + "…"


def _print_positions(template: RequestTemplate) -> None:
    parts: list[str] = []
    for point in template.points:
        kind = point.param_type.value if point.param_type is not None else "?"
        value = point.base_value.decode("utf-8", errors="replace")
        parts.append(
            f"{point.index + 1}={point.name} [{kind}] {_truncate(value, 24)!r}"
        )
    typer.echo("Posiciones: " + " · ".join(parts))


def _print_results(results: tuple[AttackResult, ...]) -> None:
    header = (
        f"{'#':>4}  {'PAYLOAD(S)':<32} {'CÓD':>4} {'TAMAÑO':>10} "
        f"{'TTFB':>10} {'TOTAL':>10} {'ESTADO':<18} ERROR"
    )
    typer.echo()
    typer.echo(header)
    typer.echo("-" * len(header))
    for result in results:
        code = str(result.status_code) if result.status_code is not None else "-"
        size = _fmt_bytes(result.length) if result.response is not None else "-"
        typer.echo(
            f"{result.index + 1:>4}  {_truncate(result.label, 32):<32} "
            f"{code:>4} {size:>10} {_fmt_ms(result.ttfb_ms):>10} "
            f"{_fmt_ms(result.total_ms):>10} {result.status.value:<18} "
            f"{result.error or ''}".rstrip()
        )


def _summary(attack: Attack, results: tuple[AttackResult, ...], elapsed: float) -> None:
    build_errors = sum(
        1
        for result in results
        if result.request is None and result.status is AttemptStatus.DROPPED
    )
    sent = len(results) - build_errors
    failed = sum(1 for result in results if not result.ok)
    typer.echo(
        f"\nResumen: esperadas {attack.expected_requests} · enviadas {sent} · "
        f"saltadas {attack.skipped} · fallidas {failed} · tiempo {elapsed:.2f} s"
    )


# ------------------------------------------------------------------- comando


@intruder_app.command("start")
def intruder_start(
    from_flow: int = typer.Option(
        ..., "--from-flow", help="Id del flujo capturado (ver `prox0x flows`)"
    ),
    flows_file: Path = typer.Option(
        default_flows_file(), "--flows-file", "-f", help="JSONL de flujos del proxy"
    ),
    request_file: Path | None = typer.Option(
        None,
        "--request-file",
        help="Petición en texto que sustituye a la del flujo (admite §…§)",
    ),
    mode: str = typer.Option("sniper", "--mode", help="sniper|battering_ram|pitchfork|cluster_bomb"),
    payload_file: list[Path] = typer.Option(
        [], "--payload-file", "-p", help="Diccionario .pay/.txt (repetible)"
    ),
    position: list[str] = typer.Option(
        [], "--position", help="Nombre o índice 1-based de la posición (repetible)"
    ),
    concurrency: int = typer.Option(
        10, "--concurrency", "-c", help="Máximo de peticiones en vuelo"
    ),
    throttle: float = typer.Option(
        0.0, "--throttle", help="Retardo fijo entre envíos (ms)"
    ),
    url_encode: bool = typer.Option(
        False, "--url-encode", help="Percent-encodea cada payload"
    ),
    prefix: str | None = typer.Option(None, "--prefix", help="Prefijo añadido al payload"),
    suffix: str | None = typer.Option(None, "--suffix", help="Sufijo añadido al payload"),
    skip: list[str] = typer.Option(
        [], "--skip", help="Payload exacto que se descarta (SKIP, repetible)"
    ),
    insecure: bool = typer.Option(
        False, "--insecure", help="No verificar el certificado upstream"
    ),
    timeout: float = typer.Option(60.0, "--timeout", help="Timeout por petición (s)"),
    follow_redirects: bool = typer.Option(
        False, "--follow-redirects", help="Seguir redirecciones (ALWAYS)"
    ),
) -> None:
    """Ejecuta un ataque y muestra la tabla de resultados y el resumen."""
    if not 1 <= concurrency <= 999:
        raise typer.BadParameter(
            "--concurrency debe estar entre 1 y 999", param_hint="--concurrency"
        )
    if throttle < 0:
        raise typer.BadParameter("--throttle no puede ser negativo", param_hint="--throttle")
    if timeout <= 0:
        raise typer.BadParameter("--timeout debe ser > 0", param_hint="--timeout")

    try:
        attack_mode = _mode(mode)
        request, service, name = _load_request(flows_file, from_flow, request_file)
        template = _select_positions(_build_template(request), position)
        sets = _load_sets(payload_file, attack_mode, template.position_count)
        processors = _build_processors(
            skip=skip,
            url_encode=url_encode,
            prefix=prefix,
            suffix=suffix,
        )
        options = RequestOptions(
            verify_upstream=not insecure,
            timeout_ms=timeout * 1000,
            throttle_ms=throttle,
            redirect=RedirectMode.ALWAYS if follow_redirects else RedirectMode.NEVER,
        )
        attack = Attack(
            template=template,
            service=service,
            mode=attack_mode,
            sets=sets,
            options=options,
            concurrency=concurrency,
            processors=processors,
        )
    except (IntruderCliError, ValueError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(
        f'Intruder — {name} · {request.method} {request.target} · {service}'
    )
    typer.echo(
        f"Modo: {attack_mode.value} · posiciones: {template.position_count} · "
        f"payloads: {attack.expected_requests} · concurrencia: {concurrency} · "
        f"throttle: {throttle:g} ms"
    )
    _print_positions(template)
    typer.echo("Ejecutando ataque…")

    started = time.perf_counter()
    results = asyncio.run(attack.run())
    elapsed = time.perf_counter() - started

    _print_results(results)
    _summary(attack, results, elapsed)
    if any(not result.ok for result in results):
        raise typer.Exit(code=1)
