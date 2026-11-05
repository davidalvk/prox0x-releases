"""CLI del Repeater: envío one-shot y modo interactivo (F2).

- ``prox0x repeater send --from-flow 3 ...`` es scriptable y lee el mismo JSONL
  que ``prox0x flows`` (puente desde el historial del Proxy).
- ``prox0x repeater`` abre una sesión con pestañas en memoria, versiones y
  comparación de respuestas, sin necesidad de UI (la UI llega en F5).

La salida muestra siempre estado, código, tamaño del cuerpo, TTFB y total.
"""

from __future__ import annotations

import asyncio
import shlex
from pathlib import Path

import typer

from core.config import default_flows_file
from core.engine import Attempt, RedirectMode, RequestEngine, RequestOptions
from core.model import HttpService, Request
from cli.flow_source import FlowSourceError, load_flow
from repeater import Repeater, Tab
from repeater.diff import DiffResult

repeater_app = typer.Typer(
    help="Repeater: pestañas, versiones, envío manual/paralelo y diff",
    no_args_is_help=False,
    invoke_without_command=True,
)

_BANNER = (
    "prox0x Repeater — pestañas en memoria. `help` para ver los comandos, "
    "`quit` para salir."
)
_MAX_BODY_PREVIEW = 4_096
_MAX_DIFF_LINES = 80


class RepeaterCliError(Exception):
    """Error de uso del CLI (se muestra sin traza)."""


# --------------------------------------------------------------------- flujos


def _load_flow(path: Path, flow_id: int) -> tuple[Request, HttpService, str]:
    """Carga un flujo del JSONL del Proxy como (request final, servicio, nombre)."""
    try:
        return load_flow(path, flow_id)
    except FlowSourceError as exc:
        raise RepeaterCliError(str(exc)) from exc


# ---------------------------------------------------------------- ediciones


def _parse_header(spec: str) -> tuple[str, str]:
    name, separator, value = spec.partition(":")
    if not separator or not name.strip():
        raise RepeaterCliError(
            f"--set-header espera 'Nombre: valor' (recibido {spec!r})"
        )
    return name.strip(), value.strip()


def _parse_replace(spec: str) -> tuple[str, str]:
    old, separator, new = spec.partition("=")
    if not separator or not old:
        raise RepeaterCliError(f"--replace espera 'viejo=nuevo' (recibido {spec!r})")
    return old, new


def _body_bytes(text: str) -> bytes:
    if text.startswith("@"):
        path = Path(text[1:])
        try:
            return path.read_bytes()
        except OSError as exc:
            raise RepeaterCliError(f"no se pudo leer el cuerpo {path}: {exc}") from exc
    return text.encode("utf-8")


def _apply_edits(
    repeater: Repeater,
    tab: Tab,
    *,
    headers: list[str],
    body: str | None,
    replacements: list[str],
) -> Tab:
    try:
        for spec in headers:
            name, value = _parse_header(spec)
            tab = repeater.set_header(tab.id, name, value)
        if body is not None:
            tab = repeater.set_body(tab.id, _body_bytes(body))
        for spec in replacements:
            old, new = _parse_replace(spec)
            tab = repeater.replace(tab.id, old, new)
    except ValueError as exc:
        raise RepeaterCliError(str(exc)) from exc
    return tab


def _options(
    *,
    insecure: bool,
    timeout: float,
    follow_redirects: bool = False,
    sni: str | None = None,
) -> RequestOptions:
    if timeout <= 0:
        raise RepeaterCliError("--timeout debe ser > 0")
    return RequestOptions(
        verify_upstream=not insecure,
        timeout_ms=timeout * 1000,
        redirect=RedirectMode.ALWAYS if follow_redirects else RedirectMode.NEVER,
        sni=sni,
    )


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
    text = text.replace("\r", "").replace("\n", " ")
    return text if len(text) <= width else text[: width - 1] + "…"


def _print_attempts(attempts: tuple[Attempt, ...], *, start: int = 1) -> None:
    header = (
        f"{'#':>3}  {'ESTADO':<18} {'CÓD':>4} {'CUERPO':>10} "
        f"{'TTFB':>10} {'TOTAL':>10}  ERROR"
    )
    typer.echo(header)
    typer.echo("-" * len(header))
    for offset, attempt in enumerate(attempts):
        body_size = len(attempt.response.body) if attempt.response is not None else 0
        typer.echo(
            f"{start + offset:>3}  {attempt.status.value:<18} "
            f"{(str(attempt.status_code) if attempt.status_code is not None else '-'):>4} "
            f"{(_fmt_bytes(body_size) if attempt.response is not None else '-'):>10} "
            f"{_fmt_ms(attempt.ttfb_ms):>10} "
            f"{_fmt_ms(attempt.total_ms):>10}  "
            f"{attempt.error or ''}".rstrip()
        )


def _print_summary(attempts: tuple[Attempt, ...]) -> None:
    if not attempts:
        typer.echo("Sin envíos.")
        return
    ok = sum(1 for attempt in attempts if attempt.ok)
    failures = len(attempts) - ok
    suffix = f" · {failures} fallo(s)" if failures else ""
    typer.echo(f"\n{ok}/{len(attempts)} con respuesta{suffix}.")


def _print_diff(result: DiffResult, *, label: str) -> None:
    if result.summary:
        typer.echo(result.summary)
    if not result.has_changes:
        typer.echo(f"Diff {label}: sin diferencias.")
        return

    kind = "binario" if result.binary else "texto"
    typer.echo(
        f"Diff {label} ({kind}): +{result.stats.added} -{result.stats.removed} "
        f"~{result.stats.changed} · {result.old_size:,} → {result.new_size:,} bytes"
    )
    if result.large:
        return

    shown = 0
    for op in result.ops:
        if op.kind == "equal":
            continue
        for line in op.old_lines:
            typer.echo(f"- {_truncate(line, 160)}")
            shown += 1
        for line in op.new_lines:
            typer.echo(f"+ {_truncate(line, 160)}")
            shown += 1
        if shown >= _MAX_DIFF_LINES:
            typer.echo("… (diff truncado)")
            break


def _print_request(request: Request, service: HttpService) -> None:
    raw = request.to_bytes()
    head, _, body = raw.partition(b"\r\n\r\n")
    typer.echo(head.decode("latin-1"))
    typer.echo(f"→ {service}")
    if body:
        typer.echo(f"[cuerpo: {len(body)} bytes]")
        preview = body[:_MAX_BODY_PREVIEW]
        typer.echo(preview.decode("utf-8", errors="replace"))
        if len(body) > _MAX_BODY_PREVIEW:
            typer.echo(f"… ({len(body) - _MAX_BODY_PREVIEW} bytes más)")


# -------------------------------------------------------------------- one-shot


async def _send_async(
    request: Request,
    service: HttpService,
    name: str,
    *,
    headers: list[str],
    body: str | None,
    replacements: list[str],
    count: int,
    concurrency: int,
    options: RequestOptions,
    show_diff: bool,
    diff_headers: bool,
) -> None:
    engine = RequestEngine(max_concurrency=max(1, concurrency))
    repeater = Repeater(engine=engine)
    tab = repeater.send_to_repeater(request, service, name=name)
    if headers or body is not None or replacements:
        tab = _apply_edits(
            repeater, tab, headers=headers, body=body, replacements=replacements
        )

    typer.echo(
        f'Pestaña {tab.id} "{tab.name}" — '
        f"{tab.current.method} {tab.current.target} {tab.current.version}"
    )
    typer.echo(
        f"Servicio: {service} · versiones: {tab.version_count} · "
        f"envíos: {count} (concurrencia {concurrency})"
    )
    attempts = await repeater.send(
        tab.id, count=count, options=options, concurrency=concurrency
    )
    typer.echo()
    _print_attempts(attempts)
    _print_summary(attempts)

    if show_diff and len(attempts) >= 2:
        result = repeater.diff(
            tab.id, 0, -1, ignore_headers=not diff_headers
        )
        typer.echo()
        _print_diff(
            result,
            label=f"respuestas #1 vs #{len(attempts)}"
            + ("" if diff_headers else " (cuerpo)"),
        )
    if any(not attempt.ok for attempt in attempts):
        raise typer.Exit(code=1)


@repeater_app.command("send")
def repeater_send(
    from_flow: int = typer.Option(
        ..., "--from-flow", help="Id del flujo capturado (ver `prox0x flows`)"
    ),
    flows_file: Path = typer.Option(
        default_flows_file(), "--flows-file", "-f", help="JSONL de flujos del proxy"
    ),
    set_header: list[str] = typer.Option(
        [], "--set-header", "-H", help="Cabecera a fijar, formato 'Nombre: valor'"
    ),
    body: str | None = typer.Option(
        None, "--body", "-b", help="Cuerpo nuevo ('@fichero' lee de disco)"
    ),
    replace: list[str] = typer.Option(
        [], "--replace", help="Reemplazo textual 'viejo=nuevo'"
    ),
    count: int = typer.Option(1, "--count", "-n", help="Nº de envíos"),
    concurrency: int = typer.Option(
        1, "--concurrency", "-c", help="Envíos simultáneos"
    ),
    show_diff: bool = typer.Option(
        False, "--diff", help="Diff entre la primera y la última respuesta"
    ),
    diff_headers: bool = typer.Option(
        False, "--diff-headers", help="Incluir cabeceras en el diff"
    ),
    insecure: bool = typer.Option(
        False, "--insecure", help="No verificar el certificado upstream"
    ),
    timeout: float = typer.Option(60.0, "--timeout", help="Timeout por petición (s)"),
    follow_redirects: bool = typer.Option(
        False, "--follow-redirects", help="Seguir redirecciones (ALWAYS)"
    ),
    sni: str | None = typer.Option(None, "--sni", help="SNI explícito"),
) -> None:
    """Envía una petición del historial con ediciones y muestra las respuestas."""
    if count < 1:
        raise typer.BadParameter("--count debe ser >= 1", param_hint="--count")
    if concurrency < 1:
        raise typer.BadParameter(
            "--concurrency debe ser >= 1", param_hint="--concurrency"
        )
    try:
        request, service, name = _load_flow(flows_file, from_flow)
        options = _options(
            insecure=insecure,
            timeout=timeout,
            follow_redirects=follow_redirects,
            sni=sni,
        )
        asyncio.run(
            _send_async(
                request,
                service,
                name,
                headers=set_header,
                body=body,
                replacements=replace,
                count=count,
                concurrency=concurrency,
                options=options,
                show_diff=show_diff,
                diff_headers=diff_headers,
            )
        )
    except RepeaterCliError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


# ------------------------------------------------------------------ interactivo


def _print_help() -> None:
    typer.echo(
        "\n".join(
            (
                "Comandos:",
                "  new <flow_id> [nombre]   crea una pestaña desde el historial del proxy",
                "  tabs                     lista las pestañas",
                "  use <tab_id>             activa una pestaña",
                "  show                     muestra la petición actual",
                "  set header Nombre: valor fija una cabecera (nueva versión)",
                "  set body <texto|@file>   sustituye el cuerpo (nueva versión)",
                "  replace \"viejo\" \"nuevo\"  reemplazo textual (nueva versión)",
                "  raw                      pega una petición completa (termina con '.')",
                "  send [-n N] [-c C]       envía la versión actual 1..N veces",
                "  responses                tabla de respuestas de la pestaña",
                "  diff <a> <b>             compara respuestas (1-based, sin cabeceras)",
                "  undo / redo              navega por el historial de versiones",
                "  quit                     sale",
            )
        )
    )


def _require_tab(repeater: Repeater, current: int | None) -> Tab:
    if current is None:
        raise RepeaterCliError("no hay pestaña activa; usa `new <flow_id>`")
    return repeater.get(current)


def _parse_send_args(rest: str) -> tuple[int, int]:
    args = shlex.split(rest)
    count, concurrency = 1, 1
    index = 0
    while index < len(args):
        token = args[index]
        if token in ("-n", "--count") and index + 1 < len(args):
            count = int(args[index + 1])
            index += 2
        elif token in ("-c", "--concurrency") and index + 1 < len(args):
            concurrency = int(args[index + 1])
            index += 2
        else:
            raise RepeaterCliError(f"argumento no reconocido en send: {token!r}")
    if count < 1 or concurrency < 1:
        raise RepeaterCliError("-n y -c deben ser >= 1")
    return count, concurrency


async def _repl(
    flows_file: Path,
    *,
    insecure: bool,
    timeout: float,
) -> None:
    engine = RequestEngine(max_concurrency=8)
    repeater = Repeater(engine=engine)
    current: int | None = None
    try:
        options = _options(insecure=insecure, timeout=timeout)
    except RepeaterCliError as exc:
        typer.echo(f"Error: {exc}", err=True)
        return

    typer.echo(_BANNER)
    while True:
        try:
            line = input("repeater> ")
        except EOFError:
            typer.echo()
            break

        line = line.strip()
        if not line:
            continue
        command, _, rest = line.partition(" ")
        command = command.lower()
        rest = rest.strip()

        try:
            if command in ("quit", "exit"):
                break
            if command in ("help", "?"):
                _print_help()
            elif command == "new":
                parts = rest.split(maxsplit=1)
                if not parts:
                    raise RepeaterCliError("uso: new <flow_id> [nombre]")
                request, service, name = _load_flow(flows_file, int(parts[0]))
                if len(parts) > 1:
                    name = parts[1]
                tab = repeater.send_to_repeater(request, service, name=name)
                current = tab.id
                typer.echo(
                    f'Pestaña {tab.id} "{tab.name}" creada: '
                    f"{tab.current.method} {tab.current.target} {tab.current.version} → {service}"
                )
            elif command == "tabs":
                if not repeater.tabs:
                    typer.echo("No hay pestañas. Usa `new <flow_id>`.")
                else:
                    typer.echo(
                        f"  {'ID':>3}  {'NOMBRE':<24} {'VERS':>4} {'RESP':>4}  REQUEST"
                    )
                    for tab in repeater.tabs:
                        marker = "*" if tab.id == current else " "
                        typer.echo(
                            f"{marker} {tab.id:>3}  {_truncate(tab.name, 24):<24} "
                            f"{tab.version_count:>4} {tab.response_count:>4}  "
                            f"{tab.current.method} {_truncate(tab.current.target, 50)}"
                        )
            elif command == "use":
                tab = repeater.get(int(rest))
                current = tab.id
                typer.echo(f'Pestaña activa: {tab.id} "{tab.name}"')
            elif command == "show":
                tab = _require_tab(repeater, current)
                _print_request(tab.current, tab.service)
                typer.echo(
                    f"\nVersión {tab.selected_version + 1}/{tab.version_count} · "
                    f"{tab.response_count} respuesta(s)"
                )
            elif command == "set":
                tab = _require_tab(repeater, current)
                kind, _, args = rest.partition(" ")
                if kind == "header":
                    name, value = _parse_header(args)
                    tab = repeater.set_header(tab.id, name, value)
                elif kind == "body":
                    tab = repeater.set_body(tab.id, _body_bytes(args))
                else:
                    raise RepeaterCliError("uso: set header Nombre: valor | set body <texto>")
                typer.echo(
                    f"Versión {tab.selected_version + 1}/{tab.version_count} creada."
                )
            elif command == "replace":
                tab = _require_tab(repeater, current)
                args = shlex.split(rest)
                if len(args) != 2:
                    raise RepeaterCliError('uso: replace "viejo" "nuevo"')
                tab = repeater.replace(tab.id, args[0], args[1])
                typer.echo(
                    f"Versión {tab.selected_version + 1}/{tab.version_count} creada."
                )
            elif command == "raw":
                tab = _require_tab(repeater, current)
                typer.echo("Pega la petición completa; termina con una línea que sea solo '.'")
                lines: list[str] = []
                while True:
                    try:
                        part = input("... ")
                    except EOFError:
                        break
                    if part.strip() == ".":
                        break
                    lines.append(part)
                tab = repeater.set_raw(tab.id, "\n".join(lines).encode("utf-8"))
                typer.echo(
                    f"Versión {tab.selected_version + 1}/{tab.version_count} creada."
                )
            elif command == "send":
                tab = _require_tab(repeater, current)
                count, concurrency = _parse_send_args(rest)
                typer.echo(f"Enviando {count} petición(es)…")
                attempts = await repeater.send(
                    tab.id,
                    count=count,
                    options=options,
                    concurrency=concurrency,
                )
                updated = repeater.get(tab.id)
                start = updated.response_count - len(attempts) + 1
                _print_attempts(attempts, start=start)
                _print_summary(attempts)
            elif command == "responses":
                tab = _require_tab(repeater, current)
                if not tab.responses:
                    typer.echo("La pestaña no tiene respuestas. Usa `send`.")
                else:
                    _print_attempts(tab.responses)
            elif command == "diff":
                tab = _require_tab(repeater, current)
                args = shlex.split(rest)
                if not args:
                    raise RepeaterCliError("uso: diff <a> <b> (índices 1-based)")
                if len(args) == 1:
                    first, second = 1, int(args[0])
                elif len(args) == 2:
                    first, second = int(args[0]), int(args[1])
                else:
                    raise RepeaterCliError("uso: diff <a> <b>")
                if first < 1 or second < 1:
                    raise RepeaterCliError("los índices empiezan en 1")
                result = repeater.diff(
                    tab.id, first - 1, second - 1, ignore_headers=True
                )
                _print_diff(result, label=f"respuestas #{first} vs #{second} (cuerpo)")
            elif command == "undo":
                tab = _require_tab(repeater, current)
                tab = repeater.undo(tab.id)
                typer.echo(
                    f"Versión seleccionada: {tab.selected_version + 1}/{tab.version_count}"
                )
            elif command == "redo":
                tab = _require_tab(repeater, current)
                tab = repeater.redo(tab.id)
                typer.echo(
                    f"Versión seleccionada: {tab.selected_version + 1}/{tab.version_count}"
                )
            else:
                typer.echo("Comando desconocido. Escribe `help`.")
        except RepeaterCliError as exc:
            typer.echo(f"Error: {exc}", err=True)
        except (KeyError, ValueError, IndexError) as exc:
            typer.echo(f"Error: {exc}", err=True)


@repeater_app.callback(invoke_without_command=True)
def repeater_root(
    ctx: typer.Context,
    flows_file: Path = typer.Option(
        default_flows_file(), "--flows-file", "-f", help="JSONL de flujos del proxy"
    ),
    insecure: bool = typer.Option(
        False, "--insecure", help="No verificar el certificado upstream"
    ),
    timeout: float = typer.Option(60.0, "--timeout", help="Timeout por petición (s)"),
) -> None:
    """Modo interactivo del Repeater (sin subcomando)."""
    if ctx.invoked_subcommand is not None:
        return
    try:
        asyncio.run(_repl(flows_file, insecure=insecure, timeout=timeout))
    except KeyboardInterrupt:
        typer.echo("\nHasta luego.")
