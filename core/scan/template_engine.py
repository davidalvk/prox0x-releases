"""Motor de plantillas compatible con un subconjunto de Nuclei.

No pretende ejecutar todo el DSL de Nuclei. Cubre plantillas HTTP con matchers
``status``/``word``/``regex`` y extractores ``regex`` sobre el subconjunto
documentado en ``docs/NUCLEI_ENGINE.md``.

El motor es independiente de la API: recibe un ``RequestEngine`` y devuelve
``TemplateMatch``. La API decide cómo persistir los flujos y hallazgos.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import yaml

from core.engine import Attempt, RedirectMode, RequestEngine, RequestOptions
from core.model import Header, HttpService, Request, Response, Timing
from core.scan.template_manager import (
    NON_HTTP_PROTOCOL_KEYS,
    is_http_template_text,
)
from core.scanner import Finding

DEFAULT_TEMPLATE_CONCURRENCY = 5
DEFAULT_TEMPLATE_THROTTLE_MS = 50.0
DEFAULT_TEMPLATE_TIMEOUT_MS = 15_000.0
MAX_TEMPLATE_BODY_BYTES = 2_000_000
MAX_EVIDENCE_CHARS = 1_200

_BUILTIN_VARIABLES = frozenset(
    {
        "BaseURL",
        "RootURL",
        "Hostname",
        "Host",
        "Port",
        "Path",
        "File",
        "Scheme",
    }
)
_VARIABLE_RE = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")
_SUPPORTED_PARTS = frozenset({"body", "header", "all", "raw"})
_SUPPORTED_MATCHERS = frozenset({"status", "word", "regex"})
_UNSUPPORTED_TEMPLATE_KEYS = frozenset(
    {"flow", "raw", "payloads", "attack", "req-condition", "global-matchers"}
)
_VALID_SEVERITIES = frozenset(
    {"critical", "high", "medium", "low", "info", "unknown"}
)
_UNSAFE_HEADERS = frozenset({"host", "content-length", "transfer-encoding"})
# libyaml (C) es ~10x más rápido que el parser Python para el catálogo completo.
_YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


class UnsupportedTemplate(ValueError):
    """La plantilla usa una función fuera del subconjunto soportado."""


@dataclass(frozen=True, slots=True)
class NucleiMatcher:
    type: str
    part: str = "body"
    condition: str = "or"
    negative: bool = False
    name: str = ""
    status: tuple[int, ...] = ()
    words: tuple[str, ...] = ()
    patterns: tuple[re.Pattern[str], ...] = ()
    case_insensitive: bool = False


@dataclass(frozen=True, slots=True)
class NucleiExtractor:
    name: str
    part: str = "body"
    group: int = 0
    patterns: tuple[re.Pattern[str], ...] = ()
    internal: bool = False


@dataclass(frozen=True, slots=True)
class NucleiRequestSpec:
    method: str
    paths: tuple[str, ...]
    headers: tuple[tuple[str, str], ...] = ()
    body: str = ""
    redirects: bool = False
    max_redirects: int = 10
    matchers_condition: str = "or"
    matchers: tuple[NucleiMatcher, ...] = ()
    extractors: tuple[NucleiExtractor, ...] = ()
    stop_at_first_match: bool = False


@dataclass(frozen=True, slots=True)
class NucleiTemplate:
    id: str
    name: str
    severity: str
    tags: tuple[str, ...]
    description: str
    references: tuple[str, ...]
    variables: tuple[tuple[str, str], ...]
    requests: tuple[NucleiRequestSpec, ...]
    path: Path


@dataclass(slots=True)
class TemplateLoadResult:
    templates: list[NucleiTemplate] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    total_files: int = 0
    filtered_out: int = 0


@dataclass(frozen=True, slots=True)
class TemplateMatch:
    template_id: str
    name: str
    severity: str
    tags: tuple[str, ...]
    url: str
    method: str
    status_code: int
    matcher: str
    evidence: str
    extracted: tuple[tuple[str, tuple[str, ...]], ...]
    request: Request
    response: Response
    service: HttpService
    timing: Timing | None = None

    def to_finding(self, flow_id: int) -> Finding:
        return Finding(
            flow_id=flow_id,
            url=self.url,
            kind="nuclei_template",
            severity=self.severity,
            evidence=self.evidence[:MAX_EVIDENCE_CHARS],
        )


@dataclass(frozen=True, slots=True)
class _PendingRequest:
    template: NucleiTemplate
    spec: NucleiRequestSpec
    request: Request
    service: HttpService
    url: str


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalize_tags(value: Any) -> tuple[str, ...]:
    raw: list[str] = []
    if isinstance(value, str):
        raw = re.split(r"[,\s]+", value)
    elif isinstance(value, list):
        for item in value:
            raw.extend(re.split(r"[,\s]+", str(item)))
    return tuple(sorted({item.lower() for item in raw if item}))


def _normalize_severity(value: Any) -> str:
    severity = str(value or "info").strip().lower()
    return severity if severity in _VALID_SEVERITIES else "info"


def _extract_variable_names(text: str) -> set[str]:
    return {match.group(1).strip() for match in _VARIABLE_RE.finditer(text)}


def _validate_variables(
    texts: Sequence[str],
    static_variables: set[str],
) -> None:
    for text in texts:
        for name in _extract_variable_names(text):
            if name in _BUILTIN_VARIABLES or name in static_variables:
                continue
            raise UnsupportedTemplate(f"variable no soportada: {{{{{name}}}}}")


def _substitute(text: str, variables: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1).strip()
        if name not in variables:
            raise UnsupportedTemplate(f"variable sin resolver: {{{{{name}}}}}")
        return variables[name]

    return _VARIABLE_RE.sub(replace, text)


def _latin1_safe(value: str) -> str:
    """Elimina caracteres que no se pueden serializar en cabeceras HTTP/1.1."""

    return value.encode("latin-1", errors="ignore").decode("latin-1")


def _decode_body(response: Response) -> str:
    return response.body[:MAX_TEMPLATE_BODY_BYTES].decode(
        "utf-8", errors="replace"
    )


def _response_part(response: Response, part: str) -> str:
    if part in ("all", "raw"):
        return response.raw[:MAX_TEMPLATE_BODY_BYTES].decode(
            "utf-8", errors="replace"
        )
    if part == "header":
        return "\r\n".join(
            f"{header.name}: {header.value}" for header in response.headers
        )
    return _decode_body(response)


def _build_variables(url: str, static: dict[str, str]) -> dict[str, str]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = parts.hostname or ""
    port = parts.port or (443 if scheme == "https" else 80)
    netloc = parts.netloc
    path = parts.path or "/"
    if path != "/" and not path.endswith("/"):
        path_dir = path.rsplit("/", 1)[0] or "/"
        filename = path.rsplit("/", 1)[-1]
    else:
        path_dir = path
        filename = ""
    # Nuclei usa BaseURL sin barra final; así ``{{BaseURL}}/ruta`` no genera
    # dobles barras al escanear raíces normalizadas por el crawler.
    base_url = url.rstrip("/") or url
    variables = {
        "BaseURL": base_url,
        "RootURL": f"{scheme}://{netloc}",
        "Hostname": netloc,
        "Host": host,
        "Port": str(port),
        "Path": path_dir,
        "File": filename,
        "Scheme": scheme,
    }
    variables.update(static)
    return variables


def _build_request(
    base_url: str,
    path_value: str,
    spec: NucleiRequestSpec,
    variables: dict[str, str],
) -> tuple[Request, HttpService, str]:
    rendered_path = _substitute(path_value, variables).strip()
    if not rendered_path:
        raise UnsupportedTemplate("path vacío")

    if rendered_path.startswith(("http://", "https://")):
        target_url = rendered_path
    else:
        target_url = urljoin(variables["RootURL"] + "/", rendered_path)

    base = urlsplit(base_url)
    target = urlsplit(target_url)
    if target.scheme not in ("http", "https") or not target.hostname:
        raise UnsupportedTemplate(f"URL inválida en plantilla: {target_url!r}")

    base_port = base.port or (443 if base.scheme == "https" else 80)
    target_port = target.port or (443 if target.scheme == "https" else 80)
    if target.hostname.lower() != (base.hostname or "").lower() or (
        target_port != base_port
    ):
        raise UnsupportedTemplate("la plantilla apunta fuera del host objetivo")

    secure = target.scheme == "https"
    service = HttpService(
        host=target.hostname,
        port=target_port,
        secure=secure,
    )

    header_values: dict[str, str] = {
        "Host": service.authority,
        "User-Agent": "prox0x-nuclei/1.1",
        "Accept": "*/*",
    }
    for name, value in spec.headers:
        lower = name.lower()
        if lower in _UNSAFE_HEADERS:
            continue
        rendered_name = _latin1_safe(_substitute(name, variables))
        rendered_value = _latin1_safe(_substitute(value, variables))
        if not rendered_name:
            continue
        for current in list(header_values):
            if current.lower() == lower:
                del header_values[current]
        header_values[rendered_name] = rendered_value

    body = _substitute(spec.body, variables).encode("utf-8")
    if body:
        header_values["Content-Length"] = str(len(body))

    headers = [Header(name, value) for name, value in header_values.items()]
    raw_target = target.path or "/"
    if target.query:
        raw_target += f"?{target.query}"
    head = (
        f"{spec.method} {raw_target} HTTP/1.1\r\n"
        + "".join(f"{header.name}: {header.value}\r\n" for header in headers)
        + "\r\n"
    ).encode("latin-1")

    request = Request(
        raw=head + body,
        headers=tuple(headers),
        body=body,
        body_offset=len(head),
        version="HTTP/1.1",
        method=spec.method,
        target=raw_target,
        http_service=service,
    )
    return request, service, urlunsplit(
        (target.scheme, target.netloc, target.path or "/", target.query, "")
    )


def _compile_word_matcher(
    raw: dict[str, Any],
    condition: str,
    part: str,
) -> NucleiMatcher:
    words = tuple(str(word) for word in _as_list(raw.get("words")))
    if not words:
        raise UnsupportedTemplate("matcher word sin words")
    encoding = str(raw.get("encoding") or "").strip().lower()
    if encoding == "hex":
        decoded: list[str] = []
        for word in words:
            try:
                decoded.append(bytes.fromhex(word).decode("latin-1"))
            except ValueError as exc:
                raise UnsupportedTemplate(
                    f"word hex inválido: {word!r}"
                ) from exc
        words = tuple(decoded)
    elif encoding:
        raise UnsupportedTemplate(f"encoding no soportado: {encoding}")
    case_insensitive = bool(raw.get("case-insensitive", False))
    if case_insensitive:
        words = tuple(word.lower() for word in words)
    return NucleiMatcher(
        type="word",
        part=part,
        condition=condition,
        negative=bool(raw.get("negative", False)),
        name=str(raw.get("name") or ""),
        words=words,
        case_insensitive=case_insensitive,
    )


def _compile_regex_matcher(
    raw: dict[str, Any],
    condition: str,
    part: str,
) -> NucleiMatcher:
    patterns: list[re.Pattern[str]] = []
    regex_values = _as_list(raw.get("regex"))
    if not regex_values:
        raise UnsupportedTemplate("matcher regex sin regex")
    if raw.get("case-insensitive"):
        raise UnsupportedTemplate(
            "case-insensitive no está soportado en matcher regex"
        )
    for value in regex_values:
        try:
            patterns.append(re.compile(str(value)))
        except re.error as exc:
            raise UnsupportedTemplate(
                f"regex incompatible: {value!r}: {exc}"
            ) from exc
    return NucleiMatcher(
        type="regex",
        part=part,
        condition=condition,
        negative=bool(raw.get("negative", False)),
        name=str(raw.get("name") or ""),
        patterns=tuple(patterns),
    )


def _compile_matchers(values: Any) -> tuple[NucleiMatcher, ...]:
    matchers: list[NucleiMatcher] = []
    for raw in _as_list(values):
        if not isinstance(raw, dict):
            raise UnsupportedTemplate("matcher inválido")
        matcher_type = str(raw.get("type") or "").strip().lower()
        if matcher_type not in _SUPPORTED_MATCHERS:
            raise UnsupportedTemplate(
                f"matcher no soportado: {matcher_type or '?'}"
            )
        condition = str(raw.get("condition") or "or").strip().lower()
        if condition not in ("and", "or"):
            raise UnsupportedTemplate(
                f"condition de matcher inválida: {condition}"
            )
        part = str(raw.get("part") or "body").strip().lower()
        if matcher_type != "status" and part not in _SUPPORTED_PARTS:
            raise UnsupportedTemplate(f"part no soportado: {part}")
        if matcher_type == "status":
            status = tuple(int(code) for code in _as_list(raw.get("status")))
            if not status:
                raise UnsupportedTemplate("matcher status sin status")
            matchers.append(
                NucleiMatcher(
                    type="status",
                    part="",
                    condition="or",
                    negative=bool(raw.get("negative", False)),
                    name=str(raw.get("name") or ""),
                    status=status,
                )
            )
        elif matcher_type == "word":
            matchers.append(_compile_word_matcher(raw, condition, part))
        else:
            matchers.append(_compile_regex_matcher(raw, condition, part))
    return tuple(matchers)


def _compile_extractors(values: Any) -> tuple[NucleiExtractor, ...]:
    extractors: list[NucleiExtractor] = []
    for raw in _as_list(values):
        if not isinstance(raw, dict):
            raise UnsupportedTemplate("extractor inválido")
        extractor_type = str(raw.get("type") or "").strip().lower()
        if extractor_type != "regex":
            raise UnsupportedTemplate(
                f"extractor no soportado: {extractor_type or '?'}"
            )
        part = str(raw.get("part") or "body").strip().lower()
        if part not in _SUPPORTED_PARTS:
            raise UnsupportedTemplate(f"part de extractor no soportado: {part}")
        try:
            group = int(raw.get("group") or 0)
        except (TypeError, ValueError) as exc:
            raise UnsupportedTemplate("group de extractor inválido") from exc
        if group < 0:
            raise UnsupportedTemplate("group de extractor negativo")
        patterns: list[re.Pattern[str]] = []
        regex_values = _as_list(raw.get("regex"))
        if not regex_values:
            raise UnsupportedTemplate("extractor regex sin regex")
        for value in regex_values:
            try:
                compiled = re.compile(str(value))
            except re.error as exc:
                raise UnsupportedTemplate(
                    f"regex de extractor incompatible: {value!r}: {exc}"
                ) from exc
            if group > compiled.groups:
                raise UnsupportedTemplate(
                    f"group {group} fuera de rango en extractor"
                )
            patterns.append(compiled)
        extractors.append(
            NucleiExtractor(
                name=str(raw.get("name") or ""),
                part=part,
                group=group,
                patterns=tuple(patterns),
                internal=bool(raw.get("internal", False)),
            )
        )
    return tuple(extractors)


def _compile_request(raw: Any) -> NucleiRequestSpec:
    if not isinstance(raw, dict):
        raise UnsupportedTemplate("bloque http inválido")
    if _UNSUPPORTED_TEMPLATE_KEYS & raw.keys():
        key = sorted(_UNSUPPORTED_TEMPLATE_KEYS & raw.keys())[0]
        raise UnsupportedTemplate(f"campo no soportado: {key}")

    method = str(raw.get("method") or "GET").strip().upper()
    if not re.fullmatch(r"[A-Z]+", method):
        raise UnsupportedTemplate(f"método HTTP inválido: {method}")

    paths = tuple(str(path) for path in _as_list(raw.get("path")))
    if not paths:
        raise UnsupportedTemplate("bloque http sin path")

    headers_raw = raw.get("headers") or {}
    if not isinstance(headers_raw, dict):
        raise UnsupportedTemplate("headers debe ser un mapa")
    headers = tuple(
        (str(name), str(value)) for name, value in headers_raw.items()
    )

    body = raw.get("body")
    if body is None:
        body_text = ""
    elif isinstance(body, str):
        body_text = body
    else:
        body_text = str(body)

    matchers_condition = str(
        raw.get("matchers-condition") or "or"
    ).strip().lower()
    if matchers_condition not in ("and", "or"):
        raise UnsupportedTemplate(
            f"matchers-condition inválida: {matchers_condition}"
        )

    matchers = _compile_matchers(raw.get("matchers"))
    extractors = _compile_extractors(raw.get("extractors"))
    if not matchers and not extractors:
        raise UnsupportedTemplate("sin matchers ni extractors")

    try:
        max_redirects = int(raw.get("max-redirects") or 10)
    except (TypeError, ValueError) as exc:
        raise UnsupportedTemplate("max-redirects inválido") from exc
    if max_redirects < 0:
        raise UnsupportedTemplate("max-redirects negativo")

    return NucleiRequestSpec(
        method=method,
        paths=paths,
        headers=headers,
        body=body_text,
        redirects=bool(raw.get("redirects", False)),
        max_redirects=max_redirects,
        matchers_condition=matchers_condition,
        matchers=matchers,
        extractors=extractors,
        stop_at_first_match=bool(raw.get("stop-at-first-match", False)),
    )


def _compile_template(path: Path) -> NucleiTemplate:
    try:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise UnsupportedTemplate(f"no se pudo leer: {exc}") from exc
    if not is_http_template_text(raw_text):
        raise UnsupportedTemplate("protocolo no soportado (solo HTTP)")
    if "interactsh" in raw_text.lower():
        raise UnsupportedTemplate("plantilla OOB/Interactsh no soportada")
    try:
        data = yaml.load(raw_text, Loader=_YAML_LOADER)
    except yaml.YAMLError as exc:
        raise UnsupportedTemplate(f"YAML inválido: {exc}") from exc
    if not isinstance(data, dict):
        raise UnsupportedTemplate("YAML sin objeto raíz")

    if _UNSUPPORTED_TEMPLATE_KEYS & data.keys():
        key = sorted(_UNSUPPORTED_TEMPLATE_KEYS & data.keys())[0]
        raise UnsupportedTemplate(f"campo no soportado: {key}")
    if NON_HTTP_PROTOCOL_KEYS & data.keys():
        raise UnsupportedTemplate("protocolo no soportado (solo HTTP)")
    if "http" not in data and "requests" not in data:
        raise UnsupportedTemplate("sin bloque http")

    template_id = str(data.get("id") or "").strip()
    if not template_id:
        raise UnsupportedTemplate("sin id")
    info = data.get("info") or {}
    if not isinstance(info, dict):
        raise UnsupportedTemplate("info inválido")
    name = str(info.get("name") or template_id)
    severity = _normalize_severity(info.get("severity"))
    tags = _normalize_tags(info.get("tags"))
    description = str(info.get("description") or "").strip()
    references = tuple(
        str(item)
        for item in _as_list(info.get("reference"))
        if str(item).strip()
    )

    variables_raw = data.get("variables") or {}
    if not isinstance(variables_raw, dict):
        raise UnsupportedTemplate("variables inválidas")
    variables: list[tuple[str, str]] = []
    for key, value in variables_raw.items():
        value_text = str(value)
        if "{{" in value_text or "}}" in value_text:
            raise UnsupportedTemplate(
                f"variable DSL no soportada: {key}"
            )
        variables.append((str(key), value_text))
    static_names = {key for key, _ in variables}

    requests_raw = _as_list(
        data.get("http") if "http" in data else data.get("requests")
    )
    requests: list[NucleiRequestSpec] = []
    for request_raw in requests_raw:
        spec = _compile_request(request_raw)
        texts: list[str] = list(spec.paths) + [spec.body]
        texts.extend(name for name, _ in spec.headers)
        texts.extend(value for _, value in spec.headers)
        for matcher in spec.matchers:
            texts.extend(matcher.words)
        _validate_variables(texts, static_names)
        requests.append(spec)

    if not requests:
        raise UnsupportedTemplate("sin peticiones http")

    return NucleiTemplate(
        id=template_id,
        name=name,
        severity=severity,
        tags=tags,
        description=description,
        references=references,
        variables=tuple(variables),
        requests=tuple(requests),
        path=path,
    )


class TemplateEngine:
    """Carga y ejecuta plantillas Nuclei del subconjunto soportado."""

    def __init__(
        self,
        request_engine: RequestEngine,
        *,
        concurrency: int = DEFAULT_TEMPLATE_CONCURRENCY,
        throttle_ms: float = DEFAULT_TEMPLATE_THROTTLE_MS,
        timeout_ms: float = DEFAULT_TEMPLATE_TIMEOUT_MS,
    ) -> None:
        if concurrency < 1:
            raise ValueError("concurrency debe ser >= 1")
        self.request_engine = request_engine
        self.concurrency = concurrency
        self.throttle_ms = throttle_ms
        self.timeout_ms = timeout_ms

    async def load_templates(
        self,
        directory: Path,
        *,
        tags: Sequence[str] = ("cve",),
        max_templates: int = 500,
    ) -> TemplateLoadResult:
        return await asyncio.to_thread(
            self._load_templates_sync,
            directory,
            tuple(tag.lower() for tag in tags if tag),
            max_templates,
        )

    def _load_templates_sync(
        self,
        directory: Path,
        tags: tuple[str, ...],
        max_templates: int,
    ) -> TemplateLoadResult:
        result = TemplateLoadResult()
        if not directory.is_dir():
            result.skipped.append((str(directory), "no existe el directorio"))
            return result
        try:
            files = list(directory.rglob("*.yaml")) + list(
                directory.rglob("*.yml")
            )
        except OSError as exc:
            result.skipped.append((str(directory), f"no se pudo leer: {exc}"))
            return result
        # Prioriza ``http/`` para que un límite bajo no se consuma explorando
        # protocolos no soportados; el resto se filtra en _compile_template.
        files.sort(
            key=lambda path: (
                0
                if path.relative_to(directory).parts[:1] == ("http",)
                else 1,
                str(path),
            )
        )
        result.total_files = len(files)
        if not files:
            result.skipped.append((str(directory), "no hay archivos YAML"))
            return result

        tag_set = set(tags)
        for path in files:
            if len(result.templates) >= max_templates:
                break
            try:
                template = _compile_template(path)
            except UnsupportedTemplate as exc:
                result.skipped.append((str(path), str(exc)))
                continue
            if tag_set and not tag_set.intersection(template.tags):
                result.filtered_out += 1
                continue
            result.templates.append(template)
        return result

    async def scan_urls(
        self,
        urls: Sequence[str],
        templates: Sequence[NucleiTemplate],
        *,
        on_result: Callable[[TemplateMatch], None] | None = None,
        on_progress: Callable[[int, int, int], None] | None = None,
        on_skip: Callable[[NucleiTemplate, str], None] | None = None,
        on_url_progress: Callable[[int, int], None] | None = None,
    ) -> list[TemplateMatch]:
        """Ejecuta el catálogo sobre varias URLs (modo Crawl).

        Itera URL por URL para no materializar ``urls × plantillas`` en
        memoria y para que la cancelación sea inmediata entre páginas. El
        callback ``on_progress`` informa ataques ejecutados/posibles, no
        plantillas distintas.
        """

        targets: list[str] = []
        seen_urls: set[str] = set()
        for url in urls:
            value = url.strip()
            if not value or value in seen_urls:
                continue
            seen_urls.add(value)
            targets.append(value)

        total_urls = len(targets)
        total_templates = len(templates)
        total_attacks = total_urls * total_templates
        matches: list[TemplateMatch] = []
        skipped_templates: set[str] = set()

        def forward_result(match: TemplateMatch) -> None:
            matches.append(match)
            if on_result is not None:
                on_result(match)

        def forward_skip(template: NucleiTemplate, reason: str) -> None:
            # La misma plantilla se omite en todas las URLs: no la contamos
            # N veces para no inflar el resumen del job.
            if template.id in skipped_templates:
                return
            skipped_templates.add(template.id)
            if on_skip is not None:
                on_skip(template, reason)

        for index, url in enumerate(targets):
            def page_progress(
                templates_run: int,
                _templates_total: int,
                _matches: int,
                *,
                page_index: int = index,
            ) -> None:
                if on_progress is None:
                    return
                attacks_run = min(
                    total_attacks,
                    page_index * total_templates + templates_run,
                )
                on_progress(attacks_run, total_attacks, len(matches))

            await self.scan(
                url,
                templates,
                on_result=forward_result,
                on_progress=page_progress,
                on_skip=forward_skip,
            )
            if on_url_progress is not None:
                on_url_progress(index + 1, total_urls)

        if on_progress is not None:
            on_progress(total_attacks, total_attacks, len(matches))
        return matches

    async def scan(
        self,
        url: str,
        templates: Sequence[NucleiTemplate],
        *,
        on_result: Callable[[TemplateMatch], None] | None = None,
        on_progress: Callable[[int, int, int], None] | None = None,
        on_skip: Callable[[NucleiTemplate, str], None] | None = None,
    ) -> list[TemplateMatch]:
        matches: list[TemplateMatch] = []
        matched_templates: set[str] = set()
        seen_templates: set[str] = set()
        total_templates = len(templates)
        pending: list[_PendingRequest] = []

        for template in templates:
            built: list[_PendingRequest] = []
            try:
                variables = _build_variables(
                    url, dict(template.variables)
                )
                for spec in template.requests:
                    for path_value in spec.paths:
                        try:
                            request, service, final_url = _build_request(
                                url, path_value, spec, variables
                            )
                        except UnsupportedTemplate:
                            continue
                        built.append(
                            _PendingRequest(
                                template=template,
                                spec=spec,
                                request=request,
                                service=service,
                                url=final_url,
                            )
                        )
            except (UnicodeEncodeError, UnicodeDecodeError):
                # Un carácter corrupto en URL/cabeceras no debe tumbar el
                # catálogo completo: se omite la plantilla y se continúa.
                seen_templates.add(template.id)
                if on_skip is not None:
                    on_skip(template, "Omitida por error de codificación")
                continue
            except UnsupportedTemplate:
                continue
            except ValueError:
                # Puertos duplicados o URLs malformadas (p. ej.
                # ``host:5000:9001``) hacen que urlsplit/urljoin fallen.
                seen_templates.add(template.id)
                if on_skip is not None:
                    on_skip(template, "Omitida por URL inválida")
                continue
            pending.extend(built)

        for start in range(0, len(pending), self.concurrency):
            chunk = pending[start : start + self.concurrency]
            requests = [item.request for item in chunk]
            services = [item.service for item in chunk]
            options = [
                RequestOptions(
                    redirect=(
                        RedirectMode.ALWAYS
                        if item.spec.redirects
                        else RedirectMode.NEVER
                    ),
                    max_redirects=item.spec.max_redirects,
                    timeout_ms=self.timeout_ms,
                    throttle_ms=self.throttle_ms,
                )
                for item in chunk
            ]
            attempts = await self.request_engine.send_requests(
                requests,
                services,
                options=options,
                concurrency=self.concurrency,
                labels=[
                    f"nuclei:{item.template.id}" for item in chunk
                ],
            )
            for item, attempt in zip(chunk, attempts):
                seen_templates.add(item.template.id)
                if (
                    item.spec.stop_at_first_match
                    and item.template.id in matched_templates
                ):
                    continue
                match = self._evaluate(item, attempt)
                if match is None:
                    continue
                matched_templates.add(item.template.id)
                matches.append(match)
                if on_result is not None:
                    on_result(match)
            if on_progress is not None:
                on_progress(
                    len(seen_templates), total_templates, len(matches)
                )

        if on_progress is not None:
            on_progress(
                len(seen_templates), total_templates, len(matches)
            )
        return matches

    def _evaluate(
        self, item: _PendingRequest, attempt: Attempt
    ) -> TemplateMatch | None:
        response = attempt.response
        if not attempt.ok or response is None:
            return None

        matcher_results: list[tuple[bool, str, str]] = []
        for matcher in item.spec.matchers:
            matcher_results.append(
                self._matcher_result(matcher, response)
            )

        extracts = self._extract_values(item.spec, response)

        if item.spec.matchers:
            if item.spec.matchers_condition == "and":
                matched = all(result[0] for result in matcher_results)
            else:
                matched = any(result[0] for result in matcher_results)
        else:
            matched = bool(extracts)

        if not matched:
            return None

        matched_names = [
            result[1] for result in matcher_results if result[0]
        ]
        matcher_label = ", ".join(matched_names) or (
            "extractor" if extracts else "matcher"
        )
        evidence_parts = [
            f"template={item.template.id}",
            f"name={item.template.name}",
            f"matcher={matcher_label}",
        ]
        for result in matcher_results:
            if result[0] and result[2]:
                evidence_parts.append(f"match={result[2]}")
                break
        for name, values in extracts.items():
            if values:
                evidence_parts.append(
                    f"{name}={', '.join(values[:3])}"
                )
        evidence = " · ".join(evidence_parts)[:MAX_EVIDENCE_CHARS]

        return TemplateMatch(
            template_id=item.template.id,
            name=item.template.name,
            severity=item.template.severity,
            tags=item.template.tags,
            url=item.url,
            method=item.spec.method,
            status_code=response.status_code,
            matcher=matcher_label,
            evidence=evidence,
            extracted=tuple(extracts.items()),
            request=item.request,
            response=response,
            service=item.service,
            timing=attempt.timing,
        )

    def _matcher_result(
        self, matcher: NucleiMatcher, response: Response
    ) -> tuple[bool, str, str]:
        label = matcher.name or matcher.type
        if matcher.type == "status":
            matched = response.status_code in matcher.status
            if matcher.negative:
                matched = not matched
            return matched, label, f"status={response.status_code}"

        corpus = _response_part(response, matcher.part)
        matched = False
        snippet = ""
        if matcher.type == "word":
            haystack = corpus.lower() if matcher.case_insensitive else corpus
            matches = [
                word
                for word in matcher.words
                if (word.lower() if matcher.case_insensitive else word)
                in haystack
            ]
            matched = (
                len(matches) == len(matcher.words)
                if matcher.condition == "and"
                else bool(matches)
            )
            if matches:
                snippet = matches[0]
        elif matcher.type == "regex":
            found: list[str] = []
            for pattern in matcher.patterns:
                found.extend(match.group(0) for match in pattern.finditer(corpus))
            matched = (
                bool(found)
                if matcher.condition == "or"
                else all(pattern.search(corpus) for pattern in matcher.patterns)
            )
            if found:
                snippet = found[0]
        if matcher.negative:
            matched = not matched
            snippet = ""
        return matched, label, snippet

    def _extract_values(
        self, spec: NucleiRequestSpec, response: Response
    ) -> dict[str, tuple[str, ...]]:
        extracted: dict[str, tuple[str, ...]] = {}
        for extractor in spec.extractors:
            corpus = _response_part(response, extractor.part)
            values: list[str] = []
            for pattern in extractor.patterns:
                for match in pattern.finditer(corpus):
                    try:
                        value = match.group(extractor.group)
                    except IndexError:
                        continue
                    if value and value not in values:
                        values.append(value)
            if values:
                name = extractor.name or "extract"
                extracted[name] = tuple(values)
        return extracted
