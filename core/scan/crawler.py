"""Crawler web asíncrono para descubrir endpoints (Fase 1).

El crawler es deliberadamente independiente de la UI y del Escáner Activo:

- recibe una URL semilla y un dominio base para el Scope;
- usa ``aiohttp`` para rastrear con concurrencia limitada;
- respeta ``robots.txt`` y descubre sitemaps;
- extrae enlaces HTML, formularios y endpoints referenciados desde JavaScript;
- deduplica URLs y nunca sale del host/puerto base.

La integración con el Escáner Activo se hará en una fase posterior.
"""

from __future__ import annotations

import asyncio
import gzip
import html as html_lib
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import aiohttp

DEFAULT_USER_AGENT = "prox0x-crawler/1.0"
DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_URLS = 200
UNLIMITED_MAX_URLS = 10_000
_HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_JS_TYPES = frozenset(
    {
        "application/javascript",
        "application/x-javascript",
        "text/javascript",
        "text/ecmascript",
    }
)
_JS_STRING_RE = re.compile(
    r"""(?P<quote>["'`])(?P<url>(?:https?://|//|/)[^"'`\s\\]{1,300})(?P=quote)"""
)
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE | re.DOTALL)


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _ensure_absolute(url: str) -> str:
    value = url.strip()
    if not value:
        return ""
    if value.startswith("//"):
        return f"http:{value}"
    if "://" not in value:
        return f"http://{value}"
    return value


def normalize_url(url: str) -> str:
    """Normaliza una URL para deduplicar (sin fragmento, host minúsculo)."""

    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        return ""
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        return ""
    if port is not None and port != _default_port(scheme):
        netloc = f"{host}:{port}"
    else:
        netloc = host
    path = parts.path or "/"
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    query = urlencode(sorted(pairs))
    return urlunsplit((scheme, netloc, path, query, ""))


def _resolve(base: str, href: str) -> str:
    value = html_lib.unescape(href or "").strip()
    if not value or value.startswith(("#", "mailto:", "javascript:", "tel:", "data:")):
        return ""
    try:
        return urljoin(base, value)
    except ValueError:
        return ""


def _is_http(url: str) -> bool:
    try:
        return urlsplit(url).scheme.lower() in ("http", "https")
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class CrawlerConfig:
    """Límites y switches del crawler.

    ``max_urls`` 0/-1 y ``max_depth`` 0/-1 significan "sin límite"; la API
    los normaliza al tope de seguridad ``UNLIMITED_MAX_URLS`` para las URLs.
    """

    max_urls: int = DEFAULT_MAX_URLS
    max_depth: int = DEFAULT_MAX_DEPTH
    concurrency: int = 5
    timeout_s: float = 10.0
    user_agent: str = DEFAULT_USER_AGENT
    extra_headers: tuple[tuple[str, str], ...] = ()
    respect_robots: bool = True
    parse_robots: bool = True
    parse_sitemaps: bool = True
    parse_javascript: bool = True
    verify_tls: bool = True
    max_body_bytes: int = 2_000_000
    max_js_urls_per_file: int = 200

    def __post_init__(self) -> None:
        if self.max_urls < -1:
            raise ValueError("max_urls debe ser >= -1")
        if self.max_depth < -1:
            raise ValueError("max_depth debe ser >= -1")
        if self.concurrency < 1:
            raise ValueError("concurrency debe ser >= 1")
        if self.timeout_s <= 0:
            raise ValueError("timeout_s debe ser > 0")
        if self.max_body_bytes < 1:
            raise ValueError("max_body_bytes debe ser > 0")


def normalize_crawl_limits(
    max_urls: int | None, max_depth: int | None
) -> tuple[int, int]:
    """Traduce límites de API a valores efectivos y seguros.

    Cualquier valor <= 0 (incluido -1) significa "ilimitado". Las URLs se
    capan a ``UNLIMITED_MAX_URLS`` para evitar agotar memoria. Para la
    profundidad se usa ``-1`` como sentinel de "sin límite".
    """

    pages = UNLIMITED_MAX_URLS if not max_urls or max_urls <= 0 else max_urls
    pages = min(pages, UNLIMITED_MAX_URLS)
    depth = max_depth if max_depth and max_depth > 0 else -1
    return pages, depth


@dataclass(frozen=True, slots=True)
class FormField:
    name: str
    type: str = "text"
    value: str = ""


@dataclass(frozen=True, slots=True)
class FormInfo:
    action: str
    method: str = "GET"
    enctype: str = "application/x-www-form-urlencoded"
    fields: tuple[FormField, ...] = ()


@dataclass(frozen=True, slots=True)
class CrawlPage:
    url: str
    status: int
    content_type: str
    links: tuple[str, ...] = ()
    forms: tuple[FormInfo, ...] = ()
    scripts: tuple[str, ...] = ()
    error: str | None = None


@dataclass(slots=True)
class CrawlResult:
    seed: str
    urls: list[str] = field(default_factory=list)
    visited: list[str] = field(default_factory=list)
    pages: list[CrawlPage] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)
    robots_url: str | None = None
    sitemap_urls: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _Fetched:
    url: str
    status: int
    content_type: str
    body: bytes
    headers: dict[str, str]
    error: str | None = None


@dataclass
class _FormBuilder:
    action: str
    method: str
    enctype: str
    fields: list[FormField] = field(default_factory=list)


class _PageParser(HTMLParser):
    """Extrae enlaces, formularios, scripts e inline JS de una página."""

    def __init__(self, page_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.base_href: str | None = None
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[_FormBuilder] = []
        self.inline_scripts: list[str] = []
        self._current_form: _FormBuilder | None = None
        self._in_script = False
        self._script_buffer: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        values = {
            name.lower(): value
            for name, value in attrs
            if value is not None
        }
        tag = tag.lower()

        if tag == "base" and values.get("href"):
            self.base_href = _resolve(self.page_url, values["href"])
        elif tag in {"a", "area"} and values.get("href"):
            self.links.append(values["href"])
        elif tag in {"iframe", "frame"} and values.get("src"):
            self.links.append(values["src"])
        elif tag == "form":
            self._finalize_form()
            self._current_form = _FormBuilder(
                action=values.get("action", ""),
                method=(values.get("method") or "GET").upper(),
                enctype=(
                    values.get("enctype")
                    or "application/x-www-form-urlencoded"
                ).lower(),
            )
        elif tag in {"input", "select", "textarea", "button"}:
            if self._current_form is not None and values.get("name"):
                default_type = "text" if tag == "input" else tag
                self._current_form.fields.append(
                    FormField(
                        name=values["name"],
                        type=(values.get("type") or default_type).lower(),
                        value=values.get("value", ""),
                    )
                )
        elif tag == "script":
            src = values.get("src")
            if src:
                self.scripts.append(src)
            else:
                self._in_script = True
                self._script_buffer = []

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "form":
            self._finalize_form()
        elif tag == "script" and self._in_script:
            self.inline_scripts.append("".join(self._script_buffer))
            self._in_script = False
            self._script_buffer = []

    def _finalize_form(self) -> None:
        """Cierra el formulario actual aunque falte ``</form>``."""

        if self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def close(self) -> None:
        super().close()
        self._finalize_form()

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_buffer.append(data)


class _RobotsRules:
    def __init__(self) -> None:
        self.allow: list[str] = []
        self.disallow: list[str] = []

    def allows(self, url: str) -> bool:
        path = urlsplit(url).path or "/"
        best_len = -1
        allowed = True
        for prefix in self.disallow:
            if path.startswith(prefix) and len(prefix) > best_len:
                best_len = len(prefix)
                allowed = False
        for prefix in self.allow:
            if path.startswith(prefix) and len(prefix) >= best_len:
                best_len = len(prefix)
                allowed = True
        return allowed


def _parse_robots(text: str, robots_url: str) -> tuple[_RobotsRules, list[str]]:
    rules = _RobotsRules()
    sitemaps: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "allow" and value:
            rules.allow.append(value)
        elif key == "disallow" and value:
            rules.disallow.append(value)
        elif key == "sitemap" and value:
            sitemaps.append(urljoin(robots_url, value))
    return rules, sitemaps


def extract_js_urls(text: str, base_url: str) -> list[str]:
    """Extrae strings con forma de URL/path de un archivo JavaScript."""

    found: list[str] = []
    seen: set[str] = set()
    for match in _JS_STRING_RE.finditer(text):
        raw = match.group("url")
        if any(marker in raw for marker in ("${", "{{", "}}", "#{")):
            continue
        resolved = urljoin(base_url, raw)
        if not _is_http(resolved):
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        found.append(resolved)
    return found


class Crawler:
    """Rastreador asíncrono con Scope y deduplicación."""

    def __init__(
        self,
        seed_url: str,
        base_domain: str | None = None,
        *,
        config: CrawlerConfig | None = None,
        session: aiohttp.ClientSession | None = None,
        on_progress: Callable[[CrawlResult], None] | None = None,
    ) -> None:
        absolute_seed = _ensure_absolute(seed_url)
        if not _is_http(absolute_seed):
            raise ValueError(f"URL semilla inválida: {seed_url!r}")
        self.seed_url = normalize_url(absolute_seed)
        self.config = config or CrawlerConfig()
        self._seed_host = (urlsplit(self.seed_url).hostname or "").lower()
        self._host, self._port = self._parse_scope(absolute_seed, base_domain)
        self._session = session
        self._owns_session = session is None
        self._on_progress = on_progress
        self._queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        self._enqueued: set[str] = set()
        self._visited: set[str] = set()
        self._form_keys: set[tuple[str, str, str]] = set()
        self._robots = _RobotsRules()
        self.result = CrawlResult(seed=self.seed_url)
        self._max_urls = (
            self.config.max_urls
            if self.config.max_urls > 0
            else UNLIMITED_MAX_URLS
        )
        self._max_urls = min(self._max_urls, UNLIMITED_MAX_URLS)
        self._max_depth = self.config.max_depth

    def _notify(self) -> None:
        """Notifica el progreso sin permitir que un callback rompa el crawl."""

        if self._on_progress is None:
            return
        try:
            self._on_progress(self.result)
        except Exception:  # noqa: BLE001 - el progreso es best-effort
            pass

    @staticmethod
    def _parse_scope(seed: str, base_domain: str | None) -> tuple[str, int]:
        parts = urlsplit(seed)
        host = (parts.hostname or "").lower()
        port = parts.port or _default_port(parts.scheme.lower())
        if base_domain:
            raw = base_domain.strip()
            if not raw:
                return host, port
            if "://" not in raw:
                raw = f"//{raw}"
            base = urlsplit(raw)
            if base.hostname:
                host = base.hostname.lower()
            if base.port is not None:
                port = base.port
        return host, port

    def in_scope(self, url: str) -> bool:
        try:
            parts = urlsplit(url)
        except ValueError:
            return False
        if parts.scheme.lower() not in ("http", "https"):
            return False
        host = (parts.hostname or "").lower()
        if host not in (self._host, self._seed_host):
            return False
        try:
            port = parts.port or _default_port(parts.scheme.lower())
        except ValueError:
            return False
        return port == self._port

    def _add_url(
        self, url: str, depth: int, *, ignore_robots: bool = False
    ) -> None:
        if not url:
            return
        if self._max_depth > 0 and depth > self._max_depth:
            return
        normalized = normalize_url(url)
        if not normalized or not self.in_scope(normalized):
            return
        if (
            not ignore_robots
            and self.config.respect_robots
            and not self._robots.allows(normalized)
        ):
            return
        if normalized in self._enqueued:
            return
        if len(self._enqueued) >= self._max_urls:
            return
        self._enqueued.add(normalized)
        self.result.urls.append(normalized)
        self._queue.put_nowait((normalized, depth))
        self._notify()

    def _add_form(self, form: FormInfo) -> None:
        key = (form.action, form.method, form.enctype)
        if key in self._form_keys:
            return
        self._form_keys.add(key)
        self.result.forms.append(form)
        self._notify()

    async def crawl(self) -> CrawlResult:
        """Ejecuta el rastreo y devuelve URLs, formularios y errores."""

        if self._max_urls == 0:
            return self.result

        session = self._session
        if session is None:
            connector = aiohttp.TCPConnector(
                limit=self.config.concurrency,
                limit_per_host=self.config.concurrency,
            )
            headers: dict[str, str] = {
                "User-Agent": self.config.user_agent,
            }
            for name, value in self.config.extra_headers:
                for current in list(headers):
                    if current.lower() == name.lower():
                        del headers[current]
                headers[name] = value
            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.config.timeout_s),
                headers=headers,
                connector=connector,
                trust_env=False,
            )

        try:
            sitemaps: list[str] = []
            if self.config.parse_robots:
                sitemaps = await self._load_robots(session)

            # La semilla explícita del usuario se rastrea siempre: robots.txt
            # solo se aplica a los enlaces descubiertos, no al objetivo que el
            # pentester ha indicado manualmente.
            self._add_url(self.seed_url, 1, ignore_robots=True)

            if self.config.parse_sitemaps:
                default_sitemap = urljoin(self.seed_url, "/sitemap.xml")
                sitemaps.append(default_sitemap)
                for sitemap in dict.fromkeys(sitemaps):
                    if self.in_scope(sitemap):
                        self.result.sitemap_urls.append(sitemap)
                    # El sitemap es un recurso descubierto, no la semilla.
                    self._add_url(sitemap, 2)

            workers = [
                asyncio.create_task(self._worker(session))
                for _ in range(self.config.concurrency)
            ]
            try:
                await self._queue.join()
            finally:
                # Si el job se cancela (Detener Escaneo) durante el crawl,
                # los workers deben morir con él y no seguir rastreando.
                for worker in workers:
                    worker.cancel()
                await asyncio.gather(*workers, return_exceptions=True)
        finally:
            if self._owns_session and session is not None:
                await session.close()
        return self.result

    async def _load_robots(self, session: aiohttp.ClientSession) -> list[str]:
        robots_url = urljoin(self.seed_url, "/robots.txt")
        self.result.robots_url = robots_url
        fetched = await self._fetch(session, robots_url)
        if fetched.error is not None or fetched.status != 200:
            return []
        text = fetched.body.decode("utf-8", errors="replace")
        self._robots, sitemaps = _parse_robots(text, robots_url)
        return sitemaps

    async def _fetch(self, session: aiohttp.ClientSession, url: str) -> _Fetched:
        ssl_arg = None if self.config.verify_tls else False
        try:
            async with session.get(
                url, allow_redirects=False, ssl=ssl_arg
            ) as response:
                body = await response.content.read(self.config.max_body_bytes)
                return _Fetched(
                    url=url,
                    status=response.status,
                    content_type=(
                        response.headers.get("Content-Type", "")
                        .split(";", 1)[0]
                        .strip()
                        .lower()
                    ),
                    body=body,
                    headers={
                        key.lower(): value
                        for key, value in response.headers.items()
                    },
                )
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
            return _Fetched(
                url=url,
                status=0,
                content_type="",
                body=b"",
                headers={},
                error=f"{type(exc).__name__}: {exc}",
            )

    async def _worker(self, session: aiohttp.ClientSession) -> None:
        while True:
            url, depth = await self._queue.get()
            try:
                if len(self._visited) >= self._max_urls:
                    continue
                if url in self._visited:
                    continue
                self._visited.add(url)
                await self._process(session, url, depth)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - un fallo no debe parar el crawl
                self.result.errors.append(f"{url}: {type(exc).__name__}: {exc}")
            finally:
                self._notify()
                self._queue.task_done()

    async def _process(
        self, session: aiohttp.ClientSession, url: str, depth: int
    ) -> None:
        fetched = await self._fetch(session, url)
        if fetched.error is not None:
            self.result.errors.append(f"{url}: {fetched.error}")
            return

        self.result.visited.append(url)
        status = fetched.status
        if 300 <= status < 400:
            location = fetched.headers.get("location")
            if location:
                self._add_url(urljoin(url, location), depth + 1)
            return
        if status != 200:
            return

        body = fetched.body
        content_type = fetched.content_type
        path = urlsplit(url).path.lower()

        if _looks_like_sitemap(path, content_type, body):
            self._parse_sitemap(url, body, depth)
            return

        looks_html = (
            content_type in _HTML_TYPES
            or "html" in content_type
            or (
                not content_type
                and any(
                    marker in body[:2048].lower()
                    for marker in (b"<!doctype html", b"<html")
                )
            )
        )
        if looks_html:
            self._parse_html(url, body, depth)
            return

        is_js = content_type in _JS_TYPES or path.endswith((".js", ".mjs"))
        if is_js and self.config.parse_javascript:
            self._parse_js(url, body, depth)

    def _parse_html(self, url: str, body: bytes, depth: int) -> None:
        text = body.decode("utf-8", errors="replace")
        parser = _PageParser(url)
        try:
            parser.feed(text)
            parser.close()
        except Exception as exc:  # noqa: BLE001
            self.result.errors.append(f"{url}: HTML parse: {exc}")

        base = parser.base_href or url
        links: list[str] = []
        for raw in parser.links:
            resolved = _resolve(base, raw)
            if resolved and self.in_scope(resolved):
                links.append(resolved)
                self._add_url(resolved, depth + 1)

        scripts: list[str] = []
        for raw in parser.scripts:
            resolved = _resolve(base, raw)
            if resolved and self.in_scope(resolved):
                scripts.append(resolved)
                self._add_url(resolved, depth + 1)

        forms: list[FormInfo] = []
        for builder in parser.forms:
            action = _resolve(base, builder.action) if builder.action else url
            if not action or not self.in_scope(action):
                continue
            form = FormInfo(
                action=normalize_url(action),
                method=builder.method,
                enctype=builder.enctype,
                fields=tuple(builder.fields),
            )
            forms.append(form)
            self._add_form(form)
            self._add_url(form.action, depth + 1)

        if self.config.parse_javascript:
            for inline in parser.inline_scripts:
                for endpoint in extract_js_urls(inline, base):
                    self._add_url(endpoint, depth + 1)

        self.result.pages.append(
            CrawlPage(
                url=url,
                status=200,
                content_type="text/html",
                links=tuple(links),
                forms=tuple(forms),
                scripts=tuple(scripts),
            )
        )

    def _parse_js(self, url: str, body: bytes, depth: int) -> None:
        text = body.decode("utf-8", errors="replace")
        for endpoint in extract_js_urls(text, url)[
            : self.config.max_js_urls_per_file
        ]:
            self._add_url(endpoint, depth + 1)

    def _parse_sitemap(self, url: str, body: bytes, depth: int) -> None:
        if body.startswith(b"\x1f\x8b"):
            try:
                body = gzip.decompress(body)
            except (OSError, EOFError) as exc:
                self.result.errors.append(f"{url}: gzip: {exc}")
                return
        text = body.decode("utf-8", errors="replace")
        for raw in _SITEMAP_LOC_RE.findall(text):
            location = html_lib.unescape(raw.strip())
            if location:
                self._add_url(urljoin(url, location), depth + 1)


def _looks_like_sitemap(path: str, content_type: str, body: bytes) -> bool:
    head = body[:4096].lower()
    if b"<urlset" in head or b"<sitemapindex" in head:
        return True
    return path.endswith((".xml", ".xml.gz")) and (
        "xml" in content_type or content_type == ""
    )
