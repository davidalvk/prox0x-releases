"""Detección ligera de tecnologías para el modo Auto-Tech.

No añade dependencias: analiza cabeceras, cookies, metaetiquetas y HTML de la
URL objetivo, y opcionalmente sondea rutas comunes. Cada tecnología se traduce
a uno o más tags de Nuclei para filtrar el catálogo de plantillas.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import aiohttp

DEFAULT_TIMEOUT_S = 4.0
DEFAULT_MAX_BODY_BYTES = 512_000
DEFAULT_MAX_PROBES = 8
DEFAULT_USER_AGENT = "prox0x-tech/1.0"

_META_GENERATOR_RE = re.compile(
    r"<meta\b[^>]*\bname\s*=\s*[\"']generator[\"'][^>]*>",
    re.IGNORECASE,
)
_META_CONTENT_RE = re.compile(
    r"\bcontent\s*=\s*[\"']([^\"']*)[\"']",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class TechSignature:
    """Firma declarativa de una tecnología y sus tags de Nuclei."""

    name: str
    tags: tuple[str, ...]
    header_terms: tuple[tuple[str, str], ...] = ()
    header_present: tuple[str, ...] = ()
    cookie_terms: tuple[str, ...] = ()
    body_terms: tuple[str, ...] = ()
    meta_terms: tuple[str, ...] = ()
    probe: str | None = None
    probe_terms: tuple[str, ...] = ()
    probe_status: tuple[int, ...] = (200,)


# El orden define el orden de los tags devueltos.
_SIGNATURES: tuple[TechSignature, ...] = (
    TechSignature(
        name="WordPress",
        tags=("wordpress", "wp", "wp-plugin"),
        header_terms=(
            ("x-powered-by", "wordpress"),
            ("link", "wp-json"),
            ("x-pingback", "xmlrpc.php"),
        ),
        cookie_terms=("wordpress_", "wp-settings", "wp_"),
        body_terms=("wp-content", "wp-includes", "/wp-json/"),
        meta_terms=("wordpress",),
        probe="/wp-json/",
        probe_terms=('"namespaces"', "wp/v2"),
    ),
    TechSignature(
        name="Apache",
        tags=("apache",),
        header_terms=(("server", "apache/"), ("server", "apache ")),
    ),
    TechSignature(
        name="Nginx",
        tags=("nginx",),
        header_terms=(("server", "nginx"),),
    ),
    TechSignature(
        name="IIS",
        tags=("iis",),
        header_terms=(("server", "microsoft-iis"), ("x-powered-by", "asp.net")),
        header_present=("x-aspnet-version", "x-aspnetmvc-version"),
    ),
    TechSignature(
        name="Tomcat",
        tags=("tomcat",),
        header_terms=(("server", "coyote"), ("server", "tomcat")),
    ),
    TechSignature(
        name="Jetty",
        tags=("jetty", "java"),
        header_terms=(("server", "jetty"),),
    ),
    TechSignature(
        name="PHP",
        tags=("php",),
        header_terms=(("x-powered-by", "php"),),
        cookie_terms=("phpsessid",),
    ),
    TechSignature(
        name="Laravel",
        tags=("laravel", "php"),
        header_terms=(("x-powered-by", "laravel"),),
        cookie_terms=("laravel_session",),
        body_terms=("laravel",),
    ),
    TechSignature(
        name="Jira",
        tags=("jira", "atlassian"),
        header_present=(
            "x-arequestid",
            "x-asessionid",
            "x-ausername",
            "x-seraph-loginreason",
        ),
        cookie_terms=("atlassian.xsrf.token",),
        body_terms=("atlassian jira", "jira software", "jira core"),
        probe="/rest/api/2/serverInfo",
        probe_terms=('"servertitle"', '"baseurl"', '"version"'),
    ),
    TechSignature(
        name="Spring Boot",
        tags=("springboot", "spring"),
        header_present=("x-application-context",),
        body_terms=(
            "whitelabel error page",
            "spring boot",
            "org.springframework",
        ),
        probe="/actuator/health",
        probe_terms=(
            '"status":"up"',
            '"status": "up"',
            '"status":"down"',
            '"status": "down"',
        ),
    ),
    TechSignature(
        name="Drupal",
        tags=("drupal",),
        header_terms=(("x-generator", "drupal"),),
        header_present=("x-drupal-cache", "x-drupal-dynamic-cache"),
        body_terms=("drupal.settings", "sites/default/files"),
        meta_terms=("drupal",),
        probe="/CHANGELOG.txt",
        probe_terms=("drupal",),
    ),
    TechSignature(
        name="Joomla",
        tags=("joomla",),
        body_terms=("/media/system/js/", 'content="joomla', "joomla!"),
        meta_terms=("joomla",),
        probe="/administrator/",
        probe_terms=("joomla", "com_login"),
        probe_status=(200, 303),
    ),
    TechSignature(
        name="Jenkins",
        tags=("jenkins",),
        header_present=("x-jenkins",),
        body_terms=("jenkins",),
        probe="/login",
        probe_terms=("jenkins",),
    ),
    TechSignature(
        name="Flask",
        tags=("flask",),
        header_terms=(("server", "werkzeug"),),
    ),
    TechSignature(
        name="Express",
        tags=("express", "nodejs"),
        header_terms=(("x-powered-by", "express"),),
    ),
    TechSignature(
        name="ASP.NET",
        tags=("aspnet", "dotnet"),
        header_terms=(("x-powered-by", "asp.net"),),
        header_present=("x-aspnet-version", "x-aspnetmvc-version"),
    ),
    TechSignature(
        name="Next.js",
        tags=("nextjs",),
        body_terms=("__next_data__", "/_next/static/"),
    ),
    TechSignature(
        name="Angular",
        tags=("angular",),
        body_terms=("ng-version=",),
    ),
)


@dataclass(frozen=True, slots=True)
class TechDetection:
    """Resultado de la detección de tecnologías."""

    technologies: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    error: str | None = None

    def to_record(self) -> dict[str, object]:
        return {
            "technologies": list(self.technologies),
            "tags": list(self.tags),
            "evidence": list(self.evidence),
            "error": self.error,
        }


@dataclass(slots=True)
class _FetchedPage:
    url: str
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    cookies: tuple[str, ...] = ()
    body: str = ""
    error: str | None = None


def _is_http(url: str) -> bool:
    try:
        return urlsplit(url).scheme.lower() in ("http", "https")
    except ValueError:
        return False


def _tags_for(technologies: Iterable[str]) -> tuple[str, ...]:
    found = set(technologies)
    tags: list[str] = []
    for signature in _SIGNATURES:
        if signature.name not in found:
            continue
        for tag in signature.tags:
            if tag not in tags:
                tags.append(tag)
    return tuple(tags)


def _meta_generators(body: str) -> tuple[str, ...]:
    generators: list[str] = []
    for tag in _META_GENERATOR_RE.findall(body):
        match = _META_CONTENT_RE.search(tag)
        if match and match.group(1).strip():
            generators.append(match.group(1).strip().lower())
    return tuple(generators)


class TechDetector:
    """Detecta tecnologías y las traduce a tags de Nuclei."""

    def __init__(
        self,
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        max_probes: int = DEFAULT_MAX_PROBES,
        user_agent: str = DEFAULT_USER_AGENT,
        verify_tls: bool = True,
    ) -> None:
        if timeout_s <= 0:
            raise ValueError("timeout_s debe ser > 0")
        if max_body_bytes < 1:
            raise ValueError("max_body_bytes debe ser > 0")
        if max_probes < 0:
            raise ValueError("max_probes no puede ser negativo")
        self.timeout_s = timeout_s
        self.max_body_bytes = max_body_bytes
        self.max_probes = max_probes
        self.user_agent = user_agent
        self.verify_tls = verify_tls

    def analyze(
        self,
        *,
        headers: Mapping[str, str] | None = None,
        cookies: Iterable[str] = (),
        body: str = "",
    ) -> TechDetection:
        """Analiza una respuesta ya obtenida (sin red)."""

        normalized_headers = {
            str(name).lower(): str(value) for name, value in (headers or {}).items()
        }
        cookie_names = tuple(str(cookie).lower() for cookie in cookies)
        lower_body = body.lower()
        generators = _meta_generators(body)

        found: set[str] = set()
        evidence: list[str] = []

        for signature in _SIGNATURES:
            matched = False
            for header_name, term in signature.header_terms:
                value = normalized_headers.get(header_name)
                if value is not None and term in value.lower():
                    matched = True
                    evidence.append(
                        f"{signature.name}: cabecera {header_name}={value!r}"
                    )
                    break
            if not matched:
                for header_name in signature.header_present:
                    if header_name in normalized_headers:
                        matched = True
                        evidence.append(
                            f"{signature.name}: cabecera {header_name}"
                        )
                        break
            if not matched:
                for cookie in cookie_names:
                    if any(
                        cookie == term or cookie.startswith(term)
                        for term in signature.cookie_terms
                    ):
                        matched = True
                        evidence.append(f"{signature.name}: cookie {cookie!r}")
                        break
            if not matched:
                for term in signature.body_terms:
                    if term in lower_body:
                        matched = True
                        evidence.append(
                            f"{signature.name}: cuerpo contiene {term!r}"
                        )
                        break
            if not matched:
                for generator in generators:
                    if any(term in generator for term in signature.meta_terms):
                        matched = True
                        evidence.append(
                            f"{signature.name}: meta generator {generator!r}"
                        )
                        break
            if matched:
                found.add(signature.name)

        technologies = tuple(
            signature.name
            for signature in _SIGNATURES
            if signature.name in found
        )
        return TechDetection(
            technologies=technologies,
            tags=_tags_for(technologies),
            evidence=tuple(evidence),
        )

    async def detect(self, url: str) -> TechDetection:
        """Analiza la URL objetivo y sondea rutas comunes."""

        target = (url or "").strip()
        if not _is_http(target):
            return TechDetection(error=f"URL inválida para Auto-Tech: {url!r}")

        connector = aiohttp.TCPConnector(limit=8, limit_per_host=8)
        timeout = aiohttp.ClientTimeout(total=self.timeout_s)
        headers = {"User-Agent": self.user_agent, "Accept": "*/*"}
        ssl_arg = None if self.verify_tls else False
        async with aiohttp.ClientSession(
            timeout=timeout,
            headers=headers,
            connector=connector,
            trust_env=False,
        ) as session:
            root = await self._fetch(session, target, ssl_arg)
            if root.error is not None:
                return TechDetection(error=root.error)

            analysis = self.analyze(
                headers=root.headers,
                cookies=root.cookies,
                body=root.body,
            )
            found = set(analysis.technologies)
            evidence = list(analysis.evidence)

            pending = [
                signature
                for signature in _SIGNATURES
                if signature.probe and signature.name not in found
            ][: self.max_probes]
            if pending:
                responses = await asyncio.gather(
                    *(
                        self._fetch(
                            session,
                            urljoin(target, signature.probe or ""),
                            ssl_arg,
                        )
                        for signature in pending
                    ),
                    return_exceptions=True,
                )
                for signature, response in zip(pending, responses):
                    if isinstance(response, BaseException) or response.error:
                        continue
                    if response.status not in signature.probe_status:
                        continue
                    probe_body = response.body.lower()
                    if any(term in probe_body for term in signature.probe_terms):
                        found.add(signature.name)
                        evidence.append(
                            f"{signature.name}: sonda {signature.probe}"
                        )

            technologies = tuple(
                signature.name
                for signature in _SIGNATURES
                if signature.name in found
            )
            return TechDetection(
                technologies=technologies,
                tags=_tags_for(technologies),
                evidence=tuple(evidence),
            )

    async def _fetch(
        self,
        session: aiohttp.ClientSession,
        url: str,
        ssl_arg: object = None,
    ) -> _FetchedPage:
        try:
            async with session.get(
                url,
                allow_redirects=True,
                max_redirects=3,
                ssl=ssl_arg,
            ) as response:
                body = await response.content.read(self.max_body_bytes)
                return _FetchedPage(
                    url=str(response.url),
                    status=response.status,
                    headers={
                        key.lower(): value
                        for key, value in response.headers.items()
                    },
                    cookies=tuple(
                        getattr(cookie, "key", str(cookie))
                        for cookie in response.cookies
                    ),
                    body=body.decode("utf-8", errors="replace"),
                )
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
            return _FetchedPage(
                url=url,
                error=f"{type(exc).__name__}: {exc}",
            )
