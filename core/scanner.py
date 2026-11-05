"""Escáner pasivo de hallazgos (tokens, PII, recon y XSS reflejado).

El motor es síncrono y puro: el Proxy lo ejecuta con ``asyncio.to_thread`` para
no bloquear el event loop. Solo analiza cuerpos de texto de tipos seguros y
limita cada cuerpo a 1 MiB.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlsplit

from core.model import Flow, Request, Response

MAX_SCAN_BYTES = 1024 * 1024
MAX_FINDINGS_PER_FLOW = 200

SCANNABLE_RESPONSE_TYPES = frozenset(
    {
        "text/html",
        "text/javascript",
        "application/json",
        "text/plain",
    }
)

_TOKEN_HEADERS = (
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
)

_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b"
)
_GOOGLE_API_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
_AWS_ACCESS_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_BEARER_RE = re.compile(
    r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{8,})"
)
_GENERIC_TOKEN_RE = re.compile(
    r"(?i)\b(?:access[_-]?token|api[_-]?key|secret|token)"
    r"\s*[:=]\s*[\"']?([A-Za-z0-9._~+/=-]{8,})"
)
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
# Teléfonos con al menos dos separadores (espacios, guiones, puntos o
# paréntesis). Se excluye el inicio/fin pegado a letras o a otro segmento
# numérico con punto (IPs y versiones).
_PHONE_RE = re.compile(
    r"(?<![\w.])"
    r"(?:\+?\d{1,3}[ .-]?)?"
    r"(?:\(\d{2,4}\)|\d{2,4})"
    r"[ .-]\d{3,4}"
    r"[ .-]\d{3,4}"
    r"(?!\w|\.\d)"
)
_IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
# Dominios de CDN de vídeo/imágenes donde los cuerpos contienen IDs y
# metadatos que no son teléfonos.
_PHONE_BLOCKED_URL_MARKERS = (
    "googlevideo",
    "gstatic",
    "cloudfront",
)
_PASSWORD_RE = re.compile(
    r"(?i)\b(?:password|passwd|pwd|pass)"
    r"\s*[:=]\s*[\"']?([^\s\"'<>&]{4,})"
)
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+")
_ENDPOINT_RE = re.compile(
    r"(?<![\w/])/(?:api|v\d+)/[A-Za-z0-9_./{}?=&%-]+"
)
_SUBDOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:com|net|org|io|dev|app|cloud|test|local|xyz|info|co|es)\b"
)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_XSS_CHARS = frozenset("<>\"'=()")


@dataclass(frozen=True, slots=True)
class Finding:
    """Hallazgo pasivo asociado a un flujo."""

    flow_id: int
    url: str
    kind: str
    severity: str
    evidence: str
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: int = 0

    def to_record(self) -> dict:
        return {
            "id": self.id,
            "flow_id": self.flow_id,
            "url": self.url,
            "kind": self.kind,
            "severity": self.severity,
            "evidence": self.evidence,
            "at": self.at.isoformat(),
        }


def flow_url(flow: Flow) -> str:
    """URL absoluta del flujo, útil también para el enlace del hallazgo."""
    target = flow.request.target or "/"
    if target.startswith(("http://", "https://", "ws://", "wss://")):
        return target
    scheme = "https" if flow.service.secure else "http"
    return f"{scheme}://{flow.service.authority}{target}"


def _content_type(message: object) -> str:
    if not isinstance(message, (Request, Response)):
        return ""
    return (message.header("Content-Type") or "").split(";", 1)[0].strip().lower()


def _decode(body: bytes) -> str:
    if not body:
        return ""
    sample = body[:MAX_SCAN_BYTES]
    if b"\x00" in sample:
        return ""
    return sample.decode("utf-8", errors="replace")


def _request_params(request: Request) -> list[tuple[str, str]]:
    parsed = urlsplit(request.target or "")
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if request.method.upper() in {"POST", "PUT", "PATCH"} and _content_type(
        request
    ) == "application/x-www-form-urlencoded":
        params.extend(parse_qsl(_decode(request.body), keep_blank_values=True))
    return params


def _phones_blocked(url: str) -> bool:
    lowered = url.lower()
    return any(marker in lowered for marker in _PHONE_BLOCKED_URL_MARKERS)


def _is_valid_phone(candidate: str) -> bool:
    """Descarta IPs, timestamps, fechas/versiones e IDs numéricos."""
    value = candidate.strip()
    if not value:
        return False
    if _IPV4_RE.fullmatch(value):
        return False

    digits = re.sub(r"\D", "", value)
    if not 7 <= len(digits) <= 15:
        return False
    # Timestamps Unix típicos: número continuo de 10 o 13 dígitos.
    if value.isdigit() and len(digits) in (10, 13):
        return False
    # Los teléfonos deben contener al menos un separador visible.
    if not any(char in value for char in " .-()"):
        return False
    # IDs que empiezan por 0 y superan los 10 dígitos.
    if digits.startswith("0") and len(digits) > 10:
        return False
    # Fechas/versiones comprimidas tipo 2.20261030.02.00: algún segmento
    # numérico absurdamente largo delata un timestamp o un identificador.
    segments = re.findall(r"\d+", value)
    if any(len(segment) >= 5 for segment in segments):
        return False
    return True


def scan_flow(flow: Flow) -> list[Finding]:
    """Analiza un flujo y devuelve hallazgos deduplicados."""
    url = flow_url(flow)
    request = flow.request if isinstance(flow.request, Request) else None
    response = flow.response if isinstance(flow.response, Response) else None
    response_type = _content_type(response)
    response_body = (
        _decode(response.body)
        if response is not None and response_type in SCANNABLE_RESPONSE_TYPES
        else ""
    )
    request_body = _decode(request.body) if request is not None else ""
    header_text = ""
    for message in (request, response):
        if message is None:
            continue
        for name in _TOKEN_HEADERS:
            value = message.header(name)
            if value:
                header_text += f"\n{name}: {value}"
    text = "\n".join(
        part
        for part in (url, header_text, request_body, response_body)
        if part
    )

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, severity: str, evidence: str) -> None:
        clean = evidence.strip()[:500]
        if not clean or len(findings) >= MAX_FINDINGS_PER_FLOW:
            return
        key = (kind, clean)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            Finding(
                flow_id=flow.id,
                url=url,
                kind=kind,
                severity=severity,
                evidence=clean,
            )
        )

    for match in _JWT_RE.finditer(text):
        add("token", "high", match.group(0))
    for pattern in (_GOOGLE_API_RE, _AWS_ACCESS_RE):
        for match in pattern.finditer(text):
            add("token", "high", match.group(0))
    for match in _BEARER_RE.finditer(text):
        add("token", "high", match.group(0)[:500])
    for match in _GENERIC_TOKEN_RE.finditer(text):
        add("token", "high", match.group(0)[:500])

    for match in _EMAIL_RE.finditer(text):
        add("email", "medium", match.group(0))
    phone_text = "" if _phones_blocked(url) else text
    for match in _PHONE_RE.finditer(phone_text):
        candidate = match.group(0)
        if _is_valid_phone(candidate):
            add("phone", "info", candidate)
    for match in _PASSWORD_RE.finditer(text):
        add("password", "high", match.group(0)[:500])

    if (
        request is not None
        and response is not None
        and response_type == "text/html"
        and response_body
    ):
        # Los comentarios HTML no ejecutan payloads: se eliminan antes de
        # comprobar el reflejo. Un valor escapado (&lt;script&gt;) tampoco
        # coincide con el texto original.
        executable_html = _HTML_COMMENT_RE.sub("", response_body)
        for name, value in _request_params(request):
            candidate = value.strip()
            if len(candidate) < 3:
                continue
            if not any(char in candidate for char in _XSS_CHARS):
                continue
            if candidate in executable_html:
                add("xss", "high", f"{name}={candidate}")

    for match in _URL_RE.finditer(text):
        add("url", "info", match.group(0))
    for match in _ENDPOINT_RE.finditer(text):
        add("endpoint", "info", match.group(0))
    for match in _SUBDOMAIN_RE.finditer(text):
        add("subdomain", "info", match.group(0))

    return findings


async def scan_flow_async(flow: Flow) -> list[Finding]:
    """Ejecuta el motor fuera del event loop del Proxy."""
    return await asyncio.to_thread(scan_flow, flow)
