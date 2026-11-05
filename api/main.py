"""API REST + WebSocket de prox0x (F5.1).

Lee y escribe en la misma base SQLite WAL que el Proxy. La WebSocket ``/api/ws``
hace *polling* de flujos nuevos (`id > after`), así funciona tanto si la API y
el Proxy comparten proceso como si son procesos separados.

Arranque:

    uvicorn api.main:app --reload
"""

from __future__ import annotations

import asyncio
import base64
import os
import re
import sys
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import (
    parse_qsl,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import Response as FastAPIResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from api.control import (
    ControlClient,
    ControlError,
    ControlUnavailable,
)
from core import __version__ as core_version
from core.active_scanner import ActiveScanAttempt, scan_flow_active
from core.ca import CertificateAuthority
from core.config import (
    ENV_CA_DIR,
    ENV_CA_PASSPHRASE,
    ENV_PROJECTS_DIR,
    default_ca_dir,
    default_control_socket,
    default_db_file,
    default_projects_dir,
)
from core.engine import Attempt, RedirectMode, RequestEngine, RequestOptions
from core.model import Flow, Header, HttpService, MimeType, Request as HttpRequest
from core.net.wire import parse_request
from core.oob_manager import OOBError, OOBManager
from core.project import (
    DEFAULT_PROJECT_NAME,
    ProjectError,
    ProjectExistsError,
    ProjectManager,
    ProjectNotFoundError,
    ProjectPaths,
)
from core.report import render_report
from core.scan.crawler import (
    UNLIMITED_MAX_URLS,
    CrawlResult,
    Crawler,
    CrawlerConfig,
    FormInfo,
    normalize_crawl_limits,
)
from core.scan.points import config_for_intensity
from core.scan.tech_detector import TechDetector
from core.scan.template_engine import TemplateEngine, TemplateMatch
from core.scan.template_manager import TemplateManager, TemplateUpdateResult
from core.scanner import Finding
from core.session import SessionManager
from core.store import SQLiteFlowStore
from core.store.capture import message_record
from core.updates import check_for_updates
from intruder import (
    Attack,
    AttackMode,
    PayloadSet,
    Prefix,
    ProcessorChain,
    RequestTemplate,
    SkipIf,
    Suffix,
    UrlEncode,
)
from repeater import Repeater

_MODE_ALIASES = {
    "sniper": AttackMode.SNIPER,
    "battering_ram": AttackMode.BATTERING_RAM,
    "battering-ram": AttackMode.BATTERING_RAM,
    "pitchfork": AttackMode.PITCHFORK,
    "cluster_bomb": AttackMode.CLUSTER_BOMB,
    "cluster-bomb": AttackMode.CLUSTER_BOMB,
}
_MARKERS = (b"\xc2\xa7", b"\xa7")
_ALLOWED_HOSTS = ("127.0.0.1", "localhost")
_ALLOWED_WS_ORIGINS = frozenset(
    {
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    }
)


# --------------------------------------------------------------------- modelos


class RepeaterSendRequest(BaseModel):
    flow_id: int = Field(..., ge=0)
    count: int = Field(1, ge=1, le=10_000)
    concurrency: int = Field(1, ge=1, le=999)
    mode: Literal["single", "sequential", "parallel"] = "parallel"
    delay_ms: int = Field(100, ge=0, le=60_000)
    raw_request: str | None = None
    set_headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    replace: dict[str, str] = Field(default_factory=dict)
    insecure: bool = False
    timeout: float = Field(60.0, gt=0)
    follow_redirects: bool = False


class IntruderStartRequest(BaseModel):
    flow_id: int = Field(..., ge=0)
    mode: str = "sniper"
    raw_request: str | None = None
    payloads: list[str] | None = None
    payload_sets: list[list[str]] | None = None
    positions: list[str] = Field(default_factory=list)
    concurrency: int = Field(10, ge=1, le=999)
    throttle_ms: float = Field(0.0, ge=0)
    url_encode: bool = False
    prefix: str | None = None
    suffix: str | None = None
    skip: list[str] = Field(default_factory=list)
    insecure: bool = False
    timeout: float = Field(60.0, gt=0)
    background: bool = False
    max_requests: int = Field(10_000, ge=1, le=50_000)


class InterceptToggleRequest(BaseModel):
    enabled: bool | None = None
    points: list[str] | None = None


class InterceptForwardRequest(BaseModel):
    raw_message: str | None = None
    frame_payload: str | None = None


class SessionConfigRequest(BaseModel):
    login_flow_id: int | None = Field(None, ge=0)
    token_regex: str = ""


FULL_SCAN_MAX_CRAWL_URLS = 200
TEMPLATE_CRAWL_MAX_URLS = 50
CRAWL_MAX_URLS = UNLIMITED_MAX_URLS
INTERESTING_PATHS = (
    "/admin",
    "/.env",
    "/api",
    "/config",
    "/login",
    "/.git/config",
    "/actuator",
    "/swagger",
)


class OOBModeRequest(BaseModel):
    mode: Literal["local", "online"]


class ActiveScanBatchRequest(BaseModel):
    flow_ids: list[int] = Field(default_factory=list)
    host: str | None = None
    intensity: Literal["low", "medium", "high"] = "medium"


class FullSiteScanRequest(BaseModel):
    url: str = Field(..., min_length=1)
    intensity: Literal["low", "medium", "high"] = "medium"
    custom_headers: str = Field("", max_length=8_192)
    max_depth: int = Field(3, ge=-1, le=100)
    max_urls: int = Field(
        FULL_SCAN_MAX_CRAWL_URLS, ge=-1, le=UNLIMITED_MAX_URLS
    )


class CrawlRequest(BaseModel):
    url: str = Field(..., min_length=1)
    max_depth: int = Field(3, ge=-1, le=100)
    max_urls: int = Field(
        FULL_SCAN_MAX_CRAWL_URLS, ge=-1, le=UNLIMITED_MAX_URLS
    )


class TemplateScanRequest(BaseModel):
    url: str = Field(..., min_length=1)
    tags: list[str] = Field(default_factory=lambda: ["cve"])
    max_templates: int = Field(500, ge=1, le=5_000)
    concurrency: int = Field(5, ge=1, le=20)
    throttle_ms: float = Field(50.0, ge=0, le=5_000)
    crawl: bool = False
    auto_tech: bool = False
    max_depth: int = Field(3, ge=-1, le=100)
    max_urls: int = Field(
        TEMPLATE_CRAWL_MAX_URLS, ge=-1, le=UNLIMITED_MAX_URLS
    )


class ScopeUpdateRequest(BaseModel):
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


class ScopeAddRequest(BaseModel):
    host: str = Field(..., min_length=1)


class MatchReplaceRuleModel(BaseModel):
    id: str = ""
    target: Literal["request", "response"] = "request"
    match: str = Field(..., min_length=1)
    replace: str = ""
    location: Literal["headers", "body", "all"] = "all"
    regex: bool = False
    enabled: bool = True


class MatchReplaceUpdateRequest(BaseModel):
    rules: list[MatchReplaceRuleModel] = Field(default_factory=list)


class ProjectNameRequest(BaseModel):
    name: str = Field(..., min_length=1)


@dataclass
class AttackJob:
    """Estado en memoria de un ataque lanzado en segundo plano."""

    id: str
    status: str = "running"
    expected: int = 0
    skipped: int = 0
    error: str | None = None
    results: list[dict[str, Any]] = field(default_factory=list)
    details: dict[int, dict[str, Any]] = field(default_factory=dict)
    started_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    finished_at: datetime | None = None
    task: asyncio.Task[None] | None = None


MAX_INLINE_BODY_BYTES = 5 * 1024 * 1024
MAX_BATCH_SCAN_FLOWS = 200
MAX_FULL_SCAN_FLOWS = 80
CRAWL_CONCURRENCY = 5
FULL_SCAN_USER_AGENT = "prox0x-fullscan/1.0"
FULL_SCAN_LISTENER_PORT = 8080
_CUSTOM_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_FORBIDDEN_CUSTOM_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "connection",
        "transfer-encoding",
        "expect",
    }
)


def _parse_custom_headers(text: str) -> tuple[tuple[str, str], ...]:
    """Parsea ``Nombre: valor`` por línea para el Full Site Scan."""

    if not text.strip():
        return ()
    headers: dict[str, tuple[str, str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise HTTPException(
                status_code=400,
                detail=f"cabecera inválida: {line!r} (usa Nombre: valor)",
            )
        name, value = line.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not name or not _CUSTOM_HEADER_NAME_RE.match(name):
            raise HTTPException(
                status_code=400,
                detail=f"nombre de cabecera inválido: {name!r}",
            )
        if any(char in value for char in "\r\n\0"):
            raise HTTPException(
                status_code=400,
                detail=f"valor de cabecera inválido para {name}",
            )
        try:
            value.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"la cabecera {name} contiene caracteres no válidos",
            ) from exc
        lower = name.lower()
        if lower in _FORBIDDEN_CUSTOM_HEADERS:
            continue
        # La última aparición gana, sin duplicar nombres con distinto casing.
        headers.pop(lower, None)
        headers[lower] = (name, value)
        if len(headers) > 50:
            raise HTTPException(
                status_code=400, detail="demasiadas cabeceras personalizadas"
            )
    return tuple(headers.values())


@dataclass
class ActiveScanJob:
    """Estado en memoria de un escaneo activo masivo en segundo plano."""

    id: str
    flow_ids: list[int]
    host: str | None = None
    status: str = "running"
    total: int = 0
    completed: int = 0
    total_attempts: int = 0
    vulnerable: int = 0
    errors: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    mode: str = "batch"
    phase: str = "scanning"
    seed_url: str | None = None
    intensity: str = "medium"
    custom_headers: tuple[tuple[str, str], ...] = ()
    max_depth: int = 3
    max_urls: int = FULL_SCAN_MAX_CRAWL_URLS
    urls_found: int = 0
    forms_found: int = 0
    pages_found: int = 0
    started_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    finished_at: datetime | None = None
    task: asyncio.Task[None] | None = None

    def to_record(self) -> dict[str, Any]:
        return {
            "scan_id": self.id,
            "flow_id": self.flow_ids[0] if len(self.flow_ids) == 1 else None,
            "flow_ids": self.flow_ids,
            "host": self.host,
            "status": self.status,
            "mode": self.mode,
            "phase": self.phase,
            "seed_url": self.seed_url,
            "intensity": self.intensity,
            "custom_headers": [name for name, _value in self.custom_headers],
            "max_depth": self.max_depth,
            "max_urls": self.max_urls,
            "urls_found": self.urls_found,
            "forms_found": self.forms_found,
            "pages_found": self.pages_found,
            "total": self.total,
            "completed": self.completed,
            "progress": (
                round((self.completed / self.total) * 100, 1)
                if self.total
                else 0.0
            ),
            "total_attempts": self.total_attempts,
            "vulnerable": self.vulnerable,
            "errors": self.errors,
            "findings": self.findings,
            "error": self.error,
            "started_at": self.started_at.isoformat(),
            "finished_at": (
                self.finished_at.isoformat() if self.finished_at else None
            ),
        }


@dataclass
class CrawlJob:
    """Estado en memoria de un crawler independiente (sin ataques)."""

    id: str
    url: str
    host: str | None = None
    status: str = "running"
    phase: str = "crawling"
    max_urls: int = FULL_SCAN_MAX_CRAWL_URLS
    max_depth: int = 3
    urls_found: int = 0
    pages_found: int = 0
    forms_found: int = 0
    routes_saved: int = 0
    errors: int = 0
    error: str | None = None
    started_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    finished_at: datetime | None = None
    task: asyncio.Task[None] | None = None

    def to_record(self) -> dict[str, Any]:
        if self.status == "completed":
            progress = 100.0
        elif self.max_urls:
            progress = round(
                min(99.0, (self.urls_found / self.max_urls) * 100), 1
            )
        else:
            progress = 0.0
        return {
            "crawl_id": self.id,
            "seed_url": self.url,
            "host": self.host,
            "status": self.status,
            "phase": self.phase,
            "max_urls": self.max_urls,
            "max_depth": self.max_depth,
            "urls_found": self.urls_found,
            "pages_found": self.pages_found,
            "forms_found": self.forms_found,
            "routes_saved": self.routes_saved,
            "errors": self.errors,
            "progress": progress,
            "error": self.error,
            "started_at": self.started_at.isoformat(),
            "finished_at": (
                self.finished_at.isoformat() if self.finished_at else None
            ),
        }


@dataclass
class TemplateScanJob:
    """Estado en memoria de un escaneo de plantillas Nuclei."""

    id: str
    url: str
    tags: list[str]
    max_templates: int
    concurrency: int
    throttle_ms: float
    crawl: bool = False
    auto_tech: bool = False
    max_depth: int = 3
    max_urls: int = TEMPLATE_CRAWL_MAX_URLS
    status: str = "running"
    phase: str = "loading"
    detected_technologies: list[str] = field(default_factory=list)
    detected_tags: list[str] = field(default_factory=list)
    effective_tags: list[str] = field(default_factory=list)
    tech_evidence: list[str] = field(default_factory=list)
    tech_error: str | None = None
    templates_total: int = 0
    templates_run: int = 0
    templates_skipped: int = 0
    urls_found: int = 0
    urls_total: int = 0
    urls_scanned: int = 0
    attacks_total: int = 0
    attacks_run: int = 0
    matches: int = 0
    errors: int = 0
    results: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    error: str | None = None
    started_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    finished_at: datetime | None = None
    task: asyncio.Task[None] | None = None

    def to_record(self) -> dict[str, Any]:
        if self.crawl:
            progress = (
                round((self.attacks_run / self.attacks_total) * 100, 1)
                if self.attacks_total
                else 0.0
            )
        else:
            progress = (
                round((self.templates_run / self.templates_total) * 100, 1)
                if self.templates_total
                else 0.0
            )
        return {
            "scan_id": self.id,
            "url": self.url,
            "tags": self.tags,
            "max_templates": self.max_templates,
            "concurrency": self.concurrency,
            "throttle_ms": self.throttle_ms,
            "crawl": self.crawl,
            "auto_tech": self.auto_tech,
            "max_depth": self.max_depth,
            "max_urls": self.max_urls,
            "status": self.status,
            "phase": self.phase,
            "detected_technologies": self.detected_technologies,
            "detected_tags": self.detected_tags,
            "effective_tags": self.effective_tags,
            "tech_evidence": self.tech_evidence[:20],
            "tech_error": self.tech_error,
            "templates_total": self.templates_total,
            "templates_run": self.templates_run,
            "templates_skipped": self.templates_skipped,
            "urls_found": self.urls_found,
            "urls_total": self.urls_total,
            "urls_scanned": self.urls_scanned,
            "attacks_total": self.attacks_total,
            "attacks_run": self.attacks_run,
            "matches": self.matches,
            "errors": self.errors,
            "progress": progress,
            "results": self.results,
            "skipped": self.skipped[:100],
            "error": self.error,
            "started_at": self.started_at.isoformat(),
            "finished_at": (
                self.finished_at.isoformat() if self.finished_at else None
            ),
        }


def _template_result_record(
    match: TemplateMatch,
    flow_id: int,
) -> dict[str, Any]:
    return {
        "template_id": match.template_id,
        "name": match.name,
        "severity": match.severity,
        "tags": list(match.tags),
        "url": match.url,
        "method": match.method,
        "status_code": match.status_code,
        "matcher": match.matcher,
        "evidence": match.evidence,
        "extracted": {
            name: list(values) for name, values in match.extracted
        },
        "flow_id": flow_id,
    }


def _template_flow_id(base_id: int, index: int) -> int:
    flow_id = base_id + index
    # JavaScript redondea IDs > 2^53; el BaseURL del escáner usa microsegundos.
    return flow_id if flow_id < 2**53 else (base_id % (2**53 - 1)) + index


async def _run_template_scan(
    job: TemplateScanJob,
    manager: TemplateManager,
    store: SQLiteFlowStore,
) -> None:
    """Carga plantillas, ejecuta el motor y persiste hallazgos."""

    engine = RequestEngine(
        max_concurrency=job.concurrency,
        auth_refresh=SessionManager(store).refresh,
    )
    flow_index = 0
    base_id = max(store.max_id() + 1, int(time.time() * 1_000_000))

    def on_result(match: TemplateMatch) -> None:
        nonlocal flow_index
        flow_id = _template_flow_id(base_id, flow_index)
        flow_index += 1
        flow = Flow(
            id=flow_id,
            service=match.service,
            listener_port=FULL_SCAN_LISTENER_PORT,
            received_at=datetime.now(timezone.utc),
            request=match.request,
            final_request=match.request,
            response=match.response,
            mime=MimeType.from_content_type(
                match.response.header("Content-Type")
            ),
            timing=match.timing,
            in_scope=True,
            is_scan_flow=True,
        )
        store.save(flow)
        finding = match.to_finding(flow_id)
        store.add_findings([finding])
        store.add_scan_attempts(
            [
                {
                    "scan_id": job.id,
                    "flow_id": flow_id,
                    "url": match.url,
                    "parameter": match.matcher,
                    "location": "template",
                    "attack": "template",
                    "payload": match.template_id,
                    "status_code": match.status_code,
                    "result": "vulnerable",
                    "evidence": match.evidence,
                    "request_raw": match.request.raw[: 512 * 1024],
                    "response_raw": match.response.raw[: 512 * 1024],
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            ]
        )
        job.matches += 1
        job.results.append(_template_result_record(match, flow_id))

    def on_progress(
        templates_run: int, templates_total: int, matches: int
    ) -> None:
        job.matches = max(job.matches, matches)
        if job.crawl:
            job.attacks_run = max(job.attacks_run, templates_run)
            if templates_total:
                job.attacks_total = max(job.attacks_total, templates_total)
        else:
            job.templates_run = templates_run
            job.templates_total = max(job.templates_total, templates_total)
            # Sin crawl hay una sola URL: ataques y plantillas avanzan juntos.
            job.attacks_run = max(job.attacks_run, templates_run)
            if templates_total:
                job.attacks_total = max(job.attacks_total, templates_total)

    def on_url_progress(scanned: int, total: int) -> None:
        job.urls_scanned = max(job.urls_scanned, scanned)
        if total:
            job.urls_total = max(job.urls_total, total)

    def on_skip(template: Any, reason: str) -> None:
        job.templates_skipped += 1
        job.skipped.append(
            {"path": str(template.path), "reason": reason}
        )
        if len(job.skipped) > 100:
            del job.skipped[0]

    try:
        job.phase = "loading"
        if not manager.path.is_dir() or not any(manager.path.iterdir()):
            update = await manager.update()
            if update.error:
                job.errors += 1
                job.error = update.error

        effective_tags = list(job.tags)
        job.effective_tags = effective_tags
        if job.auto_tech:
            job.phase = "detecting"
            detection = await TechDetector().detect(job.url)
            job.detected_technologies = list(detection.technologies)
            job.detected_tags = list(detection.tags)
            job.tech_evidence = list(detection.evidence)
            job.tech_error = detection.error
            if detection.tags:
                try:
                    available = set(await manager.tags())
                except Exception:  # noqa: BLE001 - la detección no debe romper el job
                    available = set()
                matched = [
                    tag for tag in detection.tags if tag in available
                ]
                if matched:
                    effective_tags = matched
                else:
                    job.tech_error = (
                        "las tecnologías detectadas no tienen plantillas "
                        "compatibles; se usan los tags manuales"
                    )
            job.effective_tags = effective_tags

        job.phase = "loading"
        template_engine = TemplateEngine(
            engine,
            concurrency=job.concurrency,
            throttle_ms=job.throttle_ms,
        )
        loaded = await template_engine.load_templates(
            manager.path,
            tags=tuple(effective_tags),
            max_templates=job.max_templates,
        )
        job.templates_total = len(loaded.templates)
        job.templates_skipped = len(loaded.skipped)
        job.skipped = [
            {"path": path, "reason": reason}
            for path, reason in loaded.skipped[:100]
        ]
        if not loaded.templates:
            job.status = "completed"
            job.phase = "completed"
            job.error = (
                "no hay plantillas HTTP compatibles "
                + (
                    "para los tags indicados"
                    if effective_tags
                    else "en el repositorio local"
                )
            )
            return

        targets = [job.url]
        if job.crawl:
            job.phase = "crawling"

            def on_crawl_progress(result: CrawlResult) -> None:
                job.urls_found = len(result.urls)

            crawler = Crawler(
                job.url,
                urlsplit(job.url).hostname or "",
                config=CrawlerConfig(
                    max_urls=job.max_urls,
                    max_depth=job.max_depth,
                    concurrency=max(1, job.concurrency),
                ),
                on_progress=on_crawl_progress,
            )
            crawl_result = await crawler.crawl()
            job.urls_found = len(crawl_result.urls)
            discovered = list(
                dict.fromkeys(url for url in crawl_result.urls if url)
            )
            targets = discovered or [job.url]

        job.urls_total = len(targets)
        job.attacks_total = job.templates_total * job.urls_total
        job.phase = "scanning"

        if job.crawl:
            await template_engine.scan_urls(
                targets,
                loaded.templates,
                on_result=on_result,
                on_progress=on_progress,
                on_skip=on_skip,
                on_url_progress=on_url_progress,
            )
            job.urls_scanned = job.urls_total
            job.attacks_run = job.attacks_total
        else:
            await template_engine.scan(
                job.url,
                loaded.templates,
                on_result=on_result,
                on_progress=on_progress,
                on_skip=on_skip,
            )
            job.urls_total = 1
            job.urls_scanned = 1
            job.attacks_total = job.templates_total
            job.attacks_run = job.templates_total
        job.templates_run = job.templates_total
        job.status = "completed"
        job.phase = "completed"
    except asyncio.CancelledError:
        job.status = "failed"
        job.phase = "failed"
        job.error = "escaneo de plantillas cancelado"
        raise
    except Exception as exc:  # noqa: BLE001 - el estado debe reflejar el fallo
        job.status = "failed"
        job.phase = "failed"
        job.error = str(exc)
    finally:
        job.finished_at = datetime.now(timezone.utc)
        await engine.aclose()


def _crawl_routes(result: CrawlResult) -> list[dict[str, str]]:
    """Convierte URLs y formularios descubiertos en rutas persistibles."""

    routes: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(method: str, target: str) -> None:
        parts = urlsplit(target)
        host = (parts.hostname or "").lower()
        if not host:
            return
        normalized_method = (method or "GET").upper()
        key = (host, normalized_method, target)
        if key in seen:
            return
        seen.add(key)
        routes.append(
            {
                "host": host,
                "method": normalized_method,
                "target": target,
            }
        )

    for form in result.forms:
        add(form.method, form.action)
    for url in result.urls:
        add("GET", url)
    return routes


async def _run_crawl(job: CrawlJob, store: SQLiteFlowStore) -> None:
    """Rastrea el sitio y guarda rutas; nunca lanza ataques."""

    def on_progress(result: CrawlResult) -> None:
        job.urls_found = len(result.urls)
        job.pages_found = len(result.pages)
        job.forms_found = len(result.forms)

    try:
        job.phase = "crawling"
        crawler = Crawler(
            job.url,
            job.host,
            config=CrawlerConfig(
                max_urls=job.max_urls,
                max_depth=job.max_depth,
                concurrency=CRAWL_CONCURRENCY,
            ),
            on_progress=on_progress,
        )
        result = await crawler.crawl()
        job.urls_found = len(result.urls)
        job.pages_found = len(result.pages)
        job.forms_found = len(result.forms)
        job.errors = len(result.errors)

        job.phase = "saving"
        job.routes_saved = store.save_crawl_routes(
            job.id, _crawl_routes(result)
        )
        job.status = "completed"
        job.phase = "completed"
    except asyncio.CancelledError:
        job.status = "failed"
        job.phase = "failed"
        job.error = "crawler cancelado"
        raise
    except Exception as exc:  # noqa: BLE001 - el estado debe reflejar el fallo
        job.status = "failed"
        job.phase = "failed"
        job.error = str(exc)
    finally:
        job.finished_at = datetime.now(timezone.utc)


async def _run_active_scan(
    job: ActiveScanJob, flows: list[Flow], store: SQLiteFlowStore
) -> None:
    """Escanea los flujos y persiste cada intento y sus hallazgos."""
    config = config_for_intensity(job.intensity)
    engine = RequestEngine(
        max_concurrency=config.concurrency,
        auth_refresh=SessionManager(store).refresh,
    )

    def on_attempt(result: ActiveScanAttempt) -> None:
        job.total_attempts += 1
        if result.result == "vulnerable":
            job.vulnerable += 1
        elif result.result == "error":
            job.errors += 1
        store.add_scan_attempts(
            [
                {
                    "scan_id": job.id,
                    "flow_id": result.flow_id,
                    "url": result.url,
                    "parameter": result.parameter,
                    "location": result.location,
                    "attack": result.attack,
                    "payload": result.payload,
                    "status_code": result.status_code,
                    "result": result.result,
                    "evidence": result.evidence,
                    "evidence_match": result.evidence_match,
                    "evidence_offset": result.evidence_offset,
                    "request_raw": result.request_raw,
                    "response_raw": result.response_raw,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            ]
        )
        if result.finding is not None:
            job.findings.extend(store.add_findings([result.finding]))

    try:
        job.phase = "scanning"
        for flow in flows:
            await scan_flow_active(
                flow,
                engine,
                config=config,
                on_attempt=on_attempt,
            )
            job.completed += 1
        job.status = "completed"
        job.phase = "completed"
    except asyncio.CancelledError:
        job.status = "failed"
        job.phase = "failed"
        job.error = "escaneo cancelado"
        raise
    except Exception as exc:  # noqa: BLE001 - el estado debe reflejar el fallo
        job.status = "failed"
        job.phase = "failed"
        job.error = str(exc)
    finally:
        job.finished_at = datetime.now(timezone.utc)
        await engine.aclose()


@dataclass(frozen=True, slots=True)
class _FullScanTarget:
    method: str
    url: str
    body: bytes = b""
    content_type: str | None = None


def _full_scan_targets(result: CrawlResult) -> list[_FullScanTarget]:
    """Construye peticiones escaneables: formularios, páginas y queries."""

    targets: list[_FullScanTarget] = []
    seen: set[tuple[str, str, bytes]] = set()

    def add(
        method: str,
        url: str,
        body: bytes = b"",
        content_type: str | None = None,
    ) -> None:
        if not url or len(targets) >= MAX_FULL_SCAN_FLOWS:
            return
        key = (method, url, body)
        if key in seen:
            return
        seen.add(key)
        targets.append(
            _FullScanTarget(
                method=method,
                url=url,
                body=body,
                content_type=content_type,
            )
        )

    # Primero formularios: suelen ser los puntos de inyección más valiosos.
    for form in result.forms:
        fields = [
            (field.name, field.value)
            for field in form.fields
            if field.name
        ]
        if form.method == "GET":
            parts = urlsplit(form.action)
            pairs = parse_qsl(parts.query, keep_blank_values=True) + fields
            url = urlunsplit(
                (parts.scheme, parts.netloc, parts.path, urlencode(pairs), "")
            )
            add("GET", url)
        elif form.method == "POST":
            body = urlencode(fields).encode("utf-8")
            add(
                "POST",
                form.action,
                body,
                "application/x-www-form-urlencoded",
            )

    for page in result.pages:
        add("GET", page.url)

    for url in result.urls:
        if "?" in url:
            add("GET", url)

    return targets


def _request_for_target(
    target: _FullScanTarget,
    custom_headers: tuple[tuple[str, str], ...] = (),
) -> tuple[HttpRequest, HttpService]:
    parts = urlsplit(target.url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"URL de escaneo inválida: {target.url!r}")
    secure = parts.scheme == "https"
    port = parts.port or (443 if secure else 80)
    service = HttpService(
        host=parts.hostname,
        port=port,
        secure=secure,
    )
    header_values: dict[str, str] = {
        "Host": service.authority,
        "User-Agent": FULL_SCAN_USER_AGENT,
        "Accept": (
            "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"
        ),
    }
    for name, value in custom_headers:
        lower = name.lower()
        if lower in {"host", "content-length"}:
            continue
        for current in list(header_values):
            if current.lower() == lower:
                del header_values[current]
        header_values[name] = value
    if target.body:
        header_values["Content-Type"] = (
            target.content_type or "application/x-www-form-urlencoded"
        )
        header_values["Content-Length"] = str(len(target.body))
    headers = [Header(name, value) for name, value in header_values.items()]
    head = (
        f"{target.method} {target.url} HTTP/1.1\r\n"
        + "".join(f"{header.name}: {header.value}\r\n" for header in headers)
        + "\r\n"
    ).encode("latin-1")
    request = HttpRequest(
        raw=head + target.body,
        headers=tuple(headers),
        body=target.body,
        body_offset=len(head),
        version="HTTP/1.1",
        method=target.method,
        target=target.url,
        http_service=service,
    )
    return request, service


def _flow_from_attempt(
    flow_id: int,
    request: HttpRequest,
    service: HttpService,
    attempt: Attempt,
    *,
    is_scan_flow: bool = False,
) -> Flow:
    response = attempt.response
    content_type = response.header("Content-Type") if response else None
    return Flow(
        id=flow_id,
        service=service,
        listener_port=FULL_SCAN_LISTENER_PORT,
        received_at=datetime.now(timezone.utc),
        request=attempt.request or request,
        final_request=attempt.request or request,
        response=response,
        mime=MimeType.from_content_type(content_type),
        timing=attempt.timing,
        in_scope=True,
        is_scan_flow=is_scan_flow,
    )


def _interesting_route_urls(seed_url: str) -> list[str]:
    """Genera las URLs del fallback de rutas comunes sobre el host semilla."""

    parts = urlsplit(seed_url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return []
    base = f"{parts.scheme}://{parts.netloc}/"
    return [urljoin(base, path.lstrip("/")) for path in INTERESTING_PATHS]


async def _probe_interesting_routes(
    job: ActiveScanJob,
    seed_url: str,
    engine: RequestEngine,
    store: SQLiteFlowStore,
    *,
    custom_headers: tuple[tuple[str, str], ...] = (),
) -> None:
    """Fallback cuando el crawl no encuentra formularios ni parámetros.

    Prueba rutas comunes y reporta como hallazgo las que responden 200/403.
    También registra cada sonda como intento para que el resumen del Full Site
    Scan no termine en "0 ataques" sin haber probado nada.
    """

    urls = _interesting_route_urls(seed_url)
    if not urls:
        return

    base_id = max(store.max_id() + 1, int(time.time() * 1_000_000))
    job.total += len(urls)

    for index, url in enumerate(urls):
        target = _FullScanTarget(method="GET", url=url)
        request, service = _request_for_target(target, custom_headers)
        attempt = await engine.send(
            request,
            service,
            options=RequestOptions(throttle_ms=0),
            label=f"fullscan:route:{index}",
        )
        job.completed += 1
        job.total_attempts += 1

        if not attempt.ok or attempt.response is None:
            job.errors += 1
            continue

        status = attempt.response.status_code
        if status not in (200, 403):
            continue

        flow_id = _template_flow_id(base_id, index)
        flow = _flow_from_attempt(
            flow_id,
            request,
            service,
            attempt,
            is_scan_flow=True,
        )
        store.save(flow)
        job.flow_ids.append(flow.id)

        path = urlsplit(url).path or "/"
        evidence = (
            f"Ruta Interesante Encontrada · GET {path} → HTTP {status}"
        )
        finding = Finding(
            flow_id=flow.id,
            url=url,
            kind="interesting_route",
            severity="low" if status == 200 else "info",
            evidence=evidence,
        )
        job.findings.extend(store.add_findings([finding]))
        store.add_scan_attempts(
            [
                {
                    "scan_id": job.id,
                    "flow_id": flow.id,
                    "url": url,
                    "parameter": "",
                    "location": "path",
                    "attack": "route",
                    "payload": path,
                    "status_code": status,
                    "result": "safe",
                    "evidence": evidence,
                    "evidence_match": "",
                    "evidence_offset": None,
                    "request_raw": request.raw[: 512 * 1024],
                    "response_raw": attempt.response.raw[: 512 * 1024],
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            ]
        )


async def _run_full_site_scan(
    job: ActiveScanJob,
    seed_url: str,
    store: SQLiteFlowStore,
) -> None:
    """Rastrea el sitio, crea flujos y los pasa al Escáner Activo."""

    config = config_for_intensity(job.intensity)
    engine = RequestEngine(
        max_concurrency=config.concurrency,
        auth_refresh=SessionManager(store).refresh,
    )

    def on_attempt(result: ActiveScanAttempt) -> None:
        job.total_attempts += 1
        if result.result == "vulnerable":
            job.vulnerable += 1
        elif result.result == "error":
            job.errors += 1
        store.add_scan_attempts(
            [
                {
                    "scan_id": job.id,
                    "flow_id": result.flow_id,
                    "url": result.url,
                    "parameter": result.parameter,
                    "location": result.location,
                    "attack": result.attack,
                    "payload": result.payload,
                    "status_code": result.status_code,
                    "result": result.result,
                    "evidence": result.evidence,
                    "evidence_match": result.evidence_match,
                    "evidence_offset": result.evidence_offset,
                    "request_raw": result.request_raw,
                    "response_raw": result.response_raw,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            ]
        )
        if result.finding is not None:
            job.findings.extend(store.add_findings([result.finding]))

    try:
        job.phase = "crawling"
        host = urlsplit(seed_url).hostname or ""
        crawler = Crawler(
            seed_url,
            host,
            config=CrawlerConfig(
                max_urls=job.max_urls,
                max_depth=job.max_depth,
                concurrency=config.concurrency,
                extra_headers=job.custom_headers,
            ),
        )
        crawl = await crawler.crawl()
        job.urls_found = len(crawl.urls)
        job.pages_found = len(crawl.pages)
        job.forms_found = len(crawl.forms)

        has_forms = any(form.fields for form in crawl.forms)
        has_params = any("?" in url for url in crawl.urls)
        targets = _full_scan_targets(crawl)
        job.total = len(targets)
        job.phase = "analyzing"

        # IDs altos pero seguros en JavaScript (< 2^53): el navegador redondea
        # números mayores y el detalle del hallazgo pediría un ID inexistente.
        base_id = max(store.max_id() + 1, int(time.time() * 1_000_000))
        for index, target in enumerate(targets):
            request, service = _request_for_target(
                target, job.custom_headers
            )
            attempt = await engine.send(
                request,
                service,
                options=RequestOptions(throttle_ms=0),
                label=f"fullscan:fetch:{index}",
            )
            if not attempt.ok or attempt.response is None:
                job.errors += 1
                job.completed += 1
                continue

            flow = _flow_from_attempt(
                base_id + index,
                request,
                service,
                attempt,
                is_scan_flow=True,
            )
            store.save(flow)
            job.flow_ids.append(flow.id)
            job.phase = "scanning"
            await scan_flow_active(
                flow,
                engine,
                config=config,
                on_attempt=on_attempt,
            )
            job.completed += 1

        if not has_forms and not has_params:
            job.phase = "scanning"
            await _probe_interesting_routes(
                job,
                seed_url,
                engine,
                store,
                custom_headers=job.custom_headers,
            )

        job.status = "completed"
        job.phase = "completed"
    except asyncio.CancelledError:
        job.status = "failed"
        job.phase = "failed"
        job.error = "escaneo cancelado"
        raise
    except Exception as exc:  # noqa: BLE001 - el estado debe reflejar el fallo
        job.status = "failed"
        job.phase = "failed"
        job.error = str(exc)
    finally:
        job.finished_at = datetime.now(timezone.utc)
        await engine.aclose()


# ------------------------------------------------------------------ app/store


def ui_dist_directory() -> Path | None:
    """Directorio de la UI compilada, o None si no se ha construido.

    Prioridad: ``PROX0X_UI_DIST`` → bundle de PyInstaller (``sys._MEIPASS``) →
    ``api/ui_dist`` (copia de build) → ``ui/dist`` (desarrollo con Vite).
    """
    candidates: list[Path] = []
    override = os.environ.get("PROX0X_UI_DIST")
    if override:
        candidates.append(Path(override))

    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / "api" / "ui_dist")

    here = Path(__file__).resolve().parent
    candidates.append(here / "ui_dist")
    candidates.append(here.parent / "ui" / "dist")

    for directory in candidates:
        if (directory / "index.html").is_file():
            return directory
    return None


# Los cuerpos mayores se omiten del JSON de detalle para no bloquear el
# navegador; el cliente los descarga por streaming desde /download.
MAX_INLINE_BODY_BYTES = 5 * 1024 * 1024

_EXTENSIONS = {
    "application/gzip": ".gz",
    "application/javascript": ".js",
    "application/json": ".json",
    "application/octet-stream": ".bin",
    "application/pdf": ".pdf",
    "application/wasm": ".wasm",
    "application/xml": ".xml",
    "application/zip": ".zip",
    "font/otf": ".otf",
    "font/ttf": ".ttf",
    "font/woff": ".woff",
    "font/woff2": ".woff2",
    "image/gif": ".gif",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/svg+xml": ".svg",
    "image/webp": ".webp",
    "text/css": ".css",
    "text/csv": ".csv",
    "text/html": ".html",
    "text/plain": ".txt",
    "text/xml": ".xml",
}


def _b64_size(value: object) -> int:
    if not isinstance(value, str) or not value:
        return 0
    padding = len(value) - len(value.rstrip("="))
    return max(0, (len(value) * 3) // 4 - padding)


def _extension_for(content_type: str | None) -> str:
    essence = (content_type or "").split(";", 1)[0].strip().lower()
    if essence in _EXTENSIONS:
        return _EXTENSIONS[essence]
    subtype = essence.split("/", 1)[1] if "/" in essence else ""
    return f".{subtype}" if subtype.isalnum() else ".bin"


def _limit_inline_bodies(record: dict, flow_id: int) -> dict:
    """Elimina del JSON los cuerpos > 5 MiB y añade metadatos de descarga."""
    for field, message_kind in (
        ("request", "request"),
        ("final_request", "request"),
        ("response", "response"),
    ):
        message = record.get(field)
        if not isinstance(message, dict):
            continue
        size = _b64_size(message.get("display_raw") or message.get("raw"))
        if size <= MAX_INLINE_BODY_BYTES:
            continue
        message["raw"] = ""
        message.pop("display_raw", None)
        message["body_too_large"] = True
        message["size"] = size
        message["download_url"] = (
            f"/api/flows/{flow_id}/download?message={message_kind}"
        )
    return record


async def _compute_template_info(app: FastAPI) -> dict[str, Any]:
    """Calcula (y cachea) cuántas plantillas HTTP puede ejecutar el motor."""

    manager: TemplateManager = app.state.template_manager
    engine = TemplateEngine(None)
    result = await engine.load_templates(
        manager.path,
        tags=(),
        max_templates=1_000_000,
    )
    info: dict[str, Any] = {
        "total_available": len(result.templates),
        "skipped": len(result.skipped),
    }
    app.state.template_info = info
    return info


def create_app(
    db_path: Path | None = None,
    control_socket: Path | None = None,
    projects_dir: Path | None = None,
    ca_dir: Path | None = None,
    control: Any | None = None,
    allowed_ws_origins: set[str] | None = None,
    oob_local_port: int = 9999,
) -> FastAPI:
    database = db_path or default_db_file()
    socket_path = control_socket or default_control_socket()
    if projects_dir is not None:
        resolved_projects_dir = projects_dir
    elif db_path is not None and ENV_PROJECTS_DIR not in os.environ:
        resolved_projects_dir = db_path.parent / "projects"
    else:
        resolved_projects_dir = default_projects_dir()

    if ca_dir is not None:
        resolved_ca_dir = ca_dir
    elif db_path is not None and ENV_CA_DIR not in os.environ:
        resolved_ca_dir = db_path.parent / "ca"
    else:
        resolved_ca_dir = default_ca_dir()

    default_paths = ProjectPaths(
        name=DEFAULT_PROJECT_NAME,
        directory=database.parent,
        db_file=database,
        scope_file=database.parent / "scope.json",
        match_replace_file=database.parent / "match_replace.json",
        flows_file=database.parent / "flows.jsonl",
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.sqlite = SQLiteFlowStore(database)
        app.state.projects = ProjectManager(
            resolved_projects_dir, default_paths=default_paths
        )
        app.state.ca_dir = resolved_ca_dir
        app.state.attack_jobs = {}
        app.state.scan_jobs = {}
        app.state.crawl_jobs = {}
        app.state.template_scan_jobs = {}
        app.state.template_manager = TemplateManager()
        app.state.template_info = None
        app.state.template_info_lock = asyncio.Lock()
        app.state.template_update_task = None
        if os.environ.get("PROX0X_TEMPLATES_UPDATE", "1") != "0":

            async def update_templates_and_warm() -> None:
                try:
                    await app.state.template_manager.update()
                finally:
                    async with app.state.template_info_lock:
                        await _compute_template_info(app)

            app.state.template_update_task = asyncio.create_task(
                update_templates_and_warm(),
                name="prox0x-templates-update",
            )
        app.state.control = control if control is not None else ControlClient(socket_path)
        app.state.oob = OOBManager(
            lambda: app.state.sqlite, local_port=oob_local_port
        )
        await app.state.oob.start()
        try:
            yield
        finally:
            scan_tasks = [
                job.task
                for job in app.state.scan_jobs.values()
                if job.task is not None and not job.task.done()
            ]
            for task in scan_tasks:
                task.cancel()
            if scan_tasks:
                await asyncio.gather(*scan_tasks, return_exceptions=True)
            crawl_tasks = [
                job.task
                for job in app.state.crawl_jobs.values()
                if job.task is not None and not job.task.done()
            ]
            for task in crawl_tasks:
                task.cancel()
            if crawl_tasks:
                await asyncio.gather(*crawl_tasks, return_exceptions=True)
            template_scan_tasks = [
                job.task
                for job in app.state.template_scan_jobs.values()
                if job.task is not None and not job.task.done()
            ]
            for task in template_scan_tasks:
                task.cancel()
            if template_scan_tasks:
                await asyncio.gather(
                    *template_scan_tasks, return_exceptions=True
                )
            template_update_task = getattr(
                app.state, "template_update_task", None
            )
            if (
                template_update_task is not None
                and not template_update_task.done()
            ):
                template_update_task.cancel()
                await asyncio.gather(
                    template_update_task, return_exceptions=True
                )
            await app.state.oob.stop()
            app.state.sqlite.close()

    app = FastAPI(
        title="prox0x API",
        description="Historial de flujos, Repeater e Intruder",
        version=core_version,
        lifespan=lifespan,
    )
    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=list(_ALLOWED_HOSTS)
    )
    app.state.allowed_ws_origins = frozenset(
        allowed_ws_origins or _ALLOWED_WS_ORIGINS
    )

    def _store(request: Request | WebSocket) -> SQLiteFlowStore:
        return request.app.state.sqlite

    def _flow(store: SQLiteFlowStore, flow_id: int) -> Flow:
        flow = store.get_flow(flow_id)
        if flow is None:
            raise HTTPException(status_code=404, detail=f"no existe el flujo #{flow_id}")
        return flow

    def _request_of(flow: Flow) -> HttpRequest:
        request = flow.final_request
        if not isinstance(request, HttpRequest):
            request = flow.request
        if not isinstance(request, HttpRequest):
            raise HTTPException(status_code=422, detail="el flujo no contiene un Request")
        return request

    async def _control_call(
        request: Request, command: str, **payload: Any
    ) -> dict[str, Any]:
        try:
            return await request.app.state.control.request(command, **payload)
        except ControlUnavailable as exc:
            raise HTTPException(status_code=503, detail=exc.detail) from exc
        except ControlError as exc:
            raise HTTPException(status_code=exc.status, detail=exc.detail) from exc

    # --------------------------------------------------------------- proyectos

    def _projects(request: Request) -> ProjectManager:
        return request.app.state.projects

    @app.get("/api/projects")
    def projects_list(request: Request) -> dict[str, Any]:
        manager = _projects(request)
        return {
            "current": manager.current,
            "projects": manager.list_projects(),
        }

    @app.get("/api/projects/current")
    def projects_current(request: Request) -> dict[str, str]:
        manager = _projects(request)
        return {
            "name": manager.current,
            "current": manager.current,
        }

    @app.post("/api/projects")
    def projects_create(
        payload: ProjectNameRequest, request: Request
    ) -> dict[str, Any]:
        manager = _projects(request)
        try:
            paths = manager.create(payload.name)
        except ProjectExistsError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ProjectError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "name": paths.name,
            "current": manager.current,
            "projects": manager.list_projects(),
        }

    @app.post("/api/projects/load")
    async def projects_load(
        payload: ProjectNameRequest, request: Request
    ) -> dict[str, Any]:
        manager = _projects(request)
        try:
            paths = manager.load(payload.name)
        except ProjectNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ProjectError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        new_store = SQLiteFlowStore(paths.db_file)
        previous_store: SQLiteFlowStore = request.app.state.sqlite
        request.app.state.sqlite = new_store
        if previous_store is not new_store:
            try:
                previous_store.close()
            except Exception:
                pass

        try:
            await request.app.state.control.request(
                "project_load", **paths.to_control_payload()
            )
        except ControlUnavailable:
            # Permite cambiar la DB de la API aunque el Proxy no esté levantado.
            pass
        except ControlError as exc:
            raise HTTPException(status_code=exc.status, detail=exc.detail) from exc

        return {
            "name": paths.name,
            "current": manager.current,
            "projects": manager.list_projects(),
        }

    @app.delete("/api/projects/{name}")
    async def projects_delete(name: str, request: Request) -> dict[str, Any]:
        manager = _projects(request)
        was_active = manager.current == name.strip()
        try:
            projects = manager.delete(name)
        except ProjectNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ProjectError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if was_active:
            fallback = manager.current_paths
            new_store = SQLiteFlowStore(fallback.db_file)
            previous_store: SQLiteFlowStore = request.app.state.sqlite
            request.app.state.sqlite = new_store
            if previous_store is not new_store:
                try:
                    previous_store.close()
                except Exception:
                    pass
            try:
                await request.app.state.control.request(
                    "project_load", **fallback.to_control_payload()
                )
            except ControlUnavailable:
                pass
            except ControlError as exc:
                raise HTTPException(
                    status_code=exc.status, detail=exc.detail
                ) from exc

        return {
            "deleted": name.strip(),
            "current": manager.current,
            "projects": projects,
        }

    # -------------------------------------------------------------- intercept

    @app.get("/api/intercept/status")
    async def intercept_status(request: Request) -> dict[str, Any]:
        return await _control_call(request, "status")

    @app.post("/api/intercept/toggle")
    async def intercept_toggle(
        payload: InterceptToggleRequest, request: Request
    ) -> dict[str, Any]:
        values: dict[str, Any] = {}
        if payload.enabled is not None:
            values["enabled"] = payload.enabled
        if payload.points is not None:
            values["points"] = payload.points
        return await _control_call(request, "toggle", **values)

    @app.get("/api/intercept/pending")
    async def intercept_pending(request: Request) -> dict[str, Any]:
        return await _control_call(request, "pending")

    @app.get("/api/intercept/pending/{breakpoint_id}")
    async def intercept_get(
        breakpoint_id: str, request: Request
    ) -> dict[str, Any]:
        return await _control_call(request, "get", id=breakpoint_id)

    @app.post("/api/intercept/pending/{breakpoint_id}/forward")
    async def intercept_forward(
        breakpoint_id: str,
        payload: InterceptForwardRequest,
        request: Request,
    ) -> dict[str, Any]:
        values: dict[str, Any] = {}
        if payload.raw_message is not None:
            values["raw_b64"] = base64.b64encode(
                payload.raw_message.encode("utf-8")
            ).decode("ascii")
        if payload.frame_payload is not None:
            values["frame_payload"] = payload.frame_payload
        return await _control_call(request, "forward", id=breakpoint_id, **values)

    @app.post("/api/intercept/pending/{breakpoint_id}/drop")
    async def intercept_drop(
        breakpoint_id: str, request: Request
    ) -> dict[str, Any]:
        return await _control_call(request, "drop", id=breakpoint_id)

    # ------------------------------------------------------------- historial

    @app.get("/api/health")
    def health(request: Request) -> dict[str, Any]:
        return {"status": "ok", "flows": _store(request).count()}

    @app.get("/api/stats")
    def dashboard_stats(request: Request) -> dict[str, int]:
        store = _store(request)
        real_flows = store.count(include_scan_flows=False)
        total_flows = store.count()
        tree = store.sitemap()
        return {
            "flows": real_flows,
            "findings": store.findings_count(),
            "routes": sum(len(paths) for paths in tree.values()),
            "scan_flows": max(0, total_flows - real_flows),
        }

    @app.get("/api/certificate")
    def download_certificate(request: Request) -> FastAPIResponse:
        target_ca_dir: Path = request.app.state.ca_dir
        cert_file = target_ca_dir / "ca.pem"
        if not cert_file.is_file():
            passphrase = os.environ.get(ENV_CA_PASSPHRASE)
            if not passphrase:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "La CA no está inicializada. Ejecuta `prox0x ca init` "
                        "o arranca prox0x con PROX0X_CA_PASSPHRASE definida."
                    ),
                )
            CertificateAuthority.init(target_ca_dir, passphrase)
        pem_bytes = cert_file.read_bytes()
        return FastAPIResponse(
            content=pem_bytes,
            media_type="application/x-pem-file",
            headers={
                "Content-Disposition": 'attachment; filename="prox0x-ca.pem"',
            },
        )

    @app.get("/api/flows")
    def list_flows(
        request: Request,
        limit: int = Query(100, ge=1, le=1_000),
        include_scan_flows: bool = False,
    ) -> dict[str, Any]:
        records = _store(request).recent_records(
            limit, include_scan_flows=include_scan_flows
        )
        return {"count": len(records), "flows": records}

    @app.get("/api/flows/{flow_id}")
    def get_flow(flow_id: int, request: Request) -> dict[str, Any]:
        record = _store(request).get_record(flow_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"no existe el flujo #{flow_id}")
        return _limit_inline_bodies(record, flow_id)

    @app.get("/api/flows/{flow_id}/download")
    def download_flow_body(
        flow_id: int,
        request: Request,
        message: Literal["request", "response"] = "response",
    ) -> FastAPIResponse:
        flow = _store(request).get_flow(flow_id)
        if flow is None:
            raise HTTPException(status_code=404, detail=f"no existe el flujo #{flow_id}")
        if message == "request":
            body_message = flow.final_request
        else:
            body_message = flow.response
        if body_message is None:
            raise HTTPException(
                status_code=404,
                detail=f"el flujo #{flow_id} no tiene {message}",
            )
        content_type = (
            body_message.header("Content-Type") or "application/octet-stream"
        )
        filename = (
            f"prox0x-flow-{flow_id}-{message}{_extension_for(content_type)}"
        )
        return FastAPIResponse(
            content=body_message.body,
            media_type=content_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )

    @app.delete("/api/flows")
    def delete_flows(request: Request) -> dict[str, int]:
        return {"deleted": _store(request).delete_all()}

    # -------------------------------------------------------------- hallazgos

    @app.get("/api/findings")
    def list_findings(
        request: Request,
        limit: int = Query(500, ge=1, le=2_000),
        severity: str | None = Query(None),
        kind: str | None = Query(None),
    ) -> dict[str, Any]:
        records = _store(request).recent_findings(
            limit, severity=severity, kind=kind
        )
        return {"count": len(records), "findings": records}

    @app.delete("/api/findings")
    def delete_findings(request: Request) -> dict[str, int]:
        return {"deleted": _store(request).delete_findings()}

    # ----------------------------------------------------------- escaneo activo

    def _launch_scan(
        request: Request,
        flows: list[Flow],
        host: str | None = None,
        intensity: str = "medium",
    ) -> dict[str, Any]:
        job = ActiveScanJob(
            id=uuid.uuid4().hex,
            flow_ids=[flow.id for flow in flows],
            host=host,
            total=len(flows),
            intensity=intensity,
        )
        jobs: dict[str, ActiveScanJob] = request.app.state.scan_jobs
        jobs[job.id] = job
        job.task = asyncio.create_task(
            _run_active_scan(job, flows, _store(request)),
            name=f"prox0x-scan-{job.id}",
        )
        return job.to_record()

    def _launch_full_scan(
        request: Request,
        url: str,
        intensity: str = "medium",
        custom_headers: tuple[tuple[str, str], ...] = (),
        max_depth: int = 3,
        max_urls: int = FULL_SCAN_MAX_CRAWL_URLS,
    ) -> dict[str, Any]:
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise HTTPException(
                status_code=400,
                detail="la URL debe ser http(s) y tener un host válido",
            )
        effective_urls, effective_depth = normalize_crawl_limits(
            max_urls, max_depth
        )
        job = ActiveScanJob(
            id=uuid.uuid4().hex,
            flow_ids=[],
            host=parsed.netloc,
            total=0,
            mode="full",
            phase="crawling",
            seed_url=url,
            intensity=intensity,
            custom_headers=custom_headers,
            max_depth=effective_depth,
            max_urls=effective_urls,
        )
        jobs: dict[str, ActiveScanJob] = request.app.state.scan_jobs
        jobs[job.id] = job
        job.task = asyncio.create_task(
            _run_full_site_scan(job, url, _store(request)),
            name=f"prox0x-fullscan-{job.id}",
        )
        return job.to_record()

    def _launch_crawl(
        request: Request,
        url: str,
        max_urls: int = FULL_SCAN_MAX_CRAWL_URLS,
        max_depth: int = 3,
    ) -> dict[str, Any]:
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise HTTPException(
                status_code=400,
                detail="la URL debe ser http(s) y tener un host válido",
            )
        effective_urls, effective_depth = normalize_crawl_limits(
            max_urls, max_depth
        )
        job = CrawlJob(
            id=uuid.uuid4().hex,
            url=url,
            host=parsed.netloc,
            max_urls=effective_urls,
            max_depth=effective_depth,
        )
        jobs: dict[str, CrawlJob] = request.app.state.crawl_jobs
        jobs[job.id] = job
        job.task = asyncio.create_task(
            _run_crawl(job, _store(request)),
            name=f"prox0x-crawl-{job.id}",
        )
        return job.to_record()

    @app.post("/api/crawl")
    async def crawl_start(
        payload: CrawlRequest, request: Request
    ) -> dict[str, Any]:
        return _launch_crawl(
            request,
            payload.url.strip(),
            min(payload.max_urls, CRAWL_MAX_URLS),
            payload.max_depth,
        )

    @app.get("/api/crawl/status")
    def crawl_latest(request: Request) -> dict[str, Any] | None:
        jobs: dict[str, CrawlJob] = request.app.state.crawl_jobs
        if not jobs:
            return None
        return jobs[next(reversed(jobs))].to_record()

    @app.get("/api/crawl/status/{crawl_id}")
    def crawl_status(crawl_id: str, request: Request) -> dict[str, Any]:
        job = request.app.state.crawl_jobs.get(crawl_id)
        if job is None:
            raise HTTPException(
                status_code=404, detail="crawler no encontrado"
            )
        return job.to_record()

    def _launch_template_scan(
        request: Request,
        payload: TemplateScanRequest,
    ) -> dict[str, Any]:
        parsed = urlsplit(payload.url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise HTTPException(
                status_code=400,
                detail="la URL debe ser http(s) y tener un host válido",
            )
        tags = [
            tag.strip().lower()
            for tag in payload.tags
            if tag and tag.strip()
        ]
        effective_urls, effective_depth = normalize_crawl_limits(
            payload.max_urls, payload.max_depth
        )
        job = TemplateScanJob(
            id=uuid.uuid4().hex,
            url=payload.url.strip(),
            tags=tags,
            max_templates=payload.max_templates,
            concurrency=payload.concurrency,
            throttle_ms=payload.throttle_ms,
            crawl=payload.crawl,
            auto_tech=payload.auto_tech,
            max_depth=effective_depth,
            max_urls=effective_urls,
            effective_tags=list(tags),
        )
        jobs: dict[str, TemplateScanJob] = (
            request.app.state.template_scan_jobs
        )
        jobs[job.id] = job
        job.task = asyncio.create_task(
            _run_template_scan(
                job,
                request.app.state.template_manager,
                _store(request),
            ),
            name=f"prox0x-templates-scan-{job.id}",
        )
        return job.to_record()

    @app.post("/api/scan/templates")
    async def template_scan_start(
        payload: TemplateScanRequest, request: Request
    ) -> dict[str, Any]:
        return _launch_template_scan(request, payload)

    @app.get("/api/scan/templates/status")
    def template_scan_latest(
        request: Request,
    ) -> dict[str, Any] | None:
        jobs: dict[str, TemplateScanJob] = (
            request.app.state.template_scan_jobs
        )
        if not jobs:
            return None
        return jobs[next(reversed(jobs))].to_record()

    @app.get("/api/scan/templates/active")
    def template_scan_active(
        request: Request,
    ) -> dict[str, Any] | None:
        """Último job de plantillas en ejecución (o ``null``)."""

        jobs: dict[str, TemplateScanJob] = (
            request.app.state.template_scan_jobs
        )
        for job in reversed(list(jobs.values())):
            if job.status == "running":
                return job.to_record()
        return None

    @app.get("/api/scan/templates/status/{scan_id}")
    def template_scan_status(
        scan_id: str, request: Request
    ) -> dict[str, Any]:
        job = request.app.state.template_scan_jobs.get(scan_id)
        if job is None:
            raise HTTPException(
                status_code=404,
                detail="escaneo de plantillas no encontrado",
            )
        return job.to_record()

    @app.post("/api/scan/templates/stop/{scan_id}")
    async def template_scan_stop(
        scan_id: str, request: Request
    ) -> dict[str, Any]:
        job = request.app.state.template_scan_jobs.get(scan_id)
        if job is None:
            raise HTTPException(
                status_code=404,
                detail="escaneo de plantillas no encontrado",
            )
        if job.status == "running":
            job.status = "failed"
            job.phase = "failed"
            job.error = "escaneo de plantillas detenido por el usuario"
            job.finished_at = datetime.now(timezone.utc)
            if job.task is not None and not job.task.done():
                job.task.cancel()
        return job.to_record()

    @app.get("/api/templates/tags")
    async def templates_tags(request: Request) -> list[str]:
        return list(await request.app.state.template_manager.tags())

    @app.get("/api/templates/info")
    async def templates_info(request: Request) -> dict[str, Any]:
        cached = request.app.state.template_info
        if cached is not None:
            return cached
        async with request.app.state.template_info_lock:
            cached = request.app.state.template_info
            if cached is None:
                cached = await _compute_template_info(request.app)
            return cached

    @app.post("/api/templates/update")
    async def templates_update(request: Request) -> dict[str, Any]:
        result: TemplateUpdateResult = await request.app.state.template_manager.update()
        request.app.state.template_info = None
        return {
            "path": str(result.path),
            "cloned": result.cloned,
            "updated": result.updated,
            "templates": result.templates,
            "duration_ms": round(result.duration_ms, 1),
            "error": result.error,
        }

    @app.post("/api/scan/full")
    async def active_scan_full(
        payload: FullSiteScanRequest, request: Request
    ) -> dict[str, Any]:
        return _launch_full_scan(
            request,
            payload.url.strip(),
            payload.intensity,
            _parse_custom_headers(payload.custom_headers),
            payload.max_depth,
            payload.max_urls,
        )

    @app.post("/api/scan/batch")
    async def active_scan_batch(
        payload: ActiveScanBatchRequest, request: Request
    ) -> dict[str, Any]:
        store = _store(request)
        host = (payload.host or "").strip() or None
        if host is not None:
            flow_ids = store.flow_ids_by_host(host, MAX_BATCH_SCAN_FLOWS)
            flows = [
                flow
                for flow_id in flow_ids
                if (flow := store.get_flow(flow_id)) is not None
            ]
        else:
            if not payload.flow_ids:
                raise HTTPException(
                    status_code=400,
                    detail="indica flow_ids o un host para escanear",
                )
            unique_ids: list[int] = []
            seen: set[int] = set()
            for flow_id in payload.flow_ids:
                if flow_id in seen:
                    continue
                seen.add(flow_id)
                unique_ids.append(flow_id)
            flows = [
                flow
                for flow_id in unique_ids[:MAX_BATCH_SCAN_FLOWS]
                if (flow := store.get_flow(flow_id)) is not None
            ]
        if not flows:
            raise HTTPException(
                status_code=404, detail="no hay flujos que escanear"
            )
        return _launch_scan(request, flows, host, payload.intensity)

    @app.post("/api/scan/{flow_id}")
    async def active_scan_start(flow_id: int, request: Request) -> dict[str, Any]:
        flow = _flow(_store(request), flow_id)
        return _launch_scan(request, [flow])

    @app.post("/api/scan/stop/{scan_id}")
    async def active_scan_stop(
        scan_id: str, request: Request
    ) -> dict[str, Any]:
        job = request.app.state.scan_jobs.get(scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail="escaneo no encontrado")
        if job.status == "running":
            job.status = "failed"
            job.phase = "failed"
            job.error = "escaneo detenido por el usuario"
            job.finished_at = datetime.now(timezone.utc)
            if job.task is not None and not job.task.done():
                job.task.cancel()
        return job.to_record()

    @app.get("/api/scan/status")
    def active_scan_latest(request: Request) -> dict[str, Any] | None:
        jobs: dict[str, ActiveScanJob] = request.app.state.scan_jobs
        if not jobs:
            return None
        return jobs[next(reversed(jobs))].to_record()

    @app.get("/api/scan/status/{scan_id}")
    def active_scan_status(scan_id: str, request: Request) -> dict[str, Any]:
        job = request.app.state.scan_jobs.get(scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail="escaneo no encontrado")
        return job.to_record()

    @app.get("/api/scan/attempts")
    def list_scan_attempts(
        request: Request,
        limit: int = Query(1_000, ge=1, le=10_000),
        scan_id: str | None = Query(None),
    ) -> dict[str, Any]:
        records = _store(request).recent_scan_attempts(
            limit, scan_id=scan_id
        )
        return {"count": len(records), "attempts": records}

    @app.delete("/api/scan/attempts")
    def delete_scan_attempts(request: Request) -> dict[str, int]:
        return {"deleted": _store(request).delete_scan_attempts()}

    @app.get("/api/scan/{scan_id}")
    def active_scan_status_legacy(
        scan_id: str, request: Request
    ) -> dict[str, Any]:
        """Alias compatible con la primera versión del escaneo individual."""
        return active_scan_status(scan_id, request)

    @app.get("/api/report")
    def export_report(request: Request) -> FastAPIResponse:
        store = _store(request)
        html = render_report(
            _projects(request).current,
            store.recent_findings(2_000),
            store.count(),
        )
        return FastAPIResponse(
            content=html,
            media_type="text/html; charset=utf-8",
            headers={
                "Content-Disposition": 'attachment; filename="reporte_prox0x.html"',
            },
        )

    # ------------------------------------------------------------ updates

    @app.get("/api/updates/check")
    async def updates_check() -> dict[str, Any]:
        return await check_for_updates(core_version)

    # ------------------------------------------------------- sesión / macros

    @app.get("/api/session")
    def session_get(request: Request) -> dict[str, Any]:
        return SessionManager(_store(request)).load_config().to_record()

    @app.post("/api/session")
    def session_set(
        payload: SessionConfigRequest, request: Request
    ) -> dict[str, Any]:
        store = _store(request)
        if payload.login_flow_id is not None:
            if store.get_flow(payload.login_flow_id) is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"no existe el flujo #{payload.login_flow_id}",
                )
        regex = payload.token_regex.strip()
        if regex:
            try:
                re.compile(regex)
            except re.error as exc:
                raise HTTPException(
                    status_code=400, detail=f"regex inválida: {exc}"
                ) from exc
        return SessionManager(store).save_config(
            payload.login_flow_id, payload.token_regex
        ).to_record()

    # ------------------------------------------------------------------- OOB

    @app.get("/api/oob")
    async def oob_status(request: Request) -> dict[str, Any]:
        return request.app.state.oob.status()

    @app.post("/api/oob/mode")
    async def oob_mode(
        payload: OOBModeRequest, request: Request
    ) -> dict[str, Any]:
        try:
            return await request.app.state.oob.set_mode(payload.mode)
        except OOBError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/oob/test")
    async def oob_test(request: Request) -> dict[str, Any]:
        try:
            return await request.app.state.oob.test_connectivity()
        except OOBError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/oob/interactions")
    def oob_interactions(
        request: Request,
        limit: int = Query(500, ge=1, le=2_000),
    ) -> dict[str, Any]:
        records = _store(request).recent_oob_interactions(limit)
        return {"count": len(records), "interactions": records}

    @app.delete("/api/oob/interactions")
    def delete_oob_interactions(request: Request) -> dict[str, int]:
        return {"deleted": _store(request).delete_oob_interactions()}

    # ----------------------------------------------------------------- búsqueda

    @app.get("/api/search")
    def search_flows(
        request: Request,
        q: str = Query(..., min_length=1, max_length=200),
        limit: int = Query(100, ge=1, le=500),
    ) -> dict[str, Any]:
        results = _store(request).search_bodies(q, limit)
        return {"query": q, "count": len(results), "results": results}

    @app.get("/api/sitemap")
    def sitemap(request: Request) -> dict[str, dict[str, dict]]:
        return _store(request).sitemap()

    # ------------------------------------------------------------------ scope

    @app.get("/api/scope")
    async def scope_get(request: Request) -> dict[str, Any]:
        return await _control_call(request, "scope_get")

    @app.post("/api/scope")
    async def scope_set(
        payload: ScopeUpdateRequest, request: Request
    ) -> dict[str, Any]:
        return await _control_call(
            request,
            "scope_set",
            include=payload.include,
            exclude=payload.exclude,
        )

    @app.post("/api/scope/add")
    async def scope_add(
        payload: ScopeAddRequest, request: Request
    ) -> dict[str, Any]:
        return await _control_call(request, "scope_add", host=payload.host)

    # ------------------------------------------------------- match & replace

    @app.get("/api/match-replace")
    async def match_replace_get(request: Request) -> dict[str, Any]:
        return await _control_call(request, "match_replace_get")

    @app.post("/api/match-replace")
    async def match_replace_set(
        payload: MatchReplaceUpdateRequest, request: Request
    ) -> dict[str, Any]:
        return await _control_call(
            request,
            "match_replace_set",
            rules=[rule.model_dump() for rule in payload.rules],
        )

    # -------------------------------------------------------------- repeater

    @app.post("/api/repeater/send")
    async def repeater_send(
        payload: RepeaterSendRequest, request: Request
    ) -> dict[str, Any]:
        store = _store(request)
        flow = _flow(store, payload.flow_id)
        http_request = _request_of(flow)
        if payload.raw_request is not None:
            try:
                http_request = parse_request(payload.raw_request.encode("utf-8"))
            except ValueError as exc:
                raise HTTPException(
                    status_code=400, detail=f"raw_request inválido: {exc}"
                ) from exc

        engine = RequestEngine(
            max_concurrency=payload.concurrency,
            auth_refresh=SessionManager(
                store,
                verify_upstream=not payload.insecure,
                timeout=payload.timeout,
            ).refresh,
        )
        repeater = Repeater(engine=engine)
        try:
            try:
                tab = repeater.create_tab(http_request, flow.service)
                for name, value in payload.set_headers.items():
                    tab = repeater.set_header(tab.id, name, value)
                if payload.body is not None:
                    tab = repeater.set_body(tab.id, payload.body.encode("utf-8"))
                for old, new in payload.replace.items():
                    tab = repeater.replace(tab.id, old, new)
            except (ValueError, KeyError) as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

            options = RequestOptions(
                verify_upstream=not payload.insecure,
                timeout_ms=payload.timeout * 1000,
                redirect=(
                    RedirectMode.ALWAYS
                    if payload.follow_redirects
                    else RedirectMode.NEVER
                ),
            )
            attempts = await repeater.send(
                tab.id,
                count=payload.count,
                options=options,
                concurrency=payload.concurrency,
                mode=payload.mode,
                delay_ms=payload.delay_ms,
            )
        finally:
            await engine.aclose()

        return {
            "flow_id": payload.flow_id,
            "tab_id": tab.id,
            "attempts": [_attempt_dict(attempt) for attempt in attempts],
        }

    # --------------------------------------------------------------- intruder

    @app.post("/api/intruder/start")
    async def intruder_start(
        payload: IntruderStartRequest, request: Request
    ) -> dict[str, Any]:
        store = _store(request)
        flow = _flow(store, payload.flow_id)
        http_request = _request_of(flow)
        if payload.raw_request is not None:
            try:
                http_request = parse_request(payload.raw_request.encode("utf-8"))
            except ValueError as exc:
                raise HTTPException(
                    status_code=400,
                    detail=f"raw_request inválido: {exc}",
                ) from exc

        mode = _mode(payload.mode)
        try:
            template = _build_template(http_request)
            template = _select_positions(template, payload.positions)
            sets = _payload_sets(payload)
            processors = _processors(payload)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        engine = RequestEngine(
            max_concurrency=payload.concurrency,
            auth_refresh=SessionManager(
                store,
                verify_upstream=not payload.insecure,
                timeout=payload.timeout,
            ).refresh,
        )
        jobs: dict[str, AttackJob] = request.app.state.attack_jobs
        background_started = False
        try:
            try:
                if payload.background:
                    attack_id = uuid.uuid4().hex
                    job = AttackJob(id=attack_id)

                    def on_result(result) -> None:
                        job.results.append(
                            _attack_result_dict(result, template)
                        )
                        job.details[result.index] = _attack_result_detail(result)

                    attack = Attack(
                        template=template,
                        service=flow.service,
                        mode=mode,
                        sets=sets,
                        engine=engine,
                        options=RequestOptions(
                            verify_upstream=not payload.insecure,
                            timeout_ms=payload.timeout * 1000,
                            throttle_ms=payload.throttle_ms,
                        ),
                        concurrency=payload.concurrency,
                        processors=processors,
                        max_requests=payload.max_requests,
                        on_result=on_result,
                    )
                else:
                    attack = Attack(
                        template=template,
                        service=flow.service,
                        mode=mode,
                        sets=sets,
                        engine=engine,
                        options=RequestOptions(
                            verify_upstream=not payload.insecure,
                            timeout_ms=payload.timeout * 1000,
                            throttle_ms=payload.throttle_ms,
                        ),
                        concurrency=payload.concurrency,
                        processors=processors,
                        max_requests=payload.max_requests,
                    )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

            if attack.expected_requests > payload.max_requests:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"el ataque generaría {attack.expected_requests} peticiones, "
                        f"superando max_requests ({payload.max_requests})"
                    ),
                )

            if payload.background:
                job.expected = attack.expected_requests
                jobs[attack_id] = job
                _prune_jobs(jobs)

                async def runner() -> None:
                    try:
                        await attack.run()
                        job.skipped = attack.skipped
                        job.status = "completed"
                    except asyncio.CancelledError:
                        job.status = "failed"
                        job.error = "ataque cancelado"
                        raise
                    except Exception as exc:
                        job.status = "failed"
                        job.error = str(exc)
                    finally:
                        job.finished_at = datetime.now(timezone.utc)
                        await engine.aclose()

                job.task = asyncio.create_task(
                    runner(), name=f"prox0x-attack-{attack_id}"
                )
                background_started = True
                return _job_dict(job)

            results = await attack.run()
        finally:
            if not background_started:
                await engine.aclose()

        return {
            "flow_id": payload.flow_id,
            "mode": mode.value,
            "expected": attack.expected_requests,
            "skipped": attack.skipped,
            "results": [
                {
                    **_attack_result_dict(result, template),
                    **_attack_result_detail(result),
                }
                for result in results
            ],
        }

    @app.get("/api/intruder/{attack_id}/results/{index}")
    async def intruder_result(
        attack_id: str, index: int, request: Request
    ) -> dict[str, Any]:
        job = request.app.state.attack_jobs.get(attack_id)
        if job is None:
            raise HTTPException(
                status_code=404,
                detail=f"no existe el ataque {attack_id}",
            )
        detail = job.details.get(index)
        if detail is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"no hay detalle para el intento {index} del ataque "
                    f"{attack_id}"
                ),
            )
        return {"attack_id": attack_id, "index": index, **detail}

    @app.get("/api/intruder/{attack_id}")
    async def intruder_job(attack_id: str, request: Request) -> dict[str, Any]:
        job = request.app.state.attack_jobs.get(attack_id)
        if job is None:
            raise HTTPException(
                status_code=404,
                detail=f"no existe el ataque {attack_id}",
            )
        return _job_dict(job)

    # -------------------------------------------------------------- websocket

    async def _accept_websocket(websocket: WebSocket) -> bool:
        origin = websocket.headers.get("origin")
        allowed = getattr(
            websocket.app.state, "allowed_ws_origins", _ALLOWED_WS_ORIGINS
        )
        if origin not in allowed:
            await websocket.close(code=1008)
            return False
        await websocket.accept()
        return True

    @app.websocket("/api/ws")
    async def flow_events(websocket: WebSocket, after: int = 0) -> None:
        if not await _accept_websocket(websocket):
            return
        store = _store(websocket)
        last = max(0, after)
        try:
            while True:
                current_store = _store(websocket)
                if current_store is not store:
                    store = current_store
                    last = 0
                records = store.recent_since(last, limit=100)
                for record in records:
                    await websocket.send_json(record)
                    last = max(last, int(record["id"]))
                await asyncio.sleep(0.2)
        except WebSocketDisconnect:
            return
        except Exception:
            return

    @app.websocket("/api/ws/findings")
    async def finding_events(websocket: WebSocket, after: int = 0) -> None:
        if not await _accept_websocket(websocket):
            return
        store = _store(websocket)
        last = max(0, after)
        try:
            while True:
                current_store = _store(websocket)
                if current_store is not store:
                    store = current_store
                    last = 0
                records = store.findings_since(last, limit=100)
                for record in records:
                    await websocket.send_json(record)
                    last = max(last, int(record["id"]))
                await asyncio.sleep(0.5)
        except WebSocketDisconnect:
            return
        except Exception:
            return

    @app.websocket("/api/ws/oob")
    async def oob_events(websocket: WebSocket, after: int = 0) -> None:
        if not await _accept_websocket(websocket):
            return
        store = _store(websocket)
        last = max(0, after)
        try:
            while True:
                current_store = _store(websocket)
                if current_store is not store:
                    store = current_store
                    last = 0
                records = store.oob_since(last, limit=100)
                for record in records:
                    await websocket.send_json(record)
                    last = max(last, int(record["id"]))
                await asyncio.sleep(0.5)
        except WebSocketDisconnect:
            return
        except Exception:
            return

    @app.websocket("/api/ws/scan")
    async def scan_events(websocket: WebSocket, after: int = 0) -> None:
        if not await _accept_websocket(websocket):
            return
        store = _store(websocket)
        last = max(0, after)
        try:
            while True:
                current_store = _store(websocket)
                if current_store is not store:
                    store = current_store
                    last = 0
                records = store.scan_attempts_since(last, limit=100)
                for record in records:
                    await websocket.send_json(record)
                    last = max(last, int(record["id"]))
                await asyncio.sleep(0.5)
        except WebSocketDisconnect:
            return
        except Exception:
            return

    @app.websocket("/api/ws/intercept")
    async def intercept_events(websocket: WebSocket) -> None:
        if not await _accept_websocket(websocket):
            return
        control = websocket.app.state.control
        try:
            async for event in control.subscribe():
                await websocket.send_json(event)
        except WebSocketDisconnect:
            return
        except ControlUnavailable as exc:
            try:
                await websocket.send_json(
                    {"type": "error", "detail": exc.detail}
                )
            except Exception:
                pass
        except Exception:
            return

    ui_dist = ui_dist_directory()
    if ui_dist is not None:
        app.mount("/", StaticFiles(directory=str(ui_dist), html=True), name="ui")

    return app


app = create_app()


# ------------------------------------------------------------------- helpers


def _mode(value: str) -> AttackMode:
    mode = _MODE_ALIASES.get(value.strip().lower())
    if mode is None:
        raise HTTPException(
            status_code=400, detail=f"modo de ataque no válido: {value!r}"
        )
    return mode


def _job_dict(job: AttackJob) -> dict[str, Any]:
    return {
        "attack_id": job.id,
        "status": job.status,
        "expected": job.expected,
        "skipped": job.skipped,
        "error": job.error,
        "results": list(job.results),
        "started_at": job.started_at.isoformat(),
        "finished_at": (
            job.finished_at.isoformat() if job.finished_at is not None else None
        ),
    }


def _prune_jobs(jobs: dict[str, AttackJob], keep: int = 50) -> None:
    finished = [job for job in jobs.values() if job.status != "running"]
    for job in finished[:-keep]:
        jobs.pop(job.id, None)


def _build_template(request: HttpRequest) -> RequestTemplate:
    raw = request.to_bytes()
    if any(marker in raw for marker in _MARKERS):
        return RequestTemplate.from_markers(request)
    return RequestTemplate.auto(request)


def _select_positions(
    template: RequestTemplate, tokens: list[str]
) -> RequestTemplate:
    if not tokens:
        return template
    indices: list[int] = []
    for token in tokens:
        token = token.strip()
        if token.isdigit():
            index = int(token) - 1
            if not 0 <= index < template.position_count:
                raise ValueError(f"posición {token} fuera de rango")
            if index not in indices:
                indices.append(index)
        else:
            matches = [
                point.index for point in template.points if point.name == token
            ]
            if not matches:
                raise ValueError(f"no existe la posición {token!r}")
            for index in matches:
                if index not in indices:
                    indices.append(index)
    return template.subset(indices)


def _payload_sets(payload: IntruderStartRequest) -> tuple[PayloadSet, ...]:
    if payload.payload_sets is not None:
        raw_sets = payload.payload_sets
    elif payload.payloads is not None:
        raw_sets = [payload.payloads]
    else:
        raise ValueError("envía payloads o payload_sets")
    if any(not items for items in raw_sets):
        raise ValueError("los sets de payloads no pueden estar vacíos")
    return tuple(
        PayloadSet.from_items(items, id=f"api-{index}")
        for index, items in enumerate(raw_sets)
    )


def _processors(payload: IntruderStartRequest) -> ProcessorChain:
    processors = []
    if payload.skip:
        skipped = {item.encode("utf-8") for item in payload.skip}
        processors.append(SkipIf(lambda value: value in skipped))
    if payload.url_encode:
        processors.append(UrlEncode())
    if payload.prefix is not None:
        processors.append(Prefix(payload.prefix.encode("utf-8")))
    if payload.suffix is not None:
        processors.append(Suffix(payload.suffix.encode("utf-8")))
    return ProcessorChain(tuple(processors))


def _attempt_dict(attempt: Attempt) -> dict[str, Any]:
    response = attempt.response
    return {
        "index": attempt.index,
        "label": attempt.label,
        "status": attempt.status.value,
        "status_code": attempt.status_code,
        "length": len(response.body) if response is not None else 0,
        "response_bytes": attempt.response_bytes,
        "ttfb_ms": attempt.ttfb_ms,
        "total_ms": attempt.total_ms,
        "latency_ms": attempt.latency_ms,
        "error": attempt.error,
        "request": message_record(attempt.request),
        "response": message_record(response),
    }


def _attack_result_dict(result, template: RequestTemplate) -> dict[str, Any]:
    combo = {
        (template.points[index].name or f"pos{index}"): value.decode(
            "utf-8", errors="replace"
        )
        for index, value in result.combo
    }
    return {
        "index": result.index,
        "combo": combo,
        "label": result.label,
        "status": result.status.value,
        "status_code": result.status_code,
        "length": result.length,
        "ttfb_ms": result.ttfb_ms,
        "total_ms": result.total_ms,
        "error": result.error,
    }


def _attack_result_detail(result) -> dict[str, Any]:
    """Petición/respuesta completas, servidas bajo demanda al abrir el modal."""
    return {
        "request": message_record(result.request),
        "response": message_record(result.response),
    }
