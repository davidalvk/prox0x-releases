"""Escáner activo: XSS, SQLi, command injection y path traversal.

Fase 2 añade profundidad de fuzzing:

- base de payloads con intensidad low/medium/high;
- SQLi error-based, UNION, boolean-based y time-based;
- command injection con marcadores de salida y delays;
- path traversal con bypasses de encoding;
- XSS contextual más plantillas genéricas de evasión.

La API pública ``scan_flow_active`` mantiene su firma histórica y acepta un
``ScanConfig`` opcional.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass

from core.engine import Attempt, RequestEngine, RequestOptions
from core.model import Flow, Request, Response
from core.scanner import Finding, flow_url
from core.scan.detection import (
    SQL_ERROR_SIGNATURE,
    boolean_candidate,
    command_marker,
    sql_candidate,
    sql_markers,
    time_based_candidate,
    traversal_marker,
    xss_contexts,
    xss_executable,
    xss_payloads,
)
from core.scan.payloads import (
    SQLI_PAYLOADS,
    TRAVERSAL_PAYLOADS,
    command_payloads,
    command_time_payloads,
    sqli_boolean_pairs,
    sqli_payloads,
    sqli_time_payloads,
    traversal_payloads,
    xss_templates,
)
from core.scan.points import (
    PointProbe,
    ScanConfig,
    ScanJob,
    ScanParam,
    apply_payload,
    discover_points,
    is_valid_header_value,
)

MAX_SCAN_BYTES = 1024 * 1024
MAX_RAW_BYTES = 64 * 1024
# Los hallazgos necesitan conservar la zona donde está la evidencia, que puede
# caer más allá de los primeros 64 KB de una página HTML grande.
MAX_RAW_BYTES_VULNERABLE = 512 * 1024
MAX_PARAMS = 32
MAX_REQUESTS = 240
CONCURRENCY = 5
THROTTLE_MS = 50.0

# Compatibilidad con imports privados históricos.
_SQLI_PAYLOADS = SQLI_PAYLOADS
_TRAVERSAL_PAYLOADS = TRAVERSAL_PAYLOADS
_SQL_ERRORS = tuple(SQL_ERROR_SIGNATURE.split("|"))


@dataclass(frozen=True, slots=True)
class ActiveScanAttempt:
    """Resultado detallado de un payload enviado por el escáner activo."""

    flow_id: int
    url: str
    parameter: str
    location: str
    attack: str
    payload: str
    status_code: int | None
    result: str  # vulnerable | safe | error
    evidence: str
    evidence_match: str = ""
    evidence_offset: int | None = None
    request_raw: bytes | None = None
    response_raw: bytes | None = None
    finding: Finding | None = None


def _content_type(message: Request | Response) -> str:
    return (message.header("Content-Type") or "").split(";", 1)[0].strip().lower()


def _decode(body: bytes) -> str:
    return body[:MAX_SCAN_BYTES].decode("utf-8", errors="replace")


def _request_params(
    request: Request, config: ScanConfig | None = None
) -> list[ScanParam]:
    """Compatibilidad: descubre puntos con la configuración por defecto."""

    return discover_points(request, config or ScanConfig())


def _with_payload(request: Request, param: ScanParam, payload: str) -> Request:
    """Compatibilidad: aplica un payload sobre un punto."""

    return apply_payload(request, param, payload)


def _response_html(response: Response) -> str:
    if _content_type(response) not in {"text/html", "application/xhtml+xml"}:
        return ""
    return _decode(response.body)


def _param_key(param: ScanParam) -> tuple[str, str, int, tuple[str | int, ...]]:
    return (param.location, param.name, param.index, param.json_path)


def _analyze(
    flow: Flow,
    job: ScanJob,
    probe: PointProbe,
    attempt: Attempt,
    config: ScanConfig,
) -> Finding | None:
    response = attempt.response
    if response is None:
        return None
    url = flow_url(flow)
    body = _decode(response.body)

    if job.attack == "xss":
        html = _response_html(response)
        if not html:
            return None
        if xss_executable(html, job.payload):
            return Finding(
                flow_id=flow.id,
                url=url,
                kind="active_xss",
                severity="high",
                evidence=(
                    f"{job.param.name}={job.payload} reflejado en "
                    f"contexto {job.context or 'html'} sin escapar"
                ),
            )
        return None

    if job.attack == "sqli":
        if job.technique == "time":
            if time_based_candidate(
                attempt.latency_ms,
                probe.baseline_elapsed_ms,
                threshold_ms=config.time_based_threshold_ms,
                baseline_limit_ms=config.time_based_baseline_ms,
            ):
                return Finding(
                    flow_id=flow.id,
                    url=url,
                    kind="active_sqli",
                    severity="high",
                    evidence=(
                        f"{job.param.name}={job.payload} → "
                        "Blind SQLi (Time-based): "
                        f"{attempt.latency_ms:.0f} ms "
                        f"(baseline {probe.baseline_elapsed_ms or 0:.0f} ms)"
                    ),
                )
            return None

        if job.technique.startswith("boolean"):
            # Se evalúa en pareja al terminar scan_flow_active.
            return None

        candidate, severity, matched = sql_candidate(
            body,
            probe.sql_markers,
            response.status_code,
        )
        if candidate:
            return Finding(
                flow_id=flow.id,
                url=url,
                kind="active_sqli",
                severity=severity,
                evidence=(
                    f"{job.param.name}={job.payload} → posible error SQL "
                    f"({matched})"
                ),
            )
        return None

    if job.attack == "command":
        if job.technique == "time":
            if time_based_candidate(
                attempt.latency_ms,
                probe.baseline_elapsed_ms,
                threshold_ms=config.time_based_threshold_ms,
                baseline_limit_ms=config.time_based_baseline_ms,
            ):
                return Finding(
                    flow_id=flow.id,
                    url=url,
                    kind="active_command",
                    severity="high",
                    evidence=(
                        f"{job.param.name}={job.payload} → "
                        "Blind Command Injection (Time-based): "
                        f"{attempt.latency_ms:.0f} ms "
                        f"(baseline {probe.baseline_elapsed_ms or 0:.0f} ms)"
                    ),
                )
            return None

        marker = command_marker(body, probe.response_body)
        if marker is not None:
            return Finding(
                flow_id=flow.id,
                url=url,
                kind="active_command",
                severity="high",
                evidence=(
                    f"{job.param.name}={job.payload} → salida de comando "
                    f"({marker})"
                ),
            )
        return None

    if job.attack == "traversal":
        marker = traversal_marker(body, probe.response_body)
        if marker is not None:
            return Finding(
                flow_id=flow.id,
                url=url,
                kind="active_traversal",
                severity="high",
                evidence=f"{job.param.name}={job.payload} → {marker}",
            )
    return None


def _evidence_match(
    job: ScanJob,
    probe: PointProbe,
    body: str,
    status_code: int,
) -> str:
    """Devuelve el string exacto que justifica el hallazgo, si existe."""

    if job.attack == "xss":
        return job.payload if job.payload in body else ""

    if job.attack == "sqli":
        if job.technique:
            # Time/boolean no dejan una marca textual en el cuerpo.
            return ""
        candidate, _severity, matched = sql_candidate(
            body, probe.sql_markers, status_code
        )
        if candidate and matched:
            return max(matched.split(", "), key=len)
        return ""

    if job.attack == "command":
        if job.technique == "time":
            return ""
        return command_marker(body, probe.response_body) or ""

    if job.attack == "traversal":
        return traversal_marker(body, probe.response_body) or ""

    return ""


def _evidence_offset(body: str, match: str) -> int | None:
    if not body or not match:
        return None
    position = body.find(match)
    if position < 0:
        position = body.lower().find(match.lower())
    return position if position >= 0 else None


def _raw_message(
    message: Request | Response | None,
    *,
    limit: int = MAX_RAW_BYTES,
) -> bytes | None:
    if message is None:
        return None
    try:
        raw = message.to_bytes()
    except Exception:  # noqa: BLE001 - nunca debe romper el escaneo
        raw = message.raw
    return raw[:limit]


def _evaluate_attempt(
    flow: Flow,
    job: ScanJob,
    probe: PointProbe,
    attempt: Attempt,
    config: ScanConfig,
) -> ActiveScanAttempt:
    response = attempt.response
    status_code = response.status_code if response is not None else None
    request_raw = _raw_message(attempt.request)
    response_raw = _raw_message(response)
    if not attempt.ok or response is None:
        return ActiveScanAttempt(
            flow_id=flow.id,
            url=flow_url(flow),
            parameter=job.param.name,
            location=job.param.location,
            attack=job.attack,
            payload=job.payload,
            status_code=status_code,
            result="error",
            evidence=attempt.error or attempt.status.value,
            request_raw=request_raw,
            response_raw=response_raw,
        )

    finding = _analyze(flow, job, probe, attempt, config)
    if finding is not None:
        body = _decode(response.body)
        evidence_match = _evidence_match(job, probe, body, status_code or 0)
        response_raw = _raw_message(
            response, limit=MAX_RAW_BYTES_VULNERABLE
        )
        return ActiveScanAttempt(
            flow_id=flow.id,
            url=flow_url(flow),
            parameter=job.param.name,
            location=job.param.location,
            attack=job.attack,
            payload=job.payload,
            status_code=status_code,
            result="vulnerable",
            evidence=finding.evidence,
            evidence_match=evidence_match,
            evidence_offset=_evidence_offset(body, evidence_match),
            request_raw=request_raw,
            response_raw=response_raw,
            finding=finding,
        )

    return ActiveScanAttempt(
        flow_id=flow.id,
        url=flow_url(flow),
        parameter=job.param.name,
        location=job.param.location,
        attack=job.attack,
        payload=job.payload,
        status_code=status_code,
        result="safe",
        evidence="",
        request_raw=request_raw,
        response_raw=response_raw,
    )


async def _probe_points(
    flow: Flow,
    base: Request,
    points: list[ScanParam],
    request_engine: RequestEngine,
    config: ScanConfig,
) -> list[PointProbe]:
    """Envía un canary seguro por punto y captura baseline + contextos XSS."""

    probes: list[PointProbe] = []
    canaries = [
        f"{config.canary_prefix}_{secrets.token_hex(4)}" for _ in points
    ]

    for start in range(0, len(points), config.concurrency):
        batch = points[start : start + config.concurrency]
        batch_canaries = canaries[start : start + config.concurrency]
        requests = [
            apply_payload(base, point, canary)
            for point, canary in zip(batch, batch_canaries)
        ]
        attempts = await request_engine.send_requests(
            requests,
            flow.service,
            options=RequestOptions(throttle_ms=config.throttle_ms),
            concurrency=config.concurrency,
            labels=[
                f"active:probe:{point.location}:{point.name}" for point in batch
            ],
        )
        for point, canary, attempt in zip(batch, batch_canaries, attempts):
            response = attempt.response
            if not attempt.ok or response is None:
                probes.append(
                    PointProbe(
                        param=point,
                        canary=canary,
                        response_body=None,
                        sql_markers=frozenset(),
                        xss_contexts=(),
                    )
                )
                continue
            body = _decode(response.body)
            probes.append(
                PointProbe(
                    param=point,
                    canary=canary,
                    response_body=body,
                    sql_markers=sql_markers(body),
                    xss_contexts=xss_contexts(body, canary),
                    baseline_length=len(response.body),
                    baseline_status=response.status_code,
                    baseline_elapsed_ms=attempt.latency_ms,
                )
            )
    return probes


def _payload_allowed(param: ScanParam, payload: str) -> bool:
    """Evita payloads que h11 rechazaría en una cabecera."""

    return param.location != "header" or is_valid_header_value(payload)


def _append_job(
    jobs: list[ScanJob],
    job: ScanJob,
    config: ScanConfig,
) -> bool:
    if len(jobs) >= config.max_requests:
        return False
    if not _payload_allowed(job.param, job.payload):
        return False
    jobs.append(job)
    return True


def _append_pair(
    jobs: list[ScanJob],
    true_job: ScanJob,
    false_job: ScanJob,
    config: ScanConfig,
) -> bool:
    if len(jobs) + 2 > config.max_requests:
        return False
    if not _payload_allowed(true_job.param, true_job.payload):
        return False
    if not _payload_allowed(false_job.param, false_job.payload):
        return False
    jobs.extend((true_job, false_job))
    return True


def _build_jobs(
    base: Request,
    probes: list[PointProbe],
    config: ScanConfig,
) -> list[ScanJob]:
    jobs: list[ScanJob] = []

    for probe in probes:
        # XSS: contexto detectado + plantillas genéricas según intensidad.
        for context in probe.xss_contexts:
            contextual = list(xss_payloads(context, probe.canary))
            if config.intensity == "low":
                contextual = contextual[:2]
            payloads = list(
                dict.fromkeys(
                    contextual + list(xss_templates(config.intensity, probe.canary))
                )
            )
            for payload in payloads:
                _append_job(
                    jobs,
                    ScanJob(
                        request=base,
                        param=probe.param,
                        attack="xss",
                        payload=payload,
                        context=context,
                        canary=probe.canary,
                    ),
                    config,
                )

        # SQLi: error/UNION/auth bypass, boolean-based y time-based.
        if probe.response_body is not None:
            for payload in sqli_payloads(config.intensity):
                _append_job(
                    jobs,
                    ScanJob(
                        request=base,
                        param=probe.param,
                        attack="sqli",
                        payload=payload,
                    ),
                    config,
                )

            for index, (true_payload, false_payload) in enumerate(
                sqli_boolean_pairs(config.intensity)
            ):
                pair_id = (
                    f"{probe.param.location}|{probe.param.name}|"
                    f"{probe.param.index}|{probe.param.json_path}|{index}"
                )
                _append_pair(
                    jobs,
                    ScanJob(
                        request=base,
                        param=probe.param,
                        attack="sqli",
                        payload=true_payload,
                        technique="boolean_true",
                        pair_id=pair_id,
                    ),
                    ScanJob(
                        request=base,
                        param=probe.param,
                        attack="sqli",
                        payload=false_payload,
                        technique="boolean_false",
                        pair_id=pair_id,
                    ),
                    config,
                )

            for payload in sqli_time_payloads(config.intensity):
                _append_job(
                    jobs,
                    ScanJob(
                        request=base,
                        param=probe.param,
                        attack="sqli",
                        payload=payload,
                        technique="time",
                    ),
                    config,
                )

        # Command injection: salida directa y delays.
        for payload in command_payloads(config.intensity):
            _append_job(
                jobs,
                ScanJob(
                    request=base,
                    param=probe.param,
                    attack="command",
                    payload=payload,
                ),
                config,
            )
        for payload in command_time_payloads(config.intensity):
            _append_job(
                jobs,
                ScanJob(
                    request=base,
                    param=probe.param,
                    attack="command",
                    payload=payload,
                    technique="time",
                ),
                config,
            )

        for payload in traversal_payloads(config.intensity):
            _append_job(
                jobs,
                ScanJob(
                    request=base,
                    param=probe.param,
                    attack="traversal",
                    payload=payload,
                ),
                config,
            )

    return jobs


async def scan_flow_active(
    flow: Flow,
    request_engine: RequestEngine,
    *,
    config: ScanConfig | None = None,
    on_attempt: Callable[[ActiveScanAttempt], None] | None = None,
) -> list[Finding]:
    """Escanea los puntos del flujo y devuelve hallazgos activos.

    ``on_attempt`` recibe solo los intentos de ataque (no los canaries de
    baseline), en cuanto termina su lote de concurrencia.
    """

    base = flow.final_request
    if not isinstance(base, Request):
        base = flow.request
    if not isinstance(base, Request):
        return []

    config = config or ScanConfig(
        max_params=MAX_PARAMS,
        max_requests=MAX_REQUESTS,
        concurrency=CONCURRENCY,
        throttle_ms=THROTTLE_MS,
    )

    points = discover_points(base, config)
    if not points:
        return []

    probes = await _probe_points(flow, base, points, request_engine, config)
    jobs = _build_jobs(base, probes, config)
    if not jobs:
        return []

    probe_by_key = {_param_key(probe.param): probe for probe in probes}
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    pair_state: dict[str, dict[str, tuple[ScanJob, Attempt]]] = {}

    for start in range(0, len(jobs), config.concurrency):
        chunk = jobs[start : start + config.concurrency]
        requests = [
            apply_payload(job.request, job.param, job.payload) for job in chunk
        ]
        attempts = await request_engine.send_requests(
            requests,
            flow.service,
            options=RequestOptions(throttle_ms=config.throttle_ms),
            concurrency=config.concurrency,
            labels=[
                f"active:{job.attack}:{job.param.name}" for job in chunk
            ],
        )
        for job, attempt in zip(chunk, attempts):
            probe = probe_by_key[_param_key(job.param)]
            evaluation = _evaluate_attempt(flow, job, probe, attempt, config)
            if job.technique.startswith("boolean") and job.pair_id:
                pair_state.setdefault(job.pair_id, {})[job.technique] = (
                    job,
                    attempt,
                )
            finding = evaluation.finding
            if finding is not None:
                key = (finding.kind, finding.evidence)
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)
            if on_attempt is not None:
                on_attempt(evaluation)

    # Evaluación diferida de los pares boolean-based.
    for state in pair_state.values():
        true = state.get("boolean_true")
        false = state.get("boolean_false")
        if true is None or false is None:
            continue
        true_job, true_attempt = true
        false_job, false_attempt = false
        if (
            true_attempt.response is None
            or false_attempt.response is None
            or not true_attempt.ok
            or not false_attempt.ok
        ):
            continue
        probe = probe_by_key[_param_key(true_job.param)]
        if not boolean_candidate(
            probe.baseline_length,
            probe.baseline_status,
            len(true_attempt.response.body),
            true_attempt.response.status_code,
            len(false_attempt.response.body),
            false_attempt.response.status_code,
        ):
            continue
        finding = Finding(
            flow_id=flow.id,
            url=flow_url(flow),
            kind="active_sqli",
            severity="high",
            evidence=(
                f"{true_job.param.name} → Blind SQLi (Boolean-based): "
                f"baseline={probe.baseline_length} B, "
                f"true={len(true_attempt.response.body)} B, "
                f"false={len(false_attempt.response.body)} B"
            ),
        )
        key = (finding.kind, finding.evidence)
        if key not in seen:
            seen.add(key)
            findings.append(finding)
        if on_attempt is not None:
            on_attempt(
                ActiveScanAttempt(
                    flow_id=flow.id,
                    url=flow_url(flow),
                    parameter=true_job.param.name,
                    location=true_job.param.location,
                    attack="sqli",
                    payload=f"{true_job.payload} / {false_job.payload}",
                    status_code=true_attempt.response.status_code,
                    result="vulnerable",
                    evidence=finding.evidence,
                    request_raw=_raw_message(true_attempt.request),
                    response_raw=_raw_message(
                        true_attempt.response,
                        limit=MAX_RAW_BYTES_VULNERABLE,
                    ),
                    finding=finding,
                )
            )
    return findings
