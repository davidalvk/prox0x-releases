"""Persistencia de flujos en SQLite WAL (F5.1).

La API y la UI leen de aquí; el Proxy escribe cada ``Flow`` (y las
actualizaciones de frames WebSocket). El JSONL de F1 sigue existiendo como
diagnóstico rápido, pero SQLite es la fuente consultable.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sqlite3
import threading
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from core.model import (
    Flow,
    HttpService,
    MimeType,
    Request,
    Response,
    Timing,
    WebSocketDirection,
    WebSocketFrame,
)
from core.net.wire import parse_request, parse_response
from core.scanner import Finding
from core.scope import Scope

from .capture import flow_to_record, summary_from_record

_SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY,
    received_at TEXT NOT NULL,
    method TEXT,
    target TEXT,
    host TEXT,
    port INTEGER,
    secure INTEGER NOT NULL DEFAULT 0,
    status INTEGER,
    mime TEXT,
    request_raw BLOB NOT NULL,
    final_request_raw BLOB NOT NULL,
    response_raw BLOB,
    websocket_frames TEXT,
    dropped INTEGER NOT NULL DEFAULT 0,
    drop_reason TEXT,
    in_scope INTEGER NOT NULL DEFAULT 1,
    modified_by_rule INTEGER NOT NULL DEFAULT 0,
    is_scan_flow INTEGER NOT NULL DEFAULT 0,
    summary TEXT NOT NULL DEFAULT '{}',
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flows_received ON flows(received_at);
CREATE INDEX IF NOT EXISTS idx_flows_status ON flows(status);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    evidence TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_flow ON findings(flow_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_kind ON findings(kind);
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_unique
    ON findings(flow_id, kind, evidence);
CREATE TABLE IF NOT EXISTS scan_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    flow_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    parameter TEXT NOT NULL,
    location TEXT NOT NULL DEFAULT '',
    attack TEXT NOT NULL,
    payload TEXT NOT NULL,
    status_code INTEGER,
    result TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '',
    evidence_match TEXT NOT NULL DEFAULT '',
    evidence_offset INTEGER,
    request_raw BLOB,
    response_raw BLOB,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_attempts_scan ON scan_attempts(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_attempts_flow ON scan_attempts(flow_id);
CREATE INDEX IF NOT EXISTS idx_scan_attempts_result ON scan_attempts(result);
CREATE TABLE IF NOT EXISTS crawl_routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crawl_id TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL,
    method TEXT NOT NULL,
    target TEXT NOT NULL,
    path TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_crawl_routes_unique
    ON crawl_routes(host, method, target);
CREATE INDEX IF NOT EXISTS idx_crawl_routes_host_path
    ON crawl_routes(host, path);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS oob_interactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mode TEXT NOT NULL,
    protocol TEXT NOT NULL,
    unique_id TEXT NOT NULL DEFAULT '',
    full_id TEXT NOT NULL DEFAULT '',
    remote_address TEXT NOT NULL DEFAULT '',
    raw_request TEXT,
    raw_response TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oob_created ON oob_interactions(created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_oob_unique
    ON oob_interactions(mode, full_id, protocol, created_at);
"""


class SQLiteFlowStore:
    """Store SQLite thread-safe con WAL para lecturas concurrentes."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path.parent, 0o700)
        except PermissionError:
            pass
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(path), check_same_thread=False, timeout=5.0
        )
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(_SCHEMA)
            columns = {
                row["name"]
                for row in self._conn.execute("PRAGMA table_info(flows)")
            }
            added_scan_flag = "is_scan_flow" not in columns
            if "dropped" not in columns:
                self._conn.execute(
                    "ALTER TABLE flows ADD COLUMN dropped INTEGER NOT NULL DEFAULT 0"
                )
            if "drop_reason" not in columns:
                self._conn.execute(
                    "ALTER TABLE flows ADD COLUMN drop_reason TEXT"
                )
            if "in_scope" not in columns:
                self._conn.execute(
                    "ALTER TABLE flows ADD COLUMN in_scope INTEGER NOT NULL DEFAULT 1"
                )
            if "modified_by_rule" not in columns:
                self._conn.execute(
                    "ALTER TABLE flows ADD COLUMN "
                    "modified_by_rule INTEGER NOT NULL DEFAULT 0"
                )
            if "is_scan_flow" not in columns:
                self._conn.execute(
                    "ALTER TABLE flows ADD COLUMN "
                    "is_scan_flow INTEGER NOT NULL DEFAULT 0"
                )
            if "summary" not in columns:
                self._conn.execute(
                    "ALTER TABLE flows ADD COLUMN "
                    "summary TEXT NOT NULL DEFAULT '{}'"
                )
            scan_columns = {
                row["name"]
                for row in self._conn.execute(
                    "PRAGMA table_info(scan_attempts)"
                )
            }
            if "request_raw" not in scan_columns:
                self._conn.execute(
                    "ALTER TABLE scan_attempts ADD COLUMN request_raw BLOB"
                )
            if "response_raw" not in scan_columns:
                self._conn.execute(
                    "ALTER TABLE scan_attempts ADD COLUMN response_raw BLOB"
                )
            if "evidence_match" not in scan_columns:
                self._conn.execute(
                    "ALTER TABLE scan_attempts ADD COLUMN "
                    "evidence_match TEXT NOT NULL DEFAULT ''"
                )
            if "evidence_offset" not in scan_columns:
                self._conn.execute(
                    "ALTER TABLE scan_attempts ADD COLUMN evidence_offset INTEGER"
                )
        if added_scan_flag:
            self._backfill_scan_flows()
        self._backfill_summaries()

    def _backfill_scan_flows(self) -> None:
        """Marca como sintéticos los flujos antiguos creados por el escáner.

        Los flujos reales del Proxy siempre llevan IP de origen y destino; los
        sintéticos del Full Site Scan se guardaban sin ambas. La migración se
        ejecuta una sola vez, al añadir la columna ``is_scan_flow``.
        """

        with self._lock:
            rows = self._conn.execute(
                "SELECT id, payload FROM flows WHERE is_scan_flow = 0"
            ).fetchall()
        updates: list[tuple[int]] = []
        for row in rows:
            try:
                payload = json.loads(row["payload"])
            except (TypeError, json.JSONDecodeError):
                continue
            if not payload.get("source_ip") and not payload.get("dest_ip"):
                updates.append((int(row["id"]),))
        if updates:
            with self._lock, self._conn:
                self._conn.executemany(
                    "UPDATE flows SET is_scan_flow = 1 WHERE id = ?", updates
                )

    def _backfill_summaries(self) -> None:
        """Rellena resúmenes de bases creadas antes de existir la columna."""
        with self._lock:
            cursor = self._conn.execute(
                "SELECT id, payload FROM flows "
                "WHERE summary IS NULL OR summary = '{}'"
            )
            while True:
                rows = cursor.fetchmany(100)
                if not rows:
                    break
                updates: list[tuple[str, int]] = []
                for row in rows:
                    try:
                        payload = json.loads(row["payload"])
                    except (TypeError, json.JSONDecodeError):
                        continue
                    if not isinstance(payload, dict):
                        continue
                    updates.append(
                        (
                            json.dumps(
                                summary_from_record(payload), ensure_ascii=True
                            ),
                            int(row["id"]),
                        )
                    )
                if updates:
                    with self._conn:
                        self._conn.executemany(
                            "UPDATE flows SET summary = ? WHERE id = ?",
                            updates,
                        )

    # ------------------------------------------------------------------ escritura

    def save(self, flow: Flow) -> Flow:
        record = flow_to_record(flow)
        try:
            summary = summary_from_record(record)
        except Exception:
            # El resumen es una optimización: jamás debe impedir guardar el
            # flujo completo (el detalle sigue disponible vía GET /flows/{id}).
            summary = {
                key: value
                for key, value in record.items()
                if key
                not in ("request", "final_request", "response", "websocket_frames")
            }
            summary.update(
                request={},
                response=None,
                request_size=0,
                response_size=0,
                body_truncated=False,
            )
        request = flow.request if isinstance(flow.request, Request) else None
        final = (
            flow.final_request
            if isinstance(flow.final_request, Request)
            else request
        )
        response = flow.response if isinstance(flow.response, Response) else None
        frames = json.dumps(
            [
                {
                    "direction": frame.direction.value,
                    "opcode": frame.opcode,
                    "size": frame.size,
                    "at": frame.at.isoformat(),
                }
                for frame in flow.websocket_frames
            ],
            ensure_ascii=True,
        )
        values = (
            flow.id,
            flow.received_at.isoformat(),
            request.method if request is not None else None,
            request.target if request is not None else None,
            flow.service.host,
            flow.service.port,
            1 if flow.service.secure else 0,
            response.status_code if response is not None else None,
            flow.mime.value,
            flow.request.raw,
            final.raw if final is not None else flow.request.raw,
            response.raw if response is not None else None,
            frames if flow.websocket_frames else None,
            1 if flow.dropped else 0,
            flow.drop_reason,
            1 if flow.in_scope else 0,
            1 if flow.modified_by_rule else 0,
            1 if flow.is_scan_flow else 0,
            json.dumps(summary, ensure_ascii=True, default=str),
            json.dumps(record, ensure_ascii=True),
        )
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO flows (
                    id, received_at, method, target, host, port, secure,
                    status, mime, request_raw, final_request_raw,
                    response_raw, websocket_frames, dropped, drop_reason,
                    in_scope, modified_by_rule, is_scan_flow, summary, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    received_at=excluded.received_at,
                    method=excluded.method,
                    target=excluded.target,
                    host=excluded.host,
                    port=excluded.port,
                    secure=excluded.secure,
                    status=excluded.status,
                    mime=excluded.mime,
                    request_raw=excluded.request_raw,
                    final_request_raw=excluded.final_request_raw,
                    response_raw=excluded.response_raw,
                    websocket_frames=excluded.websocket_frames,
                    dropped=excluded.dropped,
                    drop_reason=excluded.drop_reason,
                    in_scope=excluded.in_scope,
                    modified_by_rule=excluded.modified_by_rule,
                    is_scan_flow=excluded.is_scan_flow,
                    summary=excluded.summary,
                    payload=excluded.payload
                """,
                values,
            )
        return flow

    def delete_all(self) -> int:
        with self._lock, self._conn:
            cursor = self._conn.execute("DELETE FROM flows")
            return cursor.rowcount

    # ------------------------------------------------------------------ hallazgos

    def add_findings(self, findings: Sequence[Finding]) -> list[dict]:
        """Persiste hallazgos deduplicados y devuelve los insertados."""
        records: list[dict] = []
        with self._lock, self._conn:
            for finding in findings:
                cursor = self._conn.execute(
                    """
                    INSERT OR IGNORE INTO findings (
                        flow_id, url, kind, severity, evidence, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding.flow_id,
                        finding.url,
                        finding.kind,
                        finding.severity,
                        finding.evidence,
                        finding.at.isoformat(),
                    ),
                )
                if cursor.rowcount == 0:
                    continue
                records.append(
                    {
                        "id": int(cursor.lastrowid),
                        "flow_id": finding.flow_id,
                        "url": finding.url,
                        "kind": finding.kind,
                        "severity": finding.severity,
                        "evidence": finding.evidence,
                        "at": finding.at.isoformat(),
                    }
                )
        return records

    def recent_findings(
        self,
        limit: int = 500,
        *,
        severity: str | None = None,
        kind: str | None = None,
    ) -> list[dict]:
        clauses: list[str] = []
        params: list[object] = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM findings {where} ORDER BY id DESC LIMIT ?",
                (*params, max(1, limit)),
            ).fetchall()
        return [_finding_record(row) for row in rows]

    def findings_since(self, after_id: int = 0, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE id > ? ORDER BY id ASC LIMIT ?",
                (max(0, after_id), max(1, limit)),
            ).fetchall()
        return [_finding_record(row) for row in rows]

    def delete_findings(self) -> int:
        with self._lock, self._conn:
            cursor = self._conn.execute("DELETE FROM findings")
            return cursor.rowcount

    # -------------------------------------------------------- escaneo activo

    def add_scan_attempts(self, attempts: Sequence[dict]) -> list[dict]:
        """Persiste intentos del escáner activo y devuelve los insertados."""
        records: list[dict] = []
        with self._lock, self._conn:
            for item in attempts:
                cursor = self._conn.execute(
                    """
                    INSERT INTO scan_attempts (
                        scan_id, flow_id, url, parameter, location, attack,
                        payload, status_code, result, evidence, evidence_match,
                        evidence_offset, request_raw, response_raw, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(item.get("scan_id", "")),
                        int(item.get("flow_id", 0)),
                        str(item.get("url", "")),
                        str(item.get("parameter", "")),
                        str(item.get("location", "")),
                        str(item.get("attack", "")),
                        str(item.get("payload", "")),
                        item.get("status_code"),
                        str(item.get("result", "error")),
                        str(item.get("evidence", "")),
                        str(item.get("evidence_match", "")),
                        item.get("evidence_offset"),
                        item.get("request_raw"),
                        item.get("response_raw"),
                        str(item.get("created_at", "")),
                    ),
                )
                records.append(
                    {
                        "id": int(cursor.lastrowid),
                        "scan_id": str(item.get("scan_id", "")),
                        "flow_id": int(item.get("flow_id", 0)),
                        "url": str(item.get("url", "")),
                        "parameter": str(item.get("parameter", "")),
                        "location": str(item.get("location", "")),
                        "attack": str(item.get("attack", "")),
                        "payload": str(item.get("payload", "")),
                        "status_code": item.get("status_code"),
                        "result": str(item.get("result", "error")),
                        "evidence": str(item.get("evidence", "")),
                        "evidence_match": str(item.get("evidence_match", "")),
                        "evidence_offset": item.get("evidence_offset"),
                        "request_raw": item.get("request_raw"),
                        "response_raw": item.get("response_raw"),
                        "created_at": str(item.get("created_at", "")),
                    }
                )
        return records

    def recent_scan_attempts(
        self, limit: int = 1_000, *, scan_id: str | None = None
    ) -> list[dict]:
        clauses = ""
        params: list[object] = []
        if scan_id:
            clauses = "WHERE scan_id = ?"
            params.append(scan_id)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM scan_attempts {clauses} "
                "ORDER BY id DESC LIMIT ?",
                (*params, max(1, limit)),
            ).fetchall()
        return [_scan_attempt_record(row) for row in rows]

    def scan_attempts_since(
        self, after_id: int = 0, limit: int = 100
    ) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scan_attempts WHERE id > ? "
                "ORDER BY id ASC LIMIT ?",
                (max(0, after_id), max(1, limit)),
            ).fetchall()
        return [_scan_attempt_record(row) for row in rows]

    def delete_scan_attempts(self) -> int:
        with self._lock, self._conn:
            cursor = self._conn.execute("DELETE FROM scan_attempts")
            return cursor.rowcount

    def save_crawl_routes(
        self, crawl_id: str, routes: Sequence[dict[str, str]]
    ) -> int:
        """Persiste rutas descubiertas por un crawler independiente.

        Se guardan en una tabla propia para que no ensucien el historial de
        flujos/interceptación. ``sitemap()`` las mezcla con los flujos reales.
        """

        now = datetime.now(timezone.utc).isoformat()
        inserted = 0
        with self._lock, self._conn:
            for route in routes:
                host = str(route.get("host") or "").strip()
                method = str(route.get("method") or "GET").strip().upper()
                target = str(route.get("target") or "").strip()
                if not host or not target:
                    continue
                path = urlsplit(target).path or "/"
                cursor = self._conn.execute(
                    """
                    INSERT OR IGNORE INTO crawl_routes (
                        crawl_id, host, method, target, path, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (crawl_id, host, method or "GET", target, path, now),
                )
                inserted += max(0, cursor.rowcount)
        return inserted

    def flow_ids_by_host(
        self,
        host: str,
        limit: int = 200,
        *,
        include_scan_flows: bool = False,
    ) -> list[int]:
        """IDs de flujos no descartados del host indicado (más recientes)."""
        clause = "" if include_scan_flows else "AND is_scan_flow = 0"
        with self._lock:
            rows = self._conn.execute(
                "SELECT id FROM flows WHERE host = ? AND dropped = 0 "
                f"{clause} ORDER BY id DESC LIMIT ?",
                (host, max(1, limit)),
            ).fetchall()
        return [int(row["id"]) for row in rows]

    # ---------------------------------------------------------------- ajustes

    def get_setting(self, key: str, default: str | None = None) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()
        return str(row["value"]) if row is not None else default

    def set_setting(self, key: str, value: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )

    def delete_setting(self, key: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM settings WHERE key = ?", (key,))

    # -------------------------------------------------------------------- OOB

    def add_oob_interactions(
        self, interactions: Sequence[dict]
    ) -> list[dict]:
        inserted: list[dict] = []
        with self._lock, self._conn:
            for item in interactions:
                cursor = self._conn.execute(
                    """
                    INSERT OR IGNORE INTO oob_interactions (
                        mode, protocol, unique_id, full_id, remote_address,
                        raw_request, raw_response, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(item.get("mode", "local")),
                        str(item.get("protocol", "")),
                        str(item.get("unique_id", "")),
                        str(item.get("full_id", "")),
                        str(item.get("remote_address", "")),
                        item.get("raw_request"),
                        item.get("raw_response"),
                        str(item.get("created_at", "")),
                    ),
                )
                if cursor.rowcount == 0:
                    continue
                inserted.append(
                    {
                        "id": int(cursor.lastrowid),
                        "mode": str(item.get("mode", "local")),
                        "protocol": str(item.get("protocol", "")),
                        "unique_id": str(item.get("unique_id", "")),
                        "full_id": str(item.get("full_id", "")),
                        "remote_address": str(item.get("remote_address", "")),
                        "raw_request": item.get("raw_request"),
                        "raw_response": item.get("raw_response"),
                        "created_at": str(item.get("created_at", "")),
                    }
                )
        return inserted

    def recent_oob_interactions(self, limit: int = 500) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM oob_interactions ORDER BY id DESC LIMIT ?",
                (max(1, limit),),
            ).fetchall()
        return [_oob_record(row) for row in rows]

    def oob_since(self, after_id: int = 0, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM oob_interactions WHERE id > ? "
                "ORDER BY id ASC LIMIT ?",
                (max(0, after_id), max(1, limit)),
            ).fetchall()
        return [_oob_record(row) for row in rows]

    def delete_oob_interactions(self) -> int:
        with self._lock, self._conn:
            cursor = self._conn.execute("DELETE FROM oob_interactions")
            return cursor.rowcount

    # ----------------------------------------------------------------- búsqueda

    def search_bodies(self, query: str, limit: int = 100) -> list[dict]:
        """Busca texto (sin distinguir mayúsculas) en cuerpos de petición/respuesta."""
        needle = query.strip()
        if not needle:
            return []
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, received_at, method, target, host, port, secure,
                       status, final_request_raw, response_raw
                FROM flows
                WHERE instr(lower(CAST(final_request_raw AS TEXT)), lower(?)) > 0
                   OR instr(lower(CAST(response_raw AS TEXT)), lower(?)) > 0
                ORDER BY id DESC
                LIMIT ?
                """,
                (needle, needle, max(1, limit)),
            ).fetchall()

        results: list[dict] = []
        for row in rows:
            for location, raw in (
                ("request", row["final_request_raw"]),
                ("response", row["response_raw"]),
            ):
                snippet = _snippet(_raw_body(raw), needle)
                if snippet is None:
                    continue
                results.append(
                    {
                        "flow_id": int(row["id"]),
                        "url": _row_url(row),
                        "at": str(row["received_at"]),
                        "method": row["method"],
                        "status": row["status"],
                        "location": location,
                        "snippet": snippet,
                    }
                )
                if len(results) >= limit:
                    return results
        return results

    # ------------------------------------------------------------------- lectura

    def count(self, *, include_scan_flows: bool = True) -> int:
        clause = "" if include_scan_flows else " WHERE is_scan_flow = 0"
        with self._lock:
            row = self._conn.execute(
                f"SELECT COUNT(*) AS total FROM flows{clause}"
            ).fetchone()
            return int(row["total"]) if row is not None else 0

    def findings_count(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS total FROM findings"
            ).fetchone()
            return int(row["total"]) if row is not None else 0

    def max_id(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(MAX(id), 0) AS max_id FROM flows"
            ).fetchone()
            return int(row["max_id"]) if row is not None else 0

    def get_record(self, flow_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload, in_scope, modified_by_rule, is_scan_flow "
                "FROM flows WHERE id = ?",
                (flow_id,),
            ).fetchone()
        if row is None:
            return None
        return _payload_record(row)

    def get_flow(self, flow_id: int) -> Flow | None:
        record = self.get_record(flow_id)
        return _flow_from_record(record) if record is not None else None

    def recent_records(
        self, limit: int = 100, *, include_scan_flows: bool = False
    ) -> list[dict]:
        if limit < 1:
            return []
        clause = "" if include_scan_flows else "WHERE is_scan_flow = 0"
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, summary, in_scope, modified_by_rule, is_scan_flow "
                f"FROM flows {clause} ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return self._summary_records(rows)

    def recent_since(
        self,
        after_id: int = 0,
        limit: int = 100,
        *,
        include_scan_flows: bool = False,
    ) -> list[dict]:
        """Flujos con id > ``after_id``, del más antiguo al más reciente."""
        if limit < 1:
            return []
        clause = "" if include_scan_flows else "AND is_scan_flow = 0"
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, summary, in_scope, modified_by_rule, is_scan_flow "
                f"FROM flows WHERE id > ? {clause} ORDER BY id ASC LIMIT ?",
                (after_id, limit),
            ).fetchall()
        return self._summary_records(rows)

    def _summary_records(self, rows: Sequence[sqlite3.Row]) -> list[dict]:
        records: list[dict] = []
        for row in rows:
            record = _summary_record(row)
            if record is None:
                # Fila antigua o resumen corrupto: se reconstruye una vez y se
                # devuelve también sin cuerpos.
                full = self.get_record(int(row["id"]))
                if full is None:
                    continue
                record = summary_from_record(full)
            records.append(record)
        return records

    def update_scope(self, include: Sequence[str], exclude: Sequence[str]) -> int:
        """Recalcula ``in_scope`` para todos los flujos con las reglas nuevas.

        Se ejecuta fuera del event loop (``asyncio.to_thread``) y con una copia
        local de las reglas para no compartir la caché del ``Scope`` del Proxy.
        Solo actualiza la columna ``in_scope``; las lecturas superponen ese
        valor al JSON del payload, evitando reescribir blobs grandes.
        """
        local_scope = Scope(include=include, exclude=exclude)
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, host, port, secure, target, in_scope FROM flows"
            ).fetchall()

        updates: list[tuple[int, int]] = []
        for row in rows:
            host = str(row["host"] or "")
            if not host:
                continue
            secure = bool(row["secure"])
            port = int(row["port"] or (443 if secure else 80))
            try:
                service = HttpService(host=host, port=port, secure=secure)
                in_scope = local_scope.matches(
                    service, str(row["target"] or "/")
                )
            except ValueError:
                continue
            if bool(row["in_scope"]) != in_scope:
                updates.append((1 if in_scope else 0, int(row["id"])))

        if updates:
            with self._lock, self._conn:
                self._conn.executemany(
                    "UPDATE flows SET in_scope = ? WHERE id = ?", updates
                )
        return len(updates)

    def sitemap(self) -> dict[str, dict[str, dict]]:
        """Árbol host → path → {methods, count} sin query string.

        Los flujos descartados no llegaron al origen y no forman parte del mapa
        de endpoints descubiertos.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT host, method, target FROM flows WHERE dropped = 0 ORDER BY id ASC"
            ).fetchall()
            crawl_rows = self._conn.execute(
                "SELECT host, method, target, path FROM crawl_routes ORDER BY id ASC"
            ).fetchall()

        tree: dict[str, dict[str, dict]] = {}
        for row in rows:
            host = str(row["host"] or "")
            method = str(row["method"] or "")
            target = str(row["target"] or "/")
            path = urlsplit(target).path or "/"
            if not host:
                continue
            paths = tree.setdefault(host, {})
            entry = paths.setdefault(path, {"methods": [], "count": 0})
            entry["count"] = int(entry.get("count", 0)) + 1
            methods = set(entry.get("methods") or [])
            if method:
                methods.add(method)
            entry["methods"] = sorted(methods)

        for row in crawl_rows:
            host = str(row["host"] or "")
            method = str(row["method"] or "")
            path = str(row["path"] or "/")
            if not host:
                continue
            paths = tree.setdefault(host, {})
            entry = paths.setdefault(path, {"methods": [], "count": 0})
            entry["count"] = int(entry.get("count", 0)) + 1
            methods = set(entry.get("methods") or [])
            if method:
                methods.add(method)
            entry["methods"] = sorted(methods)
        return tree

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _raw_body(raw: bytes | None) -> bytes:
    if not raw:
        return b""
    for separator in (b"\r\n\r\n", b"\n\n"):
        index = raw.find(separator)
        if index >= 0:
            return raw[index + len(separator) :]
    return raw


def _snippet(body: bytes, needle: str) -> str | None:
    text = body.decode("utf-8", errors="replace")
    index = text.lower().find(needle.lower())
    if index < 0:
        return None
    start = max(0, index - 80)
    end = min(len(text), index + len(needle) + 120)
    snippet = re.sub(r"\s+", " ", text[start:end]).strip()
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{snippet}{suffix}"


def _row_url(row: sqlite3.Row) -> str:
    target = str(row["target"] or "/")
    if target.startswith(("http://", "https://", "ws://", "wss://")):
        return target
    secure = bool(row["secure"])
    scheme = "https" if secure else "http"
    host = str(row["host"] or "")
    port = int(row["port"] or (443 if secure else 80))
    default_port = 443 if secure else 80
    authority = host if port == default_port else f"{host}:{port}"
    path = target if target.startswith("/") else f"/{target}"
    return f"{scheme}://{authority}{path}"


def _finding_record(row: sqlite3.Row) -> dict:
    return {
        "id": int(row["id"]),
        "flow_id": int(row["flow_id"]),
        "url": str(row["url"]),
        "kind": str(row["kind"]),
        "severity": str(row["severity"]),
        "evidence": str(row["evidence"]),
        "at": str(row["created_at"]),
    }


def _oob_record(row: sqlite3.Row) -> dict:
    return {
        "id": int(row["id"]),
        "mode": str(row["mode"]),
        "protocol": str(row["protocol"]),
        "unique_id": str(row["unique_id"]),
        "full_id": str(row["full_id"]),
        "remote_address": str(row["remote_address"]),
        "raw_request": row["raw_request"],
        "raw_response": row["raw_response"],
        "created_at": str(row["created_at"]),
    }


def _raw_blob_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("latin-1", errors="replace")
    text = str(value)
    return text or None


def _scan_attempt_record(row: sqlite3.Row) -> dict:
    return {
        "id": int(row["id"]),
        "scan_id": str(row["scan_id"]),
        "flow_id": int(row["flow_id"]),
        "url": str(row["url"]),
        "parameter": str(row["parameter"]),
        "location": str(row["location"]),
        "attack": str(row["attack"]),
        "payload": str(row["payload"]),
        "status_code": row["status_code"],
        "result": str(row["result"]),
        "evidence": str(row["evidence"]),
        "evidence_match": str(row["evidence_match"] or ""),
        "evidence_offset": row["evidence_offset"],
        "request_raw": _raw_blob_text(row["request_raw"]),
        "response_raw": _raw_blob_text(row["response_raw"]),
        "created_at": str(row["created_at"]),
    }


def _summary_record(row: sqlite3.Row) -> dict | None:
    """Resumen ligero con flags canónicos; nunca contiene cuerpos."""
    try:
        record = json.loads(row["summary"])
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(record, dict) or "id" not in record:
        return None
    record["in_scope"] = bool(row["in_scope"])
    record["modified_by_rule"] = bool(row["modified_by_rule"])
    record["is_scan_flow"] = bool(row["is_scan_flow"])
    return record


def _payload_record(row: sqlite3.Row) -> dict:
    """Payload JSON con los flags canónicos de las columnas SQLite."""
    record = json.loads(row["payload"])
    record["in_scope"] = bool(row["in_scope"])
    record["modified_by_rule"] = bool(row["modified_by_rule"])
    record["is_scan_flow"] = bool(row["is_scan_flow"])
    return record


def _flow_from_record(record: dict) -> Flow:
    request = parse_request(base64.b64decode(str(record["request"]["raw"])))
    final_record = record.get("final_request") or record["request"]
    final_request = parse_request(base64.b64decode(str(final_record["raw"])))
    response_record = record.get("response")
    response = (
        parse_response(base64.b64decode(str(response_record["raw"])))
        if response_record
        else None
    )

    service_data = record.get("service") or {}
    service = HttpService(
        host=str(service_data["host"]),
        port=int(service_data["port"]),
        secure=bool(service_data["secure"]),
    )

    timing = None
    timing_data = record.get("timing")
    if timing_data:
        timing = Timing(
            sent_at=datetime.fromisoformat(timing_data["sent_at"]),
            first_byte_at=(
                datetime.fromisoformat(timing_data["first_byte_at"])
                if timing_data.get("first_byte_at")
                else None
            ),
            completed_at=(
                datetime.fromisoformat(timing_data["completed_at"])
                if timing_data.get("completed_at")
                else None
            ),
        )

    frames = tuple(
        WebSocketFrame(
            direction=WebSocketDirection(frame["direction"]),
            opcode=int(frame["opcode"]),
            size=int(frame["size"]),
            at=datetime.fromisoformat(frame["at"]),
        )
        for frame in record.get("websocket_frames") or []
    )

    return Flow(
        id=int(record["id"]),
        service=service,
        listener_port=int(record.get("listener_port") or 0) or 1,
        received_at=datetime.fromisoformat(record["at"]),
        request=request,
        final_request=final_request,
        response=response,
        original_response=response,
        edited=bool(record.get("edited")),
        modified_by_rule=bool(record.get("modified_by_rule", False)),
        mime=MimeType(record.get("mime") or ""),
        timing=timing,
        source_ip=str(record.get("source_ip") or ""),
        dest_ip=str(record.get("dest_ip") or ""),
        websocket_frames=frames,
        dropped=bool(record.get("dropped", False)),
        drop_reason=record.get("drop_reason"),
        in_scope=bool(record.get("in_scope", True)),
        is_scan_flow=bool(record.get("is_scan_flow", False)),
    )
