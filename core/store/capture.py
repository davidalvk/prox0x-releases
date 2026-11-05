"""Volcado JSONL de flujos para inspección por terminal (`prox0x flows`).

El ``FlowStore`` vive en memoria del proceso del proxy; para que un proceso
 aparte (`prox0x flows`) pueda leer el historial sin UI, el proxy añade cada
 flujo capturado como una línea JSON en ``flows.jsonl`` (append-only). Es un
 diagnóstico de F1: la persistencia real (SQLite WAL con consulta) llega en F5.

Convención de registro:

- Los bytes van en base64 (``raw``) para que el JSON sea siempre válido.
- ``final_request`` solo se serializa si el flujo fue editado (si no, es el
  request original).
- Las lecturas son tolerantes a líneas corruptas (un flush a medias no puede
  romper el volcado del proxy).
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from core.logging import get_logger
from core.model import Flow, Message, Request, Response
from core.net.content_encoding import ContentDecodingError, decode_content

_log = get_logger("prox0x.store.capture")

# Tope de cuerpo que el WebSocket/listado ligero estaría dispuesto a incluir.
# El listado actual nunca envía cuerpos: el flag solo señala que el detalle
# completo debe pedirse bajo demanda.
WS_BODY_LIMIT = 64 * 1024


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _display_raw(message: Message, decoded_body: bytes) -> bytes:
    """``raw`` alternativo para la UI: cuerpo descomprimido y sin codificación.

    Se elimina ``Content-Encoding`` (y el *framing* chunked) para que lo que ve
    el usuario sea texto plano coherente. El ``raw`` canónico del mensaje no se
    toca: el Proxy sigue reenviando los bytes originales.
    """
    stripped = message.without_header("Content-Encoding").without_header(
        "Transfer-Encoding"
    )
    return stripped.with_body(decoded_body).raw


def message_record(message: Message | None) -> dict | None:
    """Registro JSON-safe de un mensaje para la API y el JSONL.

    Incluye ``display_raw`` solo cuando el cuerpo venía comprimido y se ha
    podido descomprimir. ``raw`` conserva siempre los bytes originales.
    """
    if message is None:
        return None
    record: dict[str, object] = {"raw": _b64(message.raw)}
    if isinstance(message, Request):
        record.update(
            method=message.method,
            target=message.target,
            version=message.version,
        )
    elif isinstance(message, Response):
        record.update(
            status=message.status_code,
            reason=message.reason,
            version=message.version,
        )

    encoding = message.header("Content-Encoding")
    try:
        decoded = decode_content(message.body, encoding)
    except ContentDecodingError:
        decoded = None
    if decoded is not None:
        record["display_raw"] = _b64(_display_raw(message, decoded))
        record["content_encoding"] = encoding
    return record


def flow_to_record(flow: Flow) -> dict:
    """Convierte un ``Flow`` en un registro JSON-safe."""
    record: dict[str, object] = {
        "id": flow.id,
        "at": flow.received_at.isoformat(),
        "listener_port": flow.listener_port,
        "source_ip": flow.source_ip,
        "dest_ip": flow.dest_ip,
        "service": {
            "host": flow.service.host,
            "port": flow.service.port,
            "secure": flow.service.secure,
        },
        "request": message_record(flow.request),
        "response": message_record(flow.response),
        "edited": flow.edited,
        "modified_by_rule": flow.modified_by_rule,
        "dropped": flow.dropped,
        "drop_reason": flow.drop_reason,
        "in_scope": flow.in_scope,
        "is_scan_flow": flow.is_scan_flow,
        "status": (
            "DROPPED"
            if flow.dropped
            else (
                flow.response.status_code
                if isinstance(flow.response, Response)
                else None
            )
        ),
        "mime": flow.mime.value,
    }
    if flow.edited:
        record["final_request"] = message_record(flow.final_request)
    if flow.timing is not None:
        record["timing"] = {
            "sent_at": flow.timing.sent_at.isoformat(),
            "first_byte_at": (
                flow.timing.first_byte_at.isoformat()
                if flow.timing.first_byte_at is not None
                else None
            ),
            "completed_at": (
                flow.timing.completed_at.isoformat()
                if flow.timing.completed_at is not None
                else None
            ),
            "ttfb_ms": flow.timing.ttfb_ms,
            "total_ms": flow.timing.total_ms,
        }
    if flow.websocket_frames:
        record["websocket_frames"] = [
            {
                "direction": frame.direction.value,
                "opcode": frame.opcode,
                "name": frame.opcode_name,
                "size": frame.size,
                "at": frame.at.isoformat(),
            }
            for frame in flow.websocket_frames
        ]
    return record


def _b64_size(value: object) -> int:
    if not isinstance(value, str) or not value:
        return 0
    padding = len(value) - len(value.rstrip("="))
    return max(0, (len(value) * 3) // 4 - padding)


_MESSAGE_SUMMARY_KEYS = (
    "method",
    "target",
    "version",
    "status",
    "reason",
    "content_encoding",
)


def _message_summary(record: object, size: int) -> dict | None:
    if not isinstance(record, dict):
        return None
    summary = {
        key: record[key] for key in _MESSAGE_SUMMARY_KEYS if key in record
    }
    summary["size"] = size
    return summary


def summary_from_record(record: dict) -> dict:
    """Versión ligera para tabla y WebSocket: metadatos sin cuerpos.

    ``request``/``response`` conservan método, ruta, estado y tamaño, pero
    nunca incluyen ``raw``, ``display_raw`` ni bytes. El detalle completo se
    pide aparte con ``GET /api/flows/{id}``.
    """
    summary = {
        key: value
        for key, value in record.items()
        if key
        not in ("request", "final_request", "response", "websocket_frames")
    }
    request = record.get("request")
    response = record.get("response")
    request_size = (
        _b64_size(request.get("raw")) if isinstance(request, dict) else 0
    )
    response_size = (
        _b64_size(response.get("raw")) if isinstance(response, dict) else 0
    )
    summary["request"] = _message_summary(request, request_size) or {}
    summary["response"] = _message_summary(response, response_size)
    summary["request_size"] = request_size
    summary["response_size"] = response_size
    summary["body_truncated"] = (
        request_size > WS_BODY_LIMIT or response_size > WS_BODY_LIMIT
    )
    return summary


class FlowCapture:
    """Append-only JSONL de flujos; un fallo de disco nunca corta la red."""

    def __init__(self, path: Path) -> None:
        self._path = path

    @property
    def path(self) -> Path:
        return self._path

    def append(self, flow: Flow) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._path.parent, 0o700)
        except PermissionError:
            pass
        line = (
            json.dumps(flow_to_record(flow), ensure_ascii=True).encode("utf-8")
            + b"\n"
        )
        fd = os.open(
            self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
        )
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, line)
        finally:
            os.close(fd)


def read_records(path: Path) -> tuple[list[dict], int]:
    """Lee los registros del JSONL. Devuelve ``(registros, líneas corruptas)``."""
    if not path.is_file():
        return [], 0
    records: list[dict] = []
    malformed = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            continue
        if isinstance(record, dict):
            records.append(record)
        else:
            malformed += 1
    return records, malformed
