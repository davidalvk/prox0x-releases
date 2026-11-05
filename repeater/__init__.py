"""Repeater de prox0x: pestañas, versiones inmutables, envío y diff (F2)."""

from core.net.wire import parse_request

from .diff import DiffOp, DiffResult, DiffStats, diff_bytes, diff_responses
from .tab import Repeater, Tab, request_from_record

__all__ = [
    "DiffOp",
    "DiffResult",
    "DiffStats",
    "Repeater",
    "Tab",
    "diff_bytes",
    "diff_responses",
    "parse_request",
    "request_from_record",
]
