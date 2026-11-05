"""Intruder de prox0x: plantilla, payloads, procesadores y 4 modos (F3).

No abre sockets: usa ``core.engine`` (Plan.md §7.2).
"""

from .attack import (
    Attack,
    AttackMode,
    AttackResult,
    generate_combinations,
)
from .payloads import (
    PayloadSet,
    PayloadSourceError,
    load_payload_sets,
    load_payloads,
)
from .processors import (
    CallableProcessor,
    PayloadData,
    PayloadProcessor,
    Prefix,
    ProcessingAction,
    ProcessingResult,
    ProcessorChain,
    Replace,
    SkipIf,
    Suffix,
    UrlEncode,
    make_chain,
)
from .template import InsertionPoint, RequestTemplate

__all__ = [
    "Attack",
    "AttackMode",
    "AttackResult",
    "CallableProcessor",
    "InsertionPoint",
    "PayloadData",
    "PayloadProcessor",
    "PayloadSet",
    "PayloadSourceError",
    "Prefix",
    "ProcessingAction",
    "ProcessingResult",
    "ProcessorChain",
    "Replace",
    "RequestTemplate",
    "SkipIf",
    "Suffix",
    "UrlEncode",
    "generate_combinations",
    "load_payload_sets",
    "load_payloads",
    "make_chain",
]
