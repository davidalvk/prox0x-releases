"""Macro de login y renovación de sesión para Repeater/Intruder."""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from typing import Protocol

from core.engine import RequestOptions, send_once
from core.logging import get_logger
from core.model import Flow, Request, Response

SESSION_KEY = "session_macro"
DEFAULT_TOKEN_REGEX = (
    r"(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"
)
_MAX_SCAN = 2 * 1024 * 1024

_log = get_logger("prox0x.session")


class SessionStore(Protocol):
    def get_setting(self, key: str, default: str | None = None) -> str | None: ...

    def set_setting(self, key: str, value: str) -> None: ...

    def get_flow(self, flow_id: int) -> Flow | None: ...


@dataclass(frozen=True, slots=True)
class SessionConfig:
    login_flow_id: int | None = None
    token_regex: str = DEFAULT_TOKEN_REGEX

    def to_record(self) -> dict:
        return {
            "login_flow_id": self.login_flow_id,
            "token_regex": self.token_regex,
        }


@dataclass(frozen=True, slots=True)
class Credentials:
    cookie: str | None = None
    token: str | None = None
    source: str = "body"


def _merge_cookie(existing: str | None, new_cookie: str) -> str:
    name = new_cookie.split("=", 1)[0].strip()
    parts = [
        item.strip()
        for item in (existing or "").split(";")
        if item.strip() and item.split("=", 1)[0].strip() != name
    ]
    parts.append(new_cookie.strip())
    return "; ".join(parts)


def extract_credentials(
    response: Response, token_regex: str
) -> Credentials | None:
    """Busca primero Set-Cookie y después el cuerpo con la regex del usuario."""
    try:
        pattern = re.compile(token_regex or DEFAULT_TOKEN_REGEX)
    except re.error:
        _log.warning("session_invalid_regex", regex=token_regex)
        return None
    for header in response.headers:
        if header.lowercase_name != "set-cookie":
            continue
        match = pattern.search(header.value)
        if not match:
            continue
        token = match.group(1) if match.groups() else match.group(0)
        token = token.strip()
        if not token:
            continue
        name = header.value.split("=", 1)[0].strip()
        cookie = token if "=" in token else f"{name}={token}"
        return Credentials(cookie=cookie, source="set-cookie")

    text = response.body[:_MAX_SCAN].decode("utf-8", errors="replace")
    match = pattern.search(text)
    if not match:
        return None
    token = (match.group(1) if match.groups() else match.group(0)).strip()
    if not token:
        return None
    return Credentials(token=token, source="body")


def apply_credentials(request: Request, credentials: Credentials) -> Request:
    if credentials.cookie:
        current = request.header("Cookie")
        return request.with_header(
            "Cookie", _merge_cookie(current, credentials.cookie)
        )
    assert credentials.token is not None
    value = (
        credentials.token
        if credentials.token.lower().startswith("bearer ")
        else f"Bearer {credentials.token}"
    )
    return request.with_header("Authorization", value)


class SessionManager:
    """Carga la macro del proyecto y renueva la sesión tras 401/403."""

    def __init__(
        self,
        store: SessionStore,
        *,
        verify_upstream: bool = True,
        timeout: float = 30.0,
    ) -> None:
        self._store = store
        self._verify = verify_upstream
        self._timeout = timeout
        self._lock = asyncio.Lock()

    def load_config(self) -> SessionConfig:
        raw = self._store.get_setting(SESSION_KEY)
        if not raw:
            return SessionConfig()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return SessionConfig()
        if not isinstance(data, dict):
            return SessionConfig()
        flow_id = data.get("login_flow_id")
        try:
            parsed_flow_id = int(flow_id) if flow_id is not None else None
        except (TypeError, ValueError):
            parsed_flow_id = None
        regex = str(data.get("token_regex") or DEFAULT_TOKEN_REGEX)
        return SessionConfig(parsed_flow_id, regex)

    def save_config(
        self, login_flow_id: int | None, token_regex: str
    ) -> SessionConfig:
        config = SessionConfig(
            login_flow_id=login_flow_id,
            token_regex=token_regex.strip() or DEFAULT_TOKEN_REGEX,
        )
        self._store.set_setting(
            SESSION_KEY,
            json.dumps(config.to_record(), ensure_ascii=True),
        )
        return config

    async def refresh(
        self, request: Request, _response: Response
    ) -> Request | None:
        async with self._lock:
            config = self.load_config()
            if config.login_flow_id is None:
                return None
            flow = self._store.get_flow(config.login_flow_id)
            if flow is None or not isinstance(flow.final_request, Request):
                _log.warning(
                    "session_macro_missing",
                    login_flow_id=config.login_flow_id,
                )
                return None
            try:
                result = await send_once(
                    flow.final_request,
                    flow.service,
                    options=RequestOptions(
                        verify_upstream=self._verify,
                        timeout_ms=int(self._timeout * 1000),
                    ),
                )
            except Exception:
                _log.warning(
                    "session_macro_failed",
                    login_flow_id=config.login_flow_id,
                    exc_info=True,
                )
                return None

            credentials = extract_credentials(
                result.response, config.token_regex
            )
            if credentials is None:
                _log.warning(
                    "session_token_not_found",
                    login_flow_id=config.login_flow_id,
                )
                return None

            updated = apply_credentials(request, credentials)
            _log.info(
                "session_renewed",
                login_flow_id=config.login_flow_id,
                source=credentials.source,
            )
            return updated
