"""Comprobación de actualizaciones contra las Releases públicas de prox0x."""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any

import aiohttp

from core import __version__
from core.logging import get_logger
from core.net.tls import verified_ssl_context

LATEST_RELEASE_URL = (
    "https://api.github.com/repos/davidalvk/prox0x-releases/releases/latest"
)
RELEASE_TAG_URL = (
    "https://github.com/davidalvk/prox0x-releases/releases/tag/{tag}"
)
CACHE_TTL_SECONDS = 600.0

_log = get_logger("prox0x.updates")
_cache: dict[str, Any] | None = None
_cache_at = 0.0
_lock = asyncio.Lock()


class UpdateCheckError(RuntimeError):
    pass


def _version_tuple(value: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", value.strip().lstrip("vV"))
    return tuple(int(part) for part in parts[:4])


def is_newer_version(latest: str, current: str) -> bool:
    latest_parts = _version_tuple(latest)
    current_parts = _version_tuple(current)
    if not latest_parts or not current_parts:
        return False
    return latest_parts > current_parts


async def _fetch_latest_release() -> dict[str, Any]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": f"prox0x/{__version__}",
    }
    connector = aiohttp.TCPConnector(ssl=verified_ssl_context())
    try:
        async with aiohttp.ClientSession(
            headers=headers, connector=connector
        ) as session:
            async with session.get(
                LATEST_RELEASE_URL,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if response.status != 200:
                    detail = (await response.text())[:300]
                    raise UpdateCheckError(
                        f"GitHub respondió HTTP {response.status}: {detail}"
                    )
                data = await response.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
        raise UpdateCheckError(
            f"{type(exc).__name__}: {exc}"
        ) from exc

    if not isinstance(data, dict) or not data.get("tag_name"):
        raise UpdateCheckError("respuesta de GitHub sin tag_name")
    return data


async def _latest_release() -> dict[str, Any]:
    global _cache, _cache_at
    now = time.monotonic()
    if _cache is not None and now - _cache_at < CACHE_TTL_SECONDS:
        return _cache
    async with _lock:
        now = time.monotonic()
        if _cache is not None and now - _cache_at < CACHE_TTL_SECONDS:
            return _cache
        _cache = await _fetch_latest_release()
        _cache_at = now
        return _cache


async def check_for_updates(current_version: str | None = None) -> dict[str, Any]:
    current = (current_version or __version__).strip().lstrip("vV")
    try:
        release = await _latest_release()
    except Exception as exc:  # noqa: BLE001 - el chequeo no debe romper la API
        _log.warning("update_check_failed", error=str(exc))
        return {
            "update_available": False,
            "error": "No se pudo comprobar",
        }

    latest = str(release.get("tag_name", "")).strip()
    download_url = str(
        release.get("html_url")
        or RELEASE_TAG_URL.format(tag=latest)
    )
    return {
        "update_available": is_newer_version(latest, current),
        "current_version": current,
        "latest_version": latest,
        "download_url": download_url,
    }


def reset_cache() -> None:
    """Limpia la caché (útil en tests y diagnósticos)."""
    global _cache, _cache_at
    _cache = None
    _cache_at = 0.0
