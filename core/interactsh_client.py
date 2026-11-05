"""Cliente Interactsh mínimo y fiable para prox0x.

La dependencia ``theori-io/python-interactsh`` descifraba las interacciones con
AES-CFB cuando los servidores Interactsh usan AES-CTR: el primer bloque JSON
salía bien y el resto se corrompía. Este cliente implementa el protocolo
directamente, con registro, polling y descifrado correctos.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

import aiohttp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from core.logging import get_logger
from core.net.tls import verified_ssl_context

DEFAULT_INTERACTSH_SERVERS: tuple[str, ...] = (
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.fun",
    "oast.me",
)

_XID_ALPHABET = "0123456789abcdefghijklmnopqrstuv"
_TS_RE = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2})?$"
)

_log = get_logger("prox0x.interactsh")


class InteractshError(RuntimeError):
    pass


class RegistrationError(InteractshError):
    pass


class PollingError(InteractshError):
    pass


@dataclass(frozen=True, slots=True)
class InteractshInteraction:
    protocol: str = ""
    unique_id: str = ""
    full_id: str = ""
    remote_address: str = ""
    raw_request: str | None = None
    raw_response: str | None = None
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


def _correlation_id(length: int = 20) -> str:
    return "".join(secrets.choice(_XID_ALPHABET) for _ in range(length))


def _domain_nonce(length: int = 13) -> str:
    raw = secrets.token_bytes(length)
    encoded = base64.b32encode(raw).decode("ascii").lower().rstrip("=")
    return encoded[:length]


def _parse_timestamp(value: object) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 10_000_000_000 else value
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    if not isinstance(value, str):
        return datetime.now(timezone.utc)
    text = value.strip()
    match = _TS_RE.match(text)
    if match is None:
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc)
    fraction = (match.group("frac") or "")[:6].ljust(6, "0")
    timezone_text = match.group("tz") or "Z"
    if timezone_text == "Z":
        timezone_text = "+00:00"
    elif re.fullmatch(r"[+-]\d{4}", timezone_text):
        timezone_text = f"{timezone_text[:3]}:{timezone_text[3:]}"
    try:
        return datetime.fromisoformat(
            f"{match.group('base')}.{fraction}{timezone_text}"
        )
    except ValueError:
        return datetime.now(timezone.utc)


class InteractshClient:
    """Cliente HTTP/JSON para registrar una sesión y consultar interacciones."""

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        correlation_id_length: int = 20,
    ) -> None:
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: aiohttp.ClientSession | None = None
        self._poll_lock = asyncio.Lock()
        self.correlation_id = _correlation_id(correlation_id_length)
        self.secret_key = str(uuid.uuid4())
        self.server = ""
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self._public_key = self._private_key.public_key()

    async def _client(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(ssl=verified_ssl_context())
            self._session = aiohttp.ClientSession(
                headers={"User-Agent": "prox0x-interactsh/1.0"},
                connector=connector,
            )
        return self._session

    def _public_key_b64(self) -> str:
        pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return base64.b64encode(pem).decode("ascii")

    async def register(self, server: str) -> str:
        """Registra la sesión; devuelve la URL base finalmente utilizada."""
        server = server.strip()
        if not server:
            raise RegistrationError("servidor Interactsh vacío")
        if server.startswith(("http://", "https://")):
            candidates = [server.rstrip("/")]
        else:
            candidates = [
                f"https://{server.rstrip('/')}",
                f"http://{server.rstrip('/')}",
            ]

        payload = {
            "public-key": self._public_key_b64(),
            "secret-key": self.secret_key,
            "correlation-id": self.correlation_id,
        }
        errors: list[str] = []
        for base in candidates:
            try:
                session = await self._client()
                async with session.post(
                    f"{base}/register",
                    json=payload,
                    timeout=self._timeout,
                ) as response:
                    text = await response.text()
                    if response.status != 200:
                        raise RegistrationError(
                            f"HTTP {response.status}: {text[:300]}"
                        )
                    try:
                        data = json.loads(text)
                    except ValueError as exc:
                        raise RegistrationError(
                            f"respuesta no JSON: {text[:300]}"
                        ) from exc
                    if not isinstance(data, dict) or data.get(
                        "message"
                    ) != "registration successful":
                        message = (
                            data.get("message")
                            if isinstance(data, dict)
                            else "registro rechazado"
                        )
                        raise RegistrationError(
                            str(message or "registro rechazado")
                        )
                self.server = base
                return base
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                errors.append(f"{base}: {type(exc).__name__}: {exc}")
            except RegistrationError as exc:
                errors.append(f"{base}: {exc}")
        raise RegistrationError("; ".join(errors) or "registro fallido")

    async def url(self, secure: bool = True) -> str:
        if not self.server:
            raise InteractshError("cliente Interactsh sin registrar")
        domain = urlsplit(self.server).netloc.split(":")[0]
        scheme = "https" if secure else "http"
        return (
            f"{scheme}://{self.correlation_id}{_domain_nonce()}.{domain}"
        )

    def _decrypt(self, key_b64: str, message_b64: str) -> bytes:
        encrypted_key = base64.b64decode(key_b64)
        aes_key = self._private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        ciphertext = base64.b64decode(message_b64)
        if len(ciphertext) < 16:
            raise InteractshError("ciphertext AES demasiado corto")
        iv = ciphertext[:16]
        body = ciphertext[16:]
        # Interactsh cifra con AES-CTR, no CFB. Usar CFB corrompe el JSON
        # a partir del segundo bloque.
        decryptor = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).decryptor()
        return decryptor.update(body) + decryptor.finalize()

    def _parse_interaction(self, payload: bytes | str) -> InteractshInteraction | None:
        try:
            text = (
                payload.decode("utf-8", errors="replace")
                if isinstance(payload, bytes)
                else payload
            )
            data = json.loads(text)
        except (ValueError, TypeError, UnicodeDecodeError):
            return None
        if not isinstance(data, dict):
            return None
        return InteractshInteraction(
            protocol=str(data.get("protocol", "")),
            unique_id=str(data.get("unique-id") or data.get("unique_id") or ""),
            full_id=str(data.get("full-id") or data.get("full_id") or ""),
            remote_address=str(
                data.get("remote-address") or data.get("remote_address") or ""
            ),
            raw_request=data.get("raw-request") or data.get("raw_request"),
            raw_response=data.get("raw-response") or data.get("raw_response"),
            timestamp=_parse_timestamp(
                data.get("timestamp") or data.get("created_at")
            ),
        )

    async def poll(self) -> list[InteractshInteraction]:
        if not self.server:
            raise PollingError("cliente Interactsh sin registrar")
        async with self._poll_lock:
            session = await self._client()
            url = (
                f"{self.server}/poll?id={self.correlation_id}"
                f"&secret={self.secret_key}"
            )
            try:
                async with session.get(url, timeout=self._timeout) as response:
                    text = await response.text()
                    if response.status != 200:
                        raise PollingError(
                            f"HTTP {response.status}: {text[:300]}"
                        )
                    try:
                        data = json.loads(text)
                    except ValueError as exc:
                        raise PollingError(
                            f"respuesta no JSON: {text[:300]}"
                        ) from exc
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                raise PollingError(
                    f"{type(exc).__name__}: {exc}"
                ) from exc

            if not isinstance(data, dict):
                raise PollingError("respuesta de polling con formato inválido")
            interactions: list[InteractshInteraction] = []
            key = data.get("aes_key")
            if key:
                for encrypted in data.get("data") or []:
                    try:
                        plaintext = self._decrypt(str(key), str(encrypted))
                    except Exception as exc:  # noqa: BLE001
                        _log.error(
                            "interactsh_decrypt_failed",
                            error=str(exc),
                            error_type=type(exc).__name__,
                        )
                        continue
                    interaction = self._parse_interaction(plaintext)
                    if interaction is not None:
                        interactions.append(interaction)
            for plaintext in (
                *(data.get("extra") or []),
                *(data.get("tlddata") or data.get("tld_data") or []),
            ):
                interaction = self._parse_interaction(plaintext)
                if interaction is not None:
                    interactions.append(interaction)
            return interactions

    async def close(self) -> None:
        session = self._session
        if session is None:
            return
        try:
            if self.server:
                async with session.post(
                    f"{self.server}/deregister",
                    json={
                        "correlation-id": self.correlation_id,
                        "secret-key": self.secret_key,
                    },
                    timeout=aiohttp.ClientTimeout(total=5),
                ):
                    pass
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            _log.debug("interactsh_deregister_failed", exc_info=True)
        finally:
            await session.close()
            self._session = None
