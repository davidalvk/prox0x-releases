"""CA autofirmada de prox0x y emisión de certificados hoja por host.

Implementa el diseño de la §3.4.1 del Plan:

| Aspecto | Decisión |
|---|---|
| Clave de CA | ECDSA P-256 (firmas rápidas, certificados pequeños) |
| Validez CA | 10 años |
| Extensiones CA | `basicConstraints CA:TRUE pathlen:0`, `keyUsage keyCertSign\\|cRLSign`, SKI, AKI |
| Hoja por host | on-demand, cacheada en memoria (LRU) y por contexto TLS |
| SAN | `DNS:host`, o `IP:host` si el destino es una dirección literal |
| Validez hoja | 30 días, renovación silenciosa al vaciar la caché |
| Serial | 128 bits aleatorios |
| Almacenamiento | clave privada cifrada (Scrypt + AES-256-GCM), permisos `0600` |

Los certificados hoja se escriben además como PEM en `<ca_dir>/leafs/` (0600,
nombre derivado del SHA-256 del host) porque ``ssl.load_cert_chain`` solo acepta
rutas de fichero; esos ficheros se regeneran trivialmente y la caché en memoria
evita firmar por cada petición.
"""

from __future__ import annotations

import os
import ssl
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from core.logging import get_logger

_CA_VALIDITY = timedelta(days=3650)  # 10 años
_LEAF_VALIDITY = timedelta(days=30)  # rango Plan: 7–30 días
_LEAF_CACHE_MAX = 1_024
_KEY_MAGIC = b"prox0x-key-v1\x00"
_SALT_LEN = 16
_NONCE_LEN = 12
_SCRYPT_N = 2**14

_log = get_logger("prox0x.ca")


class CaError(RuntimeError):
    """Error genérico de la CA."""


class CaPassphraseError(CaError):
    """La frase de paso no descifra la clave privada."""


@dataclass(frozen=True, slots=True)
class LeafCertificate:
    """Certificado hoja emitido para un host, con sus ficheros PEM."""

    host: str
    certificate: x509.Certificate
    cert_path: Path
    key_path: Path

    @property
    def serial_number(self) -> int:
        return self.certificate.serial_number


def _random_serial() -> int:
    """Serial de 128 bits aleatorios (§3.4.1), nunca cero."""
    serial = int.from_bytes(os.urandom(16), "big")
    return serial or 1


def _write_private(path: Path, data: bytes) -> None:
    """Escribe un fichero con permisos `0600` (la joya de la corona)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def _write_public(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def _encrypt_key(key: ec.EllipticCurvePrivateKey, passphrase: str) -> bytes:
    """Serializa la clave cifrada: `magic || salt || nonce || AES-256-GCM(ct)`.

    KDF = Scrypt (resistente a fuerza bruta con memoria), cifrado = AES-256-GCM
    con el propio magic como AAD (detecta corrupción/tampering).
    """
    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    kdf = Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=8, p=1)
    aes_key = kdf.derive(passphrase.encode("utf-8"))
    plaintext = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, _KEY_MAGIC)
    return _KEY_MAGIC + salt + nonce + ciphertext


def _decrypt_key(blob: bytes, passphrase: str) -> ec.EllipticCurvePrivateKey:
    if not blob.startswith(_KEY_MAGIC):
        raise CaError("formato de clave no reconocido (¿corrupta?)")
    offset = len(_KEY_MAGIC)
    salt = blob[offset : offset + _SALT_LEN]
    nonce = blob[offset + _SALT_LEN : offset + _SALT_LEN + _NONCE_LEN]
    ciphertext = blob[offset + _SALT_LEN + _NONCE_LEN :]
    kdf = Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=8, p=1)
    aes_key = kdf.derive(passphrase.encode("utf-8"))
    try:
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, _KEY_MAGIC)
    except InvalidTag as exc:
        raise CaPassphraseError("frase de paso incorrecta") from exc
    key = serialization.load_der_private_key(plaintext, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise CaError("la clave almacenada no es ECDSA")
    return key


def _ca_name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "prox0x"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _key_usage(*, ca: bool) -> x509.KeyUsage:
    if ca:
        return x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        )
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


class CertificateAuthority:
    """CA de prox0x: genera, carga, emite hojas por host y exporta."""

    def __init__(
        self,
        *,
        ca_dir: Path,
        certificate: x509.Certificate,
        key: ec.EllipticCurvePrivateKey,
    ) -> None:
        self._ca_dir = ca_dir
        self._cert = certificate
        self._key = key
        self._leafs: OrderedDict[str, LeafCertificate] = OrderedDict()
        self._contexts: dict[tuple[str, tuple[str, ...]], ssl.SSLContext] = {}

    # --------------------------------------------------------------- propiedades

    @property
    def ca_dir(self) -> Path:
        return self._ca_dir

    @property
    def certificate(self) -> x509.Certificate:
        return self._cert

    @property
    def cert_path(self) -> Path:
        return self._ca_dir / "ca.pem"

    @property
    def key_path(self) -> Path:
        return self._ca_dir / "ca.key.enc"

    @property
    def leafs_dir(self) -> Path:
        return self._ca_dir / "leafs"

    @property
    def not_valid_after(self) -> datetime:
        return self._cert.not_valid_after_utc

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.not_valid_after

    def fingerprint(self) -> str:
        """SHA-256 del certificado de la CA, en hex."""
        return sha256(self._cert.public_bytes(serialization.Encoding.DER)).hexdigest()

    # ------------------------------------------------------------------ creación

    @classmethod
    def exists(cls, ca_dir: Path) -> bool:
        return (ca_dir / "ca.pem").is_file() and (ca_dir / "ca.key.enc").is_file()

    @classmethod
    def init(
        cls,
        ca_dir: Path,
        passphrase: str,
        *,
        common_name: str = "prox0x CA",
        overwrite: bool = False,
    ) -> "CertificateAuthority":
        """Genera una CA autofirmada ECDSA P-256 y la guarda cifrada (0600)."""
        if not passphrase:
            raise ValueError("la frase de paso no puede estar vacía")
        if cls.exists(ca_dir) and not overwrite:
            raise CaError(f"ya existe una CA en {ca_dir} (usa --force para regenerarla)")

        key = ec.generate_private_key(ec.SECP256R1())
        name = _ca_name(common_name)
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)  # autofirmada
            .public_key(key.public_key())
            .serial_number(_random_serial())
            .not_valid_before(now - timedelta(minutes=5))  # tolerancia de reloj
            .not_valid_after(now + _CA_VALIDITY)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_key_usage(ca=True), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        _ensure_dir(ca_dir)
        _ensure_dir(ca_dir / "leafs")
        _write_public(
            ca_dir / "ca.pem", certificate.public_bytes(serialization.Encoding.PEM)
        )
        _write_private(ca_dir / "ca.key.enc", _encrypt_key(key, passphrase))
        _log.info("ca_created", ca_dir=str(ca_dir), subject=certificate.subject.rfc4514_string())
        return cls(ca_dir=ca_dir, certificate=certificate, key=key)

    @classmethod
    def load(cls, ca_dir: Path, passphrase: str) -> "CertificateAuthority":
        """Carga la CA desde disco descifrando la clave con la frase de paso."""
        cert_path = ca_dir / "ca.pem"
        key_path = ca_dir / "ca.key.enc"
        if not cert_path.is_file() or not key_path.is_file():
            raise CaError(f"no hay CA en {ca_dir}; ejecuta primero `prox0x ca init`")
        certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = _decrypt_key(key_path.read_bytes(), passphrase)
        ca = cls(ca_dir=ca_dir, certificate=certificate, key=key)
        if ca.is_expired:
            _log.warning("ca_expired", not_valid_after=ca.not_valid_after.isoformat())
        return ca

    # -------------------------------------------------------------- emisión

    def issue(self, host: str) -> LeafCertificate:
        """Certificado hoja para ``host`` (cacheado; se firma una sola vez)."""
        normalized = host.strip().lower().rstrip(".")
        if not normalized:
            raise ValueError("host vacío")
        cached = self._leafs.get(normalized)
        if cached is not None:
            self._leafs.move_to_end(normalized)  # política LRU
            return cached

        leaf = self._issue_fresh(normalized)
        self._leafs[normalized] = leaf
        while len(self._leafs) > _LEAF_CACHE_MAX:
            evicted_host, evicted = self._leafs.popitem(last=False)
            _log.debug("leaf_cache_evicted", host=evicted_host)
            self._contexts.pop((evicted_host, tuple()), None)
        _log.debug("leaf_issued", host=normalized, serial=leaf.serial_number)
        return leaf

    def _issue_fresh(self, host: str) -> LeafCertificate:
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)

        # SAN: DNS para nombres, IP para direcciones literales (§3.4.1).
        try:
            san = x509.SubjectAlternativeName([x509.IPAddress(ip_address(host))])
        except ValueError:
            san = x509.SubjectAlternativeName([x509.DNSName(host)])

        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(self._cert.subject)
            .public_key(key.public_key())
            .serial_number(_random_serial())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + _LEAF_VALIDITY)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_key_usage(ca=False), critical=True)
            .add_extension(san, critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()),
                critical=False,
            )
            .sign(self._key, hashes.SHA256())
        )

        _ensure_dir(self.leafs_dir)
        digest = sha256(host.encode("utf-8")).hexdigest()[:32]
        path = self.leafs_dir / f"{digest}.pem"
        pem = certificate.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        _write_private(path, pem)
        return LeafCertificate(
            host=host, certificate=certificate, cert_path=path, key_path=path
        )

    def server_context(
        self, host: str, alpn: Sequence[str] = ("http/1.1",)
    ) -> ssl.SSLContext:
        """Contexto TLS servidor con el certificado de ``host`` y ALPN ofrecido.

        Se crea uno por host (y por conjunto ALPN) y se cachea: el handshake no
        vuelve a firmar ni a tocar disco.
        """
        key = (host.strip().lower(), tuple(alpn))
        context = self._contexts.get(key)
        if context is not None:
            return context

        leaf = self.issue(host)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(list(alpn))
        context.load_cert_chain(str(leaf.cert_path), str(leaf.key_path))
        context.sni_callback = self._make_sni_watchdog(host)
        self._contexts[key] = context
        return context

    @staticmethod
    def _make_sni_watchdog(host: str):
        """Registra el SNI del cliente y avisa si difiere del host del CONNECT."""

        def _watchdog(ssl_object: ssl.SSLObject, servername: str | None, _ctx: ssl.SSLContext) -> None:
            # El SNI no es recuperable por API pública tras el handshake en rol
            # servidor (server_hostname es solo de cliente); se guarda en el
            # propio SSLObject para que el proxy pueda registrarlo en sus logs.
            ssl_object._prox0x_sni = servername  # noqa: SLF001 — sin alternativa pública
            if servername and servername.lower() != host:
                _log.warning("sni_mismatch", connect_host=host, sni=servername)

        return _watchdog

    # -------------------------------------------------------------- verificación

    def verify_issued(self, certificate: x509.Certificate) -> bool:
        """Comprueba que ``certificate`` está firmado directamente por esta CA."""
        try:
            certificate.verify_directly_issued_by(self._cert)
        except (InvalidSignature, ValueError):
            return False
        return True

    # -------------------------------------------------------------- exportación

    def export_pem(self, dest: Path) -> Path:
        """Exporta **solo el certificado** de la CA en PEM (para instalarlo)."""
        dest.parent.mkdir(parents=True, exist_ok=True)
        _write_public(dest, self._cert.public_bytes(serialization.Encoding.PEM))
        _log.info("ca_exported_pem", path=str(dest))
        return dest

    def export_pkcs12(self, dest: Path, passphrase: str) -> Path:
        """Exporta cert + clave privada en PKCS#12 cifrado (backup / otros tools)."""
        if not passphrase:
            raise ValueError("el PKCS#12 necesita frase de paso")
        dest.parent.mkdir(parents=True, exist_ok=True)
        blob = pkcs12.serialize_key_and_certificates(
            name=b"prox0x CA",
            key=self._key,
            cert=self._cert,
            cas=[self._cert],
            encryption_algorithm=serialization.BestAvailableEncryption(
                passphrase.encode("utf-8")
            ),
        )
        _write_private(dest, blob)
        _log.info("ca_exported_p12", path=str(dest))
        return dest
