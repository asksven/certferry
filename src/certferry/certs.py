"""Parsing of the TLS secret and rendering into the on-disk formats services expect."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtensionOID, NameOID

from certferry.errors import CertificateError

PEM_CERT_RE = re.compile(rb"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")

CertKey = (
    rsa.RSAPrivateKey
    | ec.EllipticCurvePrivateKey
    | ed25519.Ed25519PrivateKey
    | ed448.Ed448PrivateKey
    | dsa.DSAPrivateKey
)


@dataclass(frozen=True)
class FormatSpec:
    name: str
    default_filename: str
    secret: bool
    description: str


FORMATS: dict[str, FormatSpec] = {
    spec.name: spec
    for spec in (
        FormatSpec("cert", "cert.pem", False, "leaf certificate only (PEM)"),
        FormatSpec("chain", "chain.pem", False, "intermediate certificates only (PEM)"),
        FormatSpec("fullchain", "fullchain.pem", False, "leaf + intermediates (PEM; nginx, Caddy)"),
        FormatSpec("ca", "ca.pem", False, "ca.crt from the secret (PEM)"),
        FormatSpec("key", "key.pem", True, "private key exactly as stored in the secret"),
        FormatSpec("key-pkcs8", "key.pkcs8.pem", True, "private key, PKCS#8 PEM"),
        FormatSpec(
            "key-traditional",
            "key.traditional.pem",
            True,
            "private key, traditional PEM (PKCS#1 RSA / SEC1 EC)",
        ),
        FormatSpec("combined", "combined.pem", True, "fullchain + key in one PEM (HAProxy)"),
        FormatSpec("der", "cert.der", False, "leaf certificate, DER binary"),
        FormatSpec("pkcs12", "cert.p12", True, "key + leaf + chain, PKCS#12 (Java, Windows/IIS)"),
    )
}

DEFAULT_FORMATS = ["fullchain", "key"]


@dataclass(frozen=True)
class OutputFile:
    format: str
    name: str
    data: bytes
    secret: bool


@dataclass
class Pkcs12Options:
    password: bytes | None = None
    legacy: bool = False
    friendly_name: str | None = None


def load_certs(pem: bytes, what: str) -> list[x509.Certificate]:
    blocks = PEM_CERT_RE.findall(pem)
    if not blocks:
        raise CertificateError(f"{what}: no PEM certificate found")
    try:
        return [x509.load_pem_x509_certificate(block) for block in blocks]
    except ValueError as exc:
        raise CertificateError(f"{what}: cannot parse certificate: {exc}") from exc


def _spki(public_key: Any) -> bytes:
    return cast(
        bytes,
        public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
    )


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def key_type(key: CertKey) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        return f"rsa{key.key_size}"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return f"ec-{key.curve.name}"
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "ed25519"
    if isinstance(key, ed448.Ed448PrivateKey):
        return "ed448"
    return "dsa"


class CertMaterial:
    """A validated leaf certificate, its chain, the matching key and optional CA."""

    def __init__(
        self,
        certs: list[x509.Certificate],
        key: CertKey,
        key_pem: bytes,
        ca: list[x509.Certificate],
    ) -> None:
        self.certs = certs
        self.key = key
        self.key_pem = key_pem if key_pem.endswith(b"\n") else key_pem + b"\n"
        self.ca = ca

    @classmethod
    def from_pem(cls, cert_pem: bytes, key_pem: bytes, ca_pem: bytes | None = None) -> CertMaterial:
        certs = load_certs(cert_pem, "tls.crt")
        try:
            key = serialization.load_pem_private_key(key_pem, password=None)
        except (ValueError, TypeError) as exc:
            raise CertificateError(f"tls.key: cannot parse private key: {exc}") from exc
        if not isinstance(
            key,
            rsa.RSAPrivateKey
            | ec.EllipticCurvePrivateKey
            | ed25519.Ed25519PrivateKey
            | ed448.Ed448PrivateKey
            | dsa.DSAPrivateKey,
        ):
            raise CertificateError(f"tls.key: unsupported key type {type(key).__name__}")
        ca = load_certs(ca_pem, "ca.crt") if ca_pem and ca_pem.strip() else []
        material = cls(certs, key, key_pem.strip() + b"\n", ca)
        material.check_key_matches()
        return material

    @property
    def leaf(self) -> x509.Certificate:
        return self.certs[0]

    @property
    def chain(self) -> list[x509.Certificate]:
        return self.certs[1:]

    @property
    def leaf_der(self) -> bytes:
        return self.leaf.public_bytes(serialization.Encoding.DER)

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.leaf_der)

    @property
    def not_after(self) -> datetime:
        return self.leaf.not_valid_after_utc

    def check_key_matches(self) -> None:
        if _spki(self.key.public_key()) != _spki(self.leaf.public_key()):
            raise CertificateError("tls.key does not match the leaf certificate in tls.crt")

    def days_remaining(self, now: datetime | None = None) -> float:
        now = now or datetime.now(timezone.utc)
        return (self.not_after - now).total_seconds() / 86400

    def dns_names(self) -> list[str]:
        try:
            ext = self.leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        except x509.ExtensionNotFound:
            return []
        san = cast(x509.SubjectAlternativeName, ext.value)
        return list(san.get_values_for_type(x509.DNSName))

    def info(self) -> dict[str, Any]:
        cns = self.leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return {
            "subject": self.leaf.subject.rfc4514_string(),
            "common_name": str(cns[0].value) if cns else "",
            "issuer": self.leaf.issuer.rfc4514_string(),
            "dns_names": self.dns_names(),
            "serial": format(self.leaf.serial_number, "x"),
            "not_before": self.leaf.not_valid_before_utc.isoformat(),
            "not_after": self.not_after.isoformat(),
            "fingerprint_sha256": self.fingerprint,
            "key_type": key_type(self.key),
            "chain_length": len(self.chain),
            "has_ca": bool(self.ca),
        }


def _render_pkcs12(material: CertMaterial, opts: Pkcs12Options) -> bytes:
    encryption: serialization.KeySerializationEncryption
    if not opts.password:
        encryption = serialization.NoEncryption()
    elif opts.legacy:
        encryption = (
            serialization.PrivateFormat.PKCS12.encryption_builder()
            .kdf_rounds(2048)
            .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
            .hmac_hash(hashes.SHA1())  # noqa: S303 - required for legacy consumers
            .build(opts.password)
        )
    else:
        encryption = serialization.BestAvailableEncryption(opts.password)
    seen = {c.fingerprint(hashes.SHA256()) for c in material.chain}
    cas = list(material.chain) + [
        c for c in material.ca if c.fingerprint(hashes.SHA256()) not in seen
    ]
    name = (opts.friendly_name or (material.dns_names() or ["certificate"])[0]).encode()
    return pkcs12.serialize_key_and_certificates(
        name=name,
        key=material.key,
        cert=material.leaf,
        cas=cas or None,
        encryption_algorithm=encryption,
    )


def render_format(fmt: str, material: CertMaterial, pkcs12_opts: Pkcs12Options) -> bytes:
    if fmt == "cert":
        return _pem(material.leaf)
    if fmt == "chain":
        if not material.chain:
            raise CertificateError(
                "format 'chain' requested but tls.crt contains no intermediate certificates"
            )
        return b"".join(_pem(c) for c in material.chain)
    if fmt == "fullchain":
        return b"".join(_pem(c) for c in material.certs)
    if fmt == "ca":
        if not material.ca:
            raise CertificateError("format 'ca' requested but the secret has no ca.crt")
        return b"".join(_pem(c) for c in material.ca)
    if fmt == "key":
        return material.key_pem
    if fmt == "key-pkcs8":
        return material.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    if fmt == "key-traditional":
        try:
            return material.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        except ValueError as exc:
            raise CertificateError(
                f"format 'key-traditional' is not available for {key_type(material.key)} keys"
            ) from exc
    if fmt == "combined":
        return render_format("fullchain", material, pkcs12_opts) + material.key_pem
    if fmt == "der":
        return material.leaf_der
    if fmt == "pkcs12":
        return _render_pkcs12(material, pkcs12_opts)
    raise CertificateError(f"unknown format {fmt!r}")


def render(
    material: CertMaterial,
    formats: Sequence[str],
    filenames: Mapping[str, str] | None = None,
    pkcs12_opts: Pkcs12Options | None = None,
) -> list[OutputFile]:
    opts = pkcs12_opts or Pkcs12Options()
    names = filenames or {}
    files: list[OutputFile] = []
    for fmt in formats:
        spec = FORMATS[fmt]
        files.append(
            OutputFile(
                format=fmt,
                name=names.get(fmt, spec.default_filename),
                data=render_format(fmt, material, opts),
                secret=spec.secret,
            )
        )
    return files


def same_content(file: OutputFile, existing: bytes | None, pkcs12_password: bytes | None) -> bool:
    """Compare a rendered file with what is deployed.

    PKCS#12 output is randomly salted, so it is compared by its decoded content.
    """
    if existing is None:
        return False
    if file.format != "pkcs12":
        return existing == file.data
    try:
        new_key, new_cert, _ = pkcs12.load_key_and_certificates(file.data, pkcs12_password)
        old_key, old_cert, _ = pkcs12.load_key_and_certificates(existing, pkcs12_password)
    except (ValueError, TypeError):
        return False
    if new_cert is None or old_cert is None or new_key is None or old_key is None:
        return False
    return new_cert == old_cert and _spki(new_key.public_key()) == _spki(old_key.public_key())
