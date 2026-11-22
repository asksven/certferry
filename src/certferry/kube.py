"""Read TLS secrets (and optionally cert-manager Certificates) through kubectl."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any

from certferry.errors import ExtractError
from certferry.runner import RunnerProtocol

ALLOWED_SECRET_TYPES = ("kubernetes.io/tls", "Opaque")


@dataclass
class SourceConfig:
    secret: str | None = None
    certificate: str | None = None
    namespace: str | None = None
    context: str | None = None
    kubeconfig: str | None = None
    kubectl: str = "kubectl"
    require_ready: bool = True
    kubectl_timeout: float = 60.0
    cache_dir: str | None = None

    @property
    def label(self) -> str:
        kind = "certificate" if self.certificate else "secret"
        name = self.certificate or self.secret
        return f"{kind}:{self.namespace or '-'}/{name}"


@dataclass
class SecretData:
    name: str
    namespace: str
    tls_crt: bytes
    tls_key: bytes
    ca_crt: bytes | None


def kubectl_base(src: SourceConfig) -> list[str]:
    argv = [src.kubectl]
    if src.kubeconfig:
        argv += ["--kubeconfig", src.kubeconfig]
    if src.cache_dir:
        argv += ["--cache-dir", src.cache_dir]
    if src.context:
        argv += ["--context", src.context]
    if src.namespace:
        argv += ["--namespace", src.namespace]
    return argv


def _get_json(src: SourceConfig, runner: RunnerProtocol, kind: str, name: str) -> dict[str, Any]:
    argv = [*kubectl_base(src), "get", kind, name, "-o", "json"]
    res = runner.run(argv, timeout=src.kubectl_timeout)
    if not res.ok:
        raise ExtractError(
            f"kubectl get {kind} {name} failed (exit {res.returncode}): {res.stderr_text()}"
        )
    try:
        obj = json.loads(res.stdout)
    except ValueError as exc:
        raise ExtractError(f"kubectl get {kind} {name}: output is not JSON") from exc
    if not isinstance(obj, dict):
        raise ExtractError(f"kubectl get {kind} {name}: unexpected output")
    return obj


def resolve_secret_name(src: SourceConfig, runner: RunnerProtocol) -> str:
    if src.secret:
        return src.secret
    assert src.certificate  # noqa: S101 - guaranteed by config validation
    obj = _get_json(src, runner, "certificates.cert-manager.io", src.certificate)
    secret_name = (obj.get("spec") or {}).get("secretName")
    if not secret_name:
        raise ExtractError(f"certificate {src.certificate} has no spec.secretName")
    if src.require_ready:
        conditions = (obj.get("status") or {}).get("conditions") or []
        ready = next((c for c in conditions if c.get("type") == "Ready"), None)
        if not ready or ready.get("status") != "True":
            reason = (ready or {}).get("message") or (ready or {}).get("reason") or "no condition"
            raise ExtractError(f"certificate {src.certificate} is not Ready: {reason}")
    return str(secret_name)


def _decode(data: dict[str, Any], key: str, secret: str) -> bytes | None:
    value = data.get(key)
    if not value:
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ExtractError(f"secret {secret}: {key} is not valid base64") from exc


def fetch_secret(src: SourceConfig, runner: RunnerProtocol) -> SecretData:
    name = resolve_secret_name(src, runner)
    obj = _get_json(src, runner, "secret", name)
    secret_type = obj.get("type")
    if secret_type not in ALLOWED_SECRET_TYPES:
        raise ExtractError(f"secret {name} has unsupported type {secret_type!r}")
    data = obj.get("data") or {}
    crt = _decode(data, "tls.crt", name)
    key = _decode(data, "tls.key", name)
    if not crt or not key:
        raise ExtractError(f"secret {name} does not contain tls.crt and tls.key")
    namespace = (obj.get("metadata") or {}).get("namespace") or src.namespace or ""
    return SecretData(name, str(namespace), crt, key, _decode(data, "ca.crt", name))
