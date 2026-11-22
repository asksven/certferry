"""Post-deploy checks: files are in place, and endpoints actually serve the new certificate."""

from __future__ import annotations

import socket
import ssl
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from certferry.certs import OutputFile, fingerprint, same_content
from certferry.errors import CertferryError, VerifyError
from certferry.runner import RunnerProtocol
from certferry.targets import Target

PeerFetcher = Callable[[str, int, str | None, float], bytes]


@dataclass
class EndpointConfig:
    host: str
    port: int = 443
    servername: str | None = None

    @property
    def label(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        sni = f"#{self.servername}" if self.servername and self.servername != self.host else ""
        return f"{host}:{self.port}{sni}"


@dataclass
class VerifyConfig:
    files: bool = False
    endpoints: list[EndpointConfig] | None = None
    retries: int = 5
    delay: float = 2.0
    timeout: float = 5.0


def fetch_peer_cert(host: str, port: int, servername: str | None, timeout: float) -> bytes:
    """Return the DER leaf certificate presented by host:port. Trust is not validated here;
    the comparison against the expected certificate is the check."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((host, port), timeout=timeout) as sock,
        context.wrap_socket(sock, server_hostname=servername or host) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
    if not der:
        raise OSError("peer presented no certificate")
    return der


def verify_endpoint(
    endpoint: EndpointConfig,
    expected_der: bytes,
    cfg: VerifyConfig,
    fetch: PeerFetcher = fetch_peer_cert,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    attempts = max(1, cfg.retries)
    last = ""
    for attempt in range(1, attempts + 1):
        try:
            der = fetch(endpoint.host, endpoint.port, endpoint.servername, cfg.timeout)
        except (OSError, ssl.SSLError) as exc:
            last = f"connection failed: {exc}"
        else:
            if der == expected_der:
                return {"attempts": attempt, "fingerprint": fingerprint(der)}
            last = f"serves different certificate {fingerprint(der)}"
        if attempt < attempts:
            sleep(cfg.delay)
    raise VerifyError(f"endpoint {endpoint.label}: {last} after {attempts} attempt(s)")


def verify_files(
    target: Target,
    files: Sequence[OutputFile],
    runner: RunnerProtocol,
    pkcs12_password: bytes | None,
) -> list[str]:
    """Return the names of files that are missing or differ on the target."""
    bad: list[str] = []
    for f in files:
        try:
            existing = target.read(f.name, runner)
        except CertferryError:
            existing = None
        if not same_content(f, existing, pkcs12_password):
            bad.append(f.name)
    return bad
