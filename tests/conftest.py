"""Shared fixtures: a throw-away PKI, fake kubectl/ssh/scp executables, a fake runner and a
local TLS server, so the full pipeline can be exercised without a cluster or remote host."""

from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import stat
import sys
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from certferry.runner import Result

# --------------------------------------------------------------------------- PKI


def _make_key(kind: str) -> Any:
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if kind == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    return ec.generate_private_key(ec.SECP256R1())


def _make_cert(
    cn: str,
    key: Any,
    issuer_cert: x509.Certificate | None,
    issuer_key: Any,
    *,
    ca: bool,
    sans: list[str] | None = None,
    days: float = 90,
) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    algorithm = None if isinstance(issuer_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(issuer_key, algorithm)


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


@dataclass
class Pki:
    root_cert: x509.Certificate
    inter_cert: x509.Certificate
    leaf_cert: x509.Certificate
    leaf_key: Any
    key_format: str = "pkcs8"

    @property
    def tls_crt(self) -> bytes:
        return _pem(self.leaf_cert) + _pem(self.inter_cert)

    @property
    def tls_key(self) -> bytes:
        fmt = (
            serialization.PrivateFormat.TraditionalOpenSSL
            if self.key_format == "pkcs1"
            else serialization.PrivateFormat.PKCS8
        )
        return self.leaf_key.private_bytes(
            serialization.Encoding.PEM, fmt, serialization.NoEncryption()
        )

    @property
    def ca_crt(self) -> bytes:
        return _pem(self.root_cert)

    @property
    def leaf_pem(self) -> bytes:
        return _pem(self.leaf_cert)

    @property
    def leaf_der(self) -> bytes:
        return self.leaf_cert.public_bytes(serialization.Encoding.DER)

    def secret(
        self,
        name: str = "web-tls",
        namespace: str = "default",
        *,
        include_ca: bool = True,
        type_: str = "kubernetes.io/tls",
    ) -> dict[str, Any]:
        data = {
            "tls.crt": base64.b64encode(self.tls_crt).decode(),
            "tls.key": base64.b64encode(self.tls_key).decode(),
        }
        if include_ca:
            data["ca.crt"] = base64.b64encode(self.ca_crt).decode()
        return {
            "apiVersion": "v1",
            "kind": "Secret",
            "type": type_,
            "metadata": {"name": name, "namespace": namespace},
            "data": data,
        }


def make_pki(
    kind: str = "ec",
    *,
    cn: str = "www.example.test",
    days: float = 90,
    key_format: str = "pkcs8",
    sans: bool = True,
) -> Pki:
    root_key = _make_key("ec")
    root = _make_cert("Test Root", root_key, None, root_key, ca=True, days=3650)
    inter_key = _make_key("ec")
    inter = _make_cert("Test Intermediate", inter_key, root, root_key, ca=True, days=1825)
    leaf_key = _make_key(kind)
    leaf = _make_cert(
        cn,
        leaf_key,
        inter,
        inter_key,
        ca=False,
        sans=[cn, "example.test"] if sans else None,
        days=days,
    )
    return Pki(root, inter, leaf, leaf_key, key_format)


@pytest.fixture(scope="session")
def pki() -> Pki:
    return make_pki("ec")


@pytest.fixture(scope="session")
def rsa_pki() -> Pki:
    return make_pki("rsa", key_format="pkcs1")


@pytest.fixture(scope="session")
def ed_pki() -> Pki:
    return make_pki("ed25519")


@pytest.fixture(scope="session")
def other_pki() -> Pki:
    return make_pki("ec", cn="other.example.test")


def certificate_resource(
    name: str, secret_name: str, namespace: str = "default", ready: bool = True
) -> dict[str, Any]:
    return {
        "apiVersion": "cert-manager.io/v1",
        "kind": "Certificate",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"secretName": secret_name},
        "status": {
            "conditions": [
                {
                    "type": "Ready",
                    "status": "True" if ready else "False",
                    "reason": "Ready" if ready else "Issuing",
                    "message": "ok" if ready else "Issuing certificate as Secret does not exist",
                }
            ]
        },
    }


# ---------------------------------------------------------------- fake runner


@dataclass
class Call:
    cmd: Any
    shell: bool
    env: dict[str, str] | None
    timeout: float | None

    @property
    def argv(self) -> list[str]:
        return [self.cmd] if isinstance(self.cmd, str) else list(self.cmd)


@dataclass
class FakeRunner:
    """Records calls; ``handler(call)`` may return a Result, else success is assumed."""

    handler: Callable[[Call], Result | None] | None = None
    calls: list[Call] = field(default_factory=list)

    def run(
        self,
        cmd: Any,
        *,
        shell: bool = False,
        input: bytes | None = None,
        timeout: float | None = None,
        env: Any = None,
    ) -> Result:
        call = Call(cmd, shell, dict(env) if env else None, timeout)
        self.calls.append(call)
        if self.handler:
            res = self.handler(call)
            if res is not None:
                return res
        return Result(0, b"", b"")


def kubectl_handler(
    objects: dict[tuple[str, str], dict[str, Any]],
) -> Callable[[Call], Result | None]:
    """Serve ``kubectl get <kind> <name> -o json`` from a dict keyed by (kind, name)."""

    def handler(call: Call) -> Result | None:
        argv = call.argv
        if "get" not in argv:
            return None
        i = argv.index("get")
        kind, name = argv[i + 1], argv[i + 2]
        kind = "certificate" if kind.startswith("certificate") else kind
        obj = objects.get((kind, name))
        if obj is None:
            return Result(
                1, b"", f'Error from server (NotFound): {kind} "{name}" not found'.encode()
            )
        return Result(0, json.dumps(obj).encode(), b"")

    return handler


# ------------------------------------------------------ fake executables on disk

FAKE_KUBECTL = r"""
import json, os, sys
args = sys.argv[1:]
log = os.environ.get("FAKE_LOG")
if log:
    with open(log, "a") as fh:
        fh.write(json.dumps(["kubectl"] + args) + "\n")
ns = "default"
pos = []
i = 0
while i < len(args):
    a = args[i]
    if a in ("-n", "--namespace"):
        ns = args[i + 1]; i += 2; continue
    if a in ("--context", "--kubeconfig", "--cache-dir", "-o"):
        i += 2; continue
    pos.append(a); i += 1
kind, name = pos[1], pos[2]
kind = "certificate" if kind.startswith("certificate") else kind
path = os.path.join(os.environ["FAKE_KUBE_DIR"], f"{kind}-{ns}-{name}.json")
if not os.path.exists(path):
    sys.stderr.write(f'Error from server (NotFound): {kind} "{name}" not found\n')
    sys.exit(1)
with open(path) as fh:
    sys.stdout.write(fh.read())
"""

FAKE_SSH = r"""
import json, os, subprocess, sys
args = sys.argv[1:]
log = os.environ.get("FAKE_LOG")
if log:
    with open(log, "a") as fh:
        fh.write(json.dumps(["ssh"] + args) + "\n")
i = 0
while i < len(args):
    a = args[i]
    if a in ("-p", "-i", "-o", "-l", "-F"):
        i += 2; continue
    if a.startswith("-") and a != "--":
        i += 1; continue
    break
dest = args[i]
rest = args[i + 1:]
if rest and rest[0] == "--":
    rest = rest[1:]
host = dest.split("@")[-1]
if host in os.environ.get("FAKE_SSH_DOWN", "").split(","):
    sys.stderr.write(f"ssh: connect to host {host} port 22: Connection refused\n")
    sys.exit(255)
sys.exit(subprocess.run(["sh", "-c", " ".join(rest)]).returncode)
"""

FAKE_SCP = r"""
import json, os, shutil, sys
args = sys.argv[1:]
log = os.environ.get("FAKE_LOG")
if log:
    with open(log, "a") as fh:
        fh.write(json.dumps(["scp"] + args) + "\n")
i = 0
while i < len(args):
    a = args[i]
    if a in ("-P", "-i", "-o", "-F", "-l"):
        i += 2; continue
    if a.startswith("-"):
        i += 1; continue
    break
pos = args[i:]
sources, dest = pos[:-1], pos[-1]
host = dest.split("]:", 1)[0] if "]:" in dest else dest.split(":", 1)[0]
if host.split("@")[-1].strip("[") in os.environ.get("FAKE_SSH_DOWN", "").split(","):
    sys.stderr.write("ssh: connect to host: Connection refused\n")
    sys.exit(1)
path = dest.split("]:", 1)[1] if "]:" in dest else dest.split(":", 1)[1]
if not os.path.isdir(path):
    sys.stderr.write(f"scp: {path}: No such file or directory\n")
    sys.exit(1)
for src in sources:
    shutil.copy2(src, os.path.join(path, os.path.basename(src)))
"""


@dataclass
class FakeBins:
    dir: Path
    kube_dir: Path
    log: Path

    @property
    def kubectl(self) -> str:
        return str(self.dir / "kubectl")

    @property
    def ssh(self) -> str:
        return str(self.dir / "ssh")

    @property
    def scp(self) -> str:
        return str(self.dir / "scp")

    def args(self) -> list[str]:
        return ["--kubectl", self.kubectl, "--ssh-bin", self.ssh, "--scp-bin", self.scp]

    def add(self, kind: str, obj: dict[str, Any]) -> None:
        meta = obj["metadata"]
        (self.kube_dir / f"{kind}-{meta['namespace']}-{meta['name']}.json").write_text(
            json.dumps(obj)
        )

    def calls(self, tool: str | None = None) -> list[list[str]]:
        if not self.log.exists():
            return []
        rows = [json.loads(line) for line in self.log.read_text().splitlines()]
        return [r for r in rows if tool is None or r[0] == tool]


@pytest.fixture
def fake_bins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeBins:
    bin_dir = tmp_path / "bin"
    kube_dir = tmp_path / "kube"
    bin_dir.mkdir()
    kube_dir.mkdir()
    for name, body in (("kubectl", FAKE_KUBECTL), ("ssh", FAKE_SSH), ("scp", FAKE_SCP)):
        path = bin_dir / name
        path.write_text(f"#!{sys.executable}\n{body}")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    log = tmp_path / "calls.log"
    monkeypatch.setenv("FAKE_KUBE_DIR", str(kube_dir))
    monkeypatch.setenv("FAKE_LOG", str(log))
    monkeypatch.delenv("FAKE_SSH_DOWN", raising=False)
    return FakeBins(bin_dir, kube_dir, log)


# ------------------------------------------------------------- TLS server


@dataclass
class TlsServer:
    host: str
    port: int

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"


def _serve(sock: socket.socket, context: ssl.SSLContext, stop: threading.Event) -> None:
    sock.settimeout(0.2)
    while not stop.is_set():
        try:
            conn, _ = sock.accept()
        except (TimeoutError, OSError):
            continue
        try:
            conn.settimeout(2)
            with context.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)
        except (OSError, ssl.SSLError):
            pass


@pytest.fixture
def tls_server_factory(tmp_path: Path) -> Iterator[Callable[[Pki], TlsServer]]:
    stops: list[tuple[threading.Event, socket.socket, threading.Thread]] = []

    def start(material: Pki) -> TlsServer:
        index = len(stops)
        cert = tmp_path / f"server{index}.crt"
        key = tmp_path / f"server{index}.key"
        cert.write_bytes(material.tls_crt)
        key.write_bytes(material.tls_key)
        os.chmod(key, 0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(8)
        stop = threading.Event()
        thread = threading.Thread(target=_serve, args=(sock, context, stop), daemon=True)
        thread.start()
        stops.append((stop, sock, thread))
        return TlsServer("127.0.0.1", sock.getsockname()[1])

    yield start
    for stop, sock, thread in stops:
        stop.set()
        thread.join(timeout=2)
        sock.close()


@pytest.fixture
def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
