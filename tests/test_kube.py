from __future__ import annotations

import pytest

from certferry.errors import ExtractError
from certferry.kube import SourceConfig, fetch_secret, kubectl_base, resolve_secret_name
from certferry.runner import Result

from .conftest import Call, FakeRunner, Pki, certificate_resource, kubectl_handler


def test_kubectl_base_minimal() -> None:
    assert kubectl_base(SourceConfig(secret="s")) == ["kubectl"]


def test_kubectl_base_full() -> None:
    src = SourceConfig(secret="s", namespace="ns", context="prod", kubeconfig="/k", kubectl="kc")
    assert kubectl_base(src) == [
        "kc",
        "--kubeconfig",
        "/k",
        "--context",
        "prod",
        "--namespace",
        "ns",
    ]


def test_source_label() -> None:
    assert SourceConfig(secret="s", namespace="n").label == "secret:n/s"
    assert SourceConfig(certificate="c").label == "certificate:-/c"


def test_fetch_secret(pki: Pki) -> None:
    runner = FakeRunner(kubectl_handler({("secret", "web-tls"): pki.secret(namespace="web")}))
    data = fetch_secret(SourceConfig(secret="web-tls", namespace="web", kubectl_timeout=7), runner)
    assert data.tls_crt == pki.tls_crt
    assert data.tls_key == pki.tls_key
    assert data.ca_crt == pki.ca_crt
    assert data.namespace == "web"
    assert runner.calls[0].argv == [
        "kubectl",
        "--namespace",
        "web",
        "get",
        "secret",
        "web-tls",
        "-o",
        "json",
    ]
    assert runner.calls[0].timeout == 7


def test_fetch_secret_without_ca_and_opaque(pki: Pki) -> None:
    obj = pki.secret(include_ca=False, type_="Opaque")
    runner = FakeRunner(kubectl_handler({("secret", "web-tls"): obj}))
    assert fetch_secret(SourceConfig(secret="web-tls"), runner).ca_crt is None


def test_via_certificate(pki: Pki) -> None:
    runner = FakeRunner(
        kubectl_handler(
            {
                ("certificate", "web"): certificate_resource("web", "web-tls"),
                ("secret", "web-tls"): pki.secret(),
            }
        )
    )
    data = fetch_secret(SourceConfig(certificate="web"), runner)
    assert data.name == "web-tls"
    assert runner.calls[0].argv[1:3] == ["get", "certificates.cert-manager.io"]


def test_certificate_not_ready() -> None:
    runner = FakeRunner(
        kubectl_handler(
            {("certificate", "web"): certificate_resource("web", "web-tls", ready=False)}
        )
    )
    with pytest.raises(ExtractError, match="not Ready: Issuing certificate"):
        resolve_secret_name(SourceConfig(certificate="web"), runner)


def test_certificate_not_ready_allowed() -> None:
    runner = FakeRunner(
        kubectl_handler(
            {("certificate", "web"): certificate_resource("web", "web-tls", ready=False)}
        )
    )
    src = SourceConfig(certificate="web", require_ready=False)
    assert resolve_secret_name(src, runner) == "web-tls"


def test_certificate_without_conditions() -> None:
    obj = certificate_resource("web", "web-tls")
    obj["status"] = {}
    runner = FakeRunner(kubectl_handler({("certificate", "web"): obj}))
    with pytest.raises(ExtractError, match="no condition"):
        resolve_secret_name(SourceConfig(certificate="web"), runner)


def test_certificate_without_secret_name() -> None:
    obj = certificate_resource("web", "web-tls")
    obj["spec"] = {}
    runner = FakeRunner(kubectl_handler({("certificate", "web"): obj}))
    with pytest.raises(ExtractError, match="no spec.secretName"):
        resolve_secret_name(SourceConfig(certificate="web"), runner)


def test_not_found() -> None:
    runner = FakeRunner(kubectl_handler({}))
    with pytest.raises(ExtractError, match=r"failed \(exit 1\): Error from server \(NotFound\)"):
        fetch_secret(SourceConfig(secret="missing"), runner)


@pytest.mark.parametrize("payload", [b"not json", b"[1, 2]"])
def test_bad_output(payload: bytes) -> None:
    runner = FakeRunner(lambda call: Result(0, payload, b""))
    with pytest.raises(ExtractError, match="JSON|unexpected"):
        fetch_secret(SourceConfig(secret="s"), runner)


def test_wrong_type(pki: Pki) -> None:
    obj = pki.secret(type_="kubernetes.io/dockerconfigjson")
    runner = FakeRunner(kubectl_handler({("secret", "web-tls"): obj}))
    with pytest.raises(ExtractError, match="unsupported type"):
        fetch_secret(SourceConfig(secret="web-tls"), runner)


def test_missing_key(pki: Pki) -> None:
    obj = pki.secret()
    del obj["data"]["tls.key"]
    runner = FakeRunner(kubectl_handler({("secret", "web-tls"): obj}))
    with pytest.raises(ExtractError, match="does not contain"):
        fetch_secret(SourceConfig(secret="web-tls"), runner)


def test_bad_base64(pki: Pki) -> None:
    obj = pki.secret()
    obj["data"]["tls.crt"] = "!!!notbase64"
    runner = FakeRunner(kubectl_handler({("secret", "web-tls"): obj}))
    with pytest.raises(ExtractError, match="not valid base64"):
        fetch_secret(SourceConfig(secret="web-tls"), runner)


def test_namespace_falls_back_to_source(pki: Pki) -> None:
    obj = pki.secret()
    obj["metadata"] = {"name": "web-tls"}

    def handler(call: Call) -> Result | None:
        return kubectl_handler({("secret", "web-tls"): obj})(call)

    data = fetch_secret(SourceConfig(secret="web-tls", namespace="x"), FakeRunner(handler))
    assert data.namespace == "x"
