from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from certferry.config import build_job
from certferry.errors import (
    EXIT_COMMAND,
    EXIT_DEPLOY,
    EXIT_EXPIRY,
    EXIT_EXTRACT,
    EXIT_VERIFY,
)
from certferry.pipeline import RunContext, run_job
from certferry.report import Reporter
from certferry.runner import Result

from .conftest import Call, FakeRunner, Pki, kubectl_handler


def make_runner(pki: Pki, extra: Any = None) -> FakeRunner:
    kube = kubectl_handler({("secret", "web-tls"): pki.secret()})

    def handler(call: Call) -> Result | None:
        if call.argv[0] == "kubectl":
            return kube(call)
        return extra(call) if extra else None

    return FakeRunner(handler)


def context(runner: FakeRunner, **kw: Any) -> RunContext:
    return RunContext(runner=runner, reporter=Reporter(io.StringIO(), "jsonl"), **kw)


def steps(result: Any) -> list[tuple[str, str]]:
    return [(e["step"], e["status"]) for e in result.events]


def test_happy_path_dir_and_local_command(pki: Pki, tmp_path: Path) -> None:
    job = build_job(
        {
            "secret": "web-tls",
            "targets": [str(tmp_path)],
            "commands": ["systemctl reload nginx"],
            "verify": {"files": True},
        },
        0,
    )
    runner = make_runner(pki)
    result = run_job(job, context(runner))
    assert result.status == "ok" and result.exit_code == 0 and result.changed
    assert steps(result) == [
        ("extract", "ok"),
        ("render", "ok"),
        ("deploy", "ok"),
        ("command", "ok"),
        ("verify-files", "ok"),
        ("expiry", "ok"),
    ]
    assert (tmp_path / "fullchain.pem").read_bytes() == pki.tls_crt
    command_call = runner.calls[-1]
    assert command_call.env is not None
    assert command_call.env["CERTFERRY_JOB"] == "web-tls"
    assert command_call.env["CERTFERRY_FINGERPRINT"] == result.certificate["fingerprint_sha256"]
    assert command_call.env["CERTFERRY_COMMON_NAME"] == "www.example.test"


def test_no_targets_still_runs_commands(pki: Pki) -> None:
    job = build_job({"secret": "web-tls", "commands": ["true"], "only_if_changed": True}, 0)
    result = run_job(job, context(make_runner(pki)))
    assert ("command", "ok") in steps(result)
    assert result.changed is False


def test_only_if_changed(pki: Pki, tmp_path: Path) -> None:
    raw = {
        "secret": "web-tls",
        "targets": [str(tmp_path)],
        "commands": ["reload"],
        "only_if_changed": True,
        "formats": ["fullchain", "key", "pkcs12"],
        "pkcs12": {"password": "pw"},
    }
    job = build_job(raw, 0)
    first = run_job(job, context(make_runner(pki)))
    assert ("compare", "changed") in steps(first) and ("command", "ok") in steps(first)

    runner = make_runner(pki)
    second = run_job(job, context(runner))
    assert second.changed is False
    assert ("compare", "unchanged") in steps(second)
    assert ("deploy", "skipped") in steps(second) and ("command", "skipped") in steps(second)
    assert all(c.argv[0] == "kubectl" for c in runner.calls)

    forced = run_job(job, context(make_runner(pki), force=True))
    assert ("deploy", "ok") in steps(forced) and ("command", "ok") in steps(forced)
    assert not any(s == "compare" for s, _ in steps(forced))


def test_only_if_changed_mixed_targets(pki: Pki, tmp_path: Path) -> None:
    current, stale = tmp_path / "current", tmp_path / "stale"
    build_job({"secret": "web-tls", "targets": [str(current)]}, 0)
    run_job(
        build_job({"secret": "web-tls", "targets": [str(current)]}, 0), context(make_runner(pki))
    )
    job = build_job(
        {"secret": "web-tls", "targets": [str(current), str(stale)], "only_if_changed": True}, 0
    )
    result = run_job(job, context(make_runner(pki)))
    deploys = [(e["status"], e["target"]) for e in result.events if e["step"] == "deploy"]
    assert deploys == [("skipped", f"dir:{current}"), ("ok", f"dir:{stale}")]


def test_unreachable_target_counts_as_changed(pki: Pki) -> None:
    job = build_job({"secret": "web-tls", "targets": ["h:/x"], "only_if_changed": True}, 0)
    runner = make_runner(pki, lambda c: Result(255, b"", b"down"))
    result = run_job(job, context(runner))
    assert ("compare", "changed") in steps(result)
    assert result.exit_code == EXIT_DEPLOY


def test_dry_run(pki: Pki, tmp_path: Path) -> None:
    job = build_job(
        {
            "secret": "web-tls",
            "targets": [str(tmp_path / "out")],
            "commands": ["reload"],
            "verify": {"files": True, "endpoints": ["localhost:1"]},
        },
        0,
    )
    runner = make_runner(pki)
    result = run_job(job, context(runner, dry_run=True))
    assert result.exit_code == 0
    assert ("deploy", "dry-run") in steps(result) and ("command", "dry-run") in steps(result)
    assert ("verify-files", "skipped") in steps(result)
    assert ("verify-endpoint", "skipped") in steps(result)
    assert not (tmp_path / "out").exists()
    assert [c.argv[0] for c in runner.calls] == ["kubectl"]


def test_endpoint_verification(pki: Pki) -> None:
    job = build_job(
        {"secret": "web-tls", "verify": {"endpoints": ["a", "b:8443"], "retries": 2, "delay": 0}}, 0
    )
    seen: list[tuple[str, int]] = []

    def fetch(host: str, port: int, sni: str | None, timeout: float) -> bytes:
        seen.append((host, port))
        return pki.leaf_der

    result = run_job(job, context(make_runner(pki), fetch_peer=fetch))
    assert seen == [("a", 443), ("b", 8443)]
    assert [e["endpoint"] for e in result.events if e["step"] == "verify-endpoint"] == [
        "a:443",
        "b:8443",
    ]


def test_endpoint_verification_failure(pki: Pki) -> None:
    job = build_job({"secret": "web-tls", "verify": {"endpoints": ["a"], "retries": 2}}, 0)
    result = run_job(
        job, context(make_runner(pki), fetch_peer=lambda *a: b"old", sleep=lambda s: None)
    )
    assert result.exit_code == EXIT_VERIFY
    assert result.events[-1]["step"] == "verify-endpoint"
    assert result.events[-1]["status"] == "failed"


def test_verify_files_failure(pki: Pki, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from certferry import targets

    job = build_job({"secret": "web-tls", "targets": [str(tmp_path)], "verify": {"files": True}}, 0)
    monkeypatch.setattr(targets.DirTarget, "read", lambda self, name, runner: b"x")
    result = run_job(job, context(make_runner(pki)))
    assert result.exit_code == EXIT_VERIFY
    assert "fullchain.pem, key.pem" in (result.error or "")


@pytest.mark.parametrize(
    ("days_left", "min_days", "code"), [(30, 14, 0), (10, 14, EXIT_EXPIRY), (-1, 0, EXIT_EXPIRY)]
)
def test_expiry(pki: Pki, tmp_path: Path, days_left: float, min_days: float, code: int) -> None:
    job = build_job({"secret": "web-tls", "targets": [str(tmp_path)], "min_days": min_days}, 0)
    not_after = pki.leaf_cert.not_valid_after_utc
    now = not_after - timedelta(days=days_left)
    result = run_job(job, context(make_runner(pki), now=lambda: now))
    assert result.exit_code == code
    # The certificate is still deployed even when it is close to expiry.
    assert (tmp_path / "key.pem").exists()


def test_expiry_threshold_not_set(pki: Pki) -> None:
    job = build_job({"secret": "web-tls"}, 0)
    later = datetime.now(timezone.utc) + timedelta(days=365)
    result = run_job(job, context(make_runner(pki), now=lambda: later))
    assert result.exit_code == 0


def test_extract_failure(pki: Pki) -> None:
    job = build_job({"secret": "missing", "targets": ["/nonexistent"]}, 0)
    result = run_job(job, context(make_runner(pki)))
    assert result.exit_code == EXIT_EXTRACT
    assert steps(result) == [("extract", "failed")]


def test_render_failure(pki: Pki) -> None:
    obj = pki.secret(include_ca=False)
    runner = FakeRunner(kubectl_handler({("secret", "web-tls"): obj}))
    job = build_job({"secret": "web-tls", "formats": ["ca"]}, 0)
    result = run_job(job, context(runner))
    assert result.exit_code == EXIT_EXTRACT and steps(result)[-1] == ("render", "failed")


def test_command_failure_stops_job(pki: Pki, tmp_path: Path) -> None:
    job = build_job(
        {"secret": "web-tls", "targets": [str(tmp_path)], "commands": ["first", "second"]}, 0
    )
    runner = make_runner(pki, lambda c: Result(1, b"", b"boom") if c.cmd == "first" else None)
    result = run_job(job, context(runner))
    assert result.exit_code == EXIT_COMMAND
    assert [c.cmd for c in runner.calls if c.shell] == ["first"]
