"""End-to-end tests through ``main()`` using fake kubectl/ssh/scp executables on disk."""

from __future__ import annotations

import io
import itertools
import json
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from certferry import __version__
from certferry.certs import FORMATS
from certferry.cli import main

from .conftest import FakeBins, Pki, certificate_resource


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def events(stdout: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stdout.splitlines()]


@pytest.fixture
def cluster(fake_bins: FakeBins, pki: Pki) -> FakeBins:
    fake_bins.add("secret", pki.secret("web-tls", "web"))
    fake_bins.add("certificate", certificate_resource("web", "web-tls", "web"))
    return fake_bins


# ---------------------------------------------------------------- use cases


def test_use_case_1_directory_and_nginx_reload(cluster: FakeBins, pki: Pki, tmp_path: Path) -> None:
    ssl_dir = tmp_path / "etc-nginx-ssl"
    marker = tmp_path / "nginx-reloaded"
    code, out, _ = run(
        [
            *cluster.args(),
            "--secret",
            "web-tls",
            "-n",
            "web",
            "--context",
            "prod",
            "--target",
            str(ssl_dir),
            "--filename",
            "fullchain=example.com.crt",
            "--filename",
            "key=example.com.key",
            "--exec",
            f'echo "$CERTFERRY_FINGERPRINT" > {marker}',
            "--verify-files",
            "-o",
            "jsonl",
        ]
    )
    assert code == 0
    assert (ssl_dir / "example.com.crt").read_bytes() == pki.tls_crt
    assert stat.S_IMODE((ssl_dir / "example.com.key").stat().st_mode) == 0o600
    evs = events(out)
    fingerprint = evs[0]["fingerprint"]
    assert marker.read_text().strip() == fingerprint
    assert [e["step"] for e in evs] == [
        "extract",
        "render",
        "deploy",
        "command",
        "verify-files",
        "expiry",
        "summary",
    ]
    kubectl = cluster.calls("kubectl")[0]
    assert kubectl[1:] == [
        "--context",
        "prod",
        "--namespace",
        "web",
        "get",
        "secret",
        "web-tls",
        "-o",
        "json",
    ]


def test_use_case_2_scp_and_caddy_reload(cluster: FakeBins, pki: Pki, tmp_path: Path) -> None:
    remote_dir = tmp_path / "remote" / "srv" / "caddy" / "certs"
    remote_marker = tmp_path / "remote" / "caddy-reloaded"
    code, out, _ = run(
        [
            *cluster.args(),
            "--certificate",
            "web",
            "-n",
            "web",
            "--target",
            f"scp://deploy@proxy.example.test:2222{remote_dir}",
            "--remote-exec",
            "deploy@proxy.example.test:2222",
            f"touch {remote_marker} && echo docker exec caddy caddy reload --force",
            "-i",
            "/home/me/.ssh/id_ed25519",
            "--ssh-option",
            "StrictHostKeyChecking=yes",
            "--verify-files",
            "-o",
            "jsonl",
        ]
    )
    assert code == 0, out
    assert (remote_dir / "fullchain.pem").read_bytes() == pki.tls_crt
    assert (remote_dir / "key.pem").read_bytes() == pki.tls_key.strip() + b"\n"
    assert sorted(p.name for p in remote_dir.iterdir()) == ["fullchain.pem", "key.pem"]
    assert remote_marker.exists()
    scp = cluster.calls("scp")[0]
    assert scp[1:5] == ["-p", "-q", "-P", "2222"]
    assert "-i" in scp and "StrictHostKeyChecking=yes" in scp
    assert scp[-1] == f"deploy@proxy.example.test:{remote_dir}/"
    ssh_dests = {c[c.index("--") - 1] for c in cluster.calls("ssh")}
    assert ssh_dests == {"deploy@proxy.example.test"}
    targets = [e["target"] for e in events(out) if e["step"] == "deploy"]
    assert targets == [f"scp://deploy@proxy.example.test:2222{remote_dir}"]


def test_use_case_3_yaml_combination(
    cluster: FakeBins,
    pki: Pki,
    rsa_pki: Pki,
    tmp_path: Path,
    tls_server_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cluster.add("secret", rsa_pki.secret("java-tls", "apps"))
    server = tls_server_factory(pki)
    monkeypatch.setenv("P12_PASSWORD", "changeit")
    local, remote, java = tmp_path / "nginx", tmp_path / "remote", tmp_path / "java"
    log = tmp_path / "commands.log"
    config = tmp_path / "certferry.yaml"
    config.write_text(f"""
defaults:
  kubectl: {cluster.kubectl}
  context: prod
  ssh:
    ssh_bin: {cluster.ssh}
    scp_bin: {cluster.scp}
    options: [StrictHostKeyChecking=accept-new]
  verify:
    retries: 2
    delay: 0
jobs:
  - name: website
    certificate: web
    namespace: web
    formats: [fullchain, key, combined]
    targets:
      - {local}
      - type: scp
        host: proxy
        user: deploy
        path: {remote}
    commands:
      - echo nginx >> {log}
      - run: echo caddy >> {log}
        host: deploy@proxy
    verify:
      files: true
      endpoints:
        - host: {server.host}
          port: {server.port}
          servername: www.example.test
    min_days: 14
  - name: java
    secret: java-tls
    namespace: apps
    formats: [pkcs12, cert, chain, ca]
    filenames: {{pkcs12: keystore.p12}}
    pkcs12: {{password_env: P12_PASSWORD, legacy: true, friendly_name: tomcat}}
    targets: [{java}]
    commands:
      - run: [sh, -c, "echo java >> {log}"]
    verify: {{files: true}}
""")
    code, out, _ = run(["--config", str(config), "-o", "json"])
    doc = json.loads(out)
    assert code == 0, out
    assert doc["status"] == "ok" and [j["name"] for j in doc["jobs"]] == ["website", "java"]
    assert log.read_text().split() == ["nginx", "caddy", "java"]
    assert (local / "combined.pem").read_bytes().endswith(pki.tls_key.strip() + b"\n")
    assert (remote / "combined.pem").read_bytes() == (local / "combined.pem").read_bytes()
    from cryptography.hazmat.primitives.serialization import pkcs12

    bundle = pkcs12.load_pkcs12((java / "keystore.p12").read_bytes(), b"changeit")
    assert bundle.cert is not None and bundle.cert.certificate == rsa_pki.leaf_cert
    assert bundle.cert.friendly_name == b"tomcat"
    website = doc["jobs"][0]
    assert any(e["step"] == "verify-endpoint" and e["status"] == "ok" for e in website["events"])

    # Second run: --only-if-changed must skip deploy and every command.
    log.unlink()
    code, out, _ = run(["--config", str(config), "--only-if-changed", "-o", "json"])
    doc = json.loads(out)
    assert code == 0 and not log.exists()
    assert [j["changed"] for j in doc["jobs"]] == [False, False]


# --------------------------------------------------------- full option matrix

TARGETS = ["dir", "scp", "dir+scp"]
COMMANDS = ["none", "local", "remote", "local+remote"]
VERIFY = ["none", "files", "endpoint", "files+endpoint"]


@pytest.mark.parametrize(
    ("targets", "commands", "verify"), list(itertools.product(TARGETS, COMMANDS, VERIFY))
)
def test_combinations(
    cluster: FakeBins,
    pki: Pki,
    tmp_path: Path,
    tls_server_factory: Any,
    targets: str,
    commands: str,
    verify: str,
) -> None:
    argv = [
        *cluster.args(),
        "--secret",
        "web-tls",
        "-n",
        "web",
        "-o",
        "jsonl",
        "--verify-retries",
        "1",
    ]
    expect_dirs: list[Path] = []
    if "dir" in targets.split("+"):
        expect_dirs.append(tmp_path / "local")
        argv += ["-t", str(tmp_path / "local")]
    if "scp" in targets.split("+"):
        expect_dirs.append(tmp_path / "remote")
        argv += ["-t", f"deploy@proxy:{tmp_path / 'remote'}"]
    markers: list[Path] = []
    if "local" in commands.split("+"):
        markers.append(tmp_path / "local-cmd")
        argv += ["-x", f"touch {markers[-1]}"]
    if "remote" in commands.split("+"):
        markers.append(tmp_path / "remote-cmd")
        argv += ["--remote-exec", "proxy", f"touch {markers[-1]}"]
    if "files" in verify.split("+"):
        argv += ["--verify-files"]
    if "endpoint" in verify.split("+"):
        argv += [
            "--verify-endpoint",
            tls_server_factory(pki).endpoint,
            "--verify-servername",
            "www.example.test",
        ]

    code, out, _ = run(argv)
    assert code == 0, out
    for d in expect_dirs:
        assert (d / "fullchain.pem").read_bytes() == pki.tls_crt
    for m in markers:
        assert m.exists()
    step_names = [e["step"] for e in events(out)]
    assert step_names.count("deploy") == len(expect_dirs)
    assert step_names.count("command") == len(markers)
    assert step_names.count("verify-files") == (len(expect_dirs) if "files" in verify else 0)
    assert step_names.count("verify-endpoint") == (1 if "endpoint" in verify else 0)


@pytest.mark.parametrize("fmt", list(FORMATS))
@pytest.mark.parametrize("target", ["dir", "scp"])
def test_each_format_to_each_target(
    cluster: FakeBins, tmp_path: Path, fmt: str, target: str
) -> None:
    dest = tmp_path / "out"
    spec = str(dest) if target == "dir" else f"proxy:{dest}"
    code, out, _ = run(
        [
            *cluster.args(),
            "-s",
            "web-tls",
            "-n",
            "web",
            "-f",
            fmt,
            "-t",
            spec,
            "--verify-files",
            "--pkcs12-password-env",
            "HOME",
        ]
    )
    assert code == 0, out
    path = dest / FORMATS[fmt].default_filename
    expected_mode = 0o600 if FORMATS[fmt].secret else 0o644
    assert stat.S_IMODE(path.stat().st_mode) == expected_mode


# ------------------------------------------------------------- behaviour


def test_text_output_is_logfmt(cluster: FakeBins, tmp_path: Path) -> None:
    code, out, _ = run([*cluster.args(), "-s", "web-tls", "-n", "web", "-t", str(tmp_path)])
    assert code == 0
    lines = out.splitlines()
    assert lines[0].startswith("job=web-tls step=extract status=ok secret=web/web-tls ")
    assert lines[-1] == 'step=summary status=ok exit_code=0 jobs=1 failed="" changed=web-tls'
    assert all("\x1b" not in line for line in lines)


def test_modes_owner_and_no_create(cluster: FakeBins, tmp_path: Path) -> None:
    import os

    code, _, _ = run(
        [
            *cluster.args(),
            "-s",
            "web-tls",
            "-n",
            "web",
            "-t",
            str(tmp_path),
            "--cert-mode",
            "0640",
            "--key-mode",
            "0400",
            "--owner",
            str(os.getuid()),
            "--group",
            str(os.getgid()),
            "--no-create",
        ]
    )
    assert code == 0
    assert stat.S_IMODE((tmp_path / "fullchain.pem").stat().st_mode) == 0o640
    assert stat.S_IMODE((tmp_path / "key.pem").stat().st_mode) == 0o400
    code, out, _ = run(
        [
            *cluster.args(),
            "-s",
            "web-tls",
            "-n",
            "web",
            "-t",
            str(tmp_path / "missing"),
            "--no-create",
        ]
    )
    assert code == 4 and "does not exist" in out


def test_dry_run_writes_nothing(cluster: FakeBins, tmp_path: Path) -> None:
    code, out, _ = run(
        [
            *cluster.args(),
            "-s",
            "web-tls",
            "-n",
            "web",
            "-t",
            str(tmp_path / "x"),
            "-x",
            f"touch {tmp_path / 'marker'}",
            "--dry-run",
        ]
    )
    assert code == 0 and "status=dry-run" in out
    assert not (tmp_path / "x").exists() and not (tmp_path / "marker").exists()


def test_command_failure_exit_code(cluster: FakeBins, tmp_path: Path) -> None:
    code, out, err = run(
        [
            *cluster.args(),
            "-s",
            "web-tls",
            "-n",
            "web",
            "-t",
            str(tmp_path),
            "-x",
            "echo nope >&2; exit 3",
        ]
    )
    assert code == 5
    assert "step=command status=failed" in out and "nope" in out
    assert "job web-tls failed" in err


def test_remote_host_down(
    cluster: FakeBins, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_SSH_DOWN", "proxy")
    code, out, _ = run([*cluster.args(), "-s", "web-tls", "-n", "web", "-t", f"proxy:{tmp_path}"])
    assert code == 4 and "Connection refused" in out


def test_missing_secret(cluster: FakeBins) -> None:
    code, out, _ = run([*cluster.args(), "-s", "nope", "-n", "web"])
    assert code == 3 and "NotFound" in out


def test_min_days(cluster: FakeBins) -> None:
    code, out, _ = run([*cluster.args(), "-s", "web-tls", "-n", "web", "--min-days", "100"])
    assert code == 7 and "step=expiry status=failed" in out


def test_verify_endpoint_mismatch(
    cluster: FakeBins, other_pki: Pki, tls_server_factory: Any
) -> None:
    server = tls_server_factory(other_pki)
    code, out, _ = run(
        [
            *cluster.args(),
            "-s",
            "web-tls",
            "-n",
            "web",
            "--verify-endpoint",
            server.endpoint,
            "--verify-retries",
            "2",
            "--verify-delay",
            "0",
            "--verify-timeout",
            "2",
        ]
    )
    assert code == 6 and "serves different certificate" in out


def test_fail_fast_and_job_selection(cluster: FakeBins, tmp_path: Path) -> None:
    config = tmp_path / "c.yaml"
    config.write_text(f"""
defaults: {{kubectl: {cluster.kubectl}, namespace: web}}
jobs:
  - {{name: broken, secret: missing}}
  - {{name: good, secret: web-tls, targets: [{tmp_path / "good"}]}}
""")
    code, out, _ = run(["-c", str(config)])
    assert code == 3 and (tmp_path / "good" / "key.pem").exists()
    assert "failed=broken" in out.splitlines()[-1]

    (tmp_path / "good" / "key.pem").unlink()
    code, _, _ = run(["-c", str(config), "--fail-fast"])
    assert code == 3 and not (tmp_path / "good" / "key.pem").exists()

    code, _, _ = run(["-c", str(config), "-j", "good"])
    assert code == 0


def test_check_config(cluster: FakeBins, tmp_path: Path) -> None:
    code, out, _ = run(
        [
            *cluster.args(),
            "--certificate",
            "web",
            "-t",
            "/a",
            "-t",
            "h:/b",
            "-x",
            "reload",
            "--remote-exec",
            "h",
            "r",
            "--check-config",
        ]
    )
    assert code == 0
    assert out.startswith("job=web step=config status=ok source=certificate:-/web")
    assert "targets=dir:/a,scp://h/b" in out
    code, out, _ = run([*cluster.args(), "-s", "x", "--check-config", "-o", "json"])
    assert json.loads(out)[0]["job"] == "x"
    assert cluster.calls() == []


def test_list_formats() -> None:
    code, out, _ = run(["--list-formats"])
    assert code == 0 and len(out.splitlines()) == len(FORMATS)
    assert "format=pkcs12 filename=cert.p12 secret=true" in out


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        ([], "exactly one of"),
        (["-s", "a", "--filename", "nonsense"], "FORMAT=NAME"),
        (["-s", "a", "--remote-exec", "h/x", "cmd"], "must not contain a path"),
        (["-s", "a", "-t", "scp://"], "missing host"),
        (["-s", "a", "--verify-endpoint", ":1"], "invalid endpoint"),
        (["-c", "/does/not/exist.yaml"], "cannot read config"),
    ],
)
def test_config_errors(argv: list[str], message: str) -> None:
    code, out, err = run(argv)
    assert code == 2 and message in err and out == ""


def test_argparse_errors_exit_2(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["-s", "a", "-f", "nope"])
    assert exc.value.code == 2


def test_verbose_logging_goes_to_stderr(
    cluster: FakeBins, capsys: pytest.CaptureFixture[str]
) -> None:
    out = io.StringIO()
    main([*cluster.args(), "-s", "web-tls", "-n", "web", "-vv"], stdout=out)
    assert "DEBUG exec:" in capsys.readouterr().err
    assert "BEGIN" not in out.getvalue()


def test_module_entry_point_and_version() -> None:
    res = subprocess.run(
        [sys.executable, "-m", "certferry", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0 and res.stdout.strip() == f"certferry {__version__}"


def test_container_env_defaults(
    cluster: FakeBins, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "env.yaml"
    config.write_text(f"secret: web-tls\nnamespace: web\nkubectl: {cluster.kubectl}\n")
    monkeypatch.setenv("CERTFERRY_CONFIG", str(config))
    monkeypatch.setenv("CERTFERRY_KUBECTL_CACHE_DIR", str(tmp_path / "kube-cache"))
    code, out, _ = run([])
    assert code == 0, out
    kubectl = cluster.calls("kubectl")[0]
    assert kubectl[1:3] == ["--cache-dir", str(tmp_path / "kube-cache")]
    # An explicit option wins over the environment.
    code, _, _ = run(["--kubectl-cache-dir", "/other"])
    assert code == 0
    assert cluster.calls("kubectl")[-1][1:3] == ["--cache-dir", "/other"]
