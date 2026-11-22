from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from certferry.config import (
    build_job,
    load_file,
    merge,
    parse_endpoint_spec,
    parse_target_spec,
    resolve_jobs,
)
from certferry.errors import ConfigError
from certferry.targets import DirTarget, ScpTarget


def write(tmp_path: Path, text: str) -> str:
    path = tmp_path / "certferry.yaml"
    path.write_text(text)
    return str(path)


class TestTargetSpec:
    @pytest.mark.parametrize(
        ("spec", "expected"),
        [
            ("/etc/nginx/ssl", {"type": "dir", "path": "/etc/nginx/ssl"}),
            ("./certs", {"type": "dir", "path": "./certs"}),
            ("relative", {"type": "dir", "path": "relative"}),
            ("dir:/x:y", {"type": "dir", "path": "/x:y"}),
            ("file:/x", {"type": "dir", "path": "/x"}),
            (
                "host:/srv",
                {"type": "scp", "host": "host", "user": None, "port": None, "path": "/srv"},
            ),
            (
                "deploy@host:certs",
                {"type": "scp", "host": "host", "user": "deploy", "port": None, "path": "certs"},
            ),
            (
                "deploy@host:",
                {"type": "scp", "host": "host", "user": "deploy", "port": None, "path": "."},
            ),
            (
                "root@[::1]:/srv",
                {"type": "scp", "host": "::1", "user": "root", "port": None, "path": "/srv"},
            ),
            (
                "scp://deploy@host:2222/srv/caddy",
                {
                    "type": "scp",
                    "host": "host",
                    "user": "deploy",
                    "port": 2222,
                    "path": "/srv/caddy",
                },
            ),
            (
                "scp://host/~/certs",
                {"type": "scp", "host": "host", "user": None, "port": None, "path": "~/certs"},
            ),
        ],
    )
    def test_parse(self, spec: str, expected: dict[str, Any]) -> None:
        assert parse_target_spec(spec) == expected

    @pytest.mark.parametrize("spec", ["", "scp:///x", "scp://host", "scp://host:99999/x"])
    def test_invalid(self, spec: str) -> None:
        with pytest.raises(ConfigError):
            parse_target_spec(spec)


class TestEndpointSpec:
    @pytest.mark.parametrize(
        ("spec", "expected"),
        [
            ("example.com", {"host": "example.com"}),
            ("example.com:8443", {"host": "example.com", "port": "8443"}),
            ("[::1]:443", {"host": "::1", "port": "443"}),
            ("[::1]", {"host": "::1"}),
            ("::1", {"host": "::1"}),
        ],
    )
    def test_parse(self, spec: str, expected: dict[str, Any]) -> None:
        assert parse_endpoint_spec(spec) == expected

    @pytest.mark.parametrize("spec", ["", "[::1]x", ":443"])
    def test_invalid(self, spec: str) -> None:
        with pytest.raises(ConfigError):
            parse_endpoint_spec(spec)


class TestBuildJob:
    def test_defaults(self) -> None:
        job = build_job({"secret": "web-tls"}, 0)
        assert job.name == "web-tls"
        assert job.formats == ["fullchain", "key"]
        assert job.modes.cert == 0o644 and job.modes.key == 0o600
        assert job.targets == [] and job.commands == []
        assert job.source.kubectl == "kubectl" and job.source.require_ready
        assert job.ssh.batch_mode and job.ssh.connect_timeout == 10
        assert not job.verify.files and job.verify.endpoints == []
        assert job.min_days is None and not job.only_if_changed

    def test_full(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("P12PW", "pw")
        job = build_job(
            {
                "name": "web",
                "certificate": "web",
                "namespace": "web",
                "context": "prod",
                "kubeconfig": "/kc",
                "kubectl": "/usr/bin/kubectl",
                "require_ready": "no",
                "kubectl_timeout": 5,
                "formats": ["fullchain", "key", "pkcs12"],
                "filenames": {"fullchain": "site.crt", "key": "site.key"},
                "cert_mode": "0640",
                "key_mode": 0o400,
                "targets": [
                    "/etc/nginx/ssl",
                    {"host": "deploy@proxy:2222", "path": "/srv/certs", "timeout": 30},
                    {
                        "type": "dir",
                        "path": "~/certs",
                        "owner": 0,
                        "group": "root",
                        "create": False,
                    },
                ],
                "commands": [
                    "systemctl reload nginx",
                    ["docker", "exec", "caddy", "caddy", "reload"],
                    {"run": "true", "host": "proxy", "user": "u", "port": 22, "timeout": 9},
                ],
                "verify": {
                    "files": True,
                    "endpoints": ["example.com", {"host": "h", "port": 8443, "servername": "sni"}],
                    "retries": 3,
                    "delay": 0.5,
                    "timeout": 1,
                },
                "pkcs12": {"password_env": "P12PW", "legacy": True, "friendly_name": "a"},
                "ssh": {
                    "identity": "/id",
                    "options": "StrictHostKeyChecking=yes",
                    "batch_mode": False,
                    "connect_timeout": 0,
                    "ssh_bin": "s",
                    "scp_bin": "c",
                },
                "min_days": 14,
                "only_if_changed": True,
            },
            0,
        )
        assert job.source.require_ready is False and job.source.kubectl_timeout == 5
        assert job.modes.cert == 0o640 and job.modes.key == 0o400
        dir_t, scp_t, home_t = job.targets
        assert (dir_t.type, dir_t.path) == ("dir", "/etc/nginx/ssl")
        assert (scp_t.type, scp_t.host, scp_t.user, scp_t.port) == ("scp", "proxy", "deploy", 2222)
        assert scp_t.timeout == 30
        assert home_t.path == str(Path("~/certs").expanduser())
        assert (home_t.owner, home_t.group, home_t.create) == (0, "root", False)
        local_str, local_list, remote = job.commands
        assert local_str.run == "systemctl reload nginx" and local_str.location == "local"
        assert local_list.shell_text == "docker exec caddy caddy reload"
        assert remote.location == "ssh://u@proxy:22" and remote.timeout == 9
        assert job.verify.files and job.verify.retries == 3
        assert [e.label for e in job.verify.endpoints or []] == ["example.com:443", "h:8443#sni"]
        assert job.pkcs12.password == b"pw" and job.pkcs12.legacy
        assert job.ssh.options == ["StrictHostKeyChecking=yes"]
        assert job.ssh.connect_timeout is None and not job.ssh.batch_mode
        assert job.min_days == 14 and job.only_if_changed
        built = job.build_targets()
        assert isinstance(built[0], DirTarget) and isinstance(built[1], ScpTarget)
        assert built[1].label == "scp://deploy@proxy:2222/srv/certs"

    def test_pkcs12_password_file(self, tmp_path: Path) -> None:
        pw = tmp_path / "pw"
        pw.write_text("filepw\n")
        job = build_job(
            {"secret": "s", "formats": ["pkcs12"], "pkcs12": {"password_file": str(pw)}}, 0
        )
        assert job.pkcs12.password == b"filepw"

    def test_pkcs12_password_inline_and_not_needed(self) -> None:
        job = build_job(
            {
                "secret": "s",
                "pkcs12": {
                    "password": "x",
                },
            },
            0,
        )
        assert job.pkcs12.password == b"x"
        # env var is only resolved when pkcs12 output is requested
        job = build_job({"secret": "s", "pkcs12": {"password_env": "UNSET_VAR_X"}}, 0)
        assert job.pkcs12.password is None

    @pytest.mark.parametrize(
        ("raw", "message"),
        [
            ({}, "exactly one of"),
            ({"secret": "a", "certificate": "b"}, "exactly one of"),
            ({"secret": "a", "bogus": 1}, "unknown key"),
            ({"secret": "a", "formats": ["pem"]}, "unknown format"),
            ({"secret": "a", "formats": ["key", "key"]}, "duplicate format"),
            ({"secret": "a", "formats": "key", "filenames": {"nope": "x"}}, "unknown format"),
            ({"secret": "a", "filenames": {"key": "../x"}}, "invalid file name"),
            ({"secret": "a", "filenames": {"key": ".."}}, "invalid file name"),
            ({"secret": "a", "filenames": {"key": "fullchain.pem"}}, "same file name"),
            ({"secret": "a", "filenames": []}, "expected a mapping"),
            ({"secret": "a", "targets": 5}, "expected a list"),
            ({"secret": "a", "targets": [{"host": "h"}]}, "path is required"),
            ({"secret": "a", "targets": [{"type": "ftp", "path": "/x"}]}, "type must be"),
            ({"secret": "a", "targets": [{"type": "scp", "path": "/x"}]}, "requires host"),
            (
                {"secret": "a", "targets": [{"type": "dir", "path": "/x", "host": "h"}]},
                "must not have host",
            ),
            ({"secret": "a", "targets": [{"path": "/x", "port": "abc"}]}, "invalid port"),
            ({"secret": "a", "targets": [{"path": "/x", "port": 0}]}, "out of range"),
            ({"secret": "a", "targets": [{"path": "/x", "port": True}]}, "invalid port"),
            ({"secret": "a", "targets": [{"path": "/x", "owner": True}]}, "invalid owner"),
            ({"secret": "a", "targets": [{"path": "/x", "create": "maybe"}]}, "boolean"),
            ({"secret": "a", "targets": [{"path": ["x"]}]}, "expected a string"),
            ({"secret": "a", "commands": [{"run": ""}]}, "command is required"),
            ({"secret": "a", "commands": [{"run": []}]}, "non-empty list"),
            ({"secret": "a", "commands": [{"run": "x", "host": "a@b/c"}]}, "path"),
            ({"secret": "a", "verify": {"endpoints": [{"port": 1}]}}, "host is required"),
            ({"secret": "a", "verify": {"retries": 0}}, ">= 1"),
            ({"secret": "a", "verify": {"delay": "x"}}, "expected a number"),
            ({"secret": "a", "verify": {"delay": True}}, "expected a number"),
            ({"secret": "a", "verify": {"files": True}}, "requires at least one target"),
            ({"secret": "a", "cert_mode": "999"}, "invalid octal"),
            ({"secret": "a", "cert_mode": 644}, "out of range"),
            ({"secret": "a", "cert_mode": True}, "invalid file mode"),
            ({"secret": "a", "cert_mode": 1.5}, "invalid file mode"),
            ({"secret": "a", "min_days": -1}, ">= 0"),
            ({"secret": "a", "pkcs12": {"password": "x", "password_env": "Y"}}, "only one"),
            (
                {"secret": "a", "formats": ["pkcs12"], "pkcs12": {"password_env": "NOPE_X"}},
                "is not set",
            ),
            (
                {"secret": "a", "formats": ["pkcs12"], "pkcs12": {"password_file": "/nope/x"}},
                "password_file",
            ),
            ({"secret": "a", "ssh": {"port": 1}}, "unknown key"),
        ],
    )
    def test_invalid(self, raw: dict[str, Any], message: str) -> None:
        with pytest.raises(ConfigError, match=message):
            build_job(raw, 0)


class TestFiles:
    def test_defaults_and_jobs(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            """
defaults:
  context: prod
  namespace: default
  ssh: {identity: /id}
  verify: {retries: 2}
jobs:
  - name: a
    secret: a-tls
    targets: [/a]
    ssh: {options: [X=1]}
  - name: b
    secret: b-tls
    namespace: other
    verify: {files: true}
    targets: [/b]
""",
        )
        a, b = resolve_jobs(path, {})
        assert a.source.context == "prod" and a.source.namespace == "default"
        assert a.ssh.identity == "/id" and a.ssh.options == ["X=1"]
        assert b.source.namespace == "other"
        assert b.verify.retries == 2 and b.verify.files

    def test_single_job_at_top_level(self, tmp_path: Path) -> None:
        path = write(tmp_path, "secret: web-tls\ntargets: [/x]\n")
        (job,) = resolve_jobs(path, {})
        assert job.name == "web-tls"

    def test_empty_file_needs_cli_source(self, tmp_path: Path) -> None:
        path = write(tmp_path, "")
        with pytest.raises(ConfigError, match="exactly one"):
            resolve_jobs(path, {})
        (job,) = resolve_jobs(path, {"secret": "s"})
        assert job.name == "s"

    def test_cli_overrides_every_job(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            """
jobs:
  - {name: a, secret: a, context: dev, targets: [/a], verify: {retries: 9}}
  - {name: b, certificate: b, targets: [/b]}
""",
        )
        a, b = resolve_jobs(path, {"context": "prod", "targets": ["/z"], "verify": {"files": True}})
        assert a.source.context == b.source.context == "prod"
        assert [t.path for t in a.targets] == ["/z"]
        assert a.verify.files and a.verify.retries == 9

    def test_cli_source_replaces_other_kind(self, tmp_path: Path) -> None:
        path = write(tmp_path, "jobs:\n  - {name: a, certificate: c}\n")
        (job,) = resolve_jobs(path, {"secret": "s"})
        assert job.source.secret == "s" and job.source.certificate is None

    def test_select_jobs(self, tmp_path: Path) -> None:
        path = write(tmp_path, "jobs:\n  - {secret: a}\n  - {secret: b}\n  - {secret: c}\n")
        assert [j.name for j in resolve_jobs(path, {}, ["c", "a"])] == ["a", "c"]
        with pytest.raises(ConfigError, match="unknown job"):
            resolve_jobs(path, {}, ["zz"])

    def test_duplicate_names(self, tmp_path: Path) -> None:
        path = write(tmp_path, "jobs:\n  - {secret: a}\n  - {secret: a}\n")
        with pytest.raises(ConfigError, match="duplicate job"):
            resolve_jobs(path, {})

    @pytest.mark.parametrize(
        ("text", "message"),
        [
            ("[1, 2]", "must be a mapping"),
            ("jobs: [", "invalid YAML"),
            ("jobs: []", "no jobs"),
            ("jobs: [5]", "expected a mapping"),
            ("defaults: {}\njobs: [{secret: a}]\nextra: 1", "unknown key"),
            ("defaults: {name: x}\njobs: [{secret: a}]", "unknown key"),
            ("defaults: 5\njobs: [{secret: a}]", "expected a mapping"),
        ],
    )
    def test_invalid_files(self, tmp_path: Path, text: str, message: str) -> None:
        with pytest.raises(ConfigError, match=message):
            load_file(write(tmp_path, text))

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="cannot read"):
            load_file(str(tmp_path / "missing.yaml"))


def test_merge_nested_one_level() -> None:
    base = {"ssh": {"identity": "a", "options": ["x"]}, "formats": ["key"]}
    assert merge(base, {"ssh": {"options": ["y"]}, "formats": ["cert"]}) == {
        "ssh": {"identity": "a", "options": ["y"]},
        "formats": ["cert"],
    }
