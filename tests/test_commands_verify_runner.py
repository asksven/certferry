from __future__ import annotations

import ssl
from pathlib import Path
from typing import Any

import pytest

from certferry.commands import CommandConfig, run_command
from certferry.errors import CommandFailed, VerifyError
from certferry.runner import Result, Runner, describe
from certferry.ssh import SshConfig
from certferry.verify import EndpointConfig, VerifyConfig, fetch_peer_cert, verify_endpoint

from .conftest import FakeRunner, Pki, TlsServer

SSH = SshConfig(connect_timeout=None, batch_mode=False)


class TestCommands:
    def test_local_string_uses_shell_and_env(self) -> None:
        runner = FakeRunner()
        run_command(CommandConfig("nginx -t && systemctl reload nginx"), SSH, runner, {"A": "1"})
        call = runner.calls[0]
        assert call.shell and call.cmd == "nginx -t && systemctl reload nginx"
        assert call.env == {"A": "1"} and call.timeout == 120

    def test_local_list_no_shell(self) -> None:
        runner = FakeRunner()
        run_command(CommandConfig(["systemctl", "reload", "nginx"], timeout=5), SSH, runner)
        assert not runner.calls[0].shell
        assert runner.calls[0].argv == ["systemctl", "reload", "nginx"]
        assert runner.calls[0].timeout == 5

    def test_remote(self) -> None:
        runner = FakeRunner()
        cmd = CommandConfig(
            [
                "docker",
                "exec",
                "caddy",
                "caddy",
                "reload",
                "--config",
                "/etc/caddy/Caddyfile",
                "--force",
            ],
            host="proxy",
            user="u",
            port=2,
        )
        run_command(cmd, SSH, runner, {"IGNORED": "x"})
        assert runner.calls[0].argv == [
            "ssh",
            "-p",
            "2",
            "u@proxy",
            "--",
            "docker exec caddy caddy reload --config /etc/caddy/Caddyfile --force",
        ]
        assert runner.calls[0].env is None
        assert cmd.location == "ssh://u@proxy:2"

    def test_failure(self) -> None:
        runner = FakeRunner(lambda call: Result(1, b"", b"nginx: [emerg] bad config"))
        with pytest.raises(CommandFailed, match=r"local exited with 1: nginx -t: nginx: \[emerg\]"):
            run_command(CommandConfig("nginx -t"), SSH, runner)


class TestRealRunner:
    def test_success_and_env(self) -> None:
        res = Runner().run('printf %s "$CF_TEST"', shell=True, env={"CF_TEST": "v"})
        assert res.ok and res.stdout == b"v"

    def test_argv_and_stderr(self) -> None:
        res = Runner().run(["sh", "-c", "echo err >&2; exit 4"])
        assert res.returncode == 4 and res.stderr_text() == "err"

    def test_missing_executable(self, tmp_path: Path) -> None:
        res = Runner().run([str(tmp_path / "nope")])
        assert res.returncode == 127 and "not found" in res.stderr_text()

    def test_timeout(self) -> None:
        res = Runner().run(["sleep", "5"], timeout=0.1)
        assert res.returncode == 124 and "timed out" in res.stderr_text()

    def test_stderr_truncation(self) -> None:
        assert Result(1, b"", b"x" * 600).stderr_text(limit=10) == "..." + "x" * 10

    def test_describe(self) -> None:
        assert describe(["a", "b c"]) == "a 'b c'"
        assert describe("a | b") == "a | b"


class TestEndpoint:
    def test_label(self) -> None:
        assert EndpointConfig("h").label == "h:443"
        assert EndpointConfig("::1", 8443).label == "[::1]:8443"
        assert EndpointConfig("1.2.3.4", 443, "example.com").label == "1.2.3.4:443#example.com"

    def test_real_server_match(self, pki: Pki, tls_server_factory: Any) -> None:
        server: TlsServer = tls_server_factory(pki)
        der = fetch_peer_cert(server.host, server.port, "www.example.test", 5)
        assert der == pki.leaf_der
        out = verify_endpoint(
            EndpointConfig(server.host, server.port), pki.leaf_der, VerifyConfig(retries=1)
        )
        assert out["attempts"] == 1

    def test_real_server_mismatch(self, pki: Pki, other_pki: Pki, tls_server_factory: Any) -> None:
        server: TlsServer = tls_server_factory(other_pki)
        with pytest.raises(VerifyError, match="serves different certificate"):
            verify_endpoint(
                EndpointConfig(server.host, server.port),
                pki.leaf_der,
                VerifyConfig(retries=2, delay=0),
                sleep=lambda s: None,
            )

    def test_connection_refused(self, free_port: int) -> None:
        with pytest.raises(VerifyError, match="connection failed.*after 1 attempt"):
            verify_endpoint(
                EndpointConfig("127.0.0.1", free_port), b"x", VerifyConfig(retries=1, timeout=1)
            )

    def test_retries_until_reloaded(self) -> None:
        answers: list[Any] = [OSError("refused"), b"old", b"new"]
        sleeps: list[float] = []

        def fetch(host: str, port: int, sni: str | None, timeout: float) -> bytes:
            answer = answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return bytes(answer)

        out = verify_endpoint(
            EndpointConfig("h", servername="s"),
            b"new",
            VerifyConfig(retries=5, delay=0.25),
            fetch,
            sleeps.append,
        )
        assert out["attempts"] == 3 and sleeps == [0.25, 0.25]

    def test_ssl_error_is_retried(self) -> None:
        def fetch(*_: Any) -> bytes:
            raise ssl.SSLError("handshake failure")

        with pytest.raises(VerifyError, match="handshake failure"):
            verify_endpoint(
                EndpointConfig("h"), b"x", VerifyConfig(retries=2, delay=0), fetch, lambda s: None
            )
