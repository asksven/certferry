from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from certferry.certs import OutputFile
from certferry.errors import DeployError
from certferry.runner import Result
from certferry.ssh import SshConfig, parse_destination, scp_argv, ssh_argv
from certferry.targets import DirTarget, Modes, ScpTarget, _resolve_gid, _resolve_uid
from certferry.verify import verify_files

from .conftest import Call, FakeRunner

FILES = [
    OutputFile("fullchain", "fullchain.pem", b"CERT\n", False),
    OutputFile("key", "key.pem", b"KEY\n", True),
]


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


class TestDirTarget:
    def test_deploy_creates_and_sets_modes(self, tmp_path: Path) -> None:
        dest = tmp_path / "a" / "b"
        target = DirTarget(str(dest), Modes(cert=0o640, key=0o400))
        target.deploy(FILES, FakeRunner())
        assert (dest / "fullchain.pem").read_bytes() == b"CERT\n"
        assert mode_of(dest / "fullchain.pem") == 0o640
        assert mode_of(dest / "key.pem") == 0o400
        assert sorted(p.name for p in dest.iterdir()) == ["fullchain.pem", "key.pem"]
        assert target.label == f"dir:{dest}"

    def test_replaces_existing(self, tmp_path: Path) -> None:
        (tmp_path / "key.pem").write_bytes(b"OLD")
        before = (tmp_path / "key.pem").stat().st_ino
        DirTarget(str(tmp_path), Modes()).deploy(FILES, FakeRunner())
        assert (tmp_path / "key.pem").read_bytes() == b"KEY\n"
        assert (tmp_path / "key.pem").stat().st_ino != before  # atomic rename

    def test_owner_and_group_numeric(self, tmp_path: Path) -> None:
        target = DirTarget(str(tmp_path), Modes(), owner=os.getuid(), group=str(os.getgid()))
        target.deploy(FILES, FakeRunner())
        assert (tmp_path / "key.pem").stat().st_uid == os.getuid()

    def test_owner_by_name(self, tmp_path: Path) -> None:
        import grp
        import pwd

        user = pwd.getpwuid(os.getuid()).pw_name
        group = grp.getgrgid(os.getgid()).gr_name
        DirTarget(str(tmp_path), Modes(), owner=user, group=group).deploy(FILES, FakeRunner())
        assert (tmp_path / "key.pem").stat().st_gid == os.getgid()

    def test_unknown_owner(self, tmp_path: Path) -> None:
        with pytest.raises(DeployError, match="unknown user"):
            DirTarget(str(tmp_path), Modes(), owner="no-such-user-x").deploy(FILES, FakeRunner())
        with pytest.raises(DeployError, match="unknown group"):
            DirTarget(str(tmp_path), Modes(), group="no-such-group-x").deploy(FILES, FakeRunner())

    def test_resolve_helpers(self) -> None:
        assert _resolve_uid(None) == -1 and _resolve_gid("") == -1
        assert _resolve_uid("12") == 12 and _resolve_gid(7) == 7

    def test_no_create(self, tmp_path: Path) -> None:
        target = DirTarget(str(tmp_path / "missing"), Modes(), create=False)
        with pytest.raises(DeployError, match="does not exist"):
            target.deploy(FILES, FakeRunner())

    def test_no_create_existing_ok(self, tmp_path: Path) -> None:
        DirTarget(str(tmp_path), Modes(), create=False).deploy(FILES, FakeRunner())
        assert (tmp_path / "key.pem").exists()

    def test_cannot_create(self, tmp_path: Path) -> None:
        blocker = tmp_path / "file"
        blocker.write_text("x")
        with pytest.raises(DeployError, match="cannot create directory"):
            DirTarget(str(blocker / "sub"), Modes()).deploy(FILES, FakeRunner())

    def test_write_failure_cleans_up(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def broken_replace(src: str, dst: object) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(os, "replace", broken_replace)
        with pytest.raises(DeployError, match="cannot write fullchain.pem: disk full"):
            DirTarget(str(tmp_path), Modes()).deploy(FILES, FakeRunner())
        assert list(tmp_path.iterdir()) == []

    def test_read(self, tmp_path: Path) -> None:
        target = DirTarget(str(tmp_path), Modes())
        assert target.read("key.pem", FakeRunner()) is None
        target.deploy(FILES, FakeRunner())
        assert target.read("key.pem", FakeRunner()) == b"KEY\n"
        (tmp_path / "dir.pem").mkdir()
        with pytest.raises(DeployError, match="cannot read"):
            target.read("dir.pem", FakeRunner())

    def test_verify_files(self, tmp_path: Path) -> None:
        target = DirTarget(str(tmp_path), Modes())
        assert verify_files(target, FILES, FakeRunner(), None) == ["fullchain.pem", "key.pem"]
        target.deploy(FILES, FakeRunner())
        assert verify_files(target, FILES, FakeRunner(), None) == []
        (tmp_path / "key.pem").write_bytes(b"tampered")
        assert verify_files(target, FILES, FakeRunner(), None) == ["key.pem"]


class TestSshArgv:
    def test_ssh_defaults(self) -> None:
        assert ssh_argv(SshConfig(), "h", None, None, "echo hi") == [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "h",
            "--",
            "echo hi",
        ]

    def test_ssh_everything(self) -> None:
        cfg = SshConfig(
            ssh_bin="/bin/ssh",
            identity="/id",
            options=["A=1", "B=2"],
            batch_mode=False,
            connect_timeout=None,
        )
        assert ssh_argv(cfg, "h", "u", 2222, "x") == [
            "/bin/ssh",
            "-p",
            "2222",
            "-i",
            "/id",
            "-o",
            "A=1",
            "-o",
            "B=2",
            "u@h",
            "--",
            "x",
        ]

    def test_scp(self) -> None:
        cfg = SshConfig(scp_bin="scp", connect_timeout=None, batch_mode=False)
        assert scp_argv(cfg, "h", "u", 22, ["/a", "/b"], "/srv/") == [
            "scp",
            "-p",
            "-q",
            "-P",
            "22",
            "/a",
            "/b",
            "u@h:/srv/",
        ]

    def test_scp_ipv6_and_root(self) -> None:
        cfg = SshConfig(connect_timeout=None, batch_mode=False)
        assert scp_argv(cfg, "::1", None, None, ["/a"], "/")[-1] == "[::1]:/"

    @pytest.mark.parametrize(
        ("spec", "expected"),
        [
            ("host", (None, "host", None)),
            ("u@host", ("u", "host", None)),
            ("u@host:2222", ("u", "host", 2222)),
            ("ssh://u@host:2222", ("u", "host", 2222)),
            ("[::1]:22", (None, "::1", 22)),
        ],
    )
    def test_parse_destination(self, spec: str, expected: tuple[object, ...]) -> None:
        assert parse_destination(spec) == expected

    @pytest.mark.parametrize("spec", ["", "u@", "host/path", "host:abc"])
    def test_parse_destination_invalid(self, spec: str) -> None:
        from certferry.errors import ConfigError

        with pytest.raises(ConfigError):
            parse_destination(spec)


def scp_target(**kw: object) -> ScpTarget:
    defaults: dict[str, object] = {
        "host": "proxy",
        "path": "/srv/certs",
        "modes": Modes(),
        "ssh": SshConfig(connect_timeout=None, batch_mode=False),
        "user": "deploy",
    }
    defaults.update(kw)
    return ScpTarget(**defaults)  # type: ignore[arg-type]


class TestScpTarget:
    def test_deploy_sequence(self) -> None:
        staged_modes: dict[str, int] = {}

        def handler(call: Call) -> Result | None:
            if call.argv[0] == "scp":
                for src in call.argv[5:-1]:
                    staged_modes[Path(src).name] = mode_of(Path(src))
            return None

        runner = FakeRunner(handler)
        target = scp_target(port=2222, modes=Modes(cert=0o644, key=0o600))
        target.deploy(FILES, runner)
        mkdir, scp, mv = runner.calls
        assert mkdir.argv == ["ssh", "-p", "2222", "deploy@proxy", "--", "mkdir -p -- /srv/certs"]
        assert scp.argv[:5] == ["scp", "-p", "-q", "-P", "2222"]
        assert scp.argv[-1] == "deploy@proxy:/srv/certs/"
        names = sorted(staged_modes)
        assert names[0].startswith(".fullchain.pem.certferry-")
        assert staged_modes[names[0]] == 0o644 and staged_modes[names[1]] == 0o600
        command = mv.argv[-1]
        assert command.count("mv -f --") == 2
        assert "/srv/certs/fullchain.pem" in command and "/srv/certs/key.pem" in command
        assert target.label == "scp://deploy@proxy:2222/srv/certs"

    def test_no_create_skips_mkdir(self) -> None:
        runner = FakeRunner()
        scp_target(create=False).deploy(FILES, runner)
        assert [c.argv[0] for c in runner.calls] == ["scp", "ssh"]

    def test_mkdir_failure(self) -> None:
        runner = FakeRunner(lambda call: Result(255, b"", b"Connection refused"))
        with pytest.raises(DeployError, match=r"mkdir failed \(exit 255\): Connection refused"):
            scp_target().deploy(FILES, runner)

    def test_scp_failure(self) -> None:
        runner = FakeRunner(
            lambda c: Result(1, b"", b"Permission denied") if c.argv[0] == "scp" else None
        )
        with pytest.raises(DeployError, match="scp failed"):
            scp_target().deploy(FILES, runner)

    def test_move_failure_cleans_up(self) -> None:
        def handler(call: Call) -> Result | None:
            if call.argv[0] == "ssh" and call.argv[-1].startswith("mv "):
                return Result(1, b"", b"mv: cannot move")
            return None

        runner = FakeRunner(handler)
        with pytest.raises(DeployError, match="activating files failed"):
            scp_target().deploy(FILES, runner)
        assert runner.calls[-1].argv[-1].startswith("rm -f -- ")

    def test_relative_path_label(self) -> None:
        assert scp_target(path="certs", user=None).label == "scp://proxy/certs"

    @pytest.mark.parametrize(
        ("result", "expected"),
        [(Result(0, b"DATA", b""), b"DATA"), (Result(3, b"", b""), None)],
    )
    def test_read(self, result: Result, expected: bytes | None) -> None:
        runner = FakeRunner(lambda call: result)
        assert scp_target().read("key.pem", runner) == expected
        assert "cat -- /srv/certs/key.pem" in runner.calls[0].argv[-1]

    def test_read_error(self) -> None:
        runner = FakeRunner(lambda call: Result(255, b"", b"down"))
        with pytest.raises(DeployError, match="cannot read key.pem"):
            scp_target().read("key.pem", runner)
        # verify_files treats unreachable as "not in place"
        assert verify_files(scp_target(), FILES[:1], runner, None) == ["fullchain.pem"]
