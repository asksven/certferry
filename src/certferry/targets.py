"""Deployment targets: a local directory or a remote directory reached over scp/ssh."""

from __future__ import annotations

import contextlib
import os
import secrets
import shlex
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from certferry.certs import OutputFile
from certferry.errors import DeployError
from certferry.runner import RunnerProtocol
from certferry.ssh import SshConfig, destination, scp_argv, ssh_argv

# Exit status used by the remote read helper for "file does not exist".
_MISSING = 3


@dataclass
class Modes:
    cert: int = 0o644
    key: int = 0o600

    def for_file(self, f: OutputFile) -> int:
        return self.key if f.secret else self.cert


class Target(Protocol):
    @property
    def label(self) -> str: ...

    def deploy(self, files: Sequence[OutputFile], runner: RunnerProtocol) -> None: ...

    def read(self, name: str, runner: RunnerProtocol) -> bytes | None: ...


def _resolve_uid(owner: str | int | None) -> int:
    if owner is None or owner == "":
        return -1
    if isinstance(owner, int) or str(owner).isdigit():
        return int(owner)
    import pwd

    try:
        return pwd.getpwnam(str(owner)).pw_uid
    except KeyError as exc:
        raise DeployError(f"unknown user {owner!r}") from exc


def _resolve_gid(group: str | int | None) -> int:
    if group is None or group == "":
        return -1
    if isinstance(group, int) or str(group).isdigit():
        return int(group)
    import grp

    try:
        return grp.getgrnam(str(group)).gr_gid
    except KeyError as exc:
        raise DeployError(f"unknown group {group!r}") from exc


@dataclass
class DirTarget:
    path: str
    modes: Modes
    owner: str | int | None = None
    group: str | int | None = None
    create: bool = True

    @property
    def label(self) -> str:
        return f"dir:{self.path}"

    def deploy(self, files: Sequence[OutputFile], runner: RunnerProtocol) -> None:
        directory = Path(self.path)
        try:
            if self.create:
                directory.mkdir(parents=True, exist_ok=True)
            elif not directory.is_dir():
                raise DeployError(f"{self.label}: directory does not exist")
        except OSError as exc:
            raise DeployError(f"{self.label}: cannot create directory: {exc}") from exc
        uid = _resolve_uid(self.owner)
        gid = _resolve_gid(self.group)
        for f in files:
            self._write_atomic(directory, f, uid, gid)

    def _write_atomic(self, directory: Path, f: OutputFile, uid: int, gid: int) -> None:
        tmp_name: str | None = None
        try:
            fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=f".{f.name}.", suffix=".tmp")
            with os.fdopen(fd, "wb") as handle:
                os.fchmod(handle.fileno(), self.modes.for_file(f))
                if uid != -1 or gid != -1:
                    os.fchown(handle.fileno(), uid, gid)
                handle.write(f.data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, directory / f.name)
            tmp_name = None
        except OSError as exc:
            raise DeployError(f"{self.label}: cannot write {f.name}: {exc}") from exc
        finally:
            if tmp_name is not None:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)

    def read(self, name: str, runner: RunnerProtocol) -> bytes | None:
        path = Path(self.path) / name
        try:
            return path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise DeployError(f"{self.label}: cannot read {name}: {exc}") from exc


@dataclass
class ScpTarget:
    host: str
    path: str
    modes: Modes
    ssh: SshConfig
    user: str | None = None
    port: int | None = None
    create: bool = True
    timeout: float = 120.0

    @property
    def label(self) -> str:
        port = f":{self.port}" if self.port else ""
        sep = "" if self.path.startswith("/") else "/"
        return f"scp://{destination(self.host, self.user)}{port}{sep}{self.path}"

    def _remote_path(self, name: str) -> str:
        return str(PurePosixPath(self.path) / name)

    def _ssh(self, runner: RunnerProtocol, command: str) -> tuple[int, bytes, str]:
        argv = ssh_argv(self.ssh, self.host, self.user, self.port, command)
        res = runner.run(argv, timeout=self.timeout)
        return res.returncode, res.stdout, res.stderr_text()

    def deploy(self, files: Sequence[OutputFile], runner: RunnerProtocol) -> None:
        token = secrets.token_hex(4)
        temp_names = {f.name: f".{f.name}.certferry-{token}" for f in files}
        with tempfile.TemporaryDirectory(prefix="certferry-") as staging:
            sources: list[str] = []
            for f in files:
                local = Path(staging) / temp_names[f.name]
                local.write_bytes(f.data)
                local.chmod(self.modes.for_file(f))
                sources.append(str(local))

            if self.create:
                rc, _, err = self._ssh(runner, f"mkdir -p -- {shlex.quote(self.path)}")
                if rc != 0:
                    raise DeployError(f"{self.label}: mkdir failed (exit {rc}): {err}")

            res = runner.run(
                scp_argv(self.ssh, self.host, self.user, self.port, sources, self.path),
                timeout=self.timeout,
            )
            if not res.ok:
                raise DeployError(
                    f"{self.label}: scp failed (exit {res.returncode}): {res.stderr_text()}"
                )

        moves = " && ".join(
            f"mv -f -- {shlex.quote(self._remote_path(tmp))} {shlex.quote(self._remote_path(name))}"
            for name, tmp in temp_names.items()
        )
        rc, _, err = self._ssh(runner, moves)
        if rc != 0:
            cleanup = "rm -f -- " + " ".join(
                shlex.quote(self._remote_path(tmp)) for tmp in temp_names.values()
            )
            self._ssh(runner, cleanup)
            raise DeployError(f"{self.label}: activating files failed (exit {rc}): {err}")

    def read(self, name: str, runner: RunnerProtocol) -> bytes | None:
        path = shlex.quote(self._remote_path(name))
        rc, out, err = self._ssh(
            runner, f"if [ -f {path} ]; then cat -- {path}; else exit {_MISSING}; fi"
        )
        if rc == 0:
            return out
        if rc == _MISSING:
            return None
        raise DeployError(f"{self.label}: cannot read {name} (exit {rc}): {err}")
