"""Thin, injectable wrapper around subprocess so every external call can be faked in tests."""

from __future__ import annotations

import logging
import os
import shlex
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

log = logging.getLogger("certferry")

Command = str | Sequence[str]


@dataclass(frozen=True)
class Result:
    returncode: int
    stdout: bytes
    stderr: bytes

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def stderr_text(self, limit: int = 500) -> str:
        text = self.stderr.decode("utf-8", errors="replace").strip()
        if len(text) > limit:
            text = "..." + text[-limit:]
        return text


class RunnerProtocol(Protocol):
    def run(
        self,
        cmd: Command,
        *,
        shell: bool = False,
        input: bytes | None = None,
        timeout: float | None = None,
        env: Mapping[str, str] | None = None,
    ) -> Result: ...


def describe(cmd: Command) -> str:
    return cmd if isinstance(cmd, str) else shlex.join(list(cmd))


class Runner:
    """Executes commands. Never logs stdout, because it may contain private keys."""

    def run(
        self,
        cmd: Command,
        *,
        shell: bool = False,
        input: bytes | None = None,
        timeout: float | None = None,
        env: Mapping[str, str] | None = None,
    ) -> Result:
        log.debug("exec: %s", describe(cmd))
        full_env = None
        if env:
            full_env = dict(os.environ)
            full_env.update(env)
        args: str | list[str] = cmd if isinstance(cmd, str) else list(cmd)
        try:
            cp = subprocess.run(
                args,
                shell=shell,
                input=input,
                capture_output=True,
                timeout=timeout,
                env=full_env,
                check=False,
            )
        except FileNotFoundError as exc:
            return Result(127, b"", f"executable not found: {exc.filename}".encode())
        except subprocess.TimeoutExpired:
            return Result(124, b"", f"timed out after {timeout}s".encode())
        log.debug("exit: %d", cp.returncode)
        return Result(cp.returncode, cp.stdout or b"", cp.stderr or b"")
