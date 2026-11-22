"""Post-deploy commands, run locally or on a remote host via ssh."""

from __future__ import annotations

import shlex
from collections.abc import Mapping
from dataclasses import dataclass

from certferry.errors import CommandFailed
from certferry.runner import Result, RunnerProtocol
from certferry.ssh import SshConfig, destination, ssh_argv


@dataclass
class CommandConfig:
    run: str | list[str]
    host: str | None = None
    user: str | None = None
    port: int | None = None
    timeout: float = 120.0

    @property
    def shell_text(self) -> str:
        return self.run if isinstance(self.run, str) else shlex.join(self.run)

    @property
    def location(self) -> str:
        if not self.host:
            return "local"
        port = f":{self.port}" if self.port else ""
        return f"ssh://{destination(self.host, self.user)}{port}"


def run_command(
    cmd: CommandConfig,
    ssh: SshConfig,
    runner: RunnerProtocol,
    env: Mapping[str, str] | None = None,
) -> Result:
    if cmd.host:
        res = runner.run(
            ssh_argv(ssh, cmd.host, cmd.user, cmd.port, cmd.shell_text), timeout=cmd.timeout
        )
    elif isinstance(cmd.run, str):
        # A string command is a shell snippet by design (pipes, &&, env expansion).
        res = runner.run(cmd.run, shell=True, timeout=cmd.timeout, env=env)  # noqa: S604
    else:
        res = runner.run(cmd.run, timeout=cmd.timeout, env=env)
    if not res.ok:
        raise CommandFailed(
            f"command on {cmd.location} exited with {res.returncode}: "
            f"{cmd.shell_text}: {res.stderr_text()}"
        )
    return res
