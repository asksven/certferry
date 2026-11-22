"""Construction of ssh / scp argument vectors."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from certferry.errors import ConfigError


@dataclass
class SshConfig:
    ssh_bin: str = "ssh"
    scp_bin: str = "scp"
    identity: str | None = None
    options: list[str] = field(default_factory=list)
    batch_mode: bool = True
    connect_timeout: int | None = 10


def destination(host: str, user: str | None) -> str:
    return f"{user}@{host}" if user else host


def parse_destination(spec: str) -> tuple[str | None, str, int | None]:
    """Parse ``[ssh://][user@]host[:port]`` into (user, host, port)."""
    raw = spec if spec.startswith("ssh://") else "ssh://" + spec
    parts = urlsplit(raw)
    if not parts.hostname:
        raise ConfigError(f"invalid ssh destination: {spec!r}")
    if parts.path not in ("", "/"):
        raise ConfigError(f"ssh destination must not contain a path: {spec!r}")
    try:
        port = parts.port
    except ValueError as exc:
        raise ConfigError(f"invalid port in ssh destination: {spec!r}") from exc
    return parts.username, parts.hostname, port


def _common_options(cfg: SshConfig) -> list[str]:
    argv: list[str] = []
    if cfg.identity:
        argv += ["-i", cfg.identity]
    if cfg.batch_mode:
        argv += ["-o", "BatchMode=yes"]
    if cfg.connect_timeout:
        argv += ["-o", f"ConnectTimeout={cfg.connect_timeout}"]
    for opt in cfg.options:
        argv += ["-o", opt]
    return argv


def ssh_argv(
    cfg: SshConfig, host: str, user: str | None, port: int | None, remote_command: str
) -> list[str]:
    argv = [cfg.ssh_bin]
    if port is not None:
        argv += ["-p", str(port)]
    argv += _common_options(cfg)
    argv += [destination(host, user), "--", remote_command]
    return argv


def scp_argv(
    cfg: SshConfig,
    host: str,
    user: str | None,
    port: int | None,
    sources: Sequence[str],
    remote_dir: str,
) -> list[str]:
    argv = [cfg.scp_bin, "-p", "-q"]
    if port is not None:
        argv += ["-P", str(port)]
    argv += _common_options(cfg)
    scp_host = f"[{host}]" if ":" in host else host
    remote = remote_dir.rstrip("/") + "/"
    argv += [*sources, f"{destination(scp_host, user)}:{remote}"]
    return argv
