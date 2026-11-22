"""Configuration model: YAML file (defaults + jobs) merged with command line overrides."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml

from certferry.certs import DEFAULT_FORMATS, FORMATS, Pkcs12Options
from certferry.commands import CommandConfig
from certferry.errors import ConfigError
from certferry.kube import SourceConfig
from certferry.ssh import SshConfig, parse_destination
from certferry.targets import DirTarget, Modes, ScpTarget, Target
from certferry.verify import EndpointConfig, VerifyConfig

TOP_KEYS = {"defaults", "jobs"}
SOURCE_KEYS = {
    "secret",
    "certificate",
    "namespace",
    "context",
    "kubeconfig",
    "kubectl",
    "require_ready",
    "kubectl_timeout",
    "kubectl_cache_dir",
}
JOB_KEYS = SOURCE_KEYS | {
    "name",
    "formats",
    "filenames",
    "cert_mode",
    "key_mode",
    "targets",
    "commands",
    "verify",
    "pkcs12",
    "ssh",
    "min_days",
    "only_if_changed",
}
NESTED_KEYS = {"filenames", "verify", "pkcs12", "ssh"}
SSH_KEYS = {"ssh_bin", "scp_bin", "identity", "options", "batch_mode", "connect_timeout"}
TARGET_KEYS = {"type", "path", "host", "user", "port", "owner", "group", "create", "timeout"}
COMMAND_KEYS = {"run", "host", "user", "port", "timeout"}
VERIFY_KEYS = {"files", "endpoints", "retries", "delay", "timeout"}
ENDPOINT_KEYS = {"host", "port", "servername"}
PKCS12_KEYS = {"password", "password_env", "password_file", "legacy", "friendly_name"}

_SCP_SHORT = re.compile(
    r"^(?:(?P<user>[^@/:\s]+)@)?(?P<host>\[[^\]]+\]|[^:/\s\[\]@]+):(?P<path>.*)$"
)
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9._@+-]+$")


@dataclass
class TargetConfig:
    type: str
    path: str
    host: str | None = None
    user: str | None = None
    port: int | None = None
    owner: str | int | None = None
    group: str | int | None = None
    create: bool = True
    timeout: float = 120.0


@dataclass
class JobConfig:
    name: str
    source: SourceConfig
    formats: list[str] = field(default_factory=lambda: list(DEFAULT_FORMATS))
    filenames: dict[str, str] = field(default_factory=dict)
    modes: Modes = field(default_factory=Modes)
    targets: list[TargetConfig] = field(default_factory=list)
    commands: list[CommandConfig] = field(default_factory=list)
    verify: VerifyConfig = field(default_factory=VerifyConfig)
    pkcs12: Pkcs12Options = field(default_factory=Pkcs12Options)
    ssh: SshConfig = field(default_factory=SshConfig)
    min_days: float | None = None
    only_if_changed: bool = False

    def build_targets(self) -> list[Target]:
        built: list[Target] = []
        for t in self.targets:
            if t.type == "dir":
                built.append(DirTarget(t.path, self.modes, t.owner, t.group, t.create))
            else:
                assert t.host  # noqa: S101 - validated
                built.append(
                    ScpTarget(
                        t.host, t.path, self.modes, self.ssh, t.user, t.port, t.create, t.timeout
                    )
                )
        return built


# ---------------------------------------------------------------- spec parsers


def parse_target_spec(spec: str) -> dict[str, Any]:
    """Parse a target string.

    ``/path`` or ``dir:/path``            -> local directory
    ``scp://[user@]host[:port]/path``     -> remote directory (absolute path)
    ``[user@]host:path``                  -> remote directory (scp shorthand)
    """
    if not spec:
        raise ConfigError("empty target")
    if spec.startswith("scp://"):
        parts = urlsplit(spec)
        if not parts.hostname:
            raise ConfigError(f"invalid scp target {spec!r}: missing host")
        try:
            port = parts.port
        except ValueError as exc:
            raise ConfigError(f"invalid port in target {spec!r}") from exc
        path = unquote(parts.path)
        if path.startswith("/~"):
            path = path[1:]
        if not path:
            raise ConfigError(f"invalid scp target {spec!r}: missing path")
        return {
            "type": "scp",
            "host": parts.hostname,
            "user": parts.username,
            "port": port,
            "path": path,
        }
    for prefix in ("dir:", "file:"):
        if spec.startswith(prefix):
            return {"type": "dir", "path": spec[len(prefix) :]}
    match = _SCP_SHORT.match(spec)
    if match and not spec.startswith(("/", ".", "~")):
        return {
            "type": "scp",
            "host": match["host"].strip("[]"),
            "user": match["user"],
            "port": None,
            "path": match["path"] or ".",
        }
    return {"type": "dir", "path": spec}


def parse_endpoint_spec(spec: str) -> dict[str, Any]:
    """Parse ``host``, ``host:port`` or ``[v6addr]:port``."""
    port: str | None = None
    if spec.startswith("["):
        host, _, rest = spec[1:].partition("]")
        if rest:
            if not rest.startswith(":"):
                raise ConfigError(f"invalid endpoint {spec!r}")
            port = rest[1:]
    elif spec.count(":") == 1:
        host, port = spec.split(":")
    else:
        host = spec
    if not host:
        raise ConfigError(f"invalid endpoint {spec!r}")
    result: dict[str, Any] = {"host": host}
    if port is not None:
        result["port"] = port
    return result


# ------------------------------------------------------------ value helpers


def _check_keys(data: dict[str, Any], allowed: Iterable[str], where: str) -> None:
    unknown = sorted(set(data) - set(allowed))
    if unknown:
        raise ConfigError(f"{where}: unknown key(s): {', '.join(unknown)}")


def _as_dict(value: Any, where: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{where}: expected a mapping")
    return value


def _as_list(value: Any, where: str) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, dict)):
        return [value]
    if not isinstance(value, list):
        raise ConfigError(f"{where}: expected a list")
    return value


def _opt_str(value: Any, where: str) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise ConfigError(f"{where}: expected a string")
    return str(value)


def _bool(value: Any, where: str, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "yes", "1", "on"):
        return True
    if isinstance(value, str) and value.lower() in ("false", "no", "0", "off"):
        return False
    raise ConfigError(f"{where}: expected a boolean")


def _number(value: Any, where: str, default: float | None, minimum: float = 0) -> float | None:
    if value is None:
        return default
    if isinstance(value, bool):
        raise ConfigError(f"{where}: expected a number")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{where}: expected a number") from exc
    if number < minimum:
        raise ConfigError(f"{where}: must be >= {minimum:g}")
    return number


def _port(value: Any, where: str) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ConfigError(f"{where}: invalid port")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{where}: invalid port {value!r}") from exc
    if not 1 <= port <= 65535:
        raise ConfigError(f"{where}: port out of range: {port}")
    return port


def _mode(value: Any, where: str, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        raise ConfigError(f"{where}: invalid file mode")
    if isinstance(value, int):
        mode = value
    elif isinstance(value, str):
        try:
            mode = int(value, 8)
        except ValueError as exc:
            raise ConfigError(f"{where}: invalid octal file mode {value!r}") from exc
    else:
        raise ConfigError(f"{where}: invalid file mode")
    if not 0 <= mode <= 0o777:
        raise ConfigError(f"{where}: file mode out of range; use a quoted octal string like '0640'")
    return mode


def _expand(value: str | None) -> str | None:
    return os.path.expanduser(value) if value else None


def _owner(value: Any, where: str) -> str | int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ConfigError(f"{where}: invalid owner")
    if isinstance(value, int):
        return value
    return str(value)


# ----------------------------------------------------------- section builders


def _build_ssh(raw: Any, where: str) -> SshConfig:
    data = _as_dict(raw, where)
    _check_keys(data, SSH_KEYS, where)
    timeout = _number(data.get("connect_timeout"), f"{where}.connect_timeout", 10)
    return SshConfig(
        ssh_bin=_opt_str(data.get("ssh_bin"), f"{where}.ssh_bin") or "ssh",
        scp_bin=_opt_str(data.get("scp_bin"), f"{where}.scp_bin") or "scp",
        identity=_expand(_opt_str(data.get("identity"), f"{where}.identity")),
        options=[str(o) for o in _as_list(data.get("options"), f"{where}.options")],
        batch_mode=_bool(data.get("batch_mode"), f"{where}.batch_mode", True),
        connect_timeout=int(timeout) if timeout else None,
    )


def _split_host(
    host: str | None, user: str | None, port: int | None, where: str
) -> tuple[str | None, str | None, int | None]:
    """Allow ``host: user@example.com:2222`` as shorthand."""
    if host and ("@" in host or host.startswith("ssh://") or host.count(":") == 1):
        parsed_user, parsed_host, parsed_port = parse_destination(host)
        return parsed_host, user or parsed_user, port or parsed_port
    return host, user, port


def _build_target(raw: Any, where: str) -> TargetConfig:
    data = parse_target_spec(raw) if isinstance(raw, str) else _as_dict(raw, where)
    _check_keys(data, TARGET_KEYS, where)
    path = _opt_str(data.get("path"), f"{where}.path")
    if not path:
        raise ConfigError(f"{where}: path is required")
    port = _port(data.get("port"), f"{where}.port")
    host, user, port = _split_host(
        _opt_str(data.get("host"), f"{where}.host"),
        _opt_str(data.get("user"), f"{where}.user"),
        port,
        where,
    )
    kind = data.get("type") or ("scp" if host else "dir")
    if kind not in ("dir", "scp"):
        raise ConfigError(f"{where}: type must be 'dir' or 'scp'")
    if kind == "scp" and not host:
        raise ConfigError(f"{where}: scp target requires host")
    if kind == "dir" and host:
        raise ConfigError(f"{where}: dir target must not have host")
    timeout = _number(data.get("timeout"), f"{where}.timeout", 120.0)
    return TargetConfig(
        type=kind,
        path=os.path.expanduser(path) if kind == "dir" else path,
        host=host,
        user=user,
        port=port,
        owner=_owner(data.get("owner"), f"{where}.owner"),
        group=_owner(data.get("group"), f"{where}.group"),
        create=_bool(data.get("create"), f"{where}.create", True),
        timeout=timeout if timeout is not None else 120.0,
    )


def _build_command(raw: Any, where: str) -> CommandConfig:
    data = {"run": raw} if isinstance(raw, (str, list)) else _as_dict(raw, where)
    _check_keys(data, COMMAND_KEYS, where)
    run = data.get("run")
    if isinstance(run, list):
        if not run or not all(isinstance(a, (str, int, float)) for a in run):
            raise ConfigError(f"{where}.run: expected a non-empty list of strings")
        run = [str(a) for a in run]
    elif not isinstance(run, str) or not run.strip():
        raise ConfigError(f"{where}.run: command is required")
    host, user, port = _split_host(
        _opt_str(data.get("host"), f"{where}.host"),
        _opt_str(data.get("user"), f"{where}.user"),
        _port(data.get("port"), f"{where}.port"),
        where,
    )
    timeout = _number(data.get("timeout"), f"{where}.timeout", 120.0)
    return CommandConfig(
        run=run, host=host, user=user, port=port, timeout=timeout if timeout is not None else 120.0
    )


def _build_endpoint(raw: Any, where: str) -> EndpointConfig:
    data = parse_endpoint_spec(raw) if isinstance(raw, str) else _as_dict(raw, where)
    _check_keys(data, ENDPOINT_KEYS, where)
    host = _opt_str(data.get("host"), f"{where}.host")
    if not host:
        raise ConfigError(f"{where}: host is required")
    return EndpointConfig(
        host=host,
        port=_port(data.get("port"), f"{where}.port") or 443,
        servername=_opt_str(data.get("servername"), f"{where}.servername"),
    )


def _build_verify(raw: Any, where: str) -> VerifyConfig:
    data = _as_dict(raw, where)
    _check_keys(data, VERIFY_KEYS, where)
    endpoints = [
        _build_endpoint(e, f"{where}.endpoints[{i}]")
        for i, e in enumerate(_as_list(data.get("endpoints"), f"{where}.endpoints"))
    ]
    retries = _number(data.get("retries"), f"{where}.retries", 5, minimum=1)
    return VerifyConfig(
        files=_bool(data.get("files"), f"{where}.files", False),
        endpoints=endpoints,
        retries=int(retries or 5),
        delay=_number(data.get("delay"), f"{where}.delay", 2.0) or 0.0,
        timeout=_number(data.get("timeout"), f"{where}.timeout", 5.0) or 5.0,
    )


def _build_pkcs12(raw: Any, where: str, needed: bool) -> Pkcs12Options:
    data = _as_dict(raw, where)
    _check_keys(data, PKCS12_KEYS, where)
    sources = [k for k in ("password", "password_env", "password_file") if data.get(k)]
    if len(sources) > 1:
        raise ConfigError(f"{where}: use only one of password, password_env, password_file")
    password: str | None = None
    if needed and data.get("password_env"):
        var = str(data["password_env"])
        if var not in os.environ:
            raise ConfigError(f"{where}.password_env: environment variable {var} is not set")
        password = os.environ[var]
    elif needed and data.get("password_file"):
        try:
            password = Path(str(data["password_file"])).expanduser().read_text().rstrip("\r\n")
        except OSError as exc:
            raise ConfigError(f"{where}.password_file: {exc}") from exc
    elif data.get("password"):
        password = str(data["password"])
    return Pkcs12Options(
        password=password.encode() if password else None,
        legacy=_bool(data.get("legacy"), f"{where}.legacy", False),
        friendly_name=_opt_str(data.get("friendly_name"), f"{where}.friendly_name"),
    )


def build_job(raw: dict[str, Any], index: int) -> JobConfig:
    where = f"jobs[{index}]"
    _check_keys(raw, JOB_KEYS, where)
    secret = _opt_str(raw.get("secret"), f"{where}.secret")
    certificate = _opt_str(raw.get("certificate"), f"{where}.certificate")
    if bool(secret) == bool(certificate):
        raise ConfigError(f"{where}: exactly one of 'secret' or 'certificate' is required")
    name = _opt_str(raw.get("name"), f"{where}.name") or secret or certificate
    assert name  # noqa: S101
    where = f"job {name}"

    timeout = _number(raw.get("kubectl_timeout"), f"{where}.kubectl_timeout", 60.0)
    source = SourceConfig(
        secret=secret,
        certificate=certificate,
        namespace=_opt_str(raw.get("namespace"), f"{where}.namespace"),
        context=_opt_str(raw.get("context"), f"{where}.context"),
        kubeconfig=_expand(_opt_str(raw.get("kubeconfig"), f"{where}.kubeconfig")),
        kubectl=_opt_str(raw.get("kubectl"), f"{where}.kubectl") or "kubectl",
        require_ready=_bool(raw.get("require_ready"), f"{where}.require_ready", True),
        kubectl_timeout=timeout if timeout is not None else 60.0,
        cache_dir=_expand(
            _opt_str(raw.get("kubectl_cache_dir"), f"{where}.kubectl_cache_dir")
            or os.environ.get("CERTFERRY_KUBECTL_CACHE_DIR")
        ),
    )

    formats = [str(f) for f in _as_list(raw.get("formats"), f"{where}.formats")] or list(
        DEFAULT_FORMATS
    )
    unknown = [f for f in formats if f not in FORMATS]
    if unknown:
        raise ConfigError(
            f"{where}.formats: unknown format(s) {', '.join(unknown)}; "
            f"choose from {', '.join(FORMATS)}"
        )
    if len(set(formats)) != len(formats):
        raise ConfigError(f"{where}.formats: duplicate format")

    filenames: dict[str, str] = {}
    for fmt, fname in _as_dict(raw.get("filenames"), f"{where}.filenames").items():
        if fmt not in FORMATS:
            raise ConfigError(f"{where}.filenames: unknown format {fmt!r}")
        fname = str(fname)
        if not _SAFE_FILENAME.match(fname) or fname in (".", ".."):
            raise ConfigError(f"{where}.filenames.{fmt}: invalid file name {fname!r}")
        filenames[str(fmt)] = fname
    final_names = [filenames.get(f, FORMATS[f].default_filename) for f in formats]
    if len(set(final_names)) != len(final_names):
        raise ConfigError(f"{where}: two formats would be written to the same file name")

    targets = [
        _build_target(t, f"{where}.targets[{i}]")
        for i, t in enumerate(_as_list(raw.get("targets"), f"{where}.targets"))
    ]
    commands = [
        _build_command(c, f"{where}.commands[{i}]")
        for i, c in enumerate(_as_list(raw.get("commands"), f"{where}.commands"))
    ]
    verify = _build_verify(raw.get("verify"), f"{where}.verify")
    if verify.files and not targets:
        raise ConfigError(f"{where}.verify.files: requires at least one target")

    return JobConfig(
        name=name,
        source=source,
        formats=formats,
        filenames=filenames,
        modes=Modes(
            cert=_mode(raw.get("cert_mode"), f"{where}.cert_mode", 0o644),
            key=_mode(raw.get("key_mode"), f"{where}.key_mode", 0o600),
        ),
        targets=targets,
        commands=commands,
        verify=verify,
        pkcs12=_build_pkcs12(raw.get("pkcs12"), f"{where}.pkcs12", "pkcs12" in formats),
        ssh=_build_ssh(raw.get("ssh"), f"{where}.ssh"),
        min_days=_number(raw.get("min_days"), f"{where}.min_days", None),
        only_if_changed=_bool(raw.get("only_if_changed"), f"{where}.only_if_changed", False),
    )


# --------------------------------------------------------------- top level


def load_file(path: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        text = Path(path).read_text()
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    if "jobs" not in data and "defaults" not in data:
        # A single job written at the top level.
        return {}, [data]
    _check_keys(data, TOP_KEYS, path)
    defaults = _as_dict(data.get("defaults"), "defaults")
    _check_keys(defaults, JOB_KEYS - {"name"}, "defaults")
    jobs = _as_list(data.get("jobs"), "jobs")
    if not jobs:
        raise ConfigError(f"{path}: no jobs defined")
    for i, job in enumerate(jobs):
        if not isinstance(job, dict):
            raise ConfigError(f"jobs[{i}]: expected a mapping")
    return defaults, jobs


def merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Shallow merge, one level deep for nested sections."""
    result = dict(base)
    for key, value in override.items():
        if key in NESTED_KEYS and isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = {**result[key], **value}
        else:
            result[key] = value
    return result


def resolve_jobs(
    config_path: str | None,
    overrides: dict[str, Any],
    selected: list[str] | None = None,
) -> list[JobConfig]:
    if config_path:
        defaults, raw_jobs = load_file(config_path)
        raws = [merge(defaults, job) for job in raw_jobs]
    else:
        raws = [{}]
    if overrides.get("secret") or overrides.get("certificate"):
        # Selecting a source on the command line replaces the other source kind.
        for raw in raws:
            raw.pop("secret", None)
            raw.pop("certificate", None)
    raws = [merge(raw, overrides) for raw in raws]
    jobs = [build_job(raw, i) for i, raw in enumerate(raws)]

    names = [j.name for j in jobs]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise ConfigError(f"duplicate job name(s): {', '.join(duplicates)}")
    if selected:
        missing = [s for s in selected if s not in names]
        if missing:
            raise ConfigError(f"unknown job(s): {', '.join(missing)}")
        jobs = [j for j in jobs if j.name in selected]
    return jobs
