"""Command line interface."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections.abc import Sequence
from typing import IO, Any

from certferry import __version__
from certferry.certs import FORMATS
from certferry.config import JobConfig, parse_endpoint_spec, parse_target_spec, resolve_jobs
from certferry.errors import EXIT_CONFIG, CertferryError
from certferry.pipeline import RunContext, run_job
from certferry.report import OUTPUT_FORMATS, JobResult, Reporter
from certferry.runner import Runner, RunnerProtocol
from certferry.ssh import parse_destination

log = logging.getLogger("certferry")


class _CommandAction(argparse.Action):
    """Collect --exec and --remote-exec into one ordered list."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        items = list(getattr(namespace, self.dest, None) or [])
        if option_string == "--remote-exec":
            items.append(("remote", values[0], values[1]))
        else:
            items.append(("local", None, values))
        setattr(namespace, self.dest, items)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="certferry",
        description=(
            "Extract a cert-manager TLS secret with kubectl, render it into the file formats "
            "a service needs, deploy it to local or remote directories, run reload commands "
            "and verify the result. Options given on the command line override the values "
            "of every job loaded from --config."
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument(
        "-c",
        "--config",
        default=os.environ.get("CERTFERRY_CONFIG") or None,
        help="YAML configuration file (default: $CERTFERRY_CONFIG)",
    )
    p.add_argument(
        "-j",
        "--job",
        action="append",
        dest="jobs",
        metavar="NAME",
        help="only run the named job(s) from the config; repeatable",
    )

    g = p.add_argument_group("source")
    g.add_argument("-s", "--secret", help="name of the kubernetes.io/tls secret")
    g.add_argument(
        "--certificate", help="name of a cert-manager Certificate; its spec.secretName is used"
    )
    g.add_argument("-n", "--namespace")
    g.add_argument("--context", help="kubectl context")
    g.add_argument("--kubeconfig", help="kubeconfig file")
    g.add_argument("--kubectl", help="kubectl executable (default: kubectl)")
    g.add_argument("--kubectl-timeout", type=float, metavar="SECONDS")
    g.add_argument(
        "--kubectl-cache-dir",
        metavar="PATH",
        help="kubectl --cache-dir (default: $CERTFERRY_KUBECTL_CACHE_DIR, else kubectl's own)",
    )
    g.add_argument(
        "--no-require-ready",
        dest="require_ready",
        action="store_const",
        const=False,
        help="with --certificate, do not require the Certificate to be Ready",
    )

    g = p.add_argument_group("output files")
    g.add_argument(
        "-f",
        "--format",
        action="append",
        dest="formats",
        choices=list(FORMATS),
        metavar="FORMAT",
        help="file format to produce; repeatable (default: fullchain, key). See --list-formats",
    )
    g.add_argument(
        "--filename",
        action="append",
        metavar="FORMAT=NAME",
        help="override the file name of a format; repeatable",
    )
    g.add_argument("--cert-mode", metavar="OCTAL", help="mode for public files (default 0644)")
    g.add_argument(
        "--key-mode",
        metavar="OCTAL",
        help="mode for files containing the private key (default 0600)",
    )
    g.add_argument(
        "--pkcs12-password-env",
        metavar="VAR",
        help="environment variable holding the PKCS#12 password",
    )
    g.add_argument(
        "--pkcs12-password-file", metavar="PATH", help="file holding the PKCS#12 password"
    )
    g.add_argument(
        "--pkcs12-legacy",
        action="store_const",
        const=True,
        help="use legacy 3DES/SHA1 PKCS#12 encryption for old consumers",
    )
    g.add_argument("--pkcs12-name", metavar="ALIAS", help="PKCS#12 friendly name / alias")
    g.add_argument(
        "--list-formats", action="store_true", help="print the available formats and exit"
    )

    g = p.add_argument_group("targets")
    g.add_argument(
        "-t",
        "--target",
        action="append",
        dest="targets",
        metavar="TARGET",
        help="'/dir', 'dir:/dir', 'user@host:/dir' or 'scp://user@host:port/dir'; repeatable",
    )
    g.add_argument("--owner", help="owner for files written to local directory targets")
    g.add_argument("--group", help="group for files written to local directory targets")
    g.add_argument(
        "--no-create",
        dest="create",
        action="store_const",
        const=False,
        help="fail instead of creating missing target directories",
    )

    g = p.add_argument_group("ssh / scp")
    g.add_argument("--ssh-bin", help="ssh executable (default: ssh)")
    g.add_argument("--scp-bin", help="scp executable (default: scp)")
    g.add_argument("-i", "--ssh-identity", metavar="PATH", help="ssh private key")
    g.add_argument(
        "--ssh-option",
        action="append",
        metavar="OPT",
        help="extra ssh -o option, e.g. StrictHostKeyChecking=yes; repeatable",
    )
    g.add_argument("--ssh-connect-timeout", type=int, metavar="SECONDS")
    g.add_argument(
        "--ssh-interactive",
        dest="batch_mode",
        action="store_const",
        const=False,
        help="do not force BatchMode=yes",
    )

    g = p.add_argument_group("post-deploy commands (run in the given order)")
    g.add_argument(
        "-x",
        "--exec",
        dest="commands",
        action=_CommandAction,
        metavar="CMD",
        help="local shell command; repeatable",
    )
    g.add_argument(
        "--remote-exec",
        dest="commands",
        action=_CommandAction,
        nargs=2,
        metavar=("DEST", "CMD"),
        help="command on [ssh://][user@]host[:port] via ssh; repeatable",
    )
    g.add_argument("--command-timeout", type=float, metavar="SECONDS")

    g = p.add_argument_group("verification")
    g.add_argument(
        "--verify-files",
        action="store_const",
        const=True,
        help="check that every deployed file is present and identical",
    )
    g.add_argument(
        "--verify-endpoint",
        action="append",
        metavar="HOST[:PORT]",
        help="check that HOST:PORT serves the extracted certificate; repeatable",
    )
    g.add_argument(
        "--verify-servername",
        metavar="SNI",
        help="SNI name for --verify-endpoint (default: the host)",
    )
    g.add_argument("--verify-retries", type=int, metavar="N")
    g.add_argument("--verify-delay", type=float, metavar="SECONDS")
    g.add_argument("--verify-timeout", type=float, metavar="SECONDS")
    g.add_argument(
        "--min-days",
        type=float,
        metavar="DAYS",
        help="fail (exit 7) if the certificate expires within DAYS",
    )

    g = p.add_argument_group("behaviour")
    g.add_argument(
        "--only-if-changed",
        action="store_const",
        const=True,
        help="skip deploy and commands when targets already hold the certificate",
    )
    g.add_argument("--force", action="store_true", help="ignore --only-if-changed")
    g.add_argument(
        "--dry-run",
        action="store_true",
        help="extract and compare, but do not write files or run commands",
    )
    g.add_argument("--fail-fast", action="store_true", help="stop after the first failing job")
    g.add_argument(
        "--check-config",
        action="store_true",
        help="validate configuration, print the jobs and exit",
    )
    g.add_argument(
        "-o",
        "--output",
        choices=OUTPUT_FORMATS,
        default="text",
        help="stdout format (default: text, one key=value line per step)",
    )
    g.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="diagnostics on stderr; -vv shows executed commands",
    )
    return p


def _split_assignment(value: str, option: str) -> tuple[str, str]:
    key, sep, val = value.partition("=")
    if not sep or not key or not val:
        raise CertferryError(f"{option}: expected FORMAT=NAME, got {value!r}")
    return key, val


def overrides_from_args(args: argparse.Namespace) -> dict[str, Any]:
    """Translate parsed arguments into the same dict shape as a YAML job."""
    o: dict[str, Any] = {}
    for key in (
        "secret",
        "certificate",
        "namespace",
        "context",
        "kubeconfig",
        "kubectl",
        "kubectl_timeout",
        "kubectl_cache_dir",
        "require_ready",
        "formats",
        "cert_mode",
        "key_mode",
        "min_days",
        "only_if_changed",
    ):
        value = getattr(args, key)
        if value is not None:
            o[key] = value

    if args.filename:
        o["filenames"] = dict(_split_assignment(v, "--filename") for v in args.filename)

    if args.targets:
        targets = []
        for spec in args.targets:
            target = parse_target_spec(spec)
            if target["type"] == "dir":
                for key in ("owner", "group"):
                    if getattr(args, key) is not None:
                        target[key] = getattr(args, key)
            if args.create is not None:
                target["create"] = args.create
            targets.append(target)
        o["targets"] = targets

    if args.commands:
        commands = []
        for kind, dest, cmd in args.commands:
            entry: dict[str, Any] = {"run": cmd}
            if kind == "remote":
                user, host, port = parse_destination(dest)
                entry.update({"host": host, "user": user, "port": port})
            if args.command_timeout is not None:
                entry["timeout"] = args.command_timeout
            commands.append(entry)
        o["commands"] = commands

    verify: dict[str, Any] = {}
    if args.verify_files is not None:
        verify["files"] = True
    if args.verify_endpoint:
        endpoints = []
        for spec in args.verify_endpoint:
            ep = parse_endpoint_spec(spec)
            if args.verify_servername:
                ep["servername"] = args.verify_servername
            endpoints.append(ep)
        verify["endpoints"] = endpoints
    for key in ("retries", "delay", "timeout"):
        value = getattr(args, f"verify_{key}")
        if value is not None:
            verify[key] = value
    if verify:
        o["verify"] = verify

    pkcs12: dict[str, Any] = {}
    if args.pkcs12_password_env:
        pkcs12["password_env"] = args.pkcs12_password_env
    if args.pkcs12_password_file:
        pkcs12["password_file"] = args.pkcs12_password_file
    if args.pkcs12_legacy:
        pkcs12["legacy"] = True
    if args.pkcs12_name:
        pkcs12["friendly_name"] = args.pkcs12_name
    if pkcs12:
        o["pkcs12"] = pkcs12

    ssh: dict[str, Any] = {}
    for arg, key in (
        ("ssh_bin", "ssh_bin"),
        ("scp_bin", "scp_bin"),
        ("ssh_identity", "identity"),
        ("ssh_option", "options"),
        ("ssh_connect_timeout", "connect_timeout"),
        ("batch_mode", "batch_mode"),
    ):
        value = getattr(args, arg)
        if value is not None:
            ssh[key] = value
    if ssh:
        o["ssh"] = ssh
    return o


def _print_formats(out: IO[str]) -> None:
    for spec in FORMATS.values():
        out.write(
            f"format={spec.name} filename={spec.default_filename} "
            f'secret={"true" if spec.secret else "false"} description="{spec.description}"\n'
        )


def _describe_job(job: JobConfig) -> dict[str, Any]:
    return {
        "job": job.name,
        "step": "config",
        "status": "ok",
        "source": job.source.label,
        "context": job.source.context or "",
        "formats": job.formats,
        "targets": [t.label for t in job.build_targets()],
        "commands": [f"{c.location}:{c.shell_text}" for c in job.commands],
        "verify_files": job.verify.files,
        "verify_endpoints": [e.label for e in job.verify.endpoints or []],
        "only_if_changed": job.only_if_changed,
        "min_days": job.min_days if job.min_days is not None else "",
    }


def _setup_logging(verbosity: int, stream: IO[str]) -> None:
    level = logging.WARNING if verbosity == 0 else logging.INFO if verbosity == 1 else logging.DEBUG
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    log.handlers[:] = [handler]
    log.setLevel(level)
    log.propagate = False


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: RunnerProtocol | None = None,
    stdout: IO[str] | None = None,
    stderr: IO[str] | None = None,
    context: dict[str, Any] | None = None,
) -> int:
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose, err)

    if args.list_formats:
        _print_formats(out)
        return 0

    try:
        jobs = resolve_jobs(args.config, overrides_from_args(args), args.jobs)
    except CertferryError as exc:
        err.write(f"error: {exc}\n")
        return EXIT_CONFIG

    reporter = Reporter(out, args.output)
    if args.check_config:
        if args.output == "json":
            import json

            out.write(json.dumps([_describe_job(j) for j in jobs], indent=2) + "\n")
        else:
            for job in jobs:
                reporter.event(_describe_job(job))
        return 0

    ctx = RunContext(
        runner=runner or Runner(),
        reporter=reporter,
        dry_run=args.dry_run,
        force=args.force,
        **(context or {}),
    )
    results: list[JobResult] = []
    exit_code = 0
    for job in jobs:
        result = run_job(job, ctx)
        results.append(result)
        if result.exit_code:
            log.error("job %s failed: %s", job.name, result.error)
            exit_code = exit_code or result.exit_code
            if args.fail_fast:
                break
    reporter.summary(results, exit_code)
    return exit_code
