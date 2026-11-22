"""Per-job orchestration: extract -> render -> compare -> deploy -> commands -> verify -> expiry."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from certferry.certs import CertMaterial, OutputFile, render, same_content
from certferry.commands import run_command
from certferry.config import JobConfig
from certferry.errors import CertferryError, DeployError, ExpiryError, VerifyError
from certferry.kube import fetch_secret
from certferry.report import JobResult, Reporter
from certferry.runner import RunnerProtocol
from certferry.targets import Target
from certferry.verify import PeerFetcher, fetch_peer_cert, verify_endpoint, verify_files


@dataclass
class RunContext:
    runner: RunnerProtocol
    reporter: Reporter
    dry_run: bool = False
    force: bool = False
    sleep: Callable[[float], None] = time.sleep
    fetch_peer: PeerFetcher = fetch_peer_cert
    now: Callable[[], datetime] = field(default=lambda: datetime.now(timezone.utc))


def _up_to_date(
    target: Target, files: Sequence[OutputFile], runner: RunnerProtocol, password: bytes | None
) -> bool:
    for f in files:
        try:
            existing = target.read(f.name, runner)
        except DeployError:
            return False
        if not same_content(f, existing, password):
            return False
    return True


class _Job:
    def __init__(self, job: JobConfig, ctx: RunContext) -> None:
        self.job = job
        self.ctx = ctx
        self.result = JobResult(job.name)
        self.step = "extract"

    def emit(self, status: str, **fields: Any) -> None:
        event = {"job": self.job.name, "step": self.step, "status": status, **fields}
        self.result.events.append(event)
        self.ctx.reporter.event(event)

    def run(self) -> JobResult:
        try:
            self._run()
        except CertferryError as exc:
            self.result.status = "failed"
            self.result.exit_code = exc.exit_code
            self.result.error = str(exc)
            self.emit("failed", exit_code=exc.exit_code, error=str(exc))
        return self.result

    def _run(self) -> None:
        job, ctx = self.job, self.ctx

        self.step = "extract"
        secret = fetch_secret(job.source, ctx.runner)
        material = CertMaterial.from_pem(secret.tls_crt, secret.tls_key, secret.ca_crt)
        info = material.info()
        self.result.certificate = info
        self.emit(
            "ok",
            secret=f"{secret.namespace}/{secret.name}",
            common_name=info["common_name"],
            dns_names=info["dns_names"],
            not_after=info["not_after"],
            fingerprint=info["fingerprint_sha256"],
        )

        self.step = "render"
        files = render(material, job.formats, job.filenames, job.pkcs12)
        self.emit("ok", formats=job.formats, files=[f.name for f in files])

        targets = job.build_targets()
        pending = list(targets)
        if job.only_if_changed and not ctx.force:
            self.step = "compare"
            pending = []
            for target in targets:
                current = _up_to_date(target, files, ctx.runner, job.pkcs12.password)
                self.emit("unchanged" if current else "changed", target=target.label)
                if not current:
                    pending.append(target)
        self.result.changed = bool(pending)

        self.step = "deploy"
        pending_ids = {id(t) for t in pending}
        for target in targets:
            if id(target) not in pending_ids:
                self.emit("skipped", target=target.label, reason="unchanged")
            elif ctx.dry_run:
                self.emit("dry-run", target=target.label, files=[f.name for f in files])
            else:
                target.deploy(files, ctx.runner)
                self.emit("ok", target=target.label, files=[f.name for f in files])

        self.step = "command"
        run_commands = bool(pending) or not targets
        env = {
            "CERTFERRY_JOB": job.name,
            "CERTFERRY_FINGERPRINT": material.fingerprint,
            "CERTFERRY_NOT_AFTER": info["not_after"],
            "CERTFERRY_COMMON_NAME": info["common_name"],
        }
        for index, cmd in enumerate(job.commands):
            fields = {"index": index, "location": cmd.location, "command": cmd.shell_text}
            if not run_commands:
                self.emit("skipped", reason="unchanged", **fields)
            elif ctx.dry_run:
                self.emit("dry-run", **fields)
            else:
                run_command(cmd, job.ssh, ctx.runner, env)
                self.emit("ok", **fields)

        if job.verify.files:
            self.step = "verify-files"
            for target in targets:
                if ctx.dry_run:
                    self.emit("skipped", target=target.label, reason="dry-run")
                    continue
                bad = verify_files(target, files, ctx.runner, job.pkcs12.password)
                if bad:
                    raise VerifyError(
                        f"{target.label}: missing or different file(s): {', '.join(bad)}"
                    )
                self.emit("ok", target=target.label, files=[f.name for f in files])

        for endpoint in job.verify.endpoints or []:
            self.step = "verify-endpoint"
            if ctx.dry_run:
                self.emit("skipped", endpoint=endpoint.label, reason="dry-run")
                continue
            outcome = verify_endpoint(
                endpoint, material.leaf_der, job.verify, ctx.fetch_peer, ctx.sleep
            )
            self.emit("ok", endpoint=endpoint.label, **outcome)

        self.step = "expiry"
        days = material.days_remaining(ctx.now())
        if job.min_days is not None and days < job.min_days:
            raise ExpiryError(
                f"certificate expires in {days:.1f} days (threshold {job.min_days:g}), "
                f"not_after={info['not_after']}"
            )
        self.emit("ok", days_remaining=round(days, 2), not_after=info["not_after"])


def run_job(job: JobConfig, ctx: RunContext) -> JobResult:
    return _Job(job, ctx).run()
