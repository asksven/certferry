"""Machine-friendly output: logfmt text lines, JSON lines, or one JSON document."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import IO, Any

OUTPUT_FORMATS = ("text", "jsonl", "json")


@dataclass
class JobResult:
    name: str
    status: str = "ok"
    exit_code: int = 0
    error: str | None = None
    changed: bool | None = None
    certificate: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "exit_code": self.exit_code,
            "error": self.error,
            "changed": self.changed,
            "certificate": self.certificate,
            "events": self.events,
        }


def logfmt_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return '""'
    if isinstance(value, (list, tuple)):
        value = ",".join(str(v) for v in value)
    text = str(value)
    if text == "" or any(c in text for c in ' "=\t\n\r\\'):
        return json.dumps(text)
    return text


def logfmt(event: dict[str, Any]) -> str:
    return " ".join(f"{k}={logfmt_value(v)}" for k, v in event.items())


class Reporter:
    def __init__(self, stream: IO[str], fmt: str = "text") -> None:
        if fmt not in OUTPUT_FORMATS:
            raise ValueError(f"unknown output format {fmt}")
        self.stream = stream
        self.fmt = fmt

    def event(self, event: dict[str, Any]) -> None:
        if self.fmt == "text":
            self._write(logfmt(event))
        elif self.fmt == "jsonl":
            self._write(json.dumps(event, sort_keys=False))

    def summary(self, results: Sequence[JobResult], exit_code: int) -> None:
        failed = [r.name for r in results if r.status != "ok"]
        status = "ok" if exit_code == 0 else "failed"
        if self.fmt == "json":
            doc = {
                "status": status,
                "exit_code": exit_code,
                "jobs": [r.as_dict() for r in results],
            }
            self._write(json.dumps(doc, indent=2))
            return
        event = {
            "step": "summary",
            "status": status,
            "exit_code": exit_code,
            "jobs": len(results),
            "failed": failed,
            "changed": [r.name for r in results if r.changed],
        }
        self.event(event)

    def _write(self, line: str) -> None:
        self.stream.write(line + "\n")
        self.stream.flush()
