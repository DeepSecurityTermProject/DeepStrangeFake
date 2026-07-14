from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..message_bus import replay_run_summary
from .job_store import ScanJob


class ArtifactUnavailable(FileNotFoundError):
    pass


class ArtifactAccessDenied(PermissionError):
    pass


def read_runtime_state(job: ScanJob) -> dict[str, Any]:
    return _read_json(job, "runtime_state", "state.json")


def read_replay_summary(job: ScanJob) -> dict[str, Any]:
    path = _resolve_job_file(job, "messages", "messages.jsonl")
    return replay_run_summary(path, run_dir=job.run_dir)


def read_report_json(job: ScanJob) -> dict[str, Any]:
    return _read_json(job, "reports", "report.json")


def read_report_markdown(job: ScanJob) -> str:
    path = _resolve_job_file(job, "reports", "report.md")
    return path.read_text(encoding="utf-8")


def _read_json(job: ScanJob, *parts: str) -> dict[str, Any]:
    path = _resolve_job_file(job, *parts)
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve_job_file(job: ScanJob, *parts: str) -> Path:
    if not job.run_dir:
        raise ArtifactUnavailable("Job has no run directory yet.")
    root = Path(job.run_dir).resolve()
    candidate = root.joinpath(*parts).resolve()
    if candidate != root and root not in candidate.parents:
        raise ArtifactAccessDenied("Artifact path escapes job run directory.")
    if not candidate.is_file():
        raise ArtifactUnavailable(f"Artifact not found: {'/'.join(parts)}")
    return candidate
