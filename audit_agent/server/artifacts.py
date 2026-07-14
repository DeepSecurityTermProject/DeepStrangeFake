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
    if not job.run_dir:
        raise ArtifactUnavailable("Job has no run directory yet.")
    root = Path(job.run_dir).resolve()
    state_root = (root / "runtime_state").resolve()
    if root not in state_root.parents:
        raise ArtifactAccessDenied("Runtime state path escapes job run directory.")
    candidates = [path for path in state_root.glob("state*.json") if path.is_file()]
    if not candidates:
        raise ArtifactUnavailable("Artifact not found: runtime_state/state.json")
    latest = max(candidates, key=lambda path: (_state_revision(path), path.stat().st_mtime_ns))
    return json.loads(latest.read_text(encoding="utf-8"))


def _state_revision(path: Path) -> int:
    stem = path.stem
    if stem == "state":
        return 0
    suffix = stem.removeprefix("state-")
    return int(suffix) if suffix.isdigit() else -1


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
