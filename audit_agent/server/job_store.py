from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from ..models import stable_id, to_plain, utc_now


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass
class ScanJob:
    job_id: str
    target: str
    status: str
    output_dir: str
    created_at: str = field(default_factory=utc_now)
    started_at: str | None = None
    finished_at: str | None = None
    run_dir: str | None = None
    summary: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    source: dict[str, Any] | None = None
    phase: str = "queued"
    requested_revision: str | None = None
    resolved_commit: str | None = None
    acquisition_summary: dict[str, Any] = field(default_factory=dict)
    acquisition_ref: str | None = None
    cleanup_status: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


class JobStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._jobs: dict[str, ScanJob] = {}
        self._load()

    def create_job(
        self,
        target: str,
        output_dir: str | Path,
        *,
        source: dict[str, Any] | None = None,
        requested_revision: str | None = None,
    ) -> ScanJob:
        created_at = utc_now()
        job_id = stable_id("JOB", target, created_at, len(self._jobs))
        job = ScanJob(
            job_id=job_id,
            target=target,
            status=JobStatus.QUEUED.value,
            output_dir=str(Path(output_dir)),
            created_at=created_at,
            source=source,
            requested_revision=requested_revision,
        )
        with self._lock:
            self._jobs[job.job_id] = job
            self._persist()
        return job

    def get(self, job_id: str) -> ScanJob:
        with self._lock:
            try:
                return self._jobs[job_id]
            except KeyError as exc:
                raise KeyError(f"Unknown job: {job_id}") from exc

    def list_jobs(self) -> list[ScanJob]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda job: job.created_at)

    def mark_running(self, job_id: str) -> ScanJob:
        with self._lock:
            job = self.get(job_id)
            job.status = JobStatus.RUNNING.value
            job.started_at = job.started_at or utc_now()
            if job.phase == "queued":
                job.phase = "validating-source"
            self._persist()
            return job

    def mark_succeeded(self, job_id: str, summary: dict[str, Any]) -> ScanJob:
        with self._lock:
            job = self.get(job_id)
            job.status = JobStatus.SUCCEEDED.value
            job.finished_at = utc_now()
            job.summary = dict(summary or {})
            if job.summary.get("run_dir"):
                job.run_dir = str(job.summary["run_dir"])
            job.phase = "complete"
            job.resolved_commit = job.summary.get("resolved_commit")
            job.acquisition_ref = job.summary.get("acquisition_ref")
            job.cleanup_status = job.summary.get("cleanup_status")
            job.acquisition_summary = {
                key: job.summary.get(key)
                for key in ("acquisition_status", "cache_status", "network_used")
                if key in job.summary
            }
            self._persist()
            return job

    def mark_failed(
        self,
        job_id: str,
        error: str,
        *,
        run_dir: str | None = None,
        summary: dict[str, Any] | None = None,
    ) -> ScanJob:
        with self._lock:
            job = self.get(job_id)
            job.status = JobStatus.FAILED.value
            job.finished_at = utc_now()
            job.error = sanitize_error(error)
            job.phase = "failed"
            if run_dir:
                job.run_dir = run_dir
            if summary:
                job.summary.update(summary)
                job.resolved_commit = job.summary.get("resolved_commit") or job.resolved_commit
                job.acquisition_ref = job.summary.get("acquisition_ref") or job.acquisition_ref
                job.cleanup_status = job.summary.get("cleanup_status") or job.cleanup_status
                job.acquisition_summary = {
                    key: job.summary.get(key)
                    for key in ("acquisition_status", "cache_status", "network_used")
                    if key in job.summary
                }
            self._persist()
            return job

    def update_phase(
        self, job_id: str, phase: str, acquisition_summary: dict[str, Any] | None = None
    ) -> ScanJob:
        order = [
            "queued", "validating-source", "acquiring", "resolving-commit", "exporting",
            "analyzing", "scanning", "verifying", "reporting", "cleaning-up", "complete", "failed",
        ]
        with self._lock:
            job = self.get(job_id)
            if phase not in order:
                raise ValueError(f"unknown job phase: {phase}")
            if job.phase in order and phase != "failed" and order.index(phase) < order.index(job.phase):
                raise ValueError("job phase cannot move backwards")
            job.phase = phase
            if acquisition_summary:
                job.acquisition_summary.update(acquisition_summary)
            self._persist()
            return job

    def _load(self) -> None:
        if not self.path.exists():
            return
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        jobs = payload.get("jobs", []) if isinstance(payload, dict) else payload
        for item in jobs:
            job = ScanJob(**item)
            self._jobs[job.job_id] = job

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"jobs": [job.to_dict() for job in self.list_jobs()]}
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def sanitize_error(error: str) -> str:
    text = str(error)
    patterns = [
        r"(?i)(api[_-]?key\s*=\s*)[^\s]+",
        r"(?i)(token\s*=\s*)[^\s]+",
        r"(?i)(secret\s*=\s*)[^\s]+",
        r"(?i)(password\s*=\s*)[^\s]+",
        r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+",
    ]
    for pattern in patterns:
        text = re.sub(pattern, r"\1[REDACTED]", text)
    return text
