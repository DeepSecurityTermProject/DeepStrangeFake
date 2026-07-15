from __future__ import annotations

import re
import threading
import uuid
from dataclasses import dataclass, field, fields
from enum import Enum
from pathlib import Path
from typing import Any

from ..models import stable_id, to_plain, utc_now
from ..models import MessageEnvelope
from .audit_events import AuditEventService
from .posture import PostureService
from .workspace_store import Project, WorkspaceStore


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    DEGRADED = "degraded"
    CANCELLED = "cancelled"
    FAILED = "failed"


TERMINAL_JOB_STATUSES = {
    JobStatus.SUCCEEDED.value,
    JobStatus.DEGRADED.value,
    JobStatus.CANCELLED.value,
    JobStatus.FAILED.value,
}


@dataclass
class ScanJob:
    job_id: str
    target: str
    status: str
    output_dir: str
    project_id: str = ""
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
    request_snapshot: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


class JobStore:
    """Compatibility facade over the transactional project workspace database."""

    def __init__(
        self,
        path: str | Path,
        *,
        db_path: str | Path | None = None,
        busy_timeout_ms: int = 5_000,
        event_journal_root: str | Path | None = None,
    ):
        self.path = Path(path)
        self.db_path = Path(db_path) if db_path else self._default_db_path(self.path)
        self._lock = threading.RLock()
        self.workspace = WorkspaceStore(
            self.db_path,
            legacy_jobs_path=self.path,
            busy_timeout_ms=busy_timeout_ms,
        )
        self.events = AuditEventService(
            self.workspace,
            Path(event_journal_root) if event_journal_root else self.db_path.parent / "events",
        )
        self.posture = PostureService(self.workspace)

    @staticmethod
    def _default_db_path(path: Path) -> Path:
        if path.suffix.lower() in {".sqlite", ".sqlite3", ".db"}:
            return path
        return path.with_suffix(".sqlite3")

    def create_job(
        self,
        target: str,
        output_dir: str | Path,
        *,
        source: dict[str, Any] | None = None,
        requested_revision: str | None = None,
        project_id: str | None = None,
        request_snapshot: dict[str, Any] | None = None,
        project_display_name: str | None = None,
        project_languages: list[dict[str, Any]] | None = None,
        project_metadata: dict[str, Any] | None = None,
    ) -> ScanJob:
        created_at = utc_now()
        job_id = stable_id("JOB", target, created_at, uuid.uuid4().hex)
        record = {
            "job_id": job_id,
            "target": target,
            "status": JobStatus.QUEUED.value,
            "output_dir": str(Path(output_dir)),
            "created_at": created_at,
            "source": source,
            "requested_revision": requested_revision,
            "request_snapshot": request_snapshot or {},
        }
        with self._lock:
            saved, _project, _created = self.workspace.create_job_record(
                record,
                project_id=project_id,
                source=source,
                project_display_name=project_display_name,
                project_languages=project_languages,
                project_metadata=project_metadata,
            )
        job = self._job_from_record(saved)
        self._emit_event(job, "created")
        return job

    def get(self, job_id: str) -> ScanJob:
        with self._lock:
            return self._job_from_record(self.workspace.get_job_record(job_id))

    def list_jobs(
        self,
        project_id: str | None = None,
        *,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[ScanJob]:
        with self._lock:
            return [
                self._job_from_record(item)
                for item in self.workspace.list_job_records(
                    project_id=project_id,
                    limit=limit,
                    offset=offset,
                )
            ]

    def list_jobs_page(
        self,
        *,
        project_id: str | None = None,
        limit: int,
        offset: int,
    ) -> tuple[list[ScanJob], int]:
        jobs = self.list_jobs(project_id=project_id, limit=limit, offset=offset)
        return jobs, self.workspace.count_job_records(project_id)

    def mark_running(self, job_id: str) -> ScanJob:
        with self._lock:
            job = self.get(job_id)
            job.status = JobStatus.RUNNING.value
            job.started_at = job.started_at or utc_now()
            if job.phase == "queued":
                job.phase = "validating-source"
            self._persist_job(job)
            self._emit_event(job, "running")
            return job

    def mark_succeeded(self, job_id: str, summary: dict[str, Any]) -> ScanJob:
        with self._lock:
            job = self.get(job_id)
            if job.status in TERMINAL_JOB_STATUSES:
                return job
            job.status = JobStatus.SUCCEEDED.value
            job.finished_at = utc_now()
            job.summary = dict(summary or {})
            if job.summary.get("run_dir"):
                job.run_dir = str(job.summary["run_dir"])
            job.phase = "complete"
            self._apply_acquisition_summary(job)
            self._persist_job(job)
            self._project_posture(job)
            self._emit_event(job, "succeeded")
            return job

    def mark_degraded(self, job_id: str, summary: dict[str, Any]) -> ScanJob:
        with self._lock:
            job = self.get(job_id)
            if job.status in TERMINAL_JOB_STATUSES:
                return job
            job.status = JobStatus.DEGRADED.value
            job.finished_at = utc_now()
            job.summary = dict(summary or {})
            if job.summary.get("run_dir"):
                job.run_dir = str(job.summary["run_dir"])
            job.phase = "complete"
            self._apply_acquisition_summary(job)
            self._persist_job(job)
            self._project_posture(job)
            self._emit_event(job, "degraded")
            return job

    def mark_cancelled(self, job_id: str, summary: dict[str, Any] | None = None) -> ScanJob:
        with self._lock:
            job = self.get(job_id)
            if job.status in TERMINAL_JOB_STATUSES:
                return job
            job.status = JobStatus.CANCELLED.value
            job.finished_at = utc_now()
            if summary:
                job.summary = dict(summary)
                if job.summary.get("run_dir"):
                    job.run_dir = str(job.summary["run_dir"])
            job.phase = "cancelled"
            self._persist_job(job)
            self._project_posture(job)
            self._emit_event(job, "cancelled")
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
            if job.status in TERMINAL_JOB_STATUSES:
                return job
            job.status = JobStatus.FAILED.value
            job.finished_at = utc_now()
            job.error = sanitize_error(error)
            job.phase = "failed"
            if run_dir:
                job.run_dir = run_dir
            if summary:
                job.summary.update(summary)
                self._apply_acquisition_summary(job)
            self._persist_job(job)
            self._project_posture(job)
            self._emit_event(job, "failed")
            return job

    def update_phase(
        self, job_id: str, phase: str, acquisition_summary: dict[str, Any] | None = None
    ) -> ScanJob:
        order = [
            "queued",
            "validating-source",
            "acquiring",
            "resolving-commit",
            "exporting",
            "analyzing",
            "scanning",
            "verifying",
            "reporting",
            "cleaning-up",
            "complete",
            "cancelled",
            "failed",
        ]
        with self._lock:
            job = self.get(job_id)
            if job.status in TERMINAL_JOB_STATUSES:
                return job
            if phase not in order:
                raise ValueError(f"unknown job phase: {phase}")
            if job.phase in order and phase != "failed" and order.index(phase) < order.index(job.phase):
                raise ValueError("job phase cannot move backwards")
            if job.phase == phase and not acquisition_summary:
                return job
            job.phase = phase
            if acquisition_summary:
                job.acquisition_summary.update(acquisition_summary)
            self._persist_job(job)
            self._emit_event(job, "phase")
            return job

    def project_runtime_message(self, job_id: str, message: MessageEnvelope) -> None:
        try:
            job = self.get(job_id)
            self.events.project_message(job_id, job, message)
        except Exception:
            # Public projection is observational and must never alter audit orchestration.
            return

    def get_project(self, project_id: str) -> Project:
        return self.workspace.get_project(project_id)

    def get_project_by_source(self, source: dict[str, Any]) -> Project | None:
        return self.workspace.get_project_by_source(source)

    def list_projects(self, **filters: Any) -> list[Project]:
        return self.workspace.list_projects(**filters)

    def list_projects_page(self, **filters: Any) -> tuple[list[Project], int]:
        return self.workspace.list_projects_page(**filters)

    def create_or_get_project(self, source: dict[str, Any], **metadata: Any) -> tuple[Project, bool]:
        return self.workspace.create_or_get_project(source, **metadata)

    def rename_project(self, project_id: str, display_name: str) -> Project:
        return self.workspace.rename_project(project_id, display_name)

    def update_project_metadata(self, project_id: str, **metadata: Any) -> Project:
        return self.workspace.update_project_metadata(project_id, **metadata)

    def archive_project(self, project_id: str) -> Project:
        return self.workspace.archive_project(project_id)

    def restore_project(self, project_id: str) -> Project:
        return self.workspace.restore_project(project_id)

    def migration_diagnostics(self) -> list[dict[str, Any]]:
        return self.workspace.migration_diagnostics()

    def _persist_job(self, job: ScanJob) -> None:
        self.workspace.update_job_record(job.to_dict())

    def _emit_event(self, job: ScanJob, transition: str) -> None:
        try:
            self.events.project_lifecycle(job, transition)
        except Exception:
            # The event service records sanitized diagnostics. Lifecycle truth remains in SQLite.
            return

    def _project_posture(self, job: ScanJob) -> None:
        try:
            self.posture.project_run(job.to_dict())
        except Exception:
            # Posture is a rebuildable projection; terminal run truth remains authoritative.
            return

    @staticmethod
    def _apply_acquisition_summary(job: ScanJob) -> None:
        job.resolved_commit = job.summary.get("resolved_commit") or job.resolved_commit
        job.acquisition_ref = job.summary.get("acquisition_ref") or job.acquisition_ref
        job.cleanup_status = job.summary.get("cleanup_status") or job.cleanup_status
        job.acquisition_summary = {
            key: job.summary.get(key)
            for key in ("acquisition_status", "cache_status", "network_used")
            if key in job.summary
        }

    @staticmethod
    def _job_from_record(record: dict[str, Any]) -> ScanJob:
        allowed = {item.name for item in fields(ScanJob)}
        payload = {key: value for key, value in record.items() if key in allowed}
        return ScanJob(**payload)


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
