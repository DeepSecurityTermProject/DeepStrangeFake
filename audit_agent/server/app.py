from __future__ import annotations

from pathlib import Path
import os

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import PlainTextResponse

from ..config import AuditConfig
from ..integration import load_integration_environment
from ..repository_acquisition import (
    AcquisitionError,
    normalize_remote_source,
    normalize_revision,
    remote_source_kind,
)
from .artifacts import (
    ArtifactAccessDenied,
    ArtifactUnavailable,
    read_replay_summary,
    read_report_json,
    read_report_markdown,
    read_runtime_state,
)
from .job_store import JobStore, ScanJob
from .runner import ScanJobRunner
from .schemas import CreateRunResponse, JobListResponse, JobStatusResponse, ScanRunRequest


def create_app(
    job_store: JobStore | None = None,
    runner=None,
    output_dir: str | Path = "runs",
    config: AuditConfig | None = None,
) -> FastAPI:
    output_root = Path(output_dir)
    store = job_store or JobStore(output_root / "web" / "jobs.json")
    selected_config = config or AuditConfig.default()
    if config is None:
        load_integration_environment(selected_config, cwd=Path.cwd(), env=dict(os.environ))
    scan_runner = runner or ScanJobRunner(store, config=selected_config)
    app = FastAPI(title="Agentic Security Audit API")

    @app.get("/api/health")
    def health():
        return {"service": "agentic-security-audit-api", "status": "ok", "api_version": "v1"}

    @app.get("/api/options")
    def options():
        return {
            "provider_modes": ["mock", "openai-compatible"],
            "graph_modes": ["legacy", "deterministic-graph", "adaptive-graph"],
            "default_graph_mode": selected_config.graph.mode,
            "memory_modes": ["lexical", "embedding", "off"],
            "mcp_modes": ["on", "degraded", "off"],
            "validation_levels": ["static-only", "poc-generate", "sandbox", "manual"],
            "llm_decision_roles": ["orchestrator", "recon", "analysis", "verification"],
            "sandbox_runners": ["local", "docker"],
            "default_docker_image": selected_config.sandbox.docker_image,
            "default_docker_context": selected_config.sandbox.docker_context or "",
            "default_docker_host": selected_config.sandbox.docker_host or "",
            "llm_poc_repair_default": selected_config.poc_repair.enabled,
            "max_repair_attempts_default": selected_config.poc_repair.max_repair_attempts,
            "max_repair_attempts_range": [0, 2],
            "poc_repair_effective_source": selected_config.poc_repair.effective_source,
            "poc_repair_requires_docker": True,
            "default_exclude_patterns": selected_config.audit_scope.exclude_patterns,
            "remote_acquisition": {
                "enabled": selected_config.remote_acquisition.enabled,
                "network_enabled": selected_config.remote_acquisition.network_enabled,
                "allowed_hosts": selected_config.remote_acquisition.allowed_hosts,
                "supports_head": selected_config.remote_acquisition.network_enabled,
                "limits": {
                    "command_timeout_seconds": selected_config.remote_acquisition.command_timeout_seconds,
                    "total_timeout_seconds": selected_config.remote_acquisition.total_timeout_seconds,
                    "max_archive_members": selected_config.remote_acquisition.max_archive_members,
                    "max_archive_bytes": selected_config.remote_acquisition.max_archive_bytes,
                    "max_files": selected_config.remote_acquisition.max_files,
                    "max_bytes": selected_config.remote_acquisition.max_bytes,
                },
            },
        }

    @app.post("/api/runs", response_model=CreateRunResponse, status_code=status.HTTP_202_ACCEPTED)
    def create_run(request: ScanRunRequest):
        if request.source and request.source.kind in {"github", "gitlab"}:
            if not selected_config.remote_acquisition.enabled:
                raise HTTPException(
                    status_code=422,
                    detail={"error": "remote-acquisition-disabled"},
                )
            try:
                normalize_remote_source(
                    request.source.url,
                    selected_config.remote_acquisition.allowed_hosts,
                )
                normalize_revision(request.source.commit)
                if remote_source_kind(request.source.url) != request.source.kind:
                    raise AcquisitionError("source-kind-mismatch")
            except AcquisitionError as exc:
                raise HTTPException(
                    status_code=422,
                    detail={"error": exc.reason, "message": exc.detail},
                ) from exc
        selected_output = Path(request.output or output_root)
        job = store.create_job(
            request.display_target,
            output_dir=selected_output,
            source=request.source.model_dump() if request.source else None,
            requested_revision=request.requested_revision,
        )
        initial_status = job.status
        scan_runner.submit(job.job_id, request)
        return {
            "job_id": job.job_id,
            "status": initial_status,
            "status_url": f"/api/runs/{job.job_id}",
        }

    @app.get("/api/runs", response_model=JobListResponse)
    def list_runs():
        return {"jobs": [_job_payload(job) for job in store.list_jobs()]}

    @app.get("/api/runs/{job_id}", response_model=JobStatusResponse)
    def get_run(job_id: str):
        return _job_payload(_get_job_or_404(store, job_id))

    @app.get("/api/runs/{job_id}/runtime-state")
    def get_runtime_state(job_id: str):
        job = _get_job_or_404(store, job_id)
        try:
            return read_runtime_state(job)
        except ArtifactUnavailable as exc:
            raise _artifact_not_found(str(exc)) from exc
        except ArtifactAccessDenied as exc:
            raise _artifact_denied(str(exc)) from exc

    @app.get("/api/runs/{job_id}/replay-summary")
    def get_replay_summary(job_id: str):
        job = _get_job_or_404(store, job_id)
        try:
            return read_replay_summary(job)
        except ArtifactUnavailable as exc:
            raise _artifact_not_found(str(exc)) from exc
        except ArtifactAccessDenied as exc:
            raise _artifact_denied(str(exc)) from exc

    @app.get("/api/runs/{job_id}/reports/report.json")
    def get_report_json(job_id: str):
        job = _get_job_or_404(store, job_id)
        try:
            return read_report_json(job)
        except ArtifactUnavailable as exc:
            raise _artifact_not_found(str(exc)) from exc
        except ArtifactAccessDenied as exc:
            raise _artifact_denied(str(exc)) from exc

    @app.get("/api/runs/{job_id}/reports/report.md", response_class=PlainTextResponse)
    def get_report_markdown(job_id: str):
        job = _get_job_or_404(store, job_id)
        try:
            return read_report_markdown(job)
        except ArtifactUnavailable as exc:
            raise _artifact_not_found(str(exc)) from exc
        except ArtifactAccessDenied as exc:
            raise _artifact_denied(str(exc)) from exc

    return app


app = create_app()


def _get_job_or_404(store: JobStore, job_id: str) -> ScanJob:
    try:
        return store.get(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail={"error": "job-not-found", "job_id": job_id}) from exc


def _job_payload(job: ScanJob) -> dict:
    return job.to_dict()


def _artifact_not_found(message: str) -> HTTPException:
    return HTTPException(status_code=404, detail={"error": "artifact-not-found", "message": message})


def _artifact_denied(message: str) -> HTTPException:
    return HTTPException(status_code=403, detail={"error": "artifact-access-denied", "message": message})
