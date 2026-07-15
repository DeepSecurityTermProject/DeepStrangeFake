from __future__ import annotations

import asyncio
import json
from pathlib import Path
import os

from fastapi import FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse

from ..config import AuditConfig
from ..integration import load_integration_environment
from ..redaction import redact_secrets
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
from .audit_events import PUBLIC_ARTIFACT_CATEGORIES
from .job_store import JobStore, ScanJob
from .limits import (
    DEFAULT_PAGE_LIMIT,
    MAX_PAGE_LIMIT,
    MAX_PAGE_OFFSET,
    public_console_limits,
)
from .preflight import PreflightError, PreflightService, configured_local_roots
from .runner import ScanJobRunner
from .schemas import (
    CreateRunResponse,
    JobListResponse,
    JobStatusResponse,
    ProjectCreateRequest,
    ProjectListResponse,
    ProjectResponse,
    ProjectUpdateRequest,
    ScanRunRequest,
    SourcePreflightRequest,
    SourcePreflightResponse,
)


def create_app(
    job_store: JobStore | None = None,
    runner=None,
    output_dir: str | Path = "runs",
    config: AuditConfig | None = None,
    preflight_service: PreflightService | None = None,
    allowed_local_roots: list[str | Path] | None = None,
    event_heartbeat_seconds: float = 10.0,
) -> FastAPI:
    output_root = Path(output_dir)
    store = job_store or JobStore(
        output_root / "web" / "jobs.json",
        db_path=Path(".audit-cache") / "web" / "workspace.sqlite3",
    )
    selected_config = config or AuditConfig.default()
    if config is None:
        load_integration_environment(selected_config, cwd=Path.cwd(), env=dict(os.environ))
    scan_runner = runner or ScanJobRunner(store, config=selected_config)
    source_preflight = preflight_service or PreflightService(
        store,
        selected_config,
        allowed_local_roots=allowed_local_roots or configured_local_roots(),
    )
    app = FastAPI(title="Agentic Security Audit API")

    @app.get("/api/health")
    def health():
        return {"service": "agentic-security-audit-api", "status": "ok", "api_version": "v1"}

    @app.get("/api/options")
    def options():
        return {
            "provider_modes": ["mock", "openai-compatible"],
            "graph_modes": ["agent-led", "legacy", "deterministic-graph", "adaptive-graph"],
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
            "console_limits": public_console_limits(),
        }

    @app.post(
        "/api/sources/preflight",
        response_model=SourcePreflightResponse,
    )
    def preflight_source(request: SourcePreflightRequest):
        try:
            record = source_preflight.preflight(
                request.source.model_dump(),
                revision_type=request.revision_type,
                revision=request.revision,
            )
            return record.to_public_dict()
        except PreflightError as exc:
            raise _preflight_http_error(exc) from exc

    @app.get("/api/projects", response_model=ProjectListResponse)
    def list_projects(
        query: str = Query(default="", max_length=200),
        project_status: str = Query(default="active", alias="status"),
        security_status: str = Query(default="", max_length=40),
        order: str = Query(default="recent"),
        limit: int = Query(default=DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
        offset: int = Query(default=0, ge=0, le=MAX_PAGE_OFFSET),
    ):
        try:
            projects, total = store.list_projects_page(
                query=query,
                status=project_status,
                security_status=security_status,
                order=order,
                limit=limit,
                offset=offset,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail={"error": str(exc)}) from exc
        return {
            "projects": [_project_payload(project) for project in projects],
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(projects) < total,
        }

    @app.post("/api/projects", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
    def create_project(request: ProjectCreateRequest):
        source = request.source.model_dump()
        try:
            preflight = source_preflight.consume(
                request.preflight_token,
                expected_source=source,
            )
            project, _created = store.create_or_get_project(
                preflight.source,
                display_name=request.display_name or preflight.suggested_name,
                languages=preflight.languages,
                metadata=preflight.metadata,
            )
            return _project_payload(project)
        except PreflightError as exc:
            raise _preflight_http_error(exc) from exc
        except (ValueError, AcquisitionError) as exc:
            raise HTTPException(status_code=422, detail={"error": str(exc)}) from exc

    @app.get("/api/projects/{project_id}", response_model=ProjectResponse)
    def get_project(project_id: str):
        return _project_payload(_get_project_or_404(store, project_id))

    @app.get("/api/projects/{project_id}/dashboard")
    def get_project_dashboard(project_id: str):
        project = _get_project_or_404(store, project_id)
        try:
            return store.posture.dashboard(project)
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail={"error": "posture-projection-failed"},
            ) from exc

    @app.patch("/api/projects/{project_id}", response_model=ProjectResponse)
    def update_project(project_id: str, request: ProjectUpdateRequest):
        _get_project_or_404(store, project_id)
        try:
            return _project_payload(store.rename_project(project_id, request.display_name))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail={"error": str(exc)}) from exc

    @app.post("/api/projects/{project_id}/archive", response_model=ProjectResponse)
    def archive_project(project_id: str):
        _get_project_or_404(store, project_id)
        try:
            return _project_payload(store.archive_project(project_id))
        except ValueError as exc:
            raise HTTPException(status_code=409, detail={"error": str(exc)}) from exc

    @app.post("/api/projects/{project_id}/restore", response_model=ProjectResponse)
    def restore_project(project_id: str):
        _get_project_or_404(store, project_id)
        return _project_payload(store.restore_project(project_id))

    @app.get("/api/projects/{project_id}/runs", response_model=JobListResponse)
    def list_project_runs(
        project_id: str,
        limit: int = Query(default=DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
        offset: int = Query(default=0, ge=0, le=MAX_PAGE_OFFSET),
    ):
        _get_project_or_404(store, project_id)
        jobs, total = store.list_jobs_page(project_id=project_id, limit=limit, offset=offset)
        return {
            "jobs": [_job_payload(job) for job in jobs],
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(jobs) < total,
        }

    @app.post(
        "/api/projects/{project_id}/runs",
        response_model=CreateRunResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    def create_project_run(project_id: str, request: ScanRunRequest):
        return _submit_run(request, forced_project_id=project_id, require_preflight=True)

    @app.post("/api/runs", response_model=CreateRunResponse, status_code=status.HTTP_202_ACCEPTED)
    def create_run(request: ScanRunRequest):
        return _submit_run(request, forced_project_id=request.project_id, require_preflight=False)

    def _submit_run(
        request: ScanRunRequest,
        *,
        forced_project_id: str | None,
        require_preflight: bool,
    ) -> dict:
        project = _get_project_or_404(store, forced_project_id) if forced_project_id else None
        if project and project.status != "active":
            raise HTTPException(status_code=409, detail={"error": "project-archived"})
        source_payload = request.source.model_dump() if request.source else None
        preflight = None
        if require_preflight and not request.preflight_token:
            raise HTTPException(status_code=422, detail={"error": "preflight-token-required"})
        if request.preflight_token:
            try:
                preflight = source_preflight.consume(
                    request.preflight_token,
                    expected_source=source_payload or {},
                    project_id=forced_project_id,
                )
            except PreflightError as exc:
                raise _preflight_http_error(exc) from exc
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
        request_snapshot = request.model_dump(exclude={"preflight_token"})
        job = store.create_job(
            request.display_target,
            output_dir=selected_output,
            source=source_payload,
            requested_revision=request.requested_revision,
            project_id=forced_project_id,
            request_snapshot=request_snapshot,
            project_display_name=preflight.suggested_name if preflight else None,
            project_languages=preflight.languages if preflight else None,
            project_metadata=preflight.metadata if preflight else None,
        )
        if preflight and forced_project_id:
            store.update_project_metadata(
                job.project_id,
                languages=preflight.languages,
                metadata=preflight.metadata,
            )
        initial_status = job.status
        try:
            scan_runner.submit(job.job_id, request)
        except Exception as exc:
            store.mark_failed(job.job_id, f"runner-submit-failed: {exc}")
            raise HTTPException(
                status_code=503,
                detail={"error": "runner-submit-failed"},
            ) from exc
        return {
            "job_id": job.job_id,
            "status": initial_status,
            "status_url": f"/api/runs/{job.job_id}",
            "project_id": job.project_id,
            "run_url": f"/projects/{job.project_id}/runs/{job.job_id}",
        }

    @app.get("/api/runs", response_model=JobListResponse)
    def list_runs(
        limit: int = Query(default=DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
        offset: int = Query(default=0, ge=0, le=MAX_PAGE_OFFSET),
    ):
        jobs, total = store.list_jobs_page(limit=limit, offset=offset)
        return {
            "jobs": [_job_payload(job) for job in jobs],
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(jobs) < total,
        }

    @app.get("/api/runs/{job_id}", response_model=JobStatusResponse)
    def get_run(job_id: str):
        return _job_payload(_get_job_or_404(store, job_id))

    @app.get("/api/runs/{job_id}/rerun-config")
    def get_rerun_config(job_id: str):
        job = _get_job_or_404(store, job_id)
        snapshot = dict(job.request_snapshot or {})
        snapshot.pop("preflight_token", None)
        snapshot.pop("project_id", None)
        return {
            "source_run_id": job.job_id,
            "project_id": job.project_id,
            "configuration": redact_secrets(snapshot),
        }

    @app.get("/api/runs/{job_id}/events/snapshot")
    def get_run_event_snapshot(job_id: str):
        _get_job_or_404(store, job_id)
        return store.events.snapshot(job_id)

    @app.get("/api/projects/{project_id}/runs/{job_id}/events/snapshot")
    def get_project_run_event_snapshot(project_id: str, job_id: str):
        job = _get_project_run_or_404(store, project_id, job_id)
        return store.events.snapshot(job.job_id)

    def _stream_response(
        job: ScanJob,
        request: Request,
        cursor: str | None,
        last_event_id: str | None,
    ) -> StreamingResponse:
        selected_cursor = _parse_event_cursor(cursor, last_event_id)
        snapshot = store.events.snapshot(job.job_id)
        last_persisted_id = int(snapshot["last_event_id"])
        if selected_cursor > last_persisted_id:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "event-cursor-ahead",
                    "last_event_id": snapshot["last_event_id"],
                },
            )
        replay_floor = max(0, int(snapshot.get("replay_from_event_id") or 0) - 1)
        if selected_cursor < replay_floor:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "event-replay-limit-exceeded",
                    "last_event_id": last_persisted_id,
                    "replay_from_event_id": replay_floor + 1,
                    "reset_cursor": last_persisted_id,
                },
            )
        if not store.events.try_acquire_subscriber(job.job_id):
            raise HTTPException(
                status_code=429,
                detail={"error": "event-subscriber-limit-exceeded"},
                headers={"Retry-After": "5"},
            )

        async def generate():
            try:
                current = selected_cursor
                while True:
                    if await request.is_disconnected():
                        return
                    events = await asyncio.to_thread(
                        store.events.wait_for_events,
                        job.job_id,
                        current,
                        event_heartbeat_seconds,
                    )
                    for event in events:
                        current = event.event_id
                        yield _format_sse("audit-event", event.to_dict(), event_id=event.event_id)
                    latest = store.events.snapshot(job.job_id)
                    terminal = latest.get("terminal")
                    if terminal and current >= int(latest["last_event_id"]):
                        current_job = store.get(job.job_id)
                        yield _format_sse(
                            "terminal-snapshot",
                            {
                                "run_id": job.job_id,
                                "status": current_job.status,
                                "phase": current_job.phase,
                                "last_event_id": latest["last_event_id"],
                            },
                        )
                        return
                    if not events:
                        yield _format_sse(
                            "heartbeat",
                            {"run_id": job.job_id, "last_event_id": current},
                        )
            finally:
                store.events.release_subscriber(job.job_id)

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/api/runs/{job_id}/events")
    def stream_run_events(
        job_id: str,
        request: Request,
        cursor: str | None = Query(default=None),
        last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    ):
        job = _get_job_or_404(store, job_id)
        return _stream_response(job, request, cursor, last_event_id)

    @app.get("/api/projects/{project_id}/runs/{job_id}/events")
    def stream_project_run_events(
        project_id: str,
        job_id: str,
        request: Request,
        cursor: str | None = Query(default=None),
        last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    ):
        job = _get_project_run_or_404(store, project_id, job_id)
        return _stream_response(job, request, cursor, last_event_id)

    @app.post("/api/runs/{job_id}/cancel", response_model=JobStatusResponse)
    def cancel_run(job_id: str):
        _get_job_or_404(store, job_id)
        if not hasattr(scan_runner, "cancel"):
            raise HTTPException(status_code=409, detail={"error": "runner-cancellation-unavailable"})
        return _job_payload(scan_runner.cancel(job_id))

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

    @app.get("/api/runs/{job_id}/artifacts/{artifact_path:path}")
    def get_public_artifact(job_id: str, artifact_path: str):
        job = _get_job_or_404(store, job_id)
        if not job.run_dir:
            raise _artifact_not_found("run artifacts are not available yet")
        relative = Path(artifact_path)
        if relative.is_absolute() or not relative.parts or relative.parts[0] not in PUBLIC_ARTIFACT_CATEGORIES:
            raise _artifact_denied("artifact category is not public")
        root = Path(job.run_dir).resolve(strict=False)
        candidate = (root / relative).resolve(strict=False)
        try:
            resolved_relative = candidate.relative_to(root)
        except ValueError as exc:
            raise _artifact_denied("artifact path escapes the run directory") from exc
        if not resolved_relative.parts or resolved_relative.parts[0] not in PUBLIC_ARTIFACT_CATEGORIES:
            raise _artifact_denied("artifact path escapes its public category")
        if not candidate.is_file():
            raise _artifact_not_found("artifact is unavailable")
        return FileResponse(candidate)

    return app


app = create_app()


def _get_job_or_404(store: JobStore, job_id: str) -> ScanJob:
    try:
        return store.get(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail={"error": "job-not-found", "job_id": job_id}) from exc


def _get_project_or_404(store: JobStore, project_id: str | None):
    if not project_id:
        raise HTTPException(status_code=404, detail={"error": "project-not-found"})
    try:
        return store.get_project(project_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail={"error": "project-not-found", "project_id": project_id},
        ) from exc


def _get_project_run_or_404(store: JobStore, project_id: str, job_id: str) -> ScanJob:
    _get_project_or_404(store, project_id)
    job = _get_job_or_404(store, job_id)
    if job.project_id != project_id:
        raise HTTPException(
            status_code=404,
            detail={"error": "run-not-found-in-project", "project_id": project_id, "job_id": job_id},
        )
    return job


def _parse_event_cursor(cursor: str | None, last_event_id: str | None) -> int:
    selected = cursor if cursor is not None else last_event_id
    if selected in (None, ""):
        return 0
    try:
        value = int(str(selected), 10)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": "invalid-event-cursor"}) from exc
    if value < 0:
        raise HTTPException(status_code=422, detail={"error": "invalid-event-cursor"})
    return value


def _format_sse(event: str, payload: dict, *, event_id: int | None = None) -> str:
    lines = []
    if event_id is not None:
        lines.append(f"id: {event_id}")
    lines.append(f"event: {event}")
    lines.append(f"data: {json.dumps(payload, ensure_ascii=False, separators=(',', ':'))}")
    return "\n".join(lines) + "\n\n"


def _job_payload(job: ScanJob) -> dict:
    payload = job.to_dict()
    payload.pop("request_snapshot", None)
    return payload


def _job_record_payload(record: dict | None) -> dict | None:
    if record is None:
        return None
    payload = dict(record)
    payload.pop("request_snapshot", None)
    return payload


def _project_payload(project) -> dict:
    payload = project.to_dict()
    payload["latest_run"] = _job_record_payload(project.latest_run)
    return payload


def _preflight_http_error(exc: PreflightError) -> HTTPException:
    status_code = 409 if exc.reason in {"preflight-token-used", "preflight-project-mismatch"} else 422
    detail = {"error": exc.reason}
    if exc.detail:
        detail["message"] = exc.detail
    return HTTPException(status_code=status_code, detail=detail)


def _artifact_not_found(message: str) -> HTTPException:
    return HTTPException(status_code=404, detail={"error": "artifact-not-found", "message": message})


def _artifact_denied(message: str) -> HTTPException:
    return HTTPException(status_code=403, detail={"error": "artifact-access-denied", "message": message})
