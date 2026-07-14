from __future__ import annotations

from pathlib import Path
from typing import Callable
import json

from .config import AuditConfig
from .runtime import AgentRuntime
from .resource_summary import build_failed_run_resource_summary
from .repository_acquisition import (
    AcquisitionError,
    RepositoryAcquisitionService,
    prepare_audit_target,
)


def run_audit(
    target: str,
    config: AuditConfig | None = None,
    output_dir: str | Path = "runs",
    *,
    requested_revision: str | None = None,
    job_id: str | None = None,
    acquisition_service: RepositoryAcquisitionService | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> dict:
    """Backward-compatible pipeline entrypoint backed by the runtime kernel."""
    selected_config = config or AuditConfig.default()
    runtime = AgentRuntime(
        selected_config,
        output_dir=output_dir,
        progress_callback=progress_callback,
    )
    service = acquisition_service or RepositoryAcquisitionService(
        selected_config.remote_acquisition
    )
    prepared = None
    summary = None
    run_error: Exception | None = None
    try:
        if progress_callback:
            progress_callback("validating-source")
        prepared = prepare_audit_target(
            target,
            audit_scope=selected_config.audit_scope,
            config=selected_config.remote_acquisition,
            requested_revision=requested_revision,
            job_id=job_id,
            service=service,
            progress_callback=progress_callback,
        )
        if progress_callback:
            progress_callback("analyzing")
        summary = runtime.run_audit(target, prepared)
        return summary
    except Exception as exc:
        run_error = exc
        if runtime.run and runtime.run_state:
            runtime.run_state.mark_failed(type(exc).__name__)
            runtime.run.write_json_artifact("runtime_state", "state.json", runtime.run_state.to_dict())
            failed_summary = build_failed_run_resource_summary(
                run_id=runtime.run.run_id,
                target=target,
                error_reason=f"run-failed:{type(exc).__name__}",
            )
            runtime.run.write_json_artifact(
                "reports", "run-resource-summary.v1.json", failed_summary.to_dict()
            )
            try:
                setattr(exc, "run_dir", str(runtime.run.path))
            except Exception:
                pass
        raise
    finally:
        if prepared and prepared.acquisition:
            if progress_callback:
                progress_callback("cleaning-up")
            cleanup = service.cleanup(prepared.acquisition)
            final_acquisition_path = None
            if runtime.run:
                final_acquisition_path = runtime.run.write_json_artifact(
                    "metadata", "acquisition-final.json", prepared.acquisition.to_dict()
                )
            terminal_acquisition = {
                "source_kind": prepared.metadata.target.kind,
                "requested_revision": prepared.acquisition.requested_revision,
                "resolved_commit": prepared.acquisition.resolved_commit,
                "cleanup_status": cleanup.status,
                "acquisition_status": prepared.acquisition.status,
                "cache_status": prepared.acquisition.cache_status,
                "network_used": prepared.acquisition.network_used,
                "acquisition_ref": str(final_acquisition_path) if final_acquisition_path else None,
            }
            terminal_succeeded = cleanup.status == "complete" and run_error is None
            if summary is not None:
                summary.update(terminal_acquisition)
                resource_ref = summary.get("resource_summary_ref")
                if runtime.run and resource_ref and Path(resource_ref).is_file():
                    resource_payload = json.loads(Path(resource_ref).read_text(encoding="utf-8"))
                    resource_payload["acquisition"] = {
                        **dict(resource_payload.get("acquisition") or {}),
                        "status": prepared.acquisition.status,
                        "cache_status": prepared.acquisition.cache_status,
                        "network_used": prepared.acquisition.network_used,
                        "cleanup_status": cleanup.status,
                        "acquisition_ref": str(final_acquisition_path),
                    }
                    resource_payload["terminal_status"] = (
                        "succeeded" if terminal_succeeded else "failed"
                    )
                    final_resource_path = runtime.run.write_json_artifact(
                        "reports", "run-resource-summary-final.v1.json", resource_payload
                    )
                    summary["resource_summary_ref"] = str(final_resource_path)
                try:
                    report_ref = _finalize_report(
                        runtime.run.path if runtime.run else None,
                        prepared.acquisition,
                        acquisition_ref=(
                            str(final_acquisition_path) if final_acquisition_path else None
                        ),
                        succeeded=terminal_succeeded,
                    )
                except Exception as exc:
                    summary["report_finalization_status"] = "failed"
                    if runtime.run_state and runtime.artifacts:
                        runtime.run_state.mark_failed("report-finalization-failed", summary)
                        runtime.artifacts.persist_state()
                    error = AcquisitionError(
                        "report-finalization-failed",
                        str(exc),
                        acquisition=prepared.acquisition,
                        summary=summary,
                    )
                    if runtime.run:
                        error.run_dir = str(runtime.run.path)
                    raise error from exc
                if report_ref:
                    summary["report_ref"] = report_ref
                if runtime.artifacts:
                    runtime.artifacts.persist_state()
            if run_error is not None:
                existing = dict(getattr(run_error, "summary", {}) or {})
                existing.update(terminal_acquisition)
                setattr(run_error, "summary", existing)
            if cleanup.status != "complete" and summary is not None and run_error is None:
                if runtime.run_state and runtime.artifacts:
                    runtime.run_state.mark_failed("cleanup-failed", summary)
                    runtime.artifacts.persist_state()
                error = AcquisitionError(
                    "cleanup-failed",
                    cleanup.reason or "",
                    acquisition=prepared.acquisition,
                    summary=summary,
                )
                if runtime.run:
                    error.run_dir = str(runtime.run.path)
                raise error


def _finalize_report(
    run_dir: Path | None,
    acquisition,
    *,
    acquisition_ref: str | None,
    succeeded: bool,
) -> str | None:
    if run_dir is None:
        return None
    report_path = run_dir / "reports" / "report.json"
    if not report_path.is_file():
        return None
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    acquisition_payload = dict(payload.get("acquisition") or {})
    acquisition_payload.update(
        {
            "original_source": acquisition.source,
            "normalized_source": acquisition.normalized_source,
            "requested_revision": acquisition.requested_revision,
            "resolved_commit": acquisition.resolved_commit,
            "status": acquisition.status,
            "cache_status": acquisition.cache_status,
            "network_used": acquisition.network_used,
            "cleanup_status": acquisition.cleanup.status,
            "acquisition_ref": acquisition_ref,
        }
    )
    payload["acquisition"] = acquisition_payload
    payload["run_status"] = "completed" if succeeded else "failed"
    _atomic_write_text(report_path, json.dumps(payload, ensure_ascii=False, indent=2))

    markdown_path = run_dir / "reports" / "report.md"
    if markdown_path.is_file():
        text = markdown_path.read_text(encoding="utf-8")
        text = text.replace(
            "- Cleanup: pending",
            f"- Cleanup: {acquisition.cleanup.status}",
            1,
        )
        _atomic_write_text(markdown_path, text)
    return str(report_path)


def _atomic_write_text(path: Path, text: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)
