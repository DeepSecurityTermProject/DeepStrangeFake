from __future__ import annotations

from pathlib import Path

from .config import AuditConfig
from .runtime import AgentRuntime
from .resource_summary import build_failed_run_resource_summary


def run_audit(target: str, config: AuditConfig | None = None, output_dir: str | Path = "runs") -> dict:
    """Backward-compatible pipeline entrypoint backed by the runtime kernel."""
    runtime = AgentRuntime(config or AuditConfig.default(), output_dir=output_dir)
    try:
        return runtime.run_audit(target)
    except Exception as exc:
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
        raise
