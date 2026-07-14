from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from .benchmark_models import RESOURCE_SCHEMA_VERSION, RunResourceSummary
from .llm_accounting import reconcile_llm_lifecycle
from .models import RepositoryMetadata
from .redaction import redact_secrets


def build_run_resource_summary(
    *,
    run_id: str,
    run_dir: str | Path,
    metadata: RepositoryMetadata,
    run_state: Any,
    config: Any,
    validation_results: list[Any],
    status_counts: dict[str, int],
    runtime_refs: dict[str, list[str]],
    terminal_status: str,
    tool_calls_used: int | None = None,
) -> RunResourceSummary:
    run_path = Path(run_dir)
    scanned_files = len(metadata.file_tree)
    scanned_bytes = _scanned_bytes(Path(metadata.root_path or ""), metadata.file_tree) if metadata.root_path else None
    reconciliation = reconcile_llm_lifecycle(
        run_path,
        llm_enabled=bool(config.runtime_enabled),
        budget_counters=(getattr(run_state, "llm_accounting", None) or None),
    )
    llm_requests = reconciliation.llm_requests
    llm_tokens = reconciliation.llm_tokens
    llm_gaps = [
        {
            "field": item.field,
            "reason": ":".join(
                part
                for part in (
                    item.reason,
                    item.request_group_id,
                    item.provider_attempt_id,
                )
                if part
            ),
        }
        for item in reconciliation.gaps
    ]
    llm_refs = reconciliation.contributing_refs
    runner_counts = _runner_counts(validation_results)
    docker_starts = sum(
        bool((getattr(item, "environment", None) or {}).get("docker_started", False))
        for item in validation_results
    )
    repair_attempts = sum(int(getattr(item, "repair_attempt_count", 0) or 0) for item in validation_results)
    timeouts = sum(bool(getattr(item, "timed_out", False)) for item in validation_results)
    stage_durations = _task_durations(run_state)
    elapsed_seconds = _run_elapsed_seconds(run_state)
    gaps: list[dict[str, str]] = list(llm_gaps)
    tool_calls = (
        int(tool_calls_used)
        if tool_calls_used is not None
        else sum(1 for task in run_state.tasks if task.kind == "tool")
    )
    if scanned_bytes is None:
        gaps.append({"field": "scanned_bytes", "reason": "target-root-unavailable"})
    if elapsed_seconds is None:
        gaps.append({"field": "elapsed_seconds", "reason": "run-timestamps-unavailable"})
    engine_commit = _engine_commit(Path(__file__).resolve().parent.parent)
    if not engine_commit:
        gaps.append({"field": "engine_commit", "reason": "source-control-identity-unavailable"})
    expected_commit = os.getenv("AUDIT_BENCHMARK_EXPECTED_COMMIT") or metadata.commit
    target_identity = os.getenv("AUDIT_BENCHMARK_CASE_ID") or metadata.target.source
    summary = RunResourceSummary(
        schema_version=RESOURCE_SCHEMA_VERSION,
        run_id=run_id,
        target_identity=target_identity,
        target_commit=expected_commit,
        terminal_status=terminal_status,
        scanned_files=scanned_files,
        scanned_bytes=scanned_bytes,
        stage_durations_ms=stage_durations,
        final_status_counts={key: int(value) for key, value in status_counts.items()},
        llm_requests=llm_requests,
        llm_tokens=llm_tokens,
        tool_calls=tool_calls,
        docker_starts=docker_starts,
        docker_results=docker_starts,
        repair_attempts=repair_attempts,
        timeouts=timeouts,
        budget_consumption={
            "llm_requests": llm_requests,
            "llm_tokens": llm_tokens,
            "tool_calls": tool_calls,
            "docker_starts": docker_starts,
            "repair_attempts": repair_attempts,
        },
        accounting_gaps=gaps,
        contributing_refs=[
            str(run_path / "metadata" / "repository.json"),
            str(run_path / "runtime_state" / "state.json"),
            str(run_path / "reports" / "report.json"),
            *llm_refs,
            *[str(item) for item in runtime_refs.get("tool_call_refs", [])],
        ],
        ledger_present=reconciliation.ledger_present,
        accounting_source=reconciliation.accounting_source,
        llm_total_request_groups=reconciliation.total_request_groups,
        llm_dispatched_request_groups=reconciliation.llm_requests,
        llm_provider_attempts=reconciliation.provider_attempts,
        llm_retries=reconciliation.retries,
        llm_pre_dispatch_denials=reconciliation.pre_dispatch_denials,
        llm_terminal_status_counts=reconciliation.terminal_status_counts,
        llm_reconciliation_status=("complete" if reconciliation.complete else "incomplete"),
        llm_gap_ids=reconciliation.gap_ids,
        llm_contributing_refs=reconciliation.contributing_refs,
        provider=config.llm.provider if config.runtime_enabled else "disabled",
        model=config.llm.model if config.runtime_enabled else None,
        prompt_schema_version=config.prompts.default_version if config.runtime_enabled else None,
        engine_commit=engine_commit,
        language=metadata.dominant_language,
        scope={
            "include": list(config.audit_scope.include_patterns),
            "exclude": list(config.audit_scope.exclude_patterns),
        },
        safety={
            "target_writes": False,
            "project_execution": False,
            "network": False,
        },
        docker_policy={
            "enabled": bool(config.sandbox.enabled and config.sandbox.runner == "docker"),
            "runner": config.sandbox.runner,
        },
        environment={
            "python": f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}",
            "platform": os.name,
            "benchmark_project_id": os.getenv("AUDIT_BENCHMARK_PROJECT_ID"),
        },
        elapsed_seconds=elapsed_seconds,
        acquisition={
            "source_kind": metadata.target.kind,
            "requested_revision": metadata.target.requested_revision,
            "resolved_commit": metadata.commit,
            "status": metadata.materialization.get("status") if metadata.materialization else "local",
            "acquisition_ref": metadata.target.acquisition_ref,
            "exported_files": metadata.materialization.get("exported_files"),
            "exported_bytes": metadata.materialization.get("exported_bytes"),
            "cleanup_status": (
                "pending" if metadata.target.kind in {"github", "gitlab"} else "not-required"
            ),
        },
    )
    summary.validate()
    return RunResourceSummary.from_dict(redact_secrets(summary.to_dict()))


def build_failed_run_resource_summary(*, run_id: str, target: str, error_reason: str) -> RunResourceSummary:
    fields = (
        "scanned_files", "scanned_bytes", "elapsed_seconds", "llm_requests", "llm_tokens", "tool_calls",
        "docker_starts", "docker_results", "repair_attempts", "timeouts",
    )
    return RunResourceSummary(
        schema_version=RESOURCE_SCHEMA_VERSION,
        run_id=run_id,
        target_identity=target,
        target_commit=os.getenv("AUDIT_BENCHMARK_EXPECTED_COMMIT"),
        terminal_status="failed",
        scanned_files=None,
        scanned_bytes=None,
        stage_durations_ms={},
        final_status_counts={},
        llm_requests=None,
        llm_tokens=None,
        tool_calls=None,
        docker_starts=None,
        docker_results=None,
        repair_attempts=None,
        timeouts=None,
        budget_consumption={},
        accounting_gaps=[{"field": name, "reason": error_reason} for name in fields],
        contributing_refs=[],
        environment={"platform": os.name},
        elapsed_seconds=None,
        acquisition={
            "status": "failed",
            "failure_reason": error_reason,
            "source_kind": (
                "github"
                if str(target).startswith("https://github.com/")
                else "gitlab"
                if str(target).startswith("https://gitlab.com/")
                else "unknown"
            ),
        },
    )


def _llm_usage(root: Path) -> tuple[int | None, int | None, list[dict[str, str]], list[str]]:
    if not root.exists():
        return 0, 0, [], []
    requests = 0
    tokens = 0
    refs: list[str] = []
    gaps: list[dict[str, str]] = []
    for path in sorted(root.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            usage = (payload.get("response") or {}).get("usage") or payload.get("usage")
            if not isinstance(usage, dict):
                gaps.append({"field": "llm_tokens", "reason": f"usage-missing:{path.name}"})
                continue
            total = usage.get("total_tokens")
            if total is None:
                prompt = usage.get("prompt_tokens")
                completion = usage.get("completion_tokens")
                if prompt is None or completion is None:
                    gaps.append({"field": "llm_tokens", "reason": f"usage-incomplete:{path.name}"})
                    continue
                total = int(prompt) + int(completion)
            requests += 1
            tokens += int(total)
            refs.append(str(path))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            gaps.append({"field": "llm_tokens", "reason": f"usage-invalid:{path.name}"})
    if gaps:
        if requests == 0:
            gaps.append({"field": "llm_requests", "reason": "no-valid-usage-records"})
        return requests if requests else None, None, gaps, refs
    return requests, tokens, gaps, refs


def _scanned_bytes(root: Path, files: list[str]) -> int:
    total = 0
    for relative in files:
        try:
            total += (root / relative).stat().st_size
        except OSError:
            return None  # type: ignore[return-value]
    return total


def _task_durations(run_state: Any) -> dict[str, int | None]:
    durations: dict[str, int] = {}
    for task in run_state.tasks:
        if not task.started_at or not task.finished_at:
            continue
        try:
            delta = datetime.fromisoformat(task.finished_at) - datetime.fromisoformat(task.started_at)
        except ValueError:
            continue
        durations[task.role] = durations.get(task.role, 0) + max(0, int(delta.total_seconds() * 1000))
    return dict(sorted(durations.items()))


def _run_elapsed_seconds(run_state: Any) -> float | None:
    started_at = getattr(run_state, "started_at", None)
    if not started_at:
        return None
    try:
        started = datetime.fromisoformat(started_at)
        finished_at = getattr(run_state, "finished_at", None)
        finished = datetime.fromisoformat(finished_at) if finished_at else datetime.now(tz=started.tzinfo)
    except (TypeError, ValueError):
        return None
    return round(max(0.0, (finished - started).total_seconds()), 3)


def _runner_counts(results: list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for result in results:
        runner = str((getattr(result, "environment", None) or {}).get("runner") or "none")
        counts[runner] = counts.get(runner, 0) + 1
    return counts


def _engine_commit(root: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
            shell=False,
        )
        value = completed.stdout.strip()
        return value if completed.returncode == 0 and len(value) >= 40 else None
    except (OSError, subprocess.SubprocessError):
        return None
