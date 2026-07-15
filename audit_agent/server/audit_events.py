from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import MessageEnvelope, utc_now
from ..redaction import redact_secrets, redact_text
from .limits import (
    EVENT_DIAGNOSTIC_LIMIT,
    EVENT_MAX_SUBSCRIBERS_PER_RUN,
    EVENT_MAX_SUBSCRIBERS_TOTAL,
    EVENT_REPLAY_LIMIT,
)
from .workspace_store import WorkspaceStore


LOGGER = logging.getLogger(__name__)

AUDIT_EVENT_SCHEMA_VERSION = "audit-event.v1"
AUDIT_EVENT_MAX_BYTES = 16 * 1024
AUDIT_EVENT_MAX_STRING = 1_000
AUDIT_EVENT_MAX_ITEMS = 20
AUDIT_EVENT_MAX_DEPTH = 4

PUBLIC_EVENT_CATEGORIES = frozenset(
    {
        "system",
        "rationale",
        "hypothesis",
        "action",
        "tool",
        "evidence",
        "validation",
        "budget",
        "state",
        "error",
    }
)
PUBLIC_EVENT_SEVERITIES = frozenset(
    {"debug", "info", "notice", "warning", "error", "critical"}
)
PUBLIC_EVENT_STATUSES = frozenset(
    {
        "queued",
        "running",
        "recorded",
        "accepted",
        "denied",
        "succeeded",
        "degraded",
        "failed",
        "cancelled",
        "manual-required",
        "unknown",
    }
)
TERMINAL_EVENT_STATUSES = frozenset({"succeeded", "degraded", "failed", "cancelled"})
PUBLIC_ARTIFACT_CATEGORIES = frozenset(
    {"reports", "evidence", "findings", "runtime_state", "verification-plans", "evidence-gates"}
)

_FORBIDDEN_SUMMARY_KEYS = frozenset(
    {
        "prompt",
        "full_prompt",
        "system_prompt",
        "chain_of_thought",
        "reasoning",
        "hidden_reasoning",
        "raw_response",
        "response_body",
        "request_body",
        "authorization",
        "headers",
        "environment",
        "env",
        "stdout",
        "stderr",
        "source_code",
        "code",
    }
)


@dataclass(frozen=True)
class AuditEvent:
    run_id: str
    event_id: int
    category: str
    phase: str
    actor: str
    title: str
    summary: dict[str, Any]
    severity: str = "info"
    status: str = "recorded"
    correlation_id: str | None = None
    causation_id: str | None = None
    artifact_refs: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=utc_now)
    schema_version: str = AUDIT_EVENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.run_id or self.run_id != Path(self.run_id).name:
            raise ValueError("audit event run_id must be a single identifier")
        if self.event_id < 1:
            raise ValueError("audit event ID must be positive")
        if self.category not in PUBLIC_EVENT_CATEGORIES:
            raise ValueError("unsupported audit event category")
        if self.severity not in PUBLIC_EVENT_SEVERITIES:
            raise ValueError("unsupported audit event severity")
        if self.status not in PUBLIC_EVENT_STATUSES:
            raise ValueError("unsupported audit event status")
        if not self.title.strip() or len(self.title) > 200:
            raise ValueError("audit event title must contain 1..200 characters")
        if len(self.actor) > 80 or len(self.phase) > 80:
            raise ValueError("audit event actor and phase must be bounded")
        if self.schema_version != AUDIT_EVENT_SCHEMA_VERSION:
            raise ValueError("unsupported audit event schema version")
        payload = self.to_dict()
        if len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > AUDIT_EVENT_MAX_BYTES:
            raise ValueError("audit event exceeds the public size limit")

    @property
    def terminal(self) -> bool:
        return self.category == "state" and self.status in TERMINAL_EVENT_STATUSES

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "category": self.category,
            "phase": self.phase,
            "actor": self.actor,
            "title": self.title,
            "summary": self.summary,
            "severity": self.severity,
            "status": self.status,
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "artifact_refs": list(self.artifact_refs),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AuditEvent":
        return cls(
            schema_version=str(payload.get("schema_version") or ""),
            run_id=str(payload.get("run_id") or ""),
            event_id=int(payload.get("event_id") or 0),
            timestamp=str(payload.get("timestamp") or ""),
            category=str(payload.get("category") or ""),
            phase=str(payload.get("phase") or ""),
            actor=str(payload.get("actor") or ""),
            title=str(payload.get("title") or ""),
            summary=dict(payload.get("summary") or {}),
            severity=str(payload.get("severity") or ""),
            status=str(payload.get("status") or ""),
            correlation_id=_optional_text(payload.get("correlation_id")),
            causation_id=_optional_text(payload.get("causation_id")),
            artifact_refs=[str(item) for item in payload.get("artifact_refs") or []],
        )


@dataclass(frozen=True)
class ProjectedEvent:
    category: str
    title: str
    summary: dict[str, Any]
    actor: str
    severity: str = "info"
    status: str = "recorded"
    phase: str = ""
    correlation_id: str | None = None
    causation_id: str | None = None
    artifact_refs: list[str] = field(default_factory=list)


class AuditEventService:
    """Journal authority and safe projection for web-run public events."""

    def __init__(
        self,
        workspace: WorkspaceStore,
        journal_root: str | Path,
        *,
        replay_limit: int = EVENT_REPLAY_LIMIT,
        max_subscribers_per_run: int = EVENT_MAX_SUBSCRIBERS_PER_RUN,
        max_subscribers_total: int = EVENT_MAX_SUBSCRIBERS_TOTAL,
    ):
        self.workspace = workspace
        self.journal_root = Path(journal_root)
        self.journal_root.mkdir(parents=True, exist_ok=True)
        self.replay_limit = max(1, int(replay_limit))
        self.max_subscribers_per_run = max(1, int(max_subscribers_per_run))
        self.max_subscribers_total = max(
            self.max_subscribers_per_run,
            int(max_subscribers_total),
        )
        self._locks_guard = threading.Lock()
        self._locks: dict[str, threading.RLock] = {}
        self._conditions: dict[str, threading.Condition] = {}
        self._subscriber_counts: dict[str, int] = {}
        self._subscriber_total = 0
        self._diagnostics: list[dict[str, str]] = []
        self.reconcile_all()

    def diagnostics(self) -> list[dict[str, str]]:
        return list(self._diagnostics)

    def journal_path(self, run_id: str) -> Path:
        if not run_id or run_id != Path(run_id).name:
            raise ValueError("invalid run ID")
        return self.journal_root / f"{run_id}.jsonl"

    def append(
        self,
        run_id: str,
        *,
        category: str,
        phase: str,
        actor: str,
        title: str,
        summary: dict[str, Any] | None = None,
        severity: str = "info",
        status: str = "recorded",
        correlation_id: str | None = None,
        causation_id: str | None = None,
        artifact_refs: list[str] | None = None,
    ) -> AuditEvent | None:
        lock, condition = self._synchronization(run_id)
        with lock:
            path = self.journal_path(run_id)
            history = self._read_events(path, repair=True)
            terminal = next((item for item in reversed(history) if item.terminal), None)
            if terminal is not None:
                if category == "state" and status == terminal.status:
                    return terminal
                return None
            safe_summary = _safe_summary(summary or {})
            safe_title = redact_text(title).strip()[:200] or "Audit event"
            safe_refs = _safe_artifact_refs(artifact_refs or [])
            event = AuditEvent(
                run_id=run_id,
                event_id=(history[-1].event_id + 1) if history else 1,
                category=category,
                phase=redact_text(phase)[:80],
                actor=redact_text(actor)[:80],
                title=safe_title,
                summary=safe_summary,
                severity=severity,
                status=status,
                correlation_id=_bounded_optional(correlation_id),
                causation_id=_bounded_optional(causation_id),
                artifact_refs=safe_refs,
            )
            serialized = json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":")) + "\n"
            original_size = path.stat().st_size if path.exists() else 0
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a", encoding="utf-8", newline="\n") as handle:
                    handle.write(serialized)
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as exc:
                try:
                    with path.open("r+b") as rollback:
                        rollback.truncate(original_size)
                except OSError:
                    pass
                self._record_diagnostic(run_id, "journal-persistence-failed", exc)
                raise
            try:
                self.workspace.set_event_index(run_id, str(path), event.event_id)
            except Exception as exc:  # Journal is authoritative; rebuild the derived index later.
                self._record_diagnostic(run_id, "event-index-update-failed", exc)
            condition.notify_all()
            return event

    def history(
        self,
        run_id: str,
        *,
        after: int = 0,
        limit: int | None = None,
    ) -> list[AuditEvent]:
        if after < 0:
            raise ValueError("event cursor must be non-negative")
        if limit is not None and limit < 1:
            raise ValueError("event history limit must be positive")
        lock, _condition = self._synchronization(run_id)
        with lock:
            events = [
                item
                for item in self._read_events(self.journal_path(run_id), repair=False)
                if item.event_id > after
            ]
            return events[:limit] if limit is not None else events

    def snapshot(self, run_id: str) -> dict[str, Any]:
        journal = self.history(run_id)
        terminal = next((item for item in reversed(journal) if item.terminal), None)
        history_truncated = len(journal) > self.replay_limit
        events = journal[-self.replay_limit :]
        last_event_id = journal[-1].event_id if journal else 0
        return {
            "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
            "run_id": run_id,
            "events": [item.to_dict() for item in events],
            "last_event_id": last_event_id,
            "terminal": terminal.to_dict() if terminal else None,
            "history_status": (
                "truncated"
                if history_truncated
                else "complete"
                if terminal
                else "live"
                if events
                else "unavailable"
            ),
            "history_reason": (
                "replay-window-limit"
                if history_truncated
                else ""
                if events
                else "legacy-run-without-public-journal"
            ),
            "journal_event_count": len(journal),
            "replay_limit": self.replay_limit,
            "replay_from_event_id": events[0].event_id if events else 0,
            "history_truncated": history_truncated,
        }

    def wait_for_events(self, run_id: str, after: int, timeout: float) -> list[AuditEvent]:
        if after < 0:
            raise ValueError("event cursor must be non-negative")
        lock, condition = self._synchronization(run_id)
        with lock:
            events = [
                item
                for item in self._read_events(self.journal_path(run_id), repair=False)
                if item.event_id > after
            ][: self.replay_limit]
            if events:
                return events
            condition.wait(timeout=max(0.0, timeout))
            return [
                item
                for item in self._read_events(self.journal_path(run_id), repair=False)
                if item.event_id > after
            ][: self.replay_limit]

    def try_acquire_subscriber(self, run_id: str) -> bool:
        if not run_id or run_id != Path(run_id).name:
            return False
        with self._locks_guard:
            current = self._subscriber_counts.get(run_id, 0)
            if current >= self.max_subscribers_per_run:
                return False
            if self._subscriber_total >= self.max_subscribers_total:
                return False
            self._subscriber_counts[run_id] = current + 1
            self._subscriber_total += 1
            return True

    def release_subscriber(self, run_id: str) -> None:
        with self._locks_guard:
            current = self._subscriber_counts.get(run_id, 0)
            if current <= 0:
                return
            if current == 1:
                self._subscriber_counts.pop(run_id, None)
            else:
                self._subscriber_counts[run_id] = current - 1
            self._subscriber_total = max(0, self._subscriber_total - 1)

    def subscriber_usage(self) -> dict[str, Any]:
        with self._locks_guard:
            return {
                "total": self._subscriber_total,
                "by_run": dict(self._subscriber_counts),
                "max_per_run": self.max_subscribers_per_run,
                "max_total": self.max_subscribers_total,
            }

    def project_lifecycle(self, job: Any, transition: str) -> AuditEvent | None:
        status = str(job.status)
        phase = str(job.phase or transition)
        terminal = status in TERMINAL_EVENT_STATUSES
        severity = "error" if status == "failed" else "warning" if status in {"degraded", "cancelled"} else "info"
        title = {
            "created": "Audit queued",
            "running": "Audit started",
            "phase": f"Phase changed to {phase}",
            "succeeded": "Audit completed",
            "degraded": "Audit completed with limitations",
            "failed": "Audit failed",
            "cancelled": "Audit cancelled",
        }.get(transition, f"Audit state changed to {status}")
        summary: dict[str, Any] = {"job_status": status, "phase": phase}
        if transition == "failed" and job.error:
            summary["error"] = str(job.error)
        if transition in {"degraded", "succeeded"}:
            for key in ("requested_mode", "effective_mode", "fallback_reason", "degraded_reasons"):
                if key in job.summary:
                    summary[key] = job.summary[key]
        if transition == "failed" and job.error:
            self.append(
                job.job_id,
                category="error",
                phase=phase,
                actor="audit-service",
                title="Audit stopped with a public diagnostic",
                summary={"error": str(job.error), "phase": phase},
                severity="error",
                status="failed",
            )
        return self.append(
            job.job_id,
            category="state",
            phase=phase,
            actor="audit-service",
            title=title,
            summary=summary,
            severity=severity,
            status=status if terminal else "queued" if status == "queued" else "running",
        )

    def project_message(self, web_run_id: str, job: Any, message: MessageEnvelope) -> AuditEvent | None:
        projected = _project_message(message)
        if projected is None:
            return None
        refs = self._authorized_message_refs(web_run_id, job, message)
        return self.append(
            web_run_id,
            category=projected.category,
            phase=projected.phase or str(job.phase or "analyzing"),
            actor=projected.actor,
            title=projected.title,
            summary=projected.summary,
            severity=projected.severity,
            status=projected.status,
            correlation_id=projected.correlation_id or message.correlation_id,
            causation_id=projected.causation_id or message.causation_id,
            artifact_refs=[*projected.artifact_refs, *refs],
        )

    def reconcile_all(self) -> None:
        persisted_runs = {item["job_id"] for item in self.workspace.list_job_records()}
        known = persisted_runs | {path.stem for path in self.journal_root.glob("*.jsonl")}
        for run_id in sorted(known & persisted_runs):
            self.reconcile(run_id)

    def reconcile(self, run_id: str) -> int:
        lock, _condition = self._synchronization(run_id)
        with lock:
            path = self.journal_path(run_id)
            events = self._read_events(path, repair=True)
            last_event_id = events[-1].event_id if events else 0
            current = self.workspace.get_event_index(run_id)
            if last_event_id or current is not None:
                self.workspace.set_event_index(run_id, str(path), last_event_id)
            return last_event_id

    def _authorized_message_refs(self, web_run_id: str, job: Any, message: MessageEnvelope) -> list[str]:
        output_root = Path(job.output_dir).resolve(strict=False)
        runtime_root = (output_root / message.run_id).resolve(strict=False)
        try:
            runtime_root.relative_to(output_root)
        except ValueError:
            return []
        refs: list[str] = []
        for raw in message.artifact_refs:
            try:
                candidate = Path(str(raw)).resolve(strict=False)
                relative = candidate.relative_to(runtime_root)
            except (OSError, ValueError):
                continue
            if relative.parts and relative.parts[0] in PUBLIC_ARTIFACT_CATEGORIES:
                refs.append(f"/api/runs/{web_run_id}/artifacts/{relative.as_posix()}")
        return refs[:AUDIT_EVENT_MAX_ITEMS]

    def _read_events(self, path: Path, *, repair: bool) -> list[AuditEvent]:
        if not path.is_file():
            return []
        valid_lines: list[str] = []
        events: list[AuditEvent] = []
        invalid = False
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            raise
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                event = AuditEvent.from_dict(json.loads(line))
                if event.event_id != len(events) + 1 or event.run_id != path.stem:
                    raise ValueError("non-contiguous event journal")
                if events and events[-1].terminal:
                    raise ValueError("event found after terminal marker")
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                invalid = True
                self._record_diagnostic(path.stem, f"journal-truncated-at-line-{index + 1}", exc)
                break
            valid_lines.append(json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":")))
            events.append(event)
        if invalid and repair:
            temporary = path.with_suffix(".jsonl.reconcile.tmp")
            temporary.write_text("".join(f"{line}\n" for line in valid_lines), encoding="utf-8")
            temporary.replace(path)
        return events

    def _synchronization(self, run_id: str) -> tuple[threading.RLock, threading.Condition]:
        with self._locks_guard:
            lock = self._locks.setdefault(run_id, threading.RLock())
            condition = self._conditions.get(run_id)
            if condition is None:
                condition = threading.Condition(lock)
                self._conditions[run_id] = condition
            return lock, condition

    def _record_diagnostic(self, run_id: str, reason: str, exc: Exception) -> None:
        diagnostic = {
            "run_id": redact_text(run_id)[:100],
            "reason": reason[:200],
            "error_type": type(exc).__name__,
        }
        self._diagnostics.append(diagnostic)
        del self._diagnostics[:-EVENT_DIAGNOSTIC_LIMIT]
        LOGGER.warning("audit event diagnostic: %s", diagnostic)


def _project_message(message: MessageEnvelope) -> ProjectedEvent | None:
    payload = message.payload if isinstance(message.payload, dict) else {}
    message_type = message.message_type
    role = str(payload.get("role") or message.recipient or message.sender)[:80]
    task = _pick(payload, "task_id")

    if message_type == "run.start":
        return ProjectedEvent("system", "Runtime initialized", {}, "pipeline", status="running")
    if message_type == "runtime.task":
        status = _public_status(payload.get("status"))
        return ProjectedEvent(
            "action",
            f"{role} task {status}",
            {**task, **_pick(payload, "kind", "fallback_reason")},
            role,
            severity="warning" if status in {"failed", "degraded"} else "info",
            status=status,
        )
    if message_type in {"runtime.tool", "runtime.tool.denied", "tool.result"}:
        denied = message_type == "runtime.tool.denied" or payload.get("success") is False
        return ProjectedEvent(
            "tool",
            f"Tool {payload.get('tool') or 'operation'} {'denied' if denied else 'completed'}",
            {**task, **_pick(payload, "tool", "status", "success", "message", "observations")},
            role,
            severity="warning" if denied else "info",
            status="denied" if denied else "succeeded",
        )
    if message_type == "runtime.artifact":
        return ProjectedEvent(
            "evidence",
            "Authorized audit artifact recorded",
            {**task, **_pick(payload, "category")},
            role or "artifact-store",
        )
    if message_type == "investigation.hypothesis":
        return ProjectedEvent(
            "hypothesis",
            "Investigation hypothesis updated",
            _pick(
                payload,
                "hypothesis_id",
                "vulnerability_class",
                "claim",
                "rationale_summary",
                "target_paths",
                "confidence",
                "state",
                "evidence_count",
            ),
            role,
            status=_public_status(payload.get("state")),
        )
    if message_type == "investigation.action":
        return ProjectedEvent(
            "action",
            f"Investigation action {payload.get('action') or 'recorded'}",
            _pick(payload, "hypothesis_id", "action", "status", "evidence_count", "cached", "message"),
            role,
            status=_public_status(payload.get("status")),
        )
    if message_type == "investigation.evidence-gate":
        state = str(payload.get("state") or "recorded")
        return ProjectedEvent(
            "validation",
            f"Evidence gate {state}",
            _pick(payload, "hypothesis_id", "gate_id", "state", "evidence_count"),
            "verification",
            severity="warning" if state in {"rejected", "refine"} else "notice",
            status="accepted" if state == "promoted" else "denied" if state == "rejected" else "recorded",
        )
    if message_type == "investigation.budget":
        remaining = payload.get("remaining")
        if isinstance(remaining, dict):
            remaining = dict(remaining)
            if "tokens" in remaining:
                remaining["remaining_token_budget"] = remaining.pop("tokens")
        return ProjectedEvent(
            "budget",
            "Investigation budget checkpoint",
            {**_pick(payload, "checkpoint", "reason"), **({"remaining": remaining} if remaining else {})},
            "orchestrator",
        )
    if message_type == "llm.decision":
        return ProjectedEvent(
            "rationale",
            f"{role} submitted a structured decision",
            {**task, **_pick(payload, "decision_id", "confidence", "fallback_reason")},
            role,
            severity="warning" if payload.get("fallback_reason") else "info",
        )
    if message_type in {"decision.schema", "decision.policy", "decision.merge", "decision.fallback"}:
        failed = message_type == "decision.fallback" or str(payload.get("status")) in {"denied", "invalid", "failed"}
        return ProjectedEvent(
            "validation",
            message_type.replace(".", " ").title(),
            {**task, **_pick(payload, "status", "errors", "reasons", "decision_source", "fallback_reason")},
            role,
            severity="warning" if failed else "info",
            status="denied" if failed else "accepted",
        )
    if message_type == "llm.response":
        return ProjectedEvent(
            "action",
            f"{role} received a structured model response",
            {**task, **_pick(payload, "schema_repair_attempt")},
            role,
        )
    if message_type.startswith("llm.lifecycle."):
        terminal_status = _public_status(payload.get("terminal_status"))
        return ProjectedEvent(
            "budget",
            "Model request accounting updated",
            _pick(payload, "request_group_id", "provider_attempt_id", "event_kind", "terminal_status", "role"),
            role,
            severity="warning" if terminal_status in {"failed", "degraded"} else "info",
            status=terminal_status,
        )
    if message_type == "agent.plan":
        return ProjectedEvent("action", "Audit plan prepared", {"plan_fields": len(payload)}, "orchestrator")
    if message_type == "agent.handoff":
        return ProjectedEvent(
            "rationale",
            f"{message.sender} handed structured context to {message.recipient}",
            {"handoff_fields": len(payload)},
            message.sender,
        )
    if message_type in {"memory.retrieved", "mcp.dependency-batches"}:
        return ProjectedEvent(
            "evidence",
            "Repository intelligence updated",
            _pick(
                payload,
                "record_count",
                "retrieval_count",
                "input_dependency_count",
                "unique_dependency_count",
                "queries_used",
                "cache_hits",
                "budget_exhausted_count",
            ),
            role,
        )
    if message_type == "verification.attempt" or message_type.startswith("poc."):
        status = _public_status(payload.get("status") or payload.get("judge_status"))
        return ProjectedEvent(
            "validation",
            "Vulnerability validation updated",
            _pick(
                payload,
                "finding_id",
                "attempt_index",
                "status",
                "level",
                "runner",
                "exit_code",
                "timed_out",
                "judge_reason",
                "blocking_reason",
                "failure_class",
            ),
            "verification",
            severity="warning" if status in {"failed", "denied", "manual-required"} else "info",
            status=status,
        )
    if message_type == "report.generate":
        return ProjectedEvent(
            "state",
            "Audit report generation started",
            _pick(
                payload,
                "finding_count",
                "verification_candidate_count",
                "confirmed_count",
                "likely_count",
                "rejected_count",
                "manual_required_count",
            ),
            "reporting",
            status="running",
            phase="reporting",
        )
    if message_type.startswith("graph."):
        denied = message_type.endswith("denied")
        return ProjectedEvent(
            "action",
            message_type.replace(".", " ").title(),
            _pick(payload, "graph_id", "revision", "mode", "status", "node_id", "proposal_id", "reason"),
            "graph-runtime",
            severity="warning" if denied else "info",
            status="denied" if denied else "recorded",
        )
    return None


def _safe_summary(value: dict[str, Any]) -> dict[str, Any]:
    redacted = redact_secrets(value)
    bounded = _bounded_value(redacted, depth=0)
    if not isinstance(bounded, dict):
        bounded = {"value": bounded}
    # Keep headroom for the fixed event envelope. Dropping complete trailing
    # fields is deterministic and safer than returning an over-limit event.
    while bounded and len(json.dumps(bounded, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > 12_000:
        bounded.pop(next(reversed(bounded)))
    return bounded or {"bounded": True}


def _bounded_value(value: Any, *, depth: int) -> Any:
    if depth >= AUDIT_EVENT_MAX_DEPTH:
        return "[BOUNDED]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return redact_text(value)[:AUDIT_EVENT_MAX_STRING]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for raw_key, item in list(value.items())[:AUDIT_EVENT_MAX_ITEMS]:
            key = str(raw_key)[:100]
            if key.lower() in _FORBIDDEN_SUMMARY_KEYS:
                continue
            result[key] = _bounded_value(item, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple, set)):
        return [_bounded_value(item, depth=depth + 1) for item in list(value)[:AUDIT_EVENT_MAX_ITEMS]]
    return redact_text(str(value))[:AUDIT_EVENT_MAX_STRING]


def _pick(payload: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {key: payload[key] for key in keys if key in payload and payload[key] not in (None, "", [])}


def _public_status(value: Any) -> str:
    status = str(value or "recorded").strip().lower()
    aliases = {
        "complete": "succeeded",
        "completed": "succeeded",
        "success": "succeeded",
        "ok": "succeeded",
        "fallback": "degraded",
        "rejected": "denied",
        "refuted": "denied",
        "promoted": "accepted",
        "confirmed": "accepted",
        "likely": "recorded",
        "inconclusive": "recorded",
        "investigating": "running",
        "refine": "running",
        "supported": "running",
        "evidence-gate": "running",
    }
    status = aliases.get(status, status)
    return status if status in PUBLIC_EVENT_STATUSES else "unknown"


def _safe_artifact_refs(values: list[str]) -> list[str]:
    refs: list[str] = []
    for value in values[:AUDIT_EVENT_MAX_ITEMS]:
        text = redact_text(str(value))[:1_000]
        if text.startswith("/api/runs/") and "/artifacts/" in text and ".." not in text:
            refs.append(text)
    return refs


def _optional_text(value: Any) -> str | None:
    return None if value is None else str(value)


def _bounded_optional(value: Any) -> str | None:
    if value is None:
        return None
    return redact_text(str(value))[:200]
