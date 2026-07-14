from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from .models import MessageEnvelope
from .redaction import redact_secrets


Subscriber = Callable[[MessageEnvelope], None]


class MessageBus:
    def __init__(
        self,
        run_id: str,
        log_path: Path | str,
        secret_values: list[str] | tuple[str, ...] | None = None,
    ):
        self.run_id = run_id
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.subscribers: dict[str, list[Subscriber]] = {}
        self.secret_values = [item for item in (secret_values or []) if item]

    def subscribe(self, message_type: str, handler: Subscriber) -> None:
        self.subscribers.setdefault(message_type, []).append(handler)

    def publish(
        self,
        sender: str,
        recipient: str,
        message_type: str,
        payload: dict,
        correlation_id: str | None = None,
        causation_id: str | None = None,
        artifact_refs: list[str] | None = None,
    ) -> MessageEnvelope:
        envelope = MessageEnvelope(
            run_id=self.run_id,
            sender=sender,
            recipient=recipient,
            message_type=message_type,
            payload=redact_secrets(payload, self.secret_values),
            correlation_id=correlation_id,
            causation_id=causation_id,
            artifact_refs=redact_secrets(artifact_refs or [], self.secret_values),
        )
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(envelope.to_dict(), ensure_ascii=False) + "\n")
        for handler in self.subscribers.get(message_type, []):
            handler(envelope)
        for handler in self.subscribers.get("*", []):
            handler(envelope)
        return envelope


def replay_messages(log_path: Path | str) -> list[MessageEnvelope]:
    path = Path(log_path)
    if not path.exists():
        return []
    envelopes: list[MessageEnvelope] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        message_id = payload.pop("id", None)
        payload.pop("message_id", None)
        envelope = MessageEnvelope(**payload)
        envelope.id = message_id
        envelopes.append(envelope)
    return envelopes


def replay_summary(log_path: Path | str) -> dict:
    messages = replay_messages(log_path)
    counts: dict[str, int] = {}
    lifecycle = {"roles": {}, "accepted_gates": 0, "denied_gates": 0, "fallbacks": 0}
    runtime_lifecycle = {
        "roles": {},
        "tasks": {},
        "fallbacks": 0,
        "service_failures": 0,
        "tool_calls": 0,
        "artifacts": 0,
    }
    sandbox_lifecycle = {
        "attempts": 0,
        "status_counts": {},
        "runner_counts": {},
        "docker_images": {},
        "policy_denied": 0,
        "environment_failures": 0,
        "manual_required": 0,
        "confirmed": 0,
        "rejected": 0,
    }
    repair_lifecycle = {
        "events": [],
        "classifications": {},
        "repair_requests": 0,
        "validated_responses": 0,
        "contract_denials": 0,
        "semantic_denials": 0,
        "safety_denials": 0,
        "runner_starts": 0,
        "judge_results": {},
        "duplicates": 0,
        "target_integrity_changes": 0,
    }
    llm_request_lifecycle = {
        "request_groups": {},
        "provider_attempts": 0,
        "retries": 0,
        "terminal_status_counts": {},
        "incomplete_groups": [],
    }
    for message in messages:
        counts[message.message_type] = counts.get(message.message_type, 0) + 1
        if message.message_type.startswith("decision.") or message.message_type == "llm.decision":
            role = str(message.payload.get("role") or message.sender)
            role_summary = lifecycle["roles"].setdefault(
                role,
                {"proposals": 0, "accepted_gates": 0, "denied_gates": 0, "sources": {}, "fallback_reasons": []},
            )
            if message.message_type == "llm.decision":
                role_summary["proposals"] += 1
            if message.message_type == "decision.policy":
                status = message.payload.get("status")
                if status == "accepted":
                    lifecycle["accepted_gates"] += 1
                    role_summary["accepted_gates"] += 1
                if status == "denied":
                    lifecycle["denied_gates"] += 1
                    role_summary["denied_gates"] += 1
            if message.message_type == "decision.merge":
                source = str(message.payload.get("decision_source") or "unknown")
                role_summary["sources"][source] = role_summary["sources"].get(source, 0) + 1
            if message.message_type == "decision.fallback":
                lifecycle["fallbacks"] += 1
                reason = str(message.payload.get("fallback_reason") or "fallback")
                role_summary["fallback_reasons"].append(reason)
        if message.message_type.startswith("runtime."):
            _add_runtime_lifecycle(runtime_lifecycle, message)
        if message.message_type == "verification.attempt":
            _add_sandbox_lifecycle(sandbox_lifecycle, message)
        if message.message_type.startswith("poc."):
            _add_repair_lifecycle(repair_lifecycle, message)
        if message.message_type.startswith("llm.lifecycle."):
            _add_llm_request_lifecycle(llm_request_lifecycle, message)
    for group_id, group in llm_request_lifecycle["request_groups"].items():
        attempts = len(group["provider_attempt_ids"])
        llm_request_lifecycle["provider_attempts"] += attempts
        llm_request_lifecycle["retries"] += max(0, attempts - (1 if attempts else 0))
        if not group.get("terminal_status"):
            llm_request_lifecycle["incomplete_groups"].append(group_id)
    return {
        "message_count": len(messages),
        "types": counts,
        "decision_lifecycle": lifecycle,
        "runtime_lifecycle": runtime_lifecycle,
        "sandbox_lifecycle": sandbox_lifecycle,
        "repair_lifecycle": repair_lifecycle,
        "llm_request_lifecycle": llm_request_lifecycle,
    }


def replay_run_summary(
    log_path: Path | str,
    *,
    run_dir: Path | str | None = None,
    llm_enabled: bool | None = None,
) -> dict:
    """Replay messages while treating the immutable LLM ledger as authoritative."""
    summary = replay_summary(log_path)
    message_path = Path(log_path).resolve()
    if run_dir is None:
        run_root = message_path.parent.parent if message_path.parent.name == "messages" else message_path.parent
    else:
        run_root = Path(run_dir).resolve()
    if llm_enabled is None:
        state_path = run_root / "runtime_state" / "state.json"
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            configured = (state.get("config_summary") or {}).get("runtime_enabled")
            if isinstance(configured, bool):
                llm_enabled = configured
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pass

    from .llm_accounting import replay_llm_lifecycle

    accounting = replay_llm_lifecycle(run_root, llm_enabled=llm_enabled)
    summary["llm_accounting"] = accounting
    lifecycle = summary["llm_request_lifecycle"]
    lifecycle.update(
        {
            "authoritative_source": accounting["accounting_source"],
            "ledger_present": accounting["ledger_present"],
            "complete": accounting["complete"],
            "gap_ids": list(accounting.get("gap_ids") or []),
            "accounting_gaps": list(accounting.get("gaps") or []),
            "authoritative_request_groups": list(accounting.get("request_groups") or []),
        }
    )
    if accounting.get("provider_attempts") is not None:
        lifecycle["provider_attempts"] = accounting["provider_attempts"]
    if accounting.get("retries") is not None:
        lifecycle["retries"] = accounting["retries"]
    incomplete = set(lifecycle.get("incomplete_groups") or [])
    incomplete.update(
        str(item.get("request_group_id"))
        for item in accounting.get("gaps") or []
        if item.get("request_group_id")
    )
    incomplete.update(
        str(item.get("request_group_id"))
        for item in accounting.get("request_groups") or []
        if item.get("terminal_status") == "incomplete"
    )
    lifecycle["incomplete_groups"] = sorted(incomplete)
    return summary


def _add_llm_request_lifecycle(lifecycle: dict, message: MessageEnvelope) -> None:
    payload = message.payload
    group_id = str(payload.get("request_group_id") or "")
    if not group_id:
        return
    group = lifecycle["request_groups"].setdefault(
        group_id,
        {
            "role": payload.get("role"),
            "provider_attempt_ids": [],
            "events": [],
            "terminal_status": None,
        },
    )
    event = {
        "event_id": payload.get("event_id"),
        "kind": payload.get("event_kind"),
        "message_id": message.id,
        "artifact_refs": list(message.artifact_refs),
    }
    group["events"].append(event)
    attempt_id = payload.get("provider_attempt_id")
    if attempt_id and attempt_id not in group["provider_attempt_ids"]:
        group["provider_attempt_ids"].append(attempt_id)
    terminal = payload.get("terminal_status")
    if terminal:
        group["terminal_status"] = terminal
        counts = lifecycle["terminal_status_counts"]
        counts[terminal] = counts.get(terminal, 0) + 1


def _runtime_role_summary(runtime_lifecycle: dict, role: str) -> dict:
    return runtime_lifecycle["roles"].setdefault(
        role,
        {"tasks": {}, "status_counts": {}, "tools": {}, "artifacts": 0, "fallback_reasons": []},
    )


def _add_runtime_lifecycle(runtime_lifecycle: dict, message: MessageEnvelope) -> None:
    role = str(message.payload.get("role") or message.recipient or message.sender)
    role_summary = _runtime_role_summary(runtime_lifecycle, role)
    if message.message_type == "runtime.task":
        task_id = str(message.payload.get("task_id") or "")
        status = str(message.payload.get("status") or "unknown")
        kind = str(message.payload.get("kind") or "unknown")
        fallback_reason = str(message.payload.get("fallback_reason") or "")
        if task_id:
            task_summary = runtime_lifecycle["tasks"].setdefault(task_id, {"role": role, "kind": kind})
            task_summary.update({"status": status, "fallback_reason": fallback_reason})
            role_summary["tasks"][task_id] = {"kind": kind, "status": status}
        role_summary["status_counts"][status] = role_summary["status_counts"].get(status, 0) + 1
        if fallback_reason:
            runtime_lifecycle["fallbacks"] += 1
            role_summary["fallback_reasons"].append(fallback_reason)
        return
    if message.message_type in {"runtime.tool", "runtime.tool.denied"}:
        tool_name = str(message.payload.get("tool") or "unknown")
        tool_summary = role_summary["tools"].setdefault(tool_name, {"calls": 0, "denied": 0, "failed": 0})
        tool_summary["calls"] += 1
        runtime_lifecycle["tool_calls"] += 1
        if message.message_type == "runtime.tool.denied":
            tool_summary["denied"] += 1
            runtime_lifecycle["service_failures"] += 1
        elif message.payload.get("success") is False:
            tool_summary["failed"] += 1
            runtime_lifecycle["service_failures"] += 1
        return
    if message.message_type == "runtime.artifact":
        role_summary["artifacts"] += 1
        runtime_lifecycle["artifacts"] += 1


def _add_sandbox_lifecycle(sandbox_lifecycle: dict, message: MessageEnvelope) -> None:
    sandbox_lifecycle["attempts"] += 1
    status = str(message.payload.get("status") or "unknown")
    runner = str(message.payload.get("runner") or "unknown")
    image = str(message.payload.get("docker_image") or "")
    sandbox_lifecycle["status_counts"][status] = sandbox_lifecycle["status_counts"].get(status, 0) + 1
    sandbox_lifecycle["runner_counts"][runner] = sandbox_lifecycle["runner_counts"].get(runner, 0) + 1
    if image:
        sandbox_lifecycle["docker_images"][image] = sandbox_lifecycle["docker_images"].get(image, 0) + 1
    if status == "policy-denied":
        sandbox_lifecycle["policy_denied"] += 1
    blocking = str(message.payload.get("blocking_reason") or "").lower()
    if "docker" in blocking or "image" in blocking or "daemon" in blocking:
        sandbox_lifecycle["environment_failures"] += 1
    if status == "manual-required":
        sandbox_lifecycle["manual_required"] += 1
    if status == "confirmed":
        sandbox_lifecycle["confirmed"] += 1
    if status == "rejected":
        sandbox_lifecycle["rejected"] += 1


def _add_repair_lifecycle(repair_lifecycle: dict, message: MessageEnvelope) -> None:
    payload = message.payload
    event = {
        "message_id": message.id,
        "type": message.message_type,
        "finding_id": payload.get("finding_id"),
        "attempt_index": payload.get("attempt_index"),
        "status": payload.get("status") or payload.get("judge_status"),
        "failure_class": payload.get("failure_class"),
        "edit_hash": payload.get("edit_hash"),
        "script_hash": payload.get("script_hash"),
        "rule_ids": payload.get("rule_ids", []),
        "artifact_refs": list(message.artifact_refs),
    }
    repair_lifecycle["events"].append(event)
    if message.message_type == "poc.classification":
        value = str(payload.get("failure_class") or "unknown")
        repair_lifecycle["classifications"][value] = repair_lifecycle["classifications"].get(value, 0) + 1
    elif message.message_type == "poc.repair.request":
        repair_lifecycle["repair_requests"] += 1
    elif message.message_type == "poc.repair.response":
        repair_lifecycle["validated_responses"] += 1
    elif message.message_type == "poc.repair.contract-denied":
        repair_lifecycle["contract_denials"] += 1
    elif message.message_type == "poc.semantic-integrity" and payload.get("allowed") is False:
        repair_lifecycle["semantic_denials"] += 1
    elif message.message_type == "poc.safety" and payload.get("allowed") is False:
        repair_lifecycle["safety_denials"] += 1
    elif message.message_type == "poc.runner.start":
        repair_lifecycle["runner_starts"] += 1
    elif message.message_type == "poc.runner.result":
        status = str(payload.get("judge_status") or "unknown")
        repair_lifecycle["judge_results"][status] = repair_lifecycle["judge_results"].get(status, 0) + 1
    elif message.message_type == "poc.repair.duplicate":
        repair_lifecycle["duplicates"] += 1
    elif message.message_type == "poc.target-integrity" and payload.get("unchanged") is False:
        repair_lifecycle["target_integrity_changes"] += 1
