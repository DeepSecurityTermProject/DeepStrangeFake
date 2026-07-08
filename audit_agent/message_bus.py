from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from .models import MessageEnvelope


Subscriber = Callable[[MessageEnvelope], None]


class MessageBus:
    def __init__(self, run_id: str, log_path: Path | str):
        self.run_id = run_id
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.subscribers: dict[str, list[Subscriber]] = {}

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
            payload=payload,
            correlation_id=correlation_id,
            causation_id=causation_id,
            artifact_refs=artifact_refs or [],
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
    return {
        "message_count": len(messages),
        "types": counts,
        "decision_lifecycle": lifecycle,
        "runtime_lifecycle": runtime_lifecycle,
    }


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
