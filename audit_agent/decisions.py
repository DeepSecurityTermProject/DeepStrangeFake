from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import AuditConfig
from .models import Finding, VerificationDecision, stable_id, to_plain, utc_now
from .redaction import redact_secrets
from .storage import immutable_path
from .tool_protocol import ToolRuntime, build_default_tool_registry


class DecisionValidationError(RuntimeError):
    pass


DECISION_SOURCES = {"llm", "deterministic", "merged", "fallback", "policy-denied"}
CONTEXTUAL_REF_PREFIXES = ("MEM", "MR", "VI", "CVE")


@dataclass
class LLMAgentDecision:
    role: str
    action: str
    parsed_json: dict[str, Any]
    confidence: float
    rationale: str
    evidence_refs: list[str] = field(default_factory=list)
    requested_tools: list[dict[str, Any]] = field(default_factory=list)
    selected_actions: list[dict[str, Any]] = field(default_factory=list)
    prompt_ref: str | None = None
    llm_response_ref: str | None = None
    provider: str | None = None
    model: str | None = None
    provider_metadata: dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""
    schema_status: str = "valid"
    schema_errors: list[str] = field(default_factory=list)
    policy_status: str = "pending"
    fallback_reason: str = ""
    repair_attempted: bool = False
    created_at: str = field(default_factory=utc_now)
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id(
                "LLD",
                self.role,
                self.action,
                self.prompt_ref,
                self.llm_response_ref,
                self.raw_output,
                self.created_at,
            )

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class DecisionPolicyGate:
    role: str
    status: str
    reasons: list[str] = field(default_factory=list)
    accepted_evidence_refs: list[str] = field(default_factory=list)
    contextual_refs: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    denied_tools: list[dict[str, Any]] = field(default_factory=list)
    confidence_threshold: float = 0.0
    created_at: str = field(default_factory=utc_now)
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id("DPG", self.role, self.status, self.reasons, self.created_at)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class MergedAgentDecision:
    role: str
    decision_source: str
    final_output: dict[str, Any]
    llm_decision_id: str | None = None
    policy_gate_id: str | None = None
    llm_confidence: float | None = None
    conflicts: list[str] = field(default_factory=list)
    fallback_reason: str = ""
    created_at: str = field(default_factory=utc_now)
    id: str | None = None

    def __post_init__(self) -> None:
        if self.decision_source not in DECISION_SOURCES:
            raise ValueError(f"Unsupported decision source: {self.decision_source}")
        if not self.id:
            self.id = stable_id("MD", self.role, self.decision_source, self.final_output, self.created_at)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


def role_decision_schema(role: str) -> dict[str, Any]:
    schemas = _role_schemas()
    try:
        return schemas[role]
    except KeyError as exc:
        raise DecisionValidationError(f"Unknown decision role: {role}") from exc


def validate_decision_payload(role: str, payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise DecisionValidationError("Decision payload must be a JSON object")
    schema = role_decision_schema(role)
    errors = _schema_errors(payload, schema)
    if errors:
        raise DecisionValidationError("; ".join(errors))
    if payload.get("role") != role:
        raise DecisionValidationError(f"Decision role must be {role}")
    confidence = payload.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise DecisionValidationError("Field confidence must be a number")
    if confidence < 0 or confidence > 1:
        raise DecisionValidationError("Field confidence must be between 0 and 1")
    normalized = dict(payload)
    normalized["confidence"] = float(confidence)
    normalized.setdefault("evidence_refs", [])
    normalized.setdefault("requested_tools", [])
    normalized.setdefault("selected_actions", [])
    return normalized


def build_llm_decision(
    role: str,
    payload: dict[str, Any],
    prompt_ref: str | None = None,
    llm_response_ref: str | None = None,
    provider: str | None = None,
    model: str | None = None,
    provider_metadata: dict[str, Any] | None = None,
    raw_output: str = "",
    fallback_reason: str = "",
) -> LLMAgentDecision:
    normalized = validate_decision_payload(role, payload)
    return LLMAgentDecision(
        role=role,
        action=str(normalized["action"]),
        parsed_json=normalized,
        confidence=normalized["confidence"],
        rationale=str(normalized["rationale"]),
        evidence_refs=[str(item) for item in normalized.get("evidence_refs", [])],
        requested_tools=_normalize_tool_requests(normalized.get("requested_tools", [])),
        selected_actions=_normalize_selected_actions(normalized.get("selected_actions", [])),
        prompt_ref=prompt_ref,
        llm_response_ref=llm_response_ref,
        provider=provider,
        model=model,
        provider_metadata=provider_metadata or {},
        raw_output=raw_output,
        fallback_reason=fallback_reason,
    )


def build_decision_from_llm_response(
    role: str,
    payload: Any,
    prompt_ref: str | None = None,
    llm_response_ref: str | None = None,
    provider: str | None = None,
    model: str | None = None,
    provider_metadata: dict[str, Any] | None = None,
    raw_output: str = "",
    repair_enabled: bool = True,
) -> LLMAgentDecision:
    try:
        return build_llm_decision(
            role=role,
            payload=payload if isinstance(payload, dict) else {},
            prompt_ref=prompt_ref,
            llm_response_ref=llm_response_ref,
            provider=provider,
            model=model,
            provider_metadata=provider_metadata,
            raw_output=raw_output,
        )
    except DecisionValidationError as exc:
        fallback = _fallback_payload(role)
        decision = LLMAgentDecision(
            role=role,
            action=fallback["action"],
            parsed_json=fallback,
            confidence=0.0,
            rationale=fallback["rationale"],
            prompt_ref=prompt_ref,
            llm_response_ref=llm_response_ref,
            provider=provider,
            model=model,
            provider_metadata=provider_metadata or {},
            raw_output=raw_output,
            schema_status="invalid",
            schema_errors=[str(exc)],
            policy_status="denied",
            fallback_reason="schema-invalid",
            repair_attempted=repair_enabled,
        )
        return decision


def evaluate_decision_policy(role: str, decision: LLMAgentDecision, config: AuditConfig) -> DecisionPolicyGate:
    reasons: list[str] = []
    allowed_tools: list[str] = []
    denied_tools: list[dict[str, Any]] = []
    threshold = config.llm_decisions.confidence_thresholds.get(role, 0.7)

    if decision.schema_status != "valid":
        reasons.append("schema validation failed")
    if role not in set(config.llm_decisions.roles):
        reasons.append(f"role {role} is not enabled for LLM decisions")
    if decision.confidence < threshold:
        reasons.append(f"confidence below threshold {threshold}")

    evidence_refs = _collect_refs(decision)
    local_refs = [ref for ref in evidence_refs if _is_local_evidence_ref(ref)]
    contextual_refs = [ref for ref in evidence_refs if not _is_local_evidence_ref(ref)]

    if role == "analysis":
        for action in _finding_like_actions(decision.selected_actions):
            if not _action_has_local_evidence(action):
                reasons.append("analysis candidate lacks local evidence")
                break

    if role == "verification":
        for action in decision.selected_actions:
            if str(action.get("decision", "")).lower() == "accept" and not _action_refs_local_evidence(action):
                reasons.append("verification acceptance lacks local evidence")
            validation_level = action.get("validation_level")
            if validation_level:
                if validation_level not in config.validation_levels:
                    reasons.append(f"validation level {validation_level} is not configured")
                if validation_level == "sandbox" and not config.sandbox.enabled:
                    reasons.append("validation level sandbox is disabled by sandbox policy")
                if validation_level == "live-target" and not config.llm_decisions.allow_live_target_actions:
                    reasons.append("live target validation is not allowed")

    if any(action.get("live_target") or action.get("live_action") for action in decision.selected_actions):
        if not config.llm_decisions.allow_live_target_actions:
            reasons.append("live target actions are not allowed")

    denied_tools.extend(_tool_policy_denials(role, decision, config))
    if denied_tools:
        reasons.extend(item["reason"] for item in denied_tools)
    else:
        allowed_tools = [str(item.get("tool_name") or item.get("name")) for item in decision.requested_tools]

    status = "accepted" if not reasons else "denied"
    decision.policy_status = status
    if status == "denied" and not decision.fallback_reason:
        decision.fallback_reason = "policy-denied"
    return DecisionPolicyGate(
        role=role,
        status=status,
        reasons=_dedupe(reasons),
        accepted_evidence_refs=_dedupe(local_refs),
        contextual_refs=_dedupe(contextual_refs),
        allowed_tools=_dedupe(allowed_tools),
        denied_tools=denied_tools,
        confidence_threshold=threshold,
    )


def merge_decision(
    role: str,
    deterministic_output: dict[str, Any],
    proposal: LLMAgentDecision | None,
    gate_status: str,
    gate_reasons: list[str] | None = None,
    final_output: dict[str, Any] | None = None,
) -> MergedAgentDecision:
    gate_reasons = gate_reasons or []
    if proposal is None:
        return MergedAgentDecision(
            role=role,
            decision_source="deterministic",
            final_output=final_output or deterministic_output,
            fallback_reason="llm-disabled-or-missing",
        )
    if proposal.schema_status != "valid":
        source = "fallback"
    elif gate_status == "accepted":
        source = "merged"
    else:
        source = "policy-denied"
    return MergedAgentDecision(
        role=role,
        decision_source=source,
        final_output=final_output or deterministic_output,
        llm_decision_id=proposal.id,
        llm_confidence=proposal.confidence,
        conflicts=gate_reasons,
        fallback_reason=proposal.fallback_reason,
    )


def persist_decision_bundle(
    root: Path | str,
    role: str,
    llm_decision: LLMAgentDecision,
    policy_gate: DecisionPolicyGate | None = None,
    merged: MergedAgentDecision | None = None,
) -> Path:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    payload = {
        "llm_decision": llm_decision.to_dict(),
        "policy_gate": policy_gate.to_dict() if policy_gate else None,
        "merged_decision": merged.to_dict() if merged else None,
    }
    path = immutable_path(root / f"{role}-{llm_decision.id}.json")
    path.write_text(
        json.dumps(
            redact_secrets(payload, _decision_secret_values(llm_decision)),
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return path


def apply_verification_decision_proposal(
    candidates: list[Finding],
    deterministic_decisions: list[VerificationDecision],
    proposal: LLMAgentDecision,
    config: AuditConfig,
) -> tuple[list[VerificationDecision], DecisionPolicyGate, MergedAgentDecision]:
    gate = evaluate_decision_policy("verification", proposal, config)
    decisions_by_finding = {decision.finding_id: decision for decision in deterministic_decisions}
    result = list(deterministic_decisions)

    if gate.status != "accepted":
        if not result:
            for finding in candidates:
                reason = "Rejected: missing local evidence; LLM proposal denied by policy."
                if _finding_has_local_evidence(finding):
                    reason = "Rejected: LLM proposal denied by deterministic policy gate."
                result.append(
                    VerificationDecision(
                        finding=finding,
                        decision="reject",
                        reason=reason,
                        confidence=0.0,
                        validation_level="manual",
                        priority="low",
                        decision_source="policy-denied",
                        llm_confidence=proposal.confidence,
                        policy_gate=gate.to_dict(),
                        prompt_refs=_optional_list(proposal.prompt_ref),
                        llm_response_refs=_optional_list(proposal.llm_response_ref),
                        fallback_reason=proposal.fallback_reason or "policy-denied",
                    )
                )
        for decision in result:
            _annotate_verification_decision(decision, proposal, gate, "deterministic")
        merged = merge_decision(
            "verification",
            {"decision_count": len(result)},
            proposal,
            gate.status,
            gate.reasons,
        )
        merged.policy_gate_id = gate.id
        return result, gate, merged

    for action in proposal.selected_actions:
        finding_id = action.get("finding_id")
        finding = next((item for item in candidates if item.id == finding_id), None)
        if not finding:
            continue
        existing = decisions_by_finding.get(finding_id)
        decision_text = str(action.get("decision", "")).lower()
        if decision_text == "accept" and not _finding_has_local_evidence(finding):
            new_decision = VerificationDecision(
                finding=finding,
                decision="reject",
                reason="Rejected: local evidence is required even when the LLM recommends acceptance.",
                confidence=0.0,
                validation_level="manual",
                priority="low",
                decision_source="policy-denied",
                llm_confidence=proposal.confidence,
                policy_gate=gate.to_dict(),
                prompt_refs=_optional_list(proposal.prompt_ref),
                llm_response_refs=_optional_list(proposal.llm_response_ref),
            )
        elif existing:
            existing.decision_source = "merged"
            existing.llm_confidence = proposal.confidence
            existing.policy_gate = gate.to_dict()
            existing.prompt_refs = _optional_list(proposal.prompt_ref)
            existing.llm_response_refs = _optional_list(proposal.llm_response_ref)
            existing.reason = _merge_reason(existing.reason, proposal.rationale)
            if action.get("priority"):
                existing.priority = str(action["priority"])
            if action.get("validation_level") in config.validation_levels:
                existing.validation_level = str(action["validation_level"])
            new_decision = existing
        else:
            new_decision = VerificationDecision(
                finding=finding,
                decision=decision_text or "reject",
                reason=proposal.rationale,
                confidence=min(max(proposal.confidence, 0.0), 0.95),
                validation_level=str(action.get("validation_level") or config.default_validation_level),
                priority=str(action.get("priority") or "normal"),
                decision_source="llm",
                llm_confidence=proposal.confidence,
                policy_gate=gate.to_dict(),
                prompt_refs=_optional_list(proposal.prompt_ref),
                llm_response_refs=_optional_list(proposal.llm_response_ref),
            )
        if new_decision not in result:
            result.append(new_decision)

    for decision in result:
        if not decision.policy_gate:
            _annotate_verification_decision(decision, proposal, gate, "merged")
    merged = merge_decision(
        "verification",
        {"decision_count": len(deterministic_decisions)},
        proposal,
        gate.status,
        gate.reasons,
        final_output={"decision_count": len(result)},
    )
    merged.policy_gate_id = gate.id
    return result, gate, merged


def annotate_finding_from_decision(
    finding: Finding,
    proposal: LLMAgentDecision | None,
    gate: DecisionPolicyGate | None,
    merged: MergedAgentDecision | None,
) -> None:
    if merged:
        finding.metadata["decision_source"] = merged.decision_source
        finding.metadata["decision_merge_id"] = merged.id
        finding.metadata["fallback_reason"] = merged.fallback_reason
    elif "decision_source" not in finding.metadata:
        finding.metadata["decision_source"] = "deterministic"
    if proposal:
        finding.metadata["llm_confidence"] = proposal.confidence
        _append_unique(finding.metadata.setdefault("llm_decision_refs", []), proposal.id or "")
        for ref in _optional_list(proposal.prompt_ref):
            _append_unique(finding.metadata.setdefault("prompt_refs", []), ref)
        for ref in _optional_list(proposal.llm_response_ref):
            _append_unique(finding.metadata.setdefault("llm_response_refs", []), ref)
    if gate:
        finding.metadata["policy_gate"] = gate.to_dict()
        finding.metadata["contextual_intelligence_refs"] = gate.contextual_refs
        finding.metadata["local_evidence_refs"] = gate.accepted_evidence_refs or list(finding.tool_refs)


def _role_schemas() -> dict[str, dict[str, Any]]:
    base = {
        "type": "object",
        "required": ["role", "action", "confidence", "rationale", "evidence_refs", "selected_actions", "requested_tools"],
        "properties": {
            "role": {"type": "string"},
            "action": {"type": "string"},
            "confidence": {"type": "number"},
            "rationale": {"type": "string"},
            "evidence_refs": {"type": "array"},
            "selected_actions": {"type": "array"},
            "requested_tools": {"type": "array"},
        },
    }
    return {
        "orchestrator": {
            **base,
            "description": "Plan scope, budgets, focus areas, agent order, and safe tool groups.",
        },
        "recon": {
            **base,
            "description": "Select bounded context, memory queries, MCP lookups, and safe tool requests.",
        },
        "analysis": {
            **base,
            "description": "Propose evidence-bound candidate findings and ranking decisions.",
        },
        "verification": {
            **base,
            "description": "Propose accept or reject outcomes, validation levels, and priorities.",
        },
    }


def _schema_errors(payload: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for field_name in schema.get("required", []):
        if field_name not in payload:
            errors.append(f"Missing required field: {field_name}")
    for field_name, prop_schema in schema.get("properties", {}).items():
        if field_name not in payload:
            continue
        expected = prop_schema.get("type")
        value = payload[field_name]
        if expected == "string" and not isinstance(value, str):
            errors.append(f"Field {field_name} must be a string")
        elif expected == "array" and not isinstance(value, list):
            errors.append(f"Field {field_name} must be an array")
        elif expected == "object" and not isinstance(value, dict):
            errors.append(f"Field {field_name} must be an object")
        elif expected == "number" and (isinstance(value, bool) or not isinstance(value, (int, float))):
            errors.append(f"Field {field_name} must be a number")
    return errors


def _fallback_payload(role: str) -> dict[str, Any]:
    return {
        "role": role,
        "action": "deterministic-fallback",
        "confidence": 0.0,
        "rationale": "Malformed or missing LLM decision; deterministic fallback is used.",
        "evidence_refs": [],
        "selected_actions": [],
        "requested_tools": [],
    }


def _collect_refs(decision: LLMAgentDecision) -> list[str]:
    refs = [str(ref) for ref in decision.evidence_refs]
    for action in decision.selected_actions:
        if not isinstance(action, dict):
            continue
        for key in ("evidence_refs", "tool_refs", "memory_refs", "intelligence_refs"):
            value = action.get(key) or []
            if isinstance(value, str):
                refs.append(value)
            elif isinstance(value, list):
                refs.extend(str(item) for item in value)
    return _dedupe(refs)


def _is_local_evidence_ref(ref: str) -> bool:
    text = str(ref).strip()
    if not text:
        return False
    upper = text.upper()
    return not upper.startswith(CONTEXTUAL_REF_PREFIXES)


def _finding_like_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        action
        for action in actions
        if action.get("vulnerability_class") or action.get("title") or action.get("path") or action.get("file")
    ]


def _action_has_local_evidence(action: dict[str, Any]) -> bool:
    evidence = action.get("evidence") or []
    if isinstance(evidence, str) and evidence.strip():
        return True
    if isinstance(evidence, list) and any(str(item).strip() for item in evidence):
        return True
    if action.get("tool_refs"):
        return True
    return _action_refs_local_evidence(action)


def _action_refs_local_evidence(action: dict[str, Any]) -> bool:
    for key in ("evidence_refs", "tool_refs"):
        values = action.get(key) or []
        if isinstance(values, str):
            values = [values]
        if any(_is_local_evidence_ref(str(item)) for item in values):
            return True
    return False


def _tool_policy_denials(role: str, decision: LLMAgentDecision, config: AuditConfig) -> list[dict[str, Any]]:
    if not decision.requested_tools:
        return []
    registry = build_default_tool_registry(config)
    declarations = {item.name: item for item in registry.declarations()}
    permissions = ToolRuntime.DEFAULT_PERMISSIONS.get(role, set())
    limit = config.llm_decisions.tool_budget_per_role.get(role)
    denials: list[dict[str, Any]] = []
    if limit is not None and len(decision.requested_tools) > limit:
        denials.append({"tool": "*", "reason": f"tool request budget exceeded for {role}"})
    for request in decision.requested_tools:
        if not isinstance(request, dict):
            request = {"tool_name": str(request)}
        name = str(request.get("tool_name") or request.get("name") or "")
        declaration = declarations.get(name)
        if not declaration:
            denials.append({"tool": name, "reason": f"tool {name} is not registered"})
            continue
        if declaration.permission_group not in permissions:
            denials.append({"tool": name, "reason": f"tool {name} is not permitted for {role}"})
        if declaration.safety_classification != "read-only" and not config.sandbox.enabled:
            denials.append({"tool": name, "reason": f"tool {name} requires sandbox permission"})
    return denials


def _finding_has_local_evidence(finding: Finding) -> bool:
    return bool(finding.evidence or finding.tool_refs)


def _annotate_verification_decision(
    decision: VerificationDecision,
    proposal: LLMAgentDecision,
    gate: DecisionPolicyGate,
    decision_source: str,
) -> None:
    decision.decision_source = decision_source
    decision.llm_confidence = proposal.confidence
    decision.policy_gate = gate.to_dict()
    decision.prompt_refs = _optional_list(proposal.prompt_ref)
    decision.llm_response_refs = _optional_list(proposal.llm_response_ref)
    if proposal.fallback_reason:
        decision.fallback_reason = proposal.fallback_reason
    annotate_finding_from_decision(decision.finding, proposal, gate, None)
    decision.finding.metadata["decision_source"] = decision_source


def _merge_reason(existing: str, rationale: str) -> str:
    if not rationale:
        return existing
    if rationale in existing:
        return existing
    return f"{existing} LLM rationale: {rationale}"


def _optional_list(value: str | None) -> list[str]:
    return [value] if value else []


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _normalize_selected_actions(value: Any) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    if not isinstance(value, list):
        return actions
    for item in value:
        if isinstance(item, dict):
            actions.append(dict(item))
        elif item:
            actions.append({"action": str(item)})
    return actions


def _normalize_tool_requests(value: Any) -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = []
    if not isinstance(value, list):
        return requests
    for item in value:
        if isinstance(item, dict):
            normalized = dict(item)
            if "tool_name" not in normalized and "name" in normalized:
                normalized["tool_name"] = normalized["name"]
            normalized.setdefault("arguments", {})
            requests.append(normalized)
        elif item:
            requests.append({"tool_name": str(item), "arguments": {}})
    return requests


def _append_unique(values: list[str], value: str) -> None:
    if value and value not in values:
        values.append(value)


def _decision_secret_values(decision: LLMAgentDecision) -> list[str]:
    secrets: list[str] = []
    for key, value in decision.provider_metadata.items():
        lowered = str(key).lower()
        if value and any(fragment in lowered for fragment in ("key", "token", "secret", "password")):
            secrets.append(str(value))
    return secrets
