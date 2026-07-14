from __future__ import annotations

from dataclasses import MISSING, dataclass, field, fields
from typing import Any, ClassVar

from .models import stable_id, to_plain, utc_now


SUPPORTED_INVESTIGATION_CLASSES = {
    "sql-injection",
    "command-injection",
    "path-traversal",
    "hardcoded-secret",
}
INVESTIGATION_ACTIONS = {
    "search",
    "source_context",
    "callers",
    "callees",
    "dataflow",
    "sast",
    "lexical_memory",
    "submit_gate",
    "abandon",
}
HYPOTHESIS_STATES = {
    "proposed",
    "investigating",
    "supported",
    "refuted",
    "inconclusive",
    "evidence-gate",
    "promoted",
    "refine",
    "rejected",
}
HYPOTHESIS_TRANSITIONS = {
    "proposed": {"investigating", "rejected"},
    "investigating": {"investigating", "supported", "refuted", "inconclusive"},
    "supported": {"evidence-gate"},
    "refuted": {"rejected"},
    "inconclusive": {"evidence-gate", "refine", "rejected"},
    "evidence-gate": {"promoted", "refine", "rejected"},
    "refine": {"investigating", "rejected"},
    "promoted": set(),
    "rejected": set(),
}
EVIDENCE_ORIGINS = {
    "pattern",
    "source",
    "independent-source",
    "config",
    "manifest",
    "call-graph",
    "dataflow",
    "semgrep",
    "bandit",
    "gitleaks",
    "lexical-memory",
    "model",
    "cve",
    "tool-error",
}
PROMOTING_CORROBORATORS = {
    "independent-source",
    "config",
    "manifest",
    "call-graph",
    "dataflow",
    "semgrep",
    "bandit",
    "gitleaks",
}
GATE_STATES = {"promoted", "refine", "rejected"}
VERIFICATION_PRIMITIVES = {
    "sql.sqlite-parameter-binding",
    "command.argv-marker",
    "path.safe-root-boundary",
    "secret.static-semantic",
}
PRIMITIVES_BY_CLASS = {
    "sql-injection": {"sql.sqlite-parameter-binding"},
    "command-injection": {"command.argv-marker"},
    "path-traversal": {"path.safe-root-boundary"},
    "hardcoded-secret": {"secret.static-semantic"},
}


class StrictContract:
    schema: ClassVar[str]

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)

    @classmethod
    def _values(cls, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError(f"{cls.__name__} payload must be an object")
        allowed = {item.name for item in fields(cls)}
        unknown = set(payload) - allowed
        if unknown:
            raise ValueError(f"{cls.__name__} has unknown fields: {sorted(unknown)}")
        required = {
            item.name
            for item in fields(cls)
            if item.default is MISSING and item.default_factory is MISSING
        }
        missing = required - set(payload)
        if missing:
            raise ValueError(f"{cls.__name__} is missing fields: {sorted(missing)}")
        return dict(payload)

    @classmethod
    def _require_schema(cls, schema_version: str) -> None:
        if schema_version != cls.schema:
            raise ValueError(f"unsupported {cls.__name__} schema: {schema_version}")


@dataclass
class EvidenceItem(StrictContract):
    schema: ClassVar[str] = "investigation-evidence.v1"

    evidence_id: str
    origin: str
    path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    excerpt: str = ""
    content_hash: str = ""
    artifact_ref: str | None = None
    source_identity: str = ""
    vulnerability_class: str | None = None
    message: str = ""
    success: bool = True
    counterevidence: bool = False
    raw: dict[str, Any] = field(default_factory=dict)
    schema_version: str = schema

    def __post_init__(self) -> None:
        self._require_schema(self.schema_version)
        if not self.evidence_id:
            raise ValueError("evidence_id is required")
        if self.origin not in EVIDENCE_ORIGINS:
            raise ValueError(f"unsupported evidence origin: {self.origin}")
        if self.path is not None:
            _validate_relative_path(self.path)
        if self.start_line is not None and self.start_line < 1:
            raise ValueError("evidence start_line must be positive")
        if self.end_line is not None and self.end_line < (self.start_line or 1):
            raise ValueError("evidence end_line precedes start_line")
        if self.content_hash and len(self.content_hash) != 64:
            raise ValueError("evidence content_hash must be sha256")

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "EvidenceItem":
        return cls(**cls._values(payload))


@dataclass
class SecuritySignal(StrictContract):
    schema: ClassVar[str] = "security-signal.v1"

    run_id: str
    vulnerability_class: str
    path: str
    line: int
    excerpt: str
    content_hash: str
    origin: str = "pattern"
    severity: str = "medium"
    observation_ref: str | None = None
    created_at: str = field(default_factory=utc_now)
    signal_id: str | None = None
    schema_version: str = schema

    def __post_init__(self) -> None:
        self._require_schema(self.schema_version)
        _validate_class(self.vulnerability_class)
        _validate_relative_path(self.path)
        if self.line < 1:
            raise ValueError("signal line must be positive")
        if len(self.content_hash) != 64:
            raise ValueError("signal content_hash must be sha256")
        if self.origin != "pattern":
            raise ValueError("phase-one startup signals must originate from pattern")
        if not self.signal_id:
            self.signal_id = stable_id(
                "SIG", self.run_id, self.vulnerability_class, self.path, self.line, self.content_hash
            )

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SecuritySignal":
        return cls(**cls._values(payload))


@dataclass
class InvestigationHypothesis(StrictContract):
    schema: ClassVar[str] = "investigation-hypothesis.v1"

    run_id: str
    vulnerability_class: str
    claim: str
    target_paths: list[str]
    rationale: str
    confidence: float
    state: str = "proposed"
    signal_refs: list[str] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    round_count: int = 0
    tool_call_count: int = 0
    parent_hypothesis_id: str | None = None
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    hypothesis_id: str | None = None
    schema_version: str = schema

    def __post_init__(self) -> None:
        self._require_schema(self.schema_version)
        _validate_class(self.vulnerability_class)
        if not self.claim.strip() or not self.rationale.strip():
            raise ValueError("hypothesis claim and rationale are required")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("hypothesis confidence must be in 0..1")
        if self.state not in HYPOTHESIS_STATES:
            raise ValueError(f"invalid hypothesis state: {self.state}")
        if not self.target_paths:
            raise ValueError("hypothesis requires at least one target path")
        for path in self.target_paths:
            _validate_relative_path(path)
        _validate_non_negative(self.round_count, "round_count")
        _validate_non_negative(self.tool_call_count, "tool_call_count")
        self.evidence = [
            item if isinstance(item, EvidenceItem) else EvidenceItem.from_dict(item)
            for item in self.evidence
        ]
        if not self.hypothesis_id:
            self.hypothesis_id = stable_id(
                "HYP", self.run_id, self.vulnerability_class, self.claim, sorted(self.target_paths)
            )

    def transition(self, new_state: str) -> None:
        if new_state not in HYPOTHESIS_TRANSITIONS.get(self.state, set()):
            raise ValueError(f"invalid hypothesis transition: {self.state}->{new_state}")
        self.state = new_state
        self.updated_at = utc_now()

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "InvestigationHypothesis":
        values = cls._values(payload)
        values["evidence"] = [EvidenceItem.from_dict(item) for item in values.get("evidence", [])]
        return cls(**values)


@dataclass
class InvestigationStep(StrictContract):
    schema: ClassVar[str] = "investigation-step.v1"

    run_id: str
    hypothesis_id: str
    round_index: int
    action: str
    arguments: dict[str, Any]
    action_key: str
    status: str
    observation_refs: list[str] = field(default_factory=list)
    prompt_ref: str | None = None
    response_ref: str | None = None
    request_group_id: str | None = None
    provider_attempt_ids: list[str] = field(default_factory=list)
    tool_call_ref: str | None = None
    schema_status: str = "valid"
    policy_status: str = "accepted"
    budget_debit: dict[str, int | float] = field(default_factory=dict)
    message: str = ""
    created_at: str = field(default_factory=utc_now)
    step_id: str | None = None
    schema_version: str = schema

    def __post_init__(self) -> None:
        self._require_schema(self.schema_version)
        if self.action not in INVESTIGATION_ACTIONS:
            raise ValueError(f"unregistered investigation action: {self.action}")
        _validate_non_negative(self.round_index, "round_index")
        if self.status not in {"accepted", "denied", "completed", "failed", "budget-exhausted"}:
            raise ValueError(f"invalid investigation step status: {self.status}")
        if not self.action_key:
            raise ValueError("investigation action_key is required")
        _reject_authority_fields(self.arguments)
        if not self.step_id:
            self.step_id = stable_id(
                "ISTEP", self.run_id, self.hypothesis_id, self.round_index, self.action_key
            )

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "InvestigationStep":
        return cls(**cls._values(payload))


@dataclass
class EvidenceGateDecision(StrictContract):
    schema: ClassVar[str] = "evidence-gate-decision.v1"

    run_id: str
    hypothesis_id: str
    state: str
    predicate_results: dict[str, bool]
    reasons: list[str]
    local_evidence_refs: list[str] = field(default_factory=list)
    corroboration_refs: list[str] = field(default_factory=list)
    counterevidence_refs: list[str] = field(default_factory=list)
    candidate_id: str | None = None
    evidence_package_ref: str | None = None
    created_at: str = field(default_factory=utc_now)
    gate_id: str | None = None
    schema_version: str = schema

    def __post_init__(self) -> None:
        self._require_schema(self.schema_version)
        if self.state not in GATE_STATES:
            raise ValueError(f"invalid evidence gate state: {self.state}")
        if self.state == "promoted" and (
            not self.local_evidence_refs or not self.corroboration_refs
        ):
            raise ValueError("promoted gate requires local and corroborating evidence")
        if not self.gate_id:
            self.gate_id = stable_id(
                "EG", self.run_id, self.hypothesis_id, self.state, self.predicate_results
            )

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "EvidenceGateDecision":
        return cls(**cls._values(payload))


@dataclass
class VerificationEvidencePackage(StrictContract):
    schema: ClassVar[str] = "verification-evidence-package.v1"

    run_id: str
    hypothesis_id: str
    candidate_id: str
    vulnerability_class: str
    claim: str
    severity: str
    local_evidence: list[EvidenceItem]
    corroborating_evidence: list[EvidenceItem]
    counterevidence: list[EvidenceItem] = field(default_factory=list)
    gate_ref: str | None = None
    scope: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)
    package_id: str | None = None
    schema_version: str = schema

    def __post_init__(self) -> None:
        self._require_schema(self.schema_version)
        _validate_class(self.vulnerability_class)
        self.local_evidence = _coerce_evidence(self.local_evidence)
        self.corroborating_evidence = _coerce_evidence(self.corroborating_evidence)
        self.counterevidence = _coerce_evidence(self.counterevidence)
        if not self.local_evidence or not self.corroborating_evidence:
            raise ValueError("verification evidence package requires dual evidence")
        if not self.package_id:
            self.package_id = stable_id(
                "VEP", self.run_id, self.candidate_id, self.hypothesis_id
            )

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "VerificationEvidencePackage":
        values = cls._values(payload)
        for key in ("local_evidence", "corroborating_evidence", "counterevidence"):
            values[key] = [EvidenceItem.from_dict(item) for item in values.get(key, [])]
        return cls(**values)


@dataclass
class VerificationPrimitiveCall(StrictContract):
    schema: ClassVar[str] = "verification-primitive-call.v1"

    primitive_id: str
    parameters: dict[str, Any]
    expected_observations: list[str]
    evidence_refs: list[str]
    schema_version: str = schema

    def __post_init__(self) -> None:
        self._require_schema(self.schema_version)
        if self.primitive_id not in VERIFICATION_PRIMITIVES:
            raise ValueError(f"unknown verification primitive: {self.primitive_id}")
        _reject_authority_fields(self.parameters)
        if not self.expected_observations or not self.evidence_refs:
            raise ValueError("primitive call requires observations and evidence refs")

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "VerificationPrimitiveCall":
        return cls(**cls._values(payload))


@dataclass
class VerificationPlan(StrictContract):
    schema: ClassVar[str] = "verification-plan.v1"

    run_id: str
    candidate_id: str
    vulnerability_class: str
    evidence_package_ref: str
    primitives: list[VerificationPrimitiveCall]
    confidence: float
    rationale: str
    created_at: str = field(default_factory=utc_now)
    plan_id: str | None = None
    schema_version: str = schema

    def __post_init__(self) -> None:
        self._require_schema(self.schema_version)
        _validate_class(self.vulnerability_class)
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("verification plan confidence must be in 0..1")
        if not self.rationale.strip() or not self.evidence_package_ref:
            raise ValueError("verification plan rationale and package ref are required")
        self.primitives = [
            item if isinstance(item, VerificationPrimitiveCall) else VerificationPrimitiveCall.from_dict(item)
            for item in self.primitives
        ]
        if len(self.primitives) != 1:
            raise ValueError("phase-one verification plan requires exactly one primitive")
        allowed = PRIMITIVES_BY_CLASS[self.vulnerability_class]
        if any(item.primitive_id not in allowed for item in self.primitives):
            raise ValueError("verification plan primitive is incompatible with vulnerability class")
        if not self.plan_id:
            self.plan_id = stable_id(
                "VPLAN", self.run_id, self.candidate_id, [item.primitive_id for item in self.primitives]
            )

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "VerificationPlan":
        values = cls._values(payload)
        values["primitives"] = [
            VerificationPrimitiveCall.from_dict(item) for item in values.get("primitives", [])
        ]
        return cls(**values)


@dataclass
class InvestigationCheckpoint(StrictContract):
    schema: ClassVar[str] = "investigation-checkpoint.v1"

    run_id: str
    sequence: int
    hypothesis_states: dict[str, str]
    hypothesis_refs: list[str]
    completed_action_keys: list[str]
    step_refs: list[str]
    evidence_gate_refs: list[str]
    verification_plan_refs: list[str]
    remaining_budget: dict[str, int | float | None]
    last_evidence_package_refs: list[str] = field(default_factory=list)
    reason: str = "transition"
    created_at: str = field(default_factory=utc_now)
    checkpoint_id: str | None = None
    schema_version: str = schema

    def __post_init__(self) -> None:
        self._require_schema(self.schema_version)
        _validate_non_negative(self.sequence, "checkpoint sequence")
        if any(state not in HYPOTHESIS_STATES for state in self.hypothesis_states.values()):
            raise ValueError("checkpoint contains invalid hypothesis state")
        if not self.checkpoint_id:
            self.checkpoint_id = stable_id(
                "ICK", self.run_id, self.sequence, self.hypothesis_states, self.completed_action_keys
            )

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "InvestigationCheckpoint":
        return cls(**cls._values(payload))


@dataclass
class InvestigationSummary(StrictContract):
    schema: ClassVar[str] = "investigation-summary.v1"

    requested_mode: str
    effective_mode: str
    hypothesis_counts: dict[str, int] = field(default_factory=dict)
    evidence_gate_counts: dict[str, int] = field(default_factory=dict)
    verification_plan_refs: list[str] = field(default_factory=list)
    fallback_reason: str = ""
    degraded_reasons: list[str] = field(default_factory=list)
    investigation_budget: dict[str, Any] = field(default_factory=dict)
    checkpoint_summary: dict[str, Any] = field(default_factory=dict)
    schema_version: str = schema

    def __post_init__(self) -> None:
        self._require_schema(self.schema_version)
        if self.requested_mode != "agent-led":
            raise ValueError("investigation summary requested_mode must be agent-led")
        if self.effective_mode not in {"agent-led", "deterministic-graph", "legacy"}:
            raise ValueError("invalid investigation effective_mode")

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "InvestigationSummary":
        return cls(**cls._values(payload))


def _coerce_evidence(items: list[EvidenceItem | dict[str, Any]]) -> list[EvidenceItem]:
    return [item if isinstance(item, EvidenceItem) else EvidenceItem.from_dict(item) for item in items]


def _validate_class(value: str) -> None:
    if value not in SUPPORTED_INVESTIGATION_CLASSES:
        raise ValueError(f"unsupported investigation vulnerability class: {value}")


def _validate_relative_path(value: str) -> None:
    normalized = value.replace("\\", "/")
    if (
        not normalized
        or normalized.startswith("/")
        or ":" in normalized.split("/", 1)[0]
        or any(part in {"", ".", ".."} for part in normalized.split("/"))
    ):
        raise ValueError(f"path must be a normalized repository-relative path: {value}")


def _validate_non_negative(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def _reject_authority_fields(payload: dict[str, Any]) -> None:
    forbidden = {
        "code",
        "source_code",
        "script",
        "shell",
        "command",
        "argv",
        "executable",
        "environment",
        "env",
        "docker",
        "docker_args",
        "container",
        "network",
        "url",
        "verdict",
        "finding",
        "candidate",
        "status_override",
    }
    present: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if str(key).lower() in forbidden:
                    present.add(str(key).lower())
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(payload)
    if present:
        raise ValueError(f"untrusted authority fields are forbidden: {sorted(present)}")
