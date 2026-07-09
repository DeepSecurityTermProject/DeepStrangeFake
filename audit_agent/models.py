from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def stable_id(prefix: str, *parts: Any) -> str:
    material = "|".join(str(part) for part in parts if part is not None)
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{digest}"


def to_plain(value: Any) -> Any:
    if is_dataclass(value):
        return {item.name: to_plain(getattr(value, item.name)) for item in fields(value)}
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, list):
        return [to_plain(item) for item in value]
    if isinstance(value, tuple):
        return [to_plain(item) for item in value]
    if isinstance(value, dict):
        return {str(key): to_plain(val) for key, val in value.items()}
    return value


@dataclass
class SourceLocation:
    path: str
    start_line: int
    end_line: int
    symbol: str | None = None
    snippet: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class AuditTarget:
    source: str
    kind: str
    path: str | None = None
    url: str | None = None
    owner: str | None = None
    repo: str | None = None
    ref: str | None = None
    commit: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class Dependency:
    ecosystem: str
    name: str
    version: str | None
    manifest_path: str
    identifiers: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class AttackSurface:
    kind: str
    path: str
    start_line: int
    end_line: int
    symbol: str | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class RepositoryMetadata:
    target: AuditTarget
    root_path: str | None = None
    commit: str | None = None
    dominant_language: str | None = None
    languages: dict[str, int] = field(default_factory=dict)
    file_tree: list[str] = field(default_factory=list)
    file_categories: dict[str, str] = field(default_factory=dict)
    dependencies: list[Dependency] = field(default_factory=list)
    attack_surfaces: list[AttackSurface] = field(default_factory=list)
    generated_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class ToolObservation:
    tool_name: str
    kind: str
    message: str
    path: str | None = None
    line: int | None = None
    severity: str | None = None
    vulnerability_class: str | None = None
    evidence: str | None = None
    success: bool = True
    degraded: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class ToolResult:
    tool_name: str
    inputs: dict[str, Any]
    success: bool
    exit_status: int | None = None
    duration_ms: int = 0
    artifact_paths: list[str] = field(default_factory=list)
    observations: list[ToolObservation] = field(default_factory=list)
    message: str = ""
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id("TR", self.tool_name, self.inputs, self.message)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class VulnerabilityIntelligence:
    tool_name: str
    query: dict[str, Any]
    cve_id: str | None = None
    cwe_ids: list[str] = field(default_factory=list)
    cvss: float | None = None
    epss: float | None = None
    kev: bool | None = None
    public_poc_available: bool | None = None
    risk_score: float | None = None
    references: list[str] = field(default_factory=list)
    contextual: bool = True
    validation_evidence: bool = False
    retrieved_at: str = field(default_factory=utc_now)
    raw: dict[str, Any] = field(default_factory=dict)
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id("VI", self.tool_name, self.query, self.cve_id, self.cwe_ids)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class AgentTrace:
    agent_name: str
    reasoning_summary: str
    prompt: str = ""
    selected_context_refs: list[str] = field(default_factory=list)
    model_metadata: dict[str, Any] = field(default_factory=dict)
    raw_response: str = ""
    react_steps: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now)
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id("AT", self.agent_name, self.created_at, self.reasoning_summary)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class AgentHandoff:
    from_agent: str
    to_agent: str
    completed_work: str
    key_findings: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    attention_points: list[str] = field(default_factory=list)
    suggested_next_actions: list[str] = field(default_factory=list)
    intelligence_refs: list[str] = field(default_factory=list)
    trace_id: str | None = None
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id("HO", self.from_agent, self.to_agent, self.completed_work, self.trace_id)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class AuditPlan:
    target_id: str
    vulnerability_classes: list[str]
    validation_level: str
    budgets: dict[str, int]
    agent_order: list[str] = field(
        default_factory=lambda: ["orchestrator", "recon", "analysis", "verification"]
    )
    focus_areas: list[str] = field(default_factory=list)
    decision_source: str = "deterministic"

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class ReactResult:
    stop_reason: str
    steps: list[dict[str, Any]]
    tool_calls: int = 0

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class PromptRenderRecord:
    template_id: str
    version: str
    role: str
    variables: dict[str, Any]
    rendered: str
    output_schema: dict[str, Any] = field(default_factory=dict)
    safety_constraints: list[str] = field(default_factory=list)
    artifact_path: str | None = None
    created_at: str = field(default_factory=utc_now)
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id("PR", self.template_id, self.version, self.role, self.rendered)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class LLMRequest:
    role: str
    prompt: str
    model: str
    provider: str = "mock"
    temperature: float = 0.0
    max_tokens: int | None = None
    response_schema: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id("LR", self.role, self.model, self.prompt, self.created_at)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class LLMResponse:
    request_id: str
    provider: str
    model: str
    text: str
    parsed_json: dict[str, Any] | list[Any] | None = None
    usage: dict[str, Any] = field(default_factory=dict)
    finish_reason: str | None = None
    latency_ms: int = 0
    raw_response: dict[str, Any] = field(default_factory=dict)
    validation_errors: list[str] = field(default_factory=list)
    artifact_path: str | None = None
    created_at: str = field(default_factory=utc_now)
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id("LS", self.request_id, self.provider, self.model, self.text)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class ToolDeclaration:
    name: str
    description: str
    input_schema: dict[str, Any]
    permission_group: str
    output_kind: str = "tool-result"
    timeout_seconds: int = 30
    safety_classification: str = "read-only"
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id("TD", self.name, self.permission_group, self.output_kind)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class ToolCallRequest:
    agent: str
    tool_name: str
    arguments: dict[str, Any]
    correlation_id: str | None = None
    created_at: str = field(default_factory=utc_now)
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id("TC", self.agent, self.tool_name, self.arguments, self.created_at)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class ToolCallResult:
    request_id: str
    tool_name: str
    success: bool
    status: str
    message: str = ""
    observations: list[ToolObservation] = field(default_factory=list)
    output: dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0
    artifact_paths: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id("TCR", self.request_id, self.tool_name, self.status, self.message)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class MCPSessionRecord:
    command: list[str]
    transport: str = "stdio"
    initialized: bool = False
    server_info: dict[str, Any] = field(default_factory=dict)
    capabilities: dict[str, Any] = field(default_factory=dict)
    degraded: bool = False
    message: str = ""
    created_at: str = field(default_factory=utc_now)
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id("MS", self.transport, self.command, self.created_at)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class MCPCallRecord:
    session_id: str
    tool_name: str
    arguments: dict[str, Any]
    success: bool
    response: dict[str, Any] = field(default_factory=dict)
    degraded: bool = False
    duration_ms: int = 0
    message: str = ""
    raw_request: dict[str, Any] = field(default_factory=dict)
    raw_response: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id("MC", self.session_id, self.tool_name, self.arguments, self.created_at)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class MemoryRecord:
    namespace: str
    target_id: str
    content: str
    source_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    commit: str | None = None
    content_hash: str | None = None
    artifact_ref: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.content_hash:
            self.content_hash = hashlib.sha256(self.content.encode("utf-8")).hexdigest()
        if not self.id:
            self.id = stable_id(
                "MEM",
                self.namespace,
                self.target_id,
                self.source_path,
                self.start_line,
                self.end_line,
                self.content_hash,
            )

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class MemoryRetrieval:
    record: MemoryRecord
    score: float
    query: str
    citation: str
    snippet: str
    created_at: str = field(default_factory=utc_now)
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id("MR", self.record.id, self.query, self.score)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class MessageEnvelope:
    run_id: str
    sender: str
    recipient: str
    message_type: str
    payload: dict[str, Any]
    correlation_id: str | None = None
    causation_id: str | None = None
    artifact_refs: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=utc_now)
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id(
                "MSG",
                self.run_id,
                self.sender,
                self.recipient,
                self.message_type,
                self.timestamp,
            )

    @property
    def message_id(self) -> str:
        return self.id or ""

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class Finding:
    vulnerability_class: str
    severity: str
    confidence: float
    location: SourceLocation
    title: str
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""
    description: str = ""
    affected_function: str | None = None
    call_path: list[str] = field(default_factory=list)
    tool_refs: list[str] = field(default_factory=list)
    intelligence_refs: list[str] = field(default_factory=list)
    agent_trace_refs: list[str] = field(default_factory=list)
    handoff_refs: list[str] = field(default_factory=list)
    validation_level: str | None = None
    validation_status: str | None = None
    verification_status: str | None = None
    verification_reason: str | None = None
    verifier_decision: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    cvss: float | None = None
    epss: float | None = None
    kev: bool | None = None
    public_poc_available: bool | None = None
    risk_score: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            first_evidence = self.evidence[0] if self.evidence else ""
            self.id = stable_id(
                "F",
                self.vulnerability_class,
                self.title,
                self.location.path,
                self.location.start_line,
                self.location.end_line,
                first_evidence,
            )

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class VerificationDecision:
    finding: Finding
    decision: str
    reason: str
    confidence: float
    validation_level: str
    priority: str = "normal"
    intelligence_refs: list[str] = field(default_factory=list)
    decision_source: str = "deterministic"
    llm_confidence: float | None = None
    policy_gate: dict[str, Any] = field(default_factory=dict)
    prompt_refs: list[str] = field(default_factory=list)
    llm_response_refs: list[str] = field(default_factory=list)
    fallback_reason: str = ""
    finding_id: str | None = None
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not self.finding_id:
            self.finding_id = self.finding.id

    def to_dict(self) -> dict[str, Any]:
        data = to_plain(self)
        data["finding"] = self.finding.to_dict()
        return data


@dataclass
class PoCArtifact:
    finding_id: str
    vulnerability_class: str
    generator_id: str
    script_path: str
    command_argv: list[str]
    expected_signal: dict[str, Any]
    safety_profile: dict[str, Any] = field(default_factory=dict)
    source_refs: list[str] = field(default_factory=list)
    dataflow_trace_refs: list[str] = field(default_factory=list)
    target_file_refs: list[str] = field(default_factory=list)
    metadata_path: str | None = None
    created_at: str = field(default_factory=utc_now)
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id(
                "POC",
                self.finding_id,
                self.vulnerability_class,
                self.generator_id,
                self.script_path,
                self.expected_signal,
            )

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class SandboxRunResult:
    poc_id: str
    finding_id: str
    attempt_id: str
    status: str
    cwd: str
    argv: list[str]
    timeout_seconds: int
    environment: dict[str, Any] = field(default_factory=dict)
    exit_code: int | None = None
    timed_out: bool = False
    duration_ms: int = 0
    stdout_ref: str | None = None
    stderr_ref: str | None = None
    stdout_preview: str = ""
    stderr_preview: str = ""
    artifact_refs: list[str] = field(default_factory=list)
    policy: dict[str, Any] = field(default_factory=dict)
    message: str = ""
    started_at: str = field(default_factory=utc_now)
    finished_at: str | None = None
    metadata_path: str | None = None
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id("SBR", self.poc_id, self.attempt_id, self.status, self.started_at)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class VerificationAttempt:
    finding_id: str
    attempt_index: int
    status: str
    reason: str
    poc_ref: str | None = None
    sandbox_result_ref: str | None = None
    stdout_ref: str | None = None
    stderr_ref: str | None = None
    exit_code: int | None = None
    judge_reason: str = ""
    repair_reason: str = ""
    blocking_reason: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now)
    metadata_path: str | None = None
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id("VAT", self.finding_id, self.attempt_index, self.status, self.created_at)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class ValidationResult:
    finding_id: str
    level: str
    status: str
    command: str | None = None
    command_argv: list[str] = field(default_factory=list)
    verification_status: str | None = None
    verification_reason: str = ""
    judge_reason: str = ""
    exit_code: int | None = None
    timed_out: bool = False
    stdout_preview: str = ""
    stderr_preview: str = ""
    poc_refs: list[str] = field(default_factory=list)
    sandbox_result_refs: list[str] = field(default_factory=list)
    attempt_refs: list[str] = field(default_factory=list)
    environment: dict[str, Any] = field(default_factory=dict)
    artifacts: list[str] = field(default_factory=list)
    message: str = ""
    timestamp: str = field(default_factory=utc_now)

    @property
    def reason(self) -> str:
        return self.verification_reason or self.judge_reason or self.message

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class EvidenceChain:
    finding_id: str
    source_locations: list[SourceLocation]
    vulnerability_class: str
    analysis_rationale: str
    verification: dict[str, Any]
    validation: dict[str, Any]
    intelligence_refs: list[dict[str, Any]] = field(default_factory=list)
    artifact_refs: list[str] = field(default_factory=list)
    tool_refs: list[dict[str, Any]] = field(default_factory=list)
    dataflow_trace_refs: list[str] = field(default_factory=list)
    agent_traces: list[dict[str, Any]] = field(default_factory=list)
    handoffs: list[dict[str, Any]] = field(default_factory=list)
    call_path: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now)
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id("EC", self.finding_id, self.created_at)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class Report:
    target_metadata: dict[str, Any]
    executive_summary: dict[str, Any]
    findings: list[dict[str, Any]]
    evidence_chains: list[dict[str, Any]]
    verification_candidates: list[dict[str, Any]] = field(default_factory=list)
    runtime: dict[str, Any] = field(default_factory=dict)
    run_status: str = "completed"
    generated_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class BenchmarkTarget:
    name: str
    source: str
    ref: str | None = None
    expected_language: str | None = None
    setup_notes: str = ""
    safety_constraints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class BenchmarkSummary:
    total_projects: int
    completed_projects: int
    failed_projects: int
    candidate_count: int
    rejected_count: int
    validated_count: int
    validation_level_distribution: dict[str, int] = field(default_factory=dict)
    project_results: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)
