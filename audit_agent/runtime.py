from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .agents import AnalysisAgent, OrchestratorAgent, ReconAgent, VerificationAgent, findings_from_llm_candidates
from .config import AuditConfig
from .decisions import (
    annotate_finding_from_decision,
    apply_verification_decision_proposal,
    build_decision_from_llm_response,
    evaluate_decision_policy,
    merge_decision,
    persist_decision_bundle,
)
from .dependency_intelligence import (
    CommandMcpBatchProvider,
    DependencyIntelligenceRun,
    DependencyIntelligenceService,
    RuntimeMcpBatchProvider,
    cache_path_for_policy,
    summary_without_dependencies,
)
from .evidence import EvidenceBuilder
from .graph_artifacts import GraphArtifactRecorder
from .graph_models import GraphBudget
from .graph_policy import (
    CHECKPOINT_ACTIONS,
    GraphMutationOutcome,
    GraphMutationPolicy,
    parse_graph_decision_payload,
    translate_next_actions,
)
from .graph_replay import replay_graph
from .graph_scheduler import GraphNodeResult, GraphScheduler
from .graph_templates import (
    REQUIRED_TEMPLATE_IDS,
    build_default_template_catalog,
    build_deterministic_audit_graph,
)
from .intelligence import CveMcpAdapter
from .investigation_models import InvestigationSummary
from .llm import build_llm_client, persist_llm_artifact, validate_json_schema
from .llm_accounting import AuditedLLMGateway, LifecycleLedger, reconcile_llm_lifecycle
from .mcp_client import CveMcpClient  # Compatibility import for existing runtime patch points.
from .memory import LexicalMemoryStore, MemoryIndexer, persist_retrievals
from .message_bus import MessageBus
from .models import LLMRequest, PromptRenderRecord, ToolCallResult, stable_id, to_plain, utc_now
from .prompts import persist_prompt, render_default_prompt
from .redaction import redact_secrets, redact_text
from .reporting import ReportGenerator
from .repository import analyze_target
from .repository_acquisition import PreparedAuditTarget
from .resource_summary import build_run_resource_summary
from .storage import RunContext, RunStore, immutable_path
from .tool_protocol import ToolBudget, ToolRuntime, build_default_tool_registry
from .tools import PatternScanner
from .verification import VerificationEngine, VerificationStatus, verification_status_counts


TERMINAL_RUN_STATUSES = {"succeeded", "degraded", "failed", "cancelled"}
TERMINAL_TASK_STATUSES = {"succeeded", "failed", "skipped", "fallback"}


class CancellationToken:
    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._callbacks: dict[int, Callable[[], None]] = {}
        self._next_callback = 0

    def cancel(self) -> None:
        callbacks: list[Callable[[], None]] = []
        with self._lock:
            if self._event.is_set():
                return
            self._event.set()
            callbacks = list(self._callbacks.values())
            self._callbacks.clear()
        for callback in callbacks:
            try:
                callback()
            except Exception:
                continue

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout)

    def register(self, callback: Callable[[], None]) -> Callable[[], None]:
        with self._lock:
            if self._event.is_set():
                invoke_now = True
                callback_id = -1
            else:
                invoke_now = False
                self._next_callback += 1
                callback_id = self._next_callback
                self._callbacks[callback_id] = callback
        if invoke_now:
            callback()

        def unregister() -> None:
            with self._lock:
                self._callbacks.pop(callback_id, None)

        return unregister


class AuditCancelled(RuntimeError):
    pass


@dataclass
class TaskState:
    run_id: str
    role: str
    kind: str
    status: str = "pending"
    input_refs: list[str] = field(default_factory=list)
    output_refs: list[str] = field(default_factory=list)
    artifact_refs: list[str] = field(default_factory=list)
    message_refs: list[str] = field(default_factory=list)
    error: str = ""
    fallback_reason: str = ""
    started_at: str | None = None
    finished_at: str | None = None
    created_at: str = field(default_factory=utc_now)
    id: str | None = None
    graph_node_id: str | None = None
    graph_revision: int | None = None
    dependency_refs: list[str] = field(default_factory=list)
    attempt: int = 0
    lineage: dict[str, Any] = field(default_factory=dict)
    transition_refs: list[str] = field(default_factory=list)
    correlation_refs: list[str] = field(default_factory=list)
    causation_refs: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id(
                "TSK",
                self.run_id,
                self.role,
                self.kind,
                self.graph_node_id,
                self.graph_revision,
                self.attempt,
                self.created_at,
            )

    def mark_running(self, message_ref: str | None = None) -> None:
        self.status = "running"
        self.started_at = self.started_at or utc_now()
        self._append_message(message_ref)

    def mark_succeeded(self, output_refs: list[str] | None = None, message_ref: str | None = None) -> None:
        self.status = "succeeded"
        self.finished_at = utc_now()
        for ref in output_refs or []:
            self._append_unique(self.output_refs, ref)
        self._append_message(message_ref)

    def mark_failed(self, error: str, message_ref: str | None = None) -> None:
        self.status = "failed"
        self.error = error
        self.finished_at = utc_now()
        self._append_message(message_ref)

    def mark_skipped(self, reason: str, message_ref: str | None = None) -> None:
        self.status = "skipped"
        self.fallback_reason = reason
        self.finished_at = utc_now()
        self._append_message(message_ref)

    def mark_fallback(self, reason: str, message_ref: str | None = None) -> None:
        self.status = "fallback"
        self.fallback_reason = reason
        self._append_message(message_ref)

    def record_artifact(self, ref: str | Path | None) -> None:
        if ref:
            self._append_unique(self.artifact_refs, str(ref))

    def record_message(self, ref: str | None) -> None:
        self._append_message(ref)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TaskState":
        allowed = set(cls.__dataclass_fields__)
        return cls(**{key: value for key, value in payload.items() if key in allowed})

    def _append_message(self, ref: str | None) -> None:
        if ref:
            self._append_unique(self.message_refs, ref)

    @staticmethod
    def _append_unique(values: list[str], value: str) -> None:
        if value and value not in values:
            values.append(value)


@dataclass
class RunState:
    run_id: str
    target: str
    status: str = "pending"
    config_summary: dict[str, Any] = field(default_factory=dict)
    tasks: list[TaskState] = field(default_factory=list)
    artifact_refs: list[str] = field(default_factory=list)
    message_refs: list[str] = field(default_factory=list)
    final_summary: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    started_at: str | None = None
    finished_at: str | None = None
    created_at: str = field(default_factory=utc_now)
    graph_mode: str = "legacy"
    initial_graph_ref: str | None = None
    active_graph_ref: str | None = None
    final_graph_ref: str | None = None
    graph_revision_refs: list[str] = field(default_factory=list)
    graph_transition_refs: list[str] = field(default_factory=list)
    mutation_refs: list[str] = field(default_factory=list)
    checkpoint_counts: dict[str, int] = field(default_factory=dict)
    execution_path: list[str] = field(default_factory=list)
    graph_fallback_reason: str = ""
    llm_accounting: dict[str, Any] = field(default_factory=dict)
    requested_mode: str = "legacy"
    effective_mode: str = "legacy"
    fallback_reason: str = ""
    degraded_reasons: list[str] = field(default_factory=list)
    hypothesis_counts: dict[str, int] = field(default_factory=dict)
    evidence_gate_counts: dict[str, int] = field(default_factory=dict)
    verification_plan_refs: list[str] = field(default_factory=list)
    investigation_budget: dict[str, Any] = field(default_factory=dict)
    checkpoint_summary: dict[str, Any] = field(default_factory=dict)

    def mark_running(self, message_ref: str | None = None) -> None:
        self.status = "running"
        self.started_at = self.started_at or utc_now()
        self.record_message(message_ref)

    def mark_succeeded(self, summary: dict[str, Any] | None = None, message_ref: str | None = None) -> None:
        self.status = "succeeded"
        self.finished_at = utc_now()
        self.final_summary = summary or {}
        self.record_message(message_ref)

    def mark_failed(self, error: str, summary: dict[str, Any] | None = None, message_ref: str | None = None) -> None:
        self.status = "failed"
        self.error = error
        self.finished_at = utc_now()
        self.final_summary = summary or {}
        self.record_message(message_ref)

    def mark_degraded(
        self,
        summary: dict[str, Any] | None = None,
        reasons: list[str] | None = None,
        message_ref: str | None = None,
    ) -> None:
        self.status = "degraded"
        self.finished_at = utc_now()
        self.final_summary = summary or {}
        for reason in reasons or []:
            if reason and reason not in self.degraded_reasons:
                self.degraded_reasons.append(reason)
        self.record_message(message_ref)

    def mark_cancelled(
        self,
        summary: dict[str, Any] | None = None,
        message_ref: str | None = None,
    ) -> None:
        self.status = "cancelled"
        self.finished_at = utc_now()
        self.final_summary = summary or {}
        self.record_message(message_ref)

    def add_task(self, task: TaskState) -> None:
        if all(existing.id != task.id for existing in self.tasks):
            self.tasks.append(task)

    def record_artifact(self, ref: str | Path | None) -> None:
        if ref:
            self._append_unique(self.artifact_refs, str(ref))

    def record_message(self, ref: str | None) -> None:
        if ref:
            self._append_unique(self.message_refs, ref)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RunState":
        allowed = set(cls.__dataclass_fields__)
        values = {key: value for key, value in payload.items() if key in allowed and key != "tasks"}
        values["tasks"] = [TaskState.from_dict(item) for item in payload.get("tasks", [])]
        return cls(**values)

    @staticmethod
    def _append_unique(values: list[str], value: str) -> None:
        if value and value not in values:
            values.append(value)


@dataclass
class AgentInvocation:
    role: str
    run_state: RunState
    task_state: TaskState
    inputs: dict[str, Any]
    config: AuditConfig | None = None
    services: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "run_id": self.run_state.run_id,
            "task_id": self.task_state.id,
            "inputs": to_plain(self.inputs),
        }


@dataclass
class AgentOutput:
    role: str
    payload: dict[str, Any] = field(default_factory=dict)
    artifact_refs: list[str] = field(default_factory=list)
    message_refs: list[str] = field(default_factory=list)
    next_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


AgentHandler = Callable[[AgentInvocation], AgentOutput]


@dataclass
class AgentRegistration:
    role: str
    handler: AgentHandler
    description: str = ""
    required: bool = True


class AgentRegistry:
    def __init__(self):
        self._agents: dict[str, AgentRegistration] = {}

    def register(self, role: str, handler: AgentHandler, description: str = "", required: bool = True) -> None:
        if role in self._agents:
            raise ValueError(f"Duplicate agent role: {role}")
        self._agents[role] = AgentRegistration(role=role, handler=handler, description=description, required=required)

    def get(self, role: str) -> AgentRegistration:
        try:
            return self._agents[role]
        except KeyError as exc:
            raise KeyError(f"Agent role is not registered: {role}") from exc

    def validate_required(self, roles: list[str] | tuple[str, ...]) -> list[str]:
        return [role for role in roles if role not in self._agents]

    def roles(self) -> list[str]:
        return sorted(self._agents)


class ArtifactStore:
    def __init__(
        self,
        run: RunContext,
        bus: MessageBus | None = None,
        run_state: RunState | None = None,
        secret_values: list[str] | None = None,
    ):
        self.run = run
        self.bus = bus
        self.run_state = run_state
        self.secret_values = [item for item in (secret_values or []) if item]

    def write_json(
        self,
        category: str,
        name: str,
        payload: Any,
        task_state: TaskState | None = None,
        redact: bool = True,
    ) -> str:
        value = redact_secrets(to_plain(payload), self.secret_values) if redact else to_plain(payload)
        path = self.run.write_json_artifact(category, name, value)
        self._record_artifact(path, category, task_state)
        return str(path)

    def write_text(self, category: str, name: str, content: str, task_state: TaskState | None = None) -> str:
        target_dir = self.run.path / category
        target_dir.mkdir(parents=True, exist_ok=True)
        path = immutable_path(target_dir / name)
        path.write_text(redact_text(content, self.secret_values), encoding="utf-8")
        self._record_artifact(path, category, task_state)
        return str(path)

    def write_prompt(self, record, task_state: TaskState | None = None) -> str:
        path = persist_prompt(self.run.path / "prompts", record, self.secret_values)
        self._record_artifact(path, "prompts", task_state)
        return str(path)

    def write_llm(self, request: LLMRequest, response, task_state: TaskState | None = None) -> str:
        path = persist_llm_artifact(self.run.path / "llm", request, response, self.secret_values)
        self._record_artifact(path, "llm", task_state)
        return str(path)

    def write_decision(self, role: str, proposal, gate=None, merged=None, task_state: TaskState | None = None) -> str:
        path = persist_decision_bundle(
            self.run.path / "decisions",
            role,
            proposal,
            gate,
            merged,
            self.secret_values,
        )
        self._record_artifact(path, "decisions", task_state)
        return str(path)

    def persist_state(self, task_state: TaskState | None = None) -> str:
        if not self.run_state:
            return ""
        path = self.run.write_json_artifact("runtime_state", "state.json", self.run_state.to_dict())
        if task_state:
            task_state.record_artifact(path)
        self.run_state.record_artifact(path)
        return str(path)

    def _record_artifact(self, path: Path, category: str, task_state: TaskState | None) -> None:
        ref = str(path)
        if task_state:
            task_state.record_artifact(ref)
        if self.run_state:
            self.run_state.record_artifact(ref)
        if self.bus:
            msg = self.bus.publish(
                "artifact-store",
                "runtime",
                "runtime.artifact",
                {
                    "category": category,
                    "path": ref,
                    "task_id": task_state.id if task_state else None,
                    "role": task_state.role if task_state else None,
                },
                artifact_refs=[ref],
            )
            if task_state:
                task_state.record_message(msg.message_id)
            if self.run_state:
                self.run_state.record_message(msg.message_id)


class ToolBroker:
    def __init__(
        self,
        config: AuditConfig,
        artifacts: ArtifactStore,
        bus: MessageBus | None = None,
        runtime: ToolRuntime | None = None,
    ):
        self.config = config
        self.artifacts = artifacts
        self.bus = bus
        budget = ToolBudget(
            per_agent=config.llm_decisions.tool_budget_per_role or config.tools.per_agent_budgets,
            total_limit=config.audit_scope.tool_budget,
        )
        self.runtime = runtime or ToolRuntime(
            build_default_tool_registry(config),
            artifact_root=artifacts.run.path / "tool_outputs" / "broker",
            budget=budget,
        )

    def dispatch(
        self,
        role: str,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        metadata=None,
        memory_store=None,
        mcp_client=None,
        task_state: TaskState | None = None,
    ) -> ToolCallResult:
        materialized = self._materialize(tool_name, dict(arguments or {}), metadata, memory_store, mcp_client)
        if materialized is None:
            result = ToolCallResult(
                request_id="",
                tool_name=tool_name,
                success=False,
                status="denied",
                message=f"Tool {tool_name} requires unavailable runtime context",
            )
        else:
            result = self.runtime.call(role, tool_name, materialized)
        for artifact_path in result.artifact_paths:
            if task_state:
                task_state.record_artifact(artifact_path)
            if self.artifacts.run_state:
                self.artifacts.run_state.record_artifact(artifact_path)
        if task_state:
            task_state.output_refs.append(result.id or "")
        self._publish_result(role, result, task_state)
        return result

    def _materialize(self, tool_name: str, arguments: dict[str, Any], metadata, memory_store, mcp_client):
        if tool_name in {"pattern-scan", "dataflow-scan", "repository-search", "source-context"}:
            if metadata is None:
                return None
            arguments["metadata"] = metadata
        if tool_name == "dataflow-scan" and "artifact_root" not in arguments:
            arguments["artifact_root"] = self.artifacts.run.path / "dataflow" / "traces"
        if tool_name == "repository-search":
            arguments.setdefault("pattern", "os\\.system|subprocess|SELECT|secret")
        if tool_name == "source-context":
            if metadata is None:
                return None
            arguments.setdefault("path", metadata.file_tree[0] if metadata.file_tree else "")
            arguments.setdefault("start_line", 1)
            arguments.setdefault("end_line", 20)
        if tool_name == "memory.retrieve":
            if memory_store is None:
                return None
            arguments["store"] = memory_store
            arguments.setdefault("query", "request args os.system select secret")
        if tool_name == "mcp.cve.lookup":
            if mcp_client is None:
                return None
            arguments["client"] = mcp_client
        return arguments

    def _publish_result(self, role: str, result: ToolCallResult, task_state: TaskState | None) -> None:
        if not self.bus:
            return
        event_type = "runtime.tool" if result.success else "runtime.tool.denied"
        msg = self.bus.publish(
            "tool-broker",
            role,
            event_type,
            {
                "role": role,
                "task_id": task_state.id if task_state else None,
                "tool": result.tool_name,
                "status": result.status,
                "success": result.success,
                "message": result.message,
            },
            artifact_refs=result.artifact_paths,
        )
        if task_state:
            task_state.record_message(msg.message_id)
        if self.artifacts.run_state:
            self.artifacts.run_state.record_message(msg.message_id)


def _run_dependency_intelligence(
    config: AuditConfig,
    metadata,
    run_dir: Path,
) -> DependencyIntelligenceRun:
    settings = config.dependency_intelligence
    if not settings.enabled:
        service = DependencyIntelligenceService(
            None,
            batch_size=settings.batch_size,
            query_budget=0,
            cache_path=None,
            cache_ttl_seconds=settings.cache_ttl_seconds,
        )
        return service.scan(metadata.dependencies)

    provider_budget = (
        config.mcp.query_budget
        if config.runtime_enabled
        else config.cve_mcp.query_budget
    )
    query_budget = min(
        settings.query_budget,
        config.audit_scope.cve_query_budget,
        provider_budget,
    )
    cache_path = cache_path_for_policy(
        settings.cache_policy,
        settings.cache_path,
        run_dir,
    )
    provider = None
    if config.runtime_enabled and config.mcp.enabled:
        provider = RuntimeMcpBatchProvider(
            config.mcp.command,
            config.mcp.timeout_seconds,
            query_budget,
            allowed_tools=(
                config.mcp.allowed_tools
                or config.integration.safe_cve_mcp_tools
            ),
            cwd=config.mcp.working_dir,
            env=config.mcp.env,
        )
    elif not config.runtime_enabled and config.cve_mcp.enabled:
        provider = CommandMcpBatchProvider(
            CveMcpAdapter(
                enabled=True,
                command=config.cve_mcp.command,
                endpoint=config.cve_mcp.endpoint,
                env=config.cve_mcp.env,
                timeout=config.cve_mcp.timeout_seconds,
                query_budget=query_budget,
                degraded_mode=config.cve_mcp.degraded_mode,
            )
        )

    service = DependencyIntelligenceService(
        provider,
        batch_size=settings.batch_size,
        query_budget=query_budget,
        cache_path=cache_path,
        cache_ttl_seconds=settings.cache_ttl_seconds,
    )
    if isinstance(provider, RuntimeMcpBatchProvider):
        with provider:
            return service.scan(metadata.dependencies)
    return service.scan(metadata.dependencies)


def _patch_agent_led_fallback_artifacts(run_dir: Path, summary: dict[str, Any]) -> None:
    """Add agent-led fallback metadata without removing prior graph fields."""
    investigation = InvestigationSummary(
        requested_mode="agent-led",
        effective_mode="deterministic-graph",
        fallback_reason=str(summary.get("fallback_reason") or ""),
        degraded_reasons=list(summary.get("degraded_reasons") or []),
        investigation_budget={},
        checkpoint_summary={"count": 0, "latest_ref": None},
    ).to_dict()
    report_path = run_dir / "reports" / "report.json"
    if report_path.is_file():
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        runtime = dict(payload.get("runtime") or {})
        runtime.update({"status": "degraded", "investigation": investigation})
        payload["runtime"] = runtime
        payload["run_status"] = "degraded"
        temporary = report_path.with_name(f".{report_path.name}.tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(report_path)
    resource_ref = summary.get("resource_summary_ref")
    if resource_ref and Path(resource_ref).is_file():
        resource_path = Path(resource_ref)
        payload = json.loads(resource_path.read_text(encoding="utf-8"))
        payload["terminal_status"] = "degraded"
        payload["investigation"] = investigation
        temporary = resource_path.with_name(f".{resource_path.name}.tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(resource_path)


class AgentRuntime:
    def __init__(
        self,
        config: AuditConfig | None = None,
        output_dir: str | Path = "runs",
        registry: AgentRegistry | None = None,
        progress_callback=None,
        cancellation_token: CancellationToken | None = None,
        resume_run_id: str | None = None,
    ):
        self.config = config or AuditConfig.default()
        self.output_dir = output_dir
        self.registry = registry or default_agent_registry(self.config)
        self.progress_callback = progress_callback
        self.cancellation_token = cancellation_token or CancellationToken()
        self.resume_run_id = resume_run_id
        self.run: RunContext | None = None
        self.run_state: RunState | None = None
        self.artifacts: ArtifactStore | None = None
        self.bus: MessageBus | None = None
        self.tool_broker: ToolBroker | None = None
        self.llm_gateway: AuditedLLMGateway | None = None
        self.runtime_refs: dict[str, list[str]] = {
            "prompt_refs": [],
            "llm_response_refs": [],
            "message_refs": [],
            "memory_refs": [],
            "mcp_call_refs": [],
            "tool_call_refs": [],
            "decision_refs": [],
            "runtime_task_refs": [],
            "llm_lifecycle_refs": [],
        }

    def cancel(self) -> None:
        self.cancellation_token.cancel()

    def _emit_phase(self, phase: str) -> None:
        if self.progress_callback:
            self.progress_callback(phase)

    def run_audit(
        self, target: str, prepared_target: PreparedAuditTarget | None = None
    ) -> dict[str, Any]:
        if self.config.graph.mode == "agent-led":
            return self._run_agent_led_audit(target, prepared_target)
        if self.config.graph.mode != "legacy":
            return self._run_graph_audit(target, prepared_target)
        return self._run_legacy_audit(target, prepared_target)

    def _run_agent_led_audit(
        self, target: str, prepared_target: PreparedAuditTarget | None = None
    ) -> dict[str, Any]:
        from .agent_led_runtime import AgentLedInvestigationCoordinator, provider_is_usable

        if not provider_is_usable(self.config):
            requested_mode = self.config.graph.mode
            requested_runtime = self.config.runtime_enabled
            requested_decisions = self.config.llm_decisions.enabled
            self.config.graph.mode = "deterministic-graph"
            self.config.runtime_enabled = False
            self.config.llm_decisions.enabled = False
            try:
                summary = self._run_graph_audit(target, prepared_target)
            finally:
                self.config.graph.mode = requested_mode
                self.config.runtime_enabled = requested_runtime
                self.config.llm_decisions.enabled = requested_decisions
            reason = "agent-led-provider-unavailable-or-mock-not-authorized"
            summary.update(
                {
                    "status": "degraded",
                    "requested_mode": "agent-led",
                    "effective_mode": "deterministic-graph",
                    "fallback_reason": reason,
                    "degraded_reasons": [reason],
                }
            )
            if self.run_state and self.artifacts:
                self.run_state.requested_mode = "agent-led"
                self.run_state.effective_mode = "deterministic-graph"
                self.run_state.fallback_reason = reason
                self.run_state.mark_degraded(summary, [reason])
                self.artifacts.persist_state()
                _patch_agent_led_fallback_artifacts(self.run.path, summary)
            return summary
        return AgentLedInvestigationCoordinator(self, target, prepared_target).run()

    def _run_graph_audit(
        self, target: str, prepared_target: PreparedAuditTarget | None = None
    ) -> dict[str, Any]:
        return _GraphAuditExecution(self, target, prepared_target).run()

    def _run_legacy_audit(
        self, target: str, prepared_target: PreparedAuditTarget | None = None
    ) -> dict[str, Any]:
        config = self.config
        metadata = (
            prepared_target.metadata
            if prepared_target is not None
            else analyze_target(target, audit_scope=config.audit_scope)
        )
        store = RunStore(self.output_dir)
        self.run = store.create_run(metadata.target.repo or Path(metadata.target.path or target).name)
        self.run_state = RunState(
            run_id=self.run.run_id,
            target=target,
            config_summary={
                "runtime_enabled": config.runtime_enabled,
                "llm_provider": config.llm.provider,
                "llm_decisions": config.llm_decisions.enabled,
                "poc_repair": config.poc_repair.enabled,
                "poc_repair_source": config.poc_repair.effective_source,
            },
        )
        self.bus = self._build_bus(target)
        self.run_state.mark_running()
        self.artifacts = ArtifactStore(
            self.run,
            bus=self.bus,
            run_state=self.run_state,
            secret_values=[os.environ.get(config.llm.api_key_env, "")],
        )
        self.tool_broker = ToolBroker(config, self.artifacts, bus=self.bus)
        if prepared_target and prepared_target.acquisition:
            acquisition_path = self.artifacts.write_json(
                "metadata", "acquisition.json", prepared_target.acquisition.to_dict()
            )
            metadata.target.acquisition_ref = acquisition_path
        self.artifacts.write_json("metadata", "repository.json", metadata.to_dict())
        llm_client = self._build_audited_llm_client() if config.runtime_enabled else None

        plan_task = self._start_task("orchestrator", "agent")
        plan_output = self._invoke_agent("orchestrator", plan_task, {"metadata": metadata})
        plan = plan_output.payload["plan"]
        if config.runtime_enabled and llm_client:
            response, _prompt_path, _llm_path = self._run_llm_role(
                plan_task,
                llm_client,
                "orchestrator",
                "orchestrator.plan",
                {"repository_summary": metadata.to_dict(), "audit_scope": config.audit_scope.vulnerability_classes},
            )
            if self._decision_enabled("orchestrator"):
                proposal = build_decision_from_llm_response(
                    "orchestrator",
                    response.parsed_json,
                    prompt_ref=self.runtime_refs["prompt_refs"][-1] if self.runtime_refs["prompt_refs"] else None,
                    llm_response_ref=response.id,
                    provider=response.provider,
                    model=response.model,
                    provider_metadata=response.raw_response,
                    raw_output=response.text,
                    repair_enabled=config.llm_decisions.repair_enabled,
                )
                self._correlate_llm_proposal(proposal, response)
                gate = evaluate_decision_policy("orchestrator", proposal, config)
                plan = self._apply_orchestrator_proposal(plan, proposal, gate)
                merged = merge_decision(
                    "orchestrator",
                    {"plan": OrchestratorAgent(config).plan(metadata).to_dict()},
                    proposal,
                    gate.status,
                    gate.reasons,
                    final_output={"plan": plan.to_dict()},
                )
                merged.policy_gate_id = gate.id
                self._finalize_decision_accounting(proposal, gate, merged)
                path = self.artifacts.write_decision("orchestrator", proposal, gate, merged, plan_task)
                self._publish_decision_events("orchestrator", proposal, gate, merged, [path], plan_task)
        plan_path = self.artifacts.write_json("metadata", "plan.json", plan.to_dict(), plan_task)
        if self.bus:
            msg = self.bus.publish("orchestrator", "pipeline", "agent.plan", plan.to_dict(), artifact_refs=[plan_path])
            self._record_message(msg.message_id, plan_task)
        self._finish_task(plan_task, output_refs=[plan_path])

        memory_store = None
        memory_retrievals = []
        if config.runtime_enabled and config.memory.enabled and metadata.root_path:
            memory_task = self._start_task("memory", "service")
            memory_store = LexicalMemoryStore(self.run.path / "memory")
            memory_records = MemoryIndexer(memory_store, config.memory).index_repository(metadata)
            memory_retrievals = memory_store.retrieve("request args os.system select query secret", limit=5)
            retrieval_path = persist_retrievals(self.run.path / "memory", memory_retrievals, "initial-retrieval")
            memory_task.record_artifact(retrieval_path)
            self.run_state.record_artifact(retrieval_path)
            self.runtime_refs["memory_refs"].extend([item.record.id or "" for item in memory_retrievals])
            if self.bus:
                msg = self.bus.publish(
                    "memory",
                    "analysis",
                    "memory.retrieved",
                    {"record_count": len(memory_records), "retrieval_count": len(memory_retrievals), "task_id": memory_task.id},
                    artifact_refs=[str(retrieval_path)],
                )
                self._record_message(msg.message_id, memory_task)
            self._finish_task(memory_task, output_refs=[str(retrieval_path)])

        self._emit_phase("scanning")
        scan_task = self._start_task("analysis", "tool")
        dataflow_result = self.tool_broker.dispatch("analysis", "dataflow-scan", {}, metadata=metadata, task_state=scan_task)
        dataflow_path = self.artifacts.write_json("tool_outputs", "dataflow-scan.json", dataflow_result.to_dict(), scan_task)
        pattern_result = self.tool_broker.dispatch("analysis", "pattern-scan", {}, metadata=metadata, task_state=scan_task)
        pattern_path = self.artifacts.write_json("tool_outputs", "pattern-scan.json", pattern_result.to_dict(), scan_task)
        scan_results = [dataflow_result, pattern_result]
        scan_result = dataflow_result if dataflow_result.observations else pattern_result
        if self.bus:
            for result, path in ((dataflow_result, dataflow_path), (pattern_result, pattern_path)):
                msg = self.bus.publish(
                    "tool-protocol",
                    "analysis",
                    "tool.result",
                    {"tool": result.tool_name, "observations": len(result.observations), "task_id": scan_task.id},
                    artifact_refs=[path],
                )
                self._record_message(msg.message_id, scan_task)
        self._finish_task(scan_task, output_refs=[result.id or "" for result in scan_results])

        intelligence = []
        dependency_intelligence_summary = summary_without_dependencies()
        if metadata.dependencies:
            mcp_task = self._start_task("recon", "mcp-intelligence")
            dependency_run = _run_dependency_intelligence(config, metadata, self.run.path)
            intelligence.extend(dependency_run.intelligence)
            dependency_intelligence_summary = dependency_run.summary
            records_path = self.artifacts.write_json(
                "mcp" if config.runtime_enabled else "intelligence",
                "dependency-intelligence-records.json",
                [item.to_dict() for item in intelligence],
                mcp_task,
            )
            summary_path = self.artifacts.write_json(
                "intelligence",
                "dependency-intelligence-summary.v1.json",
                dependency_run.summary,
                mcp_task,
            )
            tool_path = self.artifacts.write_json(
                "tool_outputs",
                "dependency-intelligence.json",
                dependency_run.tool_result.to_dict(),
                mcp_task,
            )
            dependency_run.tool_result.artifact_paths.extend(
                [records_path, summary_path, tool_path]
            )
            scan_results.append(dependency_run.tool_result)
            self.runtime_refs["mcp_call_refs"].extend(
                item.id or "" for item in intelligence
            )
            if self.bus:
                msg = self.bus.publish(
                    "mcp",
                    "recon",
                    "mcp.dependency-batches",
                    {
                        "input_dependency_count": dependency_run.summary["input_dependency_count"],
                        "unique_dependency_count": dependency_run.summary["unique_dependency_count"],
                        "queries_used": dependency_run.summary["queries_used"],
                        "cache_hits": dependency_run.summary["cache_hits"],
                        "budget_exhausted_count": dependency_run.summary["budget_exhausted_count"],
                        "task_id": mcp_task.id,
                    },
                    artifact_refs=[records_path, summary_path, tool_path],
                )
                self._record_message(msg.message_id, mcp_task)
            self._finish_task(
                mcp_task,
                output_refs=[
                    dependency_run.tool_result.id or "",
                    *[item.id or "" for item in intelligence],
                ],
            )

        recon_task = self._start_task("recon", "agent")
        recon_output = self._invoke_agent("recon", recon_task, {"metadata": metadata, "intelligence": intelligence})
        recon = recon_output.payload["result"]
        self.artifacts.write_json("agent_traces", "recon.json", recon.trace.to_dict(), recon_task)
        self.artifacts.write_json("handoffs", "recon-to-analysis.json", recon.handoff.to_dict(), recon_task)
        if config.runtime_enabled and llm_client:
            response, _prompt_path, _llm_path = self._run_llm_role(
                recon_task,
                llm_client,
                "recon",
                "recon.summary",
                {
                    "repository_metadata": metadata.to_dict(),
                    "intelligence_context": [item.to_dict() for item in intelligence],
                    "memory_context": [item.to_dict() for item in memory_retrievals],
                },
            )
            if self._decision_enabled("recon"):
                proposal = build_decision_from_llm_response(
                    "recon",
                    response.parsed_json,
                    prompt_ref=self.runtime_refs["prompt_refs"][-1] if self.runtime_refs["prompt_refs"] else None,
                    llm_response_ref=response.id,
                    provider=response.provider,
                    model=response.model,
                    provider_metadata=response.raw_response,
                    raw_output=response.text,
                    repair_enabled=config.llm_decisions.repair_enabled,
                )
                self._correlate_llm_proposal(proposal, response)
                gate = evaluate_decision_policy("recon", proposal, config)
                if gate.status == "accepted":
                    self._apply_recon_proposal(recon, proposal)
                    self._dispatch_recon_tool_requests(recon_task, proposal, metadata, memory_store)
                    self.artifacts.write_json("agent_traces", "recon.json", recon.trace.to_dict(), recon_task)
                    self.artifacts.write_json("handoffs", "recon-to-analysis.json", recon.handoff.to_dict(), recon_task)
                merged = merge_decision(
                    "recon",
                    {"high_risk_areas": recon.payload.get("high_risk_areas", [])},
                    proposal,
                    gate.status,
                    gate.reasons,
                    final_output={"handoff": recon.handoff.to_dict(), "payload": recon.payload},
                )
                merged.policy_gate_id = gate.id
                self._finalize_decision_accounting(proposal, gate, merged)
                path = self.artifacts.write_decision("recon", proposal, gate, merged, recon_task)
                self._publish_decision_events("recon", proposal, gate, merged, [path], recon_task)
            elif self.bus:
                msg = self.bus.publish("recon", "analysis", "agent.handoff", recon.handoff.to_dict(), artifact_refs=[_prompt_path, _llm_path])
                self._record_message(msg.message_id, recon_task)
        self._finish_task(recon_task, output_refs=[recon.handoff.id or ""])

        analysis_task = self._start_task("analysis", "agent")
        analysis_output = self._invoke_agent(
            "analysis",
            analysis_task,
            {"metadata": metadata, "recon_handoff": recon.handoff, "tool_results": scan_results, "intelligence": intelligence},
        )
        analysis = analysis_output.payload["result"]
        self.artifacts.write_json("agent_traces", "analysis.json", analysis.trace.to_dict(), analysis_task)
        self.artifacts.write_json("handoffs", "analysis-to-verification.json", analysis.handoff.to_dict(), analysis_task)
        candidates = analysis.payload["candidates"]
        deterministic_candidate_count = len(candidates)
        if config.runtime_enabled and llm_client:
            response, _prompt_path, _llm_path = self._run_llm_role(
                analysis_task,
                llm_client,
                "analysis",
                "analysis.candidates",
                {
                    "repository_summary": metadata.to_dict(),
                    "tool_outputs": [result.to_dict() for result in scan_results],
                    "memory_context": [item.to_dict() for item in memory_retrievals],
                    "intelligence_context": [item.to_dict() for item in intelligence],
                },
            )
            if self._decision_enabled("analysis"):
                proposal = build_decision_from_llm_response(
                    "analysis",
                    response.parsed_json,
                    prompt_ref=self.runtime_refs["prompt_refs"][-1] if self.runtime_refs["prompt_refs"] else None,
                    llm_response_ref=response.id,
                    provider=response.provider,
                    model=response.model,
                    provider_metadata=response.raw_response,
                    raw_output=response.text,
                    repair_enabled=config.llm_decisions.repair_enabled,
                )
                self._correlate_llm_proposal(proposal, response)
                gate = evaluate_decision_policy("analysis", proposal, config)
                llm_candidates = []
                if gate.status == "accepted":
                    payload = dict(response.parsed_json or {})
                    if proposal.selected_actions:
                        payload["candidates"] = proposal.selected_actions
                    llm_candidates = findings_from_llm_candidates(payload, metadata)
                    for finding in llm_candidates:
                        annotate_finding_from_decision(finding, proposal, gate, None)
                        finding.metadata["decision_source"] = "llm"
                        finding.metadata.setdefault("prompt_refs", []).append(proposal.prompt_ref or "")
                        finding.metadata.setdefault("llm_response_refs", []).append(proposal.llm_response_ref or "")
                        finding.metadata.setdefault("memory_refs", []).extend(self.runtime_refs["memory_refs"])
                    candidates.extend(llm_candidates)
                merged = merge_decision(
                    "analysis",
                    {"candidate_count": deterministic_candidate_count},
                    proposal,
                    gate.status,
                    gate.reasons,
                    final_output={"candidate_count": len(candidates), "llm_candidate_count": len(llm_candidates)},
                )
                merged.policy_gate_id = gate.id
                for finding in candidates:
                    if "decision_source" not in finding.metadata:
                        annotate_finding_from_decision(finding, proposal, gate, merged)
                        finding.metadata.setdefault("runtime_task_refs", []).append(analysis_task.id or "")
                self._finalize_decision_accounting(proposal, gate, merged)
                path = self.artifacts.write_decision("analysis", proposal, gate, merged, analysis_task)
                self._publish_decision_events("analysis", proposal, gate, merged, [path], analysis_task)
            else:
                llm_candidates = findings_from_llm_candidates(response.parsed_json or {}, metadata)
                for finding in llm_candidates:
                    finding.metadata.setdefault("prompt_refs", []).append(self.runtime_refs["prompt_refs"][-1] if self.runtime_refs["prompt_refs"] else "")
                    finding.metadata.setdefault("llm_response_refs", []).append(response.id or "")
                    finding.metadata.setdefault("memory_refs", []).extend(self.runtime_refs["memory_refs"])
                candidates.extend(llm_candidates)
                if self.bus:
                    msg = self.bus.publish("analysis", "verification", "agent.handoff", analysis.handoff.to_dict(), artifact_refs=[_prompt_path, _llm_path])
                    self._record_message(msg.message_id, analysis_task)
        self.artifacts.write_json("findings", "candidates.json", [finding.to_dict() for finding in candidates], analysis_task)
        self._finish_task(analysis_task, output_refs=[finding.id or "" for finding in candidates])

        verification_task = self._start_task("verification", "agent")
        verification_output = self._invoke_agent(
            "verification",
            verification_task,
            {"candidates": candidates, "metadata": metadata, "intelligence": intelligence},
        )
        verification = verification_output.payload["result"]
        self.artifacts.write_json("agent_traces", "verification.json", verification.trace.to_dict(), verification_task)
        self.artifacts.write_json("handoffs", "verification-to-reporting.json", verification.handoff.to_dict(), verification_task)
        if config.runtime_enabled and llm_client:
            response, _prompt_path, _llm_path = self._run_llm_role(
                verification_task,
                llm_client,
                "verification",
                "verification.decision",
                {
                    "candidate_json": [finding.to_dict() for finding in candidates],
                    "evidence_summary": [result.to_dict() for result in scan_results],
                },
            )
            if self._decision_enabled("verification"):
                proposal = build_decision_from_llm_response(
                    "verification",
                    response.parsed_json,
                    prompt_ref=self.runtime_refs["prompt_refs"][-1] if self.runtime_refs["prompt_refs"] else None,
                    llm_response_ref=response.id,
                    provider=response.provider,
                    model=response.model,
                    provider_metadata=response.raw_response,
                    raw_output=response.text,
                    repair_enabled=config.llm_decisions.repair_enabled,
                )
                self._correlate_llm_proposal(proposal, response)
                decisions, gate, merged = apply_verification_decision_proposal(
                    candidates,
                    verification.decisions,
                    proposal,
                    config,
                )
                verification.decisions = decisions
                for decision in decisions:
                    annotate_finding_from_decision(decision.finding, proposal, gate, merged)
                    decision.finding.metadata["decision_source"] = decision.decision_source
                    decision.finding.metadata.setdefault("runtime_task_refs", []).append(verification_task.id or "")
                    if decision.llm_confidence is not None:
                        decision.finding.metadata["llm_confidence"] = decision.llm_confidence
                self._finalize_decision_accounting(proposal, gate, merged)
                path = self.artifacts.write_decision("verification", proposal, gate, merged, verification_task)
                self._publish_decision_events("verification", proposal, gate, merged, [path], verification_task)
                self.artifacts.write_json("findings", "verification-decisions.json", [decision.to_dict() for decision in decisions], verification_task)
            elif self.bus:
                msg = self.bus.publish("verification", "reporting", "agent.handoff", verification.handoff.to_dict(), artifact_refs=[_prompt_path, _llm_path])
                self._record_message(msg.message_id, verification_task)
        decisions = verification.decisions
        for decision in decisions:
            decision.finding.metadata.setdefault("decision_source", decision.decision_source)
            decision.finding.metadata.setdefault("runtime_task_refs", []).append(verification_task.id or "")
        accepted = [decision for decision in decisions if decision.decision == "accept"]
        self.artifacts.write_json("findings", "verification.json", [decision.to_dict() for decision in decisions], verification_task)
        self._finish_task(verification_task, output_refs=[decision.finding_id or "" for decision in decisions])

        self._emit_phase("verifying")
        validation_task = self._start_task("validation", "service")
        verifier = VerificationEngine(
            config,
            self.run.path,
            llm_client=llm_client,
            message_bus=self.bus,
        )
        evidence_builder = EvidenceBuilder(self.run.path / "evidence")
        evidence_chains = []
        staged_validations = []
        verifier.begin_validation_phase(metadata)
        for decision in decisions:
            for key, values in self.runtime_refs.items():
                decision.finding.metadata.setdefault(key, [])
                for value in values:
                    if value and value not in decision.finding.metadata[key]:
                        decision.finding.metadata[key].append(value)
            validation = verifier.verify(decision, metadata, config.default_validation_level)
            staged_validations.append((decision.finding, validation))

        validation_results = verifier.finalize_validation_phase(metadata, staged_validations)
        for ref in verifier.integrity_artifact_refs:
            validation_task.record_artifact(ref)
            self.run_state.record_artifact(ref)

        for decision, validation in zip(decisions, validation_results):
            for ref in validation.artifacts:
                validation_task.record_artifact(ref)
                self.run_state.record_artifact(ref)
            if self.bus:
                environment = validation.environment or {}
                msg = self.bus.publish(
                    "validation",
                    "verification",
                    "verification.attempt",
                    {
                        "finding_id": decision.finding_id,
                        "status": validation.verification_status or validation.status,
                        "level": validation.level,
                        "runner": environment.get("runner", ""),
                        "docker_image": environment.get("docker_image", ""),
                        "exit_code": validation.exit_code,
                        "timed_out": validation.timed_out,
                        "sandbox_result_refs": validation.sandbox_result_refs,
                        "judge_reason": validation.judge_reason,
                        "blocking_reason": validation.verification_reason
                        if (validation.verification_status or validation.status) == VerificationStatus.MANUAL_REQUIRED
                        else "",
                    },
                    artifact_refs=validation.artifacts,
                )
                self._record_message(msg.message_id, validation_task)
                decision.finding.metadata.setdefault("message_refs", []).append(msg.message_id)
            evidence_chains.append(
                evidence_builder.build(
                    finding=decision.finding,
                    metadata=metadata,
                    tool_results=scan_results,
                    intelligence=intelligence,
                    verification=decision,
                    validation=validation,
                    agent_traces=[recon.trace, analysis.trace, verification.trace],
                    handoffs=[recon.handoff, analysis.handoff, verification.handoff],
                )
            )
        self._finish_task(validation_task, output_refs=[chain.id or "" for chain in evidence_chains])
        status_counts = verification_status_counts(validation_results)
        active_decisions = [
            decision
            for decision in decisions
            if decision.finding.verification_status
            in {VerificationStatus.CONFIRMED, VerificationStatus.LIKELY, VerificationStatus.MANUAL_REQUIRED}
        ]

        runtime_summary = {
            "dependency_intelligence": dependency_intelligence_summary,
        }
        if config.runtime_enabled:
            runtime_summary.update({
                "llm": {"provider": config.llm.provider, "model": config.llm.model},
                "prompts": {"version": config.prompts.default_version, "count": len(self.runtime_refs["prompt_refs"])},
                "mcp": {"enabled": config.mcp.enabled, "transport": config.mcp.transport, "refs": self.runtime_refs["mcp_call_refs"]},
                "memory": {"enabled": config.memory.enabled, "mode": config.memory.mode, "refs": self.runtime_refs["memory_refs"]},
                "llm_decisions": {
                    "enabled": config.llm_decisions.enabled,
                    "roles": config.llm_decisions.roles,
                    "refs": self.runtime_refs["decision_refs"],
                },
                "poc_repair": {
                    "enabled": config.poc_repair.enabled,
                    "max_repair_attempts": config.poc_repair.max_repair_attempts,
                    "total_execution_attempts": config.poc_repair.total_execution_attempts,
                    "effective_source": config.poc_repair.effective_source,
                    "requires_docker": True,
                },
                "message_log": str(self.run.path / "messages" / config.message_bus.log_filename) if self.bus else "",
                "token_usage": {"mode": "lifecycle-ledger"},
                "verification": {
                    **status_counts,
                    "candidate_count": len(decisions),
                    "runner_counts": _runner_counts(validation_results),
                    "docker_images": sorted(
                        {
                            str(result.environment.get("docker_image"))
                            for result in validation_results
                            if result.environment.get("runner") == "docker" and result.environment.get("docker_image")
                        }
                    ),
                    "attempt_refs": [
                        ref
                        for result in validation_results
                        for ref in result.attempt_refs
                    ],
                    "poc_refs": [ref for result in validation_results for ref in result.poc_refs],
                    "sandbox_result_refs": [
                        ref
                        for result in validation_results
                        for ref in result.sandbox_result_refs
                    ],
                },
            })

        self._emit_phase("reporting")
        reporting_task = self._start_task("reporting", "service")
        if config.runtime_enabled and self.bus:
            msg = self.bus.publish(
                "reporting",
                "pipeline",
                "report.generate",
                {
                    "finding_count": len(active_decisions),
                    "verification_candidate_count": len(decisions),
                    "task_id": reporting_task.id,
                    **status_counts,
                },
            )
            self._record_message(msg.message_id, reporting_task)
            for decision in decisions:
                decision.finding.metadata.setdefault("message_refs", []).append(msg.message_id)
        state_ref = str(self.run.path / "runtime_state" / "state.json")
        runtime_summary.setdefault("kernel", {})
        runtime_summary["kernel"] = {
            "name": "AgentRuntime",
            "state_ref": state_ref,
            "task_count": len(self.run_state.tasks),
            "roles": sorted({task.role for task in self.run_state.tasks}),
        }
        runtime_summary["llm_accounting"] = reconcile_llm_lifecycle(
            self.run.path,
            llm_enabled=bool(config.runtime_enabled),
            budget_counters=self.run_state.llm_accounting or None,
        ).to_dict()
        report = ReportGenerator().build(
            metadata,
            [decision.finding for decision in active_decisions],
            evidence_chains,
            runtime=runtime_summary,
            verification_candidates=[decision.finding for decision in decisions],
        )
        report_path = self.artifacts.write_json("reports", "report.json", report.to_dict(), reporting_task)
        markdown_path = self.artifacts.write_text("reports", "report.md", ReportGenerator().to_markdown(report), reporting_task)
        resource_summary = build_run_resource_summary(
            run_id=self.run.run_id,
            run_dir=self.run.path,
            metadata=metadata,
            run_state=self.run_state,
            config=config,
            validation_results=validation_results,
            status_counts=status_counts,
            runtime_refs=self.runtime_refs,
            terminal_status="succeeded",
            tool_calls_used=self.tool_broker.runtime.budget.total_used,
        )
        resource_summary_path = self.artifacts.write_json(
            "reports", "run-resource-summary.v1.json", resource_summary.to_dict(), reporting_task
        )
        self._finish_task(reporting_task, output_refs=[report_path, markdown_path, resource_summary_path])

        summary = {
            "run_dir": str(self.run.path),
            "candidate_count": len(candidates),
            "rejected_count": len([decision for decision in decisions if decision.decision == "reject"]),
            "validated_count": len(accepted),
            **status_counts,
            "validation_level_distribution": {config.default_validation_level: len(accepted)},
            "runtime_state_ref": str(self.run.path / "runtime_state" / "state.json"),
            "resource_summary_ref": resource_summary_path,
            "source_kind": metadata.target.kind,
            "requested_revision": metadata.target.requested_revision,
            "resolved_commit": metadata.commit,
            "acquisition_ref": metadata.target.acquisition_ref,
        }
        self.run_state.mark_succeeded(summary)
        self.artifacts.persist_state()
        return summary

    def _build_bus(self, target: str) -> MessageBus | None:
        if self.config.runtime_enabled and self.config.message_bus.enabled and self.run:
            bus = MessageBus(
                self.run.run_id,
                self.run.path / "messages" / self.config.message_bus.log_filename,
                secret_values=[os.environ.get(self.config.llm.api_key_env, "")],
            )
            msg = bus.publish("pipeline", "orchestrator", "run.start", {"target": target})
            self.runtime_refs["message_refs"].append(msg.message_id)
            return bus
        return None

    def _start_task(self, role: str, kind: str, input_refs: list[str] | None = None) -> TaskState:
        task = TaskState(run_id=self.run_state.run_id, role=role, kind=kind, input_refs=input_refs or [])
        self.run_state.add_task(task)
        task.mark_running()
        self.runtime_refs["runtime_task_refs"].append(task.id or "")
        if self.bus:
            msg = self.bus.publish("runtime", role, "runtime.task", {"task_id": task.id, "role": role, "kind": kind, "status": "running"})
            self._record_message(msg.message_id, task)
        return task

    def _finish_task(self, task: TaskState, output_refs: list[str] | None = None) -> None:
        if task.status == "running":
            task.mark_succeeded(output_refs=output_refs or [])
        else:
            for ref in output_refs or []:
                task._append_unique(task.output_refs, ref)
            task.finished_at = task.finished_at or utc_now()
        if self.bus:
            msg = self.bus.publish("runtime", task.role, "runtime.task", {"task_id": task.id, "role": task.role, "kind": task.kind, "status": task.status, "fallback_reason": task.fallback_reason})
            self._record_message(msg.message_id, task)

    def _record_message(self, message_id: str, task: TaskState | None = None) -> None:
        if message_id:
            self.runtime_refs["message_refs"].append(message_id)
            if self.run_state:
                self.run_state.record_message(message_id)
            if task:
                task.record_message(message_id)

    def _invoke_agent(self, role: str, task: TaskState, inputs: dict[str, Any]) -> AgentOutput:
        registration = self.registry.get(role)
        return registration.handler(
            AgentInvocation(
                role=role,
                run_state=self.run_state,
                task_state=task,
                inputs=inputs,
                config=self.config,
                services={"artifacts": self.artifacts, "tool_broker": self.tool_broker, "message_bus": self.bus},
            )
        )

    def _run_llm_role(
        self,
        task: TaskState,
        llm_client,
        role: str,
        template_id: str,
        variables: dict[str, Any],
    ):
        prompt = render_default_prompt(role, template_id, variables, self.config.prompts)
        original_trusted_prompt = prompt.rendered
        repair_limit = (
            int(self.config.llm_decisions.max_repair_attempts)
            if template_id in {"analysis.investigation", "verification.plan"}
            and self.config.llm_decisions.repair_enabled
            else 0
        )
        for repair_attempt in range(repair_limit + 1):
            prompt_path = self.artifacts.write_prompt(prompt, task)
            self.runtime_refs["prompt_refs"].append(prompt.id or "")
            request = LLMRequest(
                role=role,
                prompt=prompt.rendered,
                model=self.config.llm.model,
                provider=self.config.llm.provider,
                response_schema=prompt.output_schema,
                response_format="auto",
                metadata={
                    "template_id": template_id,
                    "template_version": prompt.version,
                    "schema_repair_attempt": repair_attempt,
                },
            )
            receipt = None
            if isinstance(llm_client, AuditedLLMGateway):
                receipt = llm_client.invoke(request, prompt_ref=prompt_path)
                response = receipt.response
                llm_path = receipt.response_ref or ""
            else:
                response = llm_client.complete(request)
                llm_path = self.artifacts.write_llm(request, response, task)
            schema_error = None
            try:
                validate_json_schema(response.parsed_json, prompt.output_schema)
                if receipt:
                    llm_client.record_schema(receipt, valid=True)
            except Exception as exc:
                schema_error = exc
                if receipt:
                    llm_client.record_schema(receipt, valid=False, errors=[str(exc)])
                response.validation_errors.append(str(exc))

            self.runtime_refs["llm_response_refs"].append(response.id or "")
            if self.bus:
                msg = self.bus.publish(
                    role,
                    "llm",
                    "llm.response",
                    {
                        "role": role,
                        "response_id": response.id,
                        "task_id": task.id,
                        "schema_repair_attempt": repair_attempt,
                    },
                    artifact_refs=[prompt_path, llm_path],
                )
                self._record_message(msg.message_id, task)

            if schema_error is None:
                if receipt and not self._decision_enabled(role):
                    llm_client.terminalize(receipt, "accepted")
                return response, prompt_path, llm_path

            if not self._decision_enabled(role):
                if receipt:
                    llm_client.record_fallback(receipt, "schema-invalid")
                    llm_client.terminalize(receipt, "fallback")
                raise schema_error

            if repair_attempt >= repair_limit:
                task.mark_fallback("schema-invalid")
                return response, prompt_path, llm_path

            if receipt:
                llm_client.record_fallback(receipt, "schema-repair")
                llm_client.terminalize(receipt, "fallback")
            invalid_payload = (
                response.parsed_json if response.parsed_json is not None else response.text
            )
            prompt = PromptRenderRecord(
                template_id=f"{template_id}.schema-repair",
                version=prompt.version,
                role=role,
                variables={
                    "repair_attempt": repair_attempt + 1,
                    "invalid_response_id": response.id,
                    "validation_error": str(schema_error),
                },
                rendered=(
                    "Repair the following JSON response so it exactly satisfies the supplied schema.\n"
                    "Preserve valid data, include every required field (including rationale), and return "
                    "only the corrected JSON object. Use only repository paths, signal IDs, hypothesis IDs, "
                    "actions, and facts present in the original trusted request context. If a malformed "
                    "hypothesis cannot be repaired without inventing any of those values, remove that "
                    "hypothesis; an empty hypotheses array is valid. Do not add code, commands, tools, "
                    "verdicts, or any authority not already allowed by the schema and trusted context.\n"
                    f"Original trusted request context:\n{original_trusted_prompt}\n"
                    f"Validation error:\n{schema_error}\n"
                    f"Invalid response:\n{json.dumps(invalid_payload, ensure_ascii=False)}\n"
                    f"Required JSON Schema:\n{json.dumps(prompt.output_schema, ensure_ascii=False)}"
                ),
                output_schema=prompt.output_schema,
                safety_constraints=list(prompt.safety_constraints),
            )

        raise RuntimeError("unreachable schema-repair loop")

    def _build_audited_llm_client(self) -> AuditedLLMGateway:
        if not self.run or not self.run_state or not self.artifacts:
            raise RuntimeError("run-scoped LLM accounting requires initialized runtime state")
        secret = os.environ.get(self.config.llm.api_key_env, "")

        def event_sink(event, ref):
            self.runtime_refs["llm_lifecycle_refs"].append(ref)
            self.run_state.record_artifact(ref)
            if self.bus:
                message = self.bus.publish(
                    "llm-gateway",
                    "runtime",
                    f"llm.lifecycle.{event.kind}",
                    {
                        "request_group_id": event.request_group_id,
                        "provider_attempt_id": event.provider_attempt_id,
                        "event_id": event.event_id,
                        "event_kind": event.kind,
                        "terminal_status": event.terminal_status,
                        "role": event.role,
                    },
                    artifact_refs=[ref, *([event.response_ref] if event.response_ref else [])],
                )
                self.run_state.record_message(message.message_id)

        ledger = LifecycleLedger(
            self.run.path,
            self.run.run_id,
            secret_values=[secret] if secret else [],
            event_sink=event_sink,
        )

        def response_writer(request, response):
            return self.artifacts.write_llm(request, response)

        self.llm_gateway = AuditedLLMGateway(
            build_llm_client(self.config.llm),
            ledger,
            request_budget=(
                self.config.llm.request_budget
                if self.config.llm.request_budget is not None
                else 1_000_000_000
            ),
            token_budget=self.config.llm.token_budget,
            cost_budget_usd=self.config.llm.cost_budget_usd,
            response_writer=response_writer,
            accounting_state=self.run_state.llm_accounting,
            cancellation_token=self.cancellation_token,
        )
        return self.llm_gateway

    def _decision_enabled(self, role: str) -> bool:
        return bool(self.config.runtime_enabled and self.config.llm_decisions.enabled and role in set(self.config.llm_decisions.roles))

    def _publish_decision_events(
        self,
        role: str,
        proposal,
        gate,
        merged,
        artifact_refs: list[str],
        task: TaskState,
    ) -> None:
        if proposal.id:
            self.runtime_refs["decision_refs"].append(proposal.id)
        if self.llm_gateway and proposal.llm_response_ref:
            receipt = self.llm_gateway.receipt_for_response(proposal.llm_response_ref)
            if receipt and not receipt.terminal_status:
                accepted = gate.status == "accepted" and not proposal.fallback_reason
                self.llm_gateway.record_policy(receipt, accepted=accepted, reasons=gate.reasons)
                if not accepted:
                    self.llm_gateway.record_fallback(
                        receipt,
                        proposal.fallback_reason or "policy-denied",
                        refs=artifact_refs,
                    )
                self.llm_gateway.terminalize(
                    receipt,
                    "accepted" if accepted else "fallback",
                    decision_refs=artifact_refs,
                )
                proposal.terminal_ref = receipt.terminal_ref
                proposal.lifecycle_event_refs = list(receipt.event_refs)
        if gate.status != "accepted" or proposal.fallback_reason:
            task.mark_fallback(proposal.fallback_reason or "policy-denied")
        if not self.bus:
            return
        events = [
            (
                "llm.decision",
                {
                    "role": role,
                    "decision_id": proposal.id,
                    "confidence": proposal.confidence,
                    "fallback_reason": proposal.fallback_reason,
                    "task_id": task.id,
                },
            ),
            (
                "decision.schema",
                {"role": role, "status": proposal.schema_status, "errors": proposal.schema_errors, "task_id": task.id},
            ),
            (
                "decision.policy",
                {"role": role, "status": gate.status, "reasons": gate.reasons, "gate_id": gate.id, "task_id": task.id},
            ),
            (
                "decision.merge",
                {
                    "role": role,
                    "decision_source": merged.decision_source,
                    "merge_id": merged.id,
                    "fallback_reason": merged.fallback_reason,
                    "task_id": task.id,
                },
            ),
        ]
        if gate.status != "accepted" or proposal.fallback_reason:
            events.append(
                (
                    "decision.fallback",
                    {
                        "role": role,
                        "fallback_reason": proposal.fallback_reason or "policy-denied",
                        "reasons": gate.reasons,
                        "task_id": task.id,
                    },
                )
            )
        for message_type, payload in events:
            msg = self.bus.publish(role, "pipeline", message_type, payload, artifact_refs=artifact_refs)
            self._record_message(msg.message_id, task)

    def _finalize_decision_accounting(self, proposal, gate, merged) -> None:
        if not self.llm_gateway or not proposal.llm_response_ref:
            return
        receipt = self.llm_gateway.receipt_for_response(proposal.llm_response_ref)
        if not receipt:
            return
        accepted = gate.status == "accepted" and not proposal.fallback_reason
        if not receipt.policy_ref:
            self.llm_gateway.record_policy(receipt, accepted=accepted, reasons=gate.reasons)
        if not accepted and not receipt.fallback_ref:
            self.llm_gateway.record_fallback(
                receipt,
                proposal.fallback_reason or "policy-denied",
                refs=[item for item in (proposal.id, gate.id, merged.id) if item],
            )
        if not receipt.terminal_status:
            expected_decision_ref = str(
                self.run.path / "decisions" / f"{proposal.role}-{proposal.id}.json"
            )
            self.llm_gateway.terminalize(
                receipt,
                "accepted" if accepted else "fallback",
                decision_refs=[
                    item
                    for item in (expected_decision_ref, proposal.id, gate.id, merged.id)
                    if item
                ],
            )
        proposal.request_group_id = receipt.request_group_id
        proposal.provider_attempt_ids = list(receipt.provider_attempt_ids)
        proposal.lifecycle_event_refs = list(receipt.event_refs)
        proposal.schema_ref = receipt.schema_ref
        proposal.policy_ref = receipt.policy_ref
        proposal.fallback_ref = receipt.fallback_ref
        proposal.terminal_ref = receipt.terminal_ref
        proposal.provider_error_ref = receipt.error_ref
        proposal.schema_ref = receipt.schema_ref
        proposal.policy_ref = receipt.policy_ref
        proposal.fallback_ref = receipt.fallback_ref
        proposal.terminal_ref = receipt.terminal_ref
        proposal.provider_error_ref = receipt.error_ref

    def _apply_orchestrator_proposal(self, plan, proposal, gate):
        if gate.status != "accepted":
            plan.decision_source = "policy-denied"
            return plan
        payloads = list(proposal.selected_actions)
        if isinstance(proposal.parsed_json.get("plan"), dict):
            payloads.append(proposal.parsed_json["plan"])
        allowed_agents = {"orchestrator", "recon", "analysis", "verification"}
        for payload in payloads:
            classes = payload.get("vulnerability_classes") or []
            accepted_classes = [item for item in classes if item in self.config.audit_scope.vulnerability_classes]
            if accepted_classes:
                plan.vulnerability_classes = accepted_classes
            focus_areas = payload.get("focus_areas") or []
            for area in focus_areas:
                if area in self.config.audit_scope.vulnerability_classes and area not in plan.focus_areas:
                    plan.focus_areas.append(area)
            budgets = payload.get("budgets") or {}
            for key, value in budgets.items():
                if isinstance(value, int) and value > 0:
                    plan.budgets[str(key)] = min(value, max(value, plan.budgets.get(str(key), value)))
            order = payload.get("agent_order") or []
            accepted_order = [item for item in order if item in allowed_agents]
            if accepted_order:
                plan.agent_order = accepted_order
        plan.decision_source = "merged"
        return plan

    def _correlate_llm_proposal(self, proposal, response) -> None:
        if not self.llm_gateway or not response or not response.id:
            return
        receipt = self.llm_gateway.receipt_for_response(response.id)
        if not receipt:
            return
        proposal.request_group_id = receipt.request_group_id
        proposal.provider_attempt_ids = list(receipt.provider_attempt_ids)
        proposal.lifecycle_event_refs = list(receipt.event_refs)

    def _apply_recon_proposal(self, recon, proposal) -> None:
        high_risk = proposal.parsed_json.get("high_risk_areas") or []
        dependency_concerns = proposal.parsed_json.get("dependency_concerns") or []
        for action in proposal.selected_actions:
            high_risk.extend(action.get("focus_areas") or [])
            high_risk.extend(action.get("context_slices") or [])
            dependency_concerns.extend(action.get("mcp_queries") or [])
        for item in high_risk:
            text = str(item)
            if text and text not in recon.payload["high_risk_areas"]:
                recon.payload["high_risk_areas"].append(text)
                recon.handoff.key_findings.append(text)
        for item in dependency_concerns:
            text = str(item)
            if text and text not in recon.payload["dependency_concerns"]:
                recon.payload["dependency_concerns"].append(text)
                recon.handoff.attention_points.append(text)

    def _dispatch_recon_tool_requests(self, task: TaskState, proposal, metadata, memory_store) -> None:
        if not proposal.requested_tools:
            return
        for request in proposal.requested_tools:
            tool_name = str(request.get("tool_name") or request.get("name") or "")
            arguments = dict(request.get("arguments") or {})
            result = self.tool_broker.dispatch("recon", tool_name, arguments, metadata=metadata, memory_store=memory_store, task_state=task)
            self.runtime_refs["tool_call_refs"].append(result.id or "")


class _GraphAuditExecution:
    """Graph-mode composition over the existing runtime service boundaries."""

    def __init__(
        self,
        runtime: AgentRuntime,
        target: str,
        prepared_target: PreparedAuditTarget | None = None,
    ) -> None:
        self.runtime = runtime
        self.config = runtime.config
        self.target = target
        self.prepared_target = prepared_target
        self.metadata = None
        self.llm_client = None
        self.graph = None
        self.catalog = build_default_template_catalog()
        self.recorder = None
        self.policy = None
        self.tasks: dict[str, TaskState] = {}
        self.next_actions: dict[str, list[str]] = {}
        self.revision_records: list[dict[str, Any]] = []
        self.mutation_records: list[dict[str, Any]] = []
        self.memory_store = None
        self.memory_retrievals = []
        self.scan_results = []
        self.intelligence = []
        self.dependency_intelligence_summary = summary_without_dependencies()
        self.recon = None
        self.analysis = None
        self.candidates = []
        self.verification = None
        self.decisions = []
        self.validation_results = []
        self.evidence_chains = []
        self.summary: dict[str, Any] | None = None
        self.scheduler = None

    def run(self) -> dict[str, Any]:
        self._initialize()
        self.recorder.persist_initial(self.graph)
        self.revision_records.append({"revision": self.graph.revision})
        self.policy = GraphMutationPolicy(
            self.catalog,
            REQUIRED_TEMPLATE_IDS,
            allow_target_writes=False,
            artifact_ref_validator=lambda ref: ref in set(self.runtime.run_state.artifact_refs),
        )
        scheduler = GraphScheduler(
            self.graph,
            registered_templates=self.catalog.template_ids(),
            service_handlers={
                "memory-context": self._memory_context,
                "intelligence": self._intelligence,
                "post-recon-checkpoint": self._checkpoint,
                "post-analysis-checkpoint": self._checkpoint,
                "local-context-refinement": self._local_context_refinement,
                "verification-routing": self._verification_routing,
                "validation": self._validation,
                "evidence-finalization": self._evidence_finalization,
                "report-finalization": self._report_finalization,
            },
            agent_executor=self._agent_executor,
            tool_executor=self._tool_executor,
            transition_sink=self._persist_transitions,
            required_template_ids=REQUIRED_TEMPLATE_IDS,
        )
        self.scheduler = scheduler
        result = scheduler.run()
        replay = replay_graph(
            self.graph.to_dict(),
            [item.to_dict() for item in result.transitions],
            revisions=self.revision_records,
            mutation_records=self.mutation_records,
        )
        self.recorder.persist_final(self.graph, result, replay)
        if result.status != "succeeded" or self.summary is None:
            raise RuntimeError(result.failure_reason or f"graph execution ended as {result.status}")
        self.summary.update(
            {
                "graph_mode": self.graph.mode,
                "final_graph_ref": self.runtime.run_state.final_graph_ref,
                "execution_path": list(result.execution_path),
            }
        )
        self.runtime.run_state.mark_succeeded(self.summary)
        self.runtime.artifacts.persist_state()
        return self.summary

    def _initialize(self) -> None:
        runtime = self.runtime
        config = self.config
        self.metadata = (
            self.prepared_target.metadata
            if self.prepared_target is not None
            else analyze_target(self.target, audit_scope=config.audit_scope)
        )
        runtime.run = RunStore(runtime.output_dir).create_run(
            self.metadata.target.repo or Path(self.metadata.target.path or self.target).name
        )
        runtime.run_state = RunState(
            run_id=runtime.run.run_id,
            target=self.target,
            graph_mode=config.graph.mode,
            config_summary={
                "runtime_enabled": config.runtime_enabled,
                "llm_provider": config.llm.provider,
                "llm_decisions": config.llm_decisions.enabled,
                "poc_repair": config.poc_repair.enabled,
                "poc_repair_source": config.poc_repair.effective_source,
                "graph_mode": config.graph.mode,
            },
        )
        runtime.bus = runtime._build_bus(self.target)
        runtime.run_state.mark_running()
        runtime.artifacts = ArtifactStore(
            runtime.run,
            bus=runtime.bus,
            run_state=runtime.run_state,
            secret_values=[os.environ.get(config.llm.api_key_env, "")],
        )
        runtime.tool_broker = ToolBroker(config, runtime.artifacts, bus=runtime.bus)
        if self.prepared_target and self.prepared_target.acquisition:
            acquisition_path = runtime.artifacts.write_json(
                "metadata", "acquisition.json", self.prepared_target.acquisition.to_dict()
            )
            self.metadata.target.acquisition_ref = acquisition_path
        runtime.artifacts.write_json("metadata", "repository.json", self.metadata.to_dict())
        self.llm_client = runtime._build_audited_llm_client() if config.runtime_enabled else None
        budgets = GraphBudget(
            max_nodes=config.graph.max_nodes,
            max_scheduler_iterations=config.graph.max_scheduler_iterations,
            max_node_attempts=config.graph.max_node_attempts,
            max_replans=config.graph.max_replans,
            max_checkpoints=config.graph.max_checkpoints,
            max_llm_tokens=config.llm.token_budget,
            max_tool_calls=config.audit_scope.tool_budget,
        )
        self.graph = build_deterministic_audit_graph(
            runtime.run.run_id,
            mode=config.graph.mode,
            budgets=budgets,
        )
        self.recorder = GraphArtifactRecorder(runtime.artifacts, runtime.bus, runtime.run_state)

    def _task_for(self, node) -> TaskState:
        task = self.tasks.get(node.node_id)
        if task is not None:
            return task
        dependencies = sorted(
            edge.source_node_id
            for edge in self.graph.edges
            if edge.target_node_id == node.node_id
        )
        task = TaskState(
            run_id=self.runtime.run_state.run_id,
            role=node.executor_ref,
            kind=node.executor_kind,
            graph_node_id=node.node_id,
            graph_revision=self.graph.revision,
            dependency_refs=dependencies,
            attempt=node.attempt_count,
            lineage=node.lineage.to_dict(),
        )
        self.tasks[node.node_id] = task
        self.runtime.run_state.add_task(task)
        self.runtime.runtime_refs["runtime_task_refs"].append(task.id or "")
        return task

    def _persist_transitions(self, transitions) -> None:
        ref = self.recorder.persist_transitions(self.graph, transitions)
        for transition in transitions:
            node = self.graph.node(transition.node_id)
            task = self._task_for(node)
            task.graph_revision = transition.revision
            task.attempt = node.attempt_count
            task.transition_refs.append(ref)
            task.correlation_refs.extend(
                item for item in transition.correlation_refs if item not in task.correlation_refs
            )
            task.causation_refs.extend(
                item for item in transition.causation_refs if item not in task.causation_refs
            )
            if transition.new_status == "running":
                task.mark_running()
            elif transition.new_status == "succeeded":
                task.mark_succeeded(output_refs=list(node.artifact_refs))
            elif transition.new_status == "failed":
                task.mark_failed(transition.cause)
            elif transition.new_status == "skipped":
                task.mark_skipped(transition.cause)
            elif transition.new_status == "fallback":
                task.mark_fallback(transition.cause)
            else:
                task.status = transition.new_status

    def _agent_executor(self, role: str, node, inputs: dict[str, Any]) -> GraphNodeResult:
        task = self._task_for(node)
        if role == "orchestrator":
            output = self.runtime._invoke_agent(role, task, {"metadata": self.metadata})
            self.next_actions[node.node_id] = list(output.next_actions)
            plan = output.payload["plan"]
            if self.config.runtime_enabled and self.llm_client:
                response, _, _ = self._optional_llm_role(
                    task,
                    self.llm_client,
                    "orchestrator",
                    "orchestrator.plan",
                    {
                        "repository_summary": self.metadata.to_dict(),
                        "audit_scope": self.config.audit_scope.vulnerability_classes,
                    },
                )
                if response is not None and self.runtime._decision_enabled("orchestrator"):
                    proposal = self._decision_proposal("orchestrator", response)
                    gate = evaluate_decision_policy("orchestrator", proposal, self.config)
                    plan = self.runtime._apply_orchestrator_proposal(plan, proposal, gate)
                    merged = merge_decision(
                        "orchestrator",
                        {"plan": OrchestratorAgent(self.config).plan(self.metadata).to_dict()},
                        proposal,
                        gate.status,
                        gate.reasons,
                        final_output={"plan": plan.to_dict()},
                    )
                    merged.policy_gate_id = gate.id
                    self.runtime._finalize_decision_accounting(proposal, gate, merged)
                    path = self.runtime.artifacts.write_decision(
                        "orchestrator", proposal, gate, merged, task
                    )
                    self.runtime._publish_decision_events(
                        "orchestrator", proposal, gate, merged, [path], task
                    )
            path = self.runtime.artifacts.write_json("metadata", "plan.json", plan.to_dict(), task)
            return GraphNodeResult(outputs={"plan": plan}, artifact_refs=[path])
        if role == "recon":
            output = self.runtime._invoke_agent(
                role,
                task,
                {"metadata": self.metadata, "intelligence": self.intelligence},
            )
            self.next_actions[node.node_id] = list(output.next_actions)
            self.recon = output.payload["result"]
            if self.config.runtime_enabled and self.llm_client:
                response, _, _ = self._optional_llm_role(
                    task,
                    self.llm_client,
                    "recon",
                    "recon.summary",
                    {
                        "repository_metadata": self.metadata.to_dict(),
                        "intelligence_context": [item.to_dict() for item in self.intelligence],
                        "memory_context": [item.to_dict() for item in self.memory_retrievals],
                    },
                )
                if response is not None and self.runtime._decision_enabled("recon"):
                    proposal = self._decision_proposal("recon", response)
                    gate = evaluate_decision_policy("recon", proposal, self.config)
                    if gate.status == "accepted":
                        self.runtime._apply_recon_proposal(self.recon, proposal)
                        self.runtime._dispatch_recon_tool_requests(
                            task, proposal, self.metadata, self.memory_store
                        )
                    merged = merge_decision(
                        "recon",
                        {"high_risk_areas": self.recon.payload.get("high_risk_areas", [])},
                        proposal,
                        gate.status,
                        gate.reasons,
                        final_output={
                            "handoff": self.recon.handoff.to_dict(),
                            "payload": self.recon.payload,
                        },
                    )
                    merged.policy_gate_id = gate.id
                    self.runtime._finalize_decision_accounting(proposal, gate, merged)
                    path = self.runtime.artifacts.write_decision("recon", proposal, gate, merged, task)
                    self.runtime._publish_decision_events("recon", proposal, gate, merged, [path], task)
            trace = self.runtime.artifacts.write_json(
                "agent_traces", "recon.json", self.recon.trace.to_dict(), task
            )
            handoff = self.runtime.artifacts.write_json(
                "handoffs", "recon-to-analysis.json", self.recon.handoff.to_dict(), task
            )
            return GraphNodeResult(outputs={"recon": self.recon}, artifact_refs=[trace, handoff])
        if role == "analysis":
            output = self.runtime._invoke_agent(
                role,
                task,
                {
                    "metadata": self.metadata,
                    "recon_handoff": self.recon.handoff,
                    "tool_results": self.scan_results,
                    "intelligence": self.intelligence,
                    **inputs,
                },
            )
            self.next_actions[node.node_id] = list(output.next_actions)
            self.analysis = output.payload["result"]
            self.candidates = list(self.analysis.payload["candidates"])
            if self.config.runtime_enabled and self.llm_client:
                response, _, _ = self._optional_llm_role(
                    task,
                    self.llm_client,
                    "analysis",
                    "analysis.candidates",
                    {
                        "repository_summary": self.metadata.to_dict(),
                        "tool_outputs": [item.to_dict() for item in self.scan_results],
                        "memory_context": [item.to_dict() for item in self.memory_retrievals],
                        "intelligence_context": [item.to_dict() for item in self.intelligence],
                    },
                )
                if response is not None and self.runtime._decision_enabled("analysis"):
                    proposal = self._decision_proposal("analysis", response)
                    gate = evaluate_decision_policy("analysis", proposal, self.config)
                    llm_candidates = []
                    if gate.status == "accepted":
                        payload = dict(response.parsed_json or {})
                        if proposal.selected_actions:
                            payload["candidates"] = proposal.selected_actions
                        llm_candidates = findings_from_llm_candidates(payload, self.metadata)
                        for finding in llm_candidates:
                            annotate_finding_from_decision(finding, proposal, gate, None)
                            finding.metadata["decision_source"] = "llm"
                        self.candidates.extend(llm_candidates)
                    merged = merge_decision(
                        "analysis",
                        {"candidate_count": len(self.analysis.payload["candidates"])},
                        proposal,
                        gate.status,
                        gate.reasons,
                        final_output={
                            "candidate_count": len(self.candidates),
                            "llm_candidate_count": len(llm_candidates),
                        },
                    )
                    merged.policy_gate_id = gate.id
                    for finding in self.candidates:
                        if "decision_source" not in finding.metadata:
                            annotate_finding_from_decision(finding, proposal, gate, merged)
                    self.runtime._finalize_decision_accounting(proposal, gate, merged)
                    path = self.runtime.artifacts.write_decision("analysis", proposal, gate, merged, task)
                    self.runtime._publish_decision_events("analysis", proposal, gate, merged, [path], task)
                elif response is not None:
                    self.candidates.extend(
                        findings_from_llm_candidates(response.parsed_json or {}, self.metadata)
                    )
            suffix = "" if node.node_id == "analysis" else f"-{node.node_id}"
            trace = self.runtime.artifacts.write_json(
                "agent_traces", f"analysis{suffix}.json", self.analysis.trace.to_dict(), task
            )
            handoff = self.runtime.artifacts.write_json(
                "handoffs", f"analysis-to-verification{suffix}.json", self.analysis.handoff.to_dict(), task
            )
            findings = self.runtime.artifacts.write_json(
                "findings", f"candidates{suffix}.json", [item.to_dict() for item in self.candidates], task
            )
            return GraphNodeResult(
                outputs={"candidates": self.candidates},
                artifact_refs=[trace, handoff, findings],
            )
        if role == "verification":
            candidates = inputs.get("candidates", self.candidates)
            output = self.runtime._invoke_agent(
                role,
                task,
                {
                    "candidates": candidates,
                    "metadata": self.metadata,
                    "intelligence": self.intelligence,
                },
            )
            self.next_actions[node.node_id] = list(output.next_actions)
            self.verification = output.payload["result"]
            self.decisions = list(self.verification.decisions)
            if self.config.runtime_enabled and self.llm_client:
                response, _, _ = self._optional_llm_role(
                    task,
                    self.llm_client,
                    "verification",
                    "verification.decision",
                    {
                        "candidate_json": [finding.to_dict() for finding in candidates],
                        "evidence_summary": [item.to_dict() for item in self.scan_results],
                    },
                )
                if response is not None and self.runtime._decision_enabled("verification"):
                    proposal = self._decision_proposal("verification", response)
                    self.decisions, gate, merged = apply_verification_decision_proposal(
                        candidates,
                        self.decisions,
                        proposal,
                        self.config,
                    )
                    self.verification.decisions = self.decisions
                    for decision in self.decisions:
                        annotate_finding_from_decision(decision.finding, proposal, gate, merged)
                    self.runtime._finalize_decision_accounting(proposal, gate, merged)
                    path = self.runtime.artifacts.write_decision(
                        "verification", proposal, gate, merged, task
                    )
                    self.runtime._publish_decision_events(
                        "verification", proposal, gate, merged, [path], task
                    )
            for decision in self.decisions:
                decision.finding.metadata.setdefault("decision_source", decision.decision_source)
                decision.finding.metadata.setdefault("runtime_task_refs", []).append(task.id or "")
            trace = self.runtime.artifacts.write_json(
                "agent_traces", "verification.json", self.verification.trace.to_dict(), task
            )
            handoff = self.runtime.artifacts.write_json(
                "handoffs", "verification-to-reporting.json", self.verification.handoff.to_dict(), task
            )
            decisions = self.runtime.artifacts.write_json(
                "findings", "verification.json", [item.to_dict() for item in self.decisions], task
            )
            return GraphNodeResult(
                outputs={"decisions": self.decisions},
                artifact_refs=[trace, handoff, decisions],
            )
        raise KeyError(f"graph agent role is not registered: {role}")

    def _decision_proposal(self, role: str, response):
        return build_decision_from_llm_response(
            role,
            response.parsed_json,
            prompt_ref=(
                self.runtime.runtime_refs["prompt_refs"][-1]
                if self.runtime.runtime_refs["prompt_refs"]
                else None
            ),
            llm_response_ref=response.id,
            provider=response.provider,
            model=response.model,
            provider_metadata=response.raw_response,
            raw_output=response.text,
            repair_enabled=self.config.llm_decisions.repair_enabled,
        )

    def _optional_llm_role(self, task, llm_client, role, template_id, variables):
        try:
            return self.runtime._run_llm_role(
                task,
                llm_client,
                role,
                template_id,
                variables,
            )
        except Exception as exc:
            task.mark_fallback(f"llm-{type(exc).__name__}")
            path = self.runtime.artifacts.write_json(
                "runtime_errors",
                f"llm-{role}-{task.graph_node_id}.json",
                {
                    "schema_version": "llm-role-fallback.v1",
                    "role": role,
                    "graph_node_id": task.graph_node_id,
                    "fallback_reason": type(exc).__name__,
                    "message": str(exc),
                },
                task,
            )
            return None, path, None

    def _tool_executor(self, tool_ref: str, node, inputs: dict[str, Any]) -> GraphNodeResult:
        if tool_ref != "static-scan":
            raise KeyError(f"graph tool template is not registered: {tool_ref}")
        self.runtime._emit_phase("scanning")
        task = self._task_for(node)
        dataflow = self.runtime.tool_broker.dispatch(
            "analysis", "dataflow-scan", {}, metadata=self.metadata, task_state=task
        )
        pattern = self.runtime.tool_broker.dispatch(
            "analysis", "pattern-scan", {}, metadata=self.metadata, task_state=task
        )
        dependency_results = [
            item
            for item in self.scan_results
            if item.tool_name == "dependency-intelligence"
        ]
        self.scan_results = [dataflow, pattern, *dependency_results]
        paths = [
            self.runtime.artifacts.write_json("tool_outputs", "dataflow-scan.json", dataflow.to_dict(), task),
            self.runtime.artifacts.write_json("tool_outputs", "pattern-scan.json", pattern.to_dict(), task),
        ]
        return GraphNodeResult(outputs={"scan_results": self.scan_results}, artifact_refs=paths)

    def _memory_context(self, node, inputs: dict[str, Any]) -> GraphNodeResult:
        task = self._task_for(node)
        if not (
            self.config.runtime_enabled
            and self.config.memory.enabled
            and self.metadata.root_path
        ):
            return GraphNodeResult(outputs={"context": []})
        self.memory_store = LexicalMemoryStore(self.runtime.run.path / "memory")
        MemoryIndexer(self.memory_store, self.config.memory).index_repository(self.metadata)
        self.memory_retrievals = self.memory_store.retrieve(
            "request args os.system select query secret", limit=5
        )
        path = persist_retrievals(
            self.runtime.run.path / "memory", self.memory_retrievals, "initial-retrieval"
        )
        task.record_artifact(path)
        self.runtime.run_state.record_artifact(path)
        self.runtime.runtime_refs["memory_refs"].extend(
            item.record.id or "" for item in self.memory_retrievals
        )
        return GraphNodeResult(outputs={"context": self.memory_retrievals}, artifact_refs=[str(path)])

    def _local_context_refinement(self, node, inputs: dict[str, Any]) -> GraphNodeResult:
        if self.memory_store is None:
            return GraphNodeResult(outputs={"context": self.memory_retrievals})
        refined = self.memory_store.retrieve("local evidence source sink", limit=5)
        self.memory_retrievals = refined
        path = persist_retrievals(
            self.runtime.run.path / "memory", refined, f"refinement-{node.node_id}"
        )
        self._task_for(node).record_artifact(path)
        self.runtime.run_state.record_artifact(path)
        return GraphNodeResult(outputs={"context": refined}, artifact_refs=[str(path)])

    def _verification_routing(self, node, inputs: dict[str, Any]) -> GraphNodeResult:
        candidates = inputs.get("candidates", self.candidates)
        self.candidates = list(candidates)
        path = self.runtime.artifacts.write_json(
            "findings",
            f"verification-routing-{node.node_id}.json",
            [item.to_dict() for item in self.candidates],
            self._task_for(node),
        )
        return GraphNodeResult(outputs={"candidates": self.candidates}, artifact_refs=[path])

    def _intelligence(self, node, inputs: dict[str, Any]) -> GraphNodeResult:
        self.intelligence = []
        if not self.metadata.dependencies:
            return GraphNodeResult(outputs={"intelligence": self.intelligence})
        task = self._task_for(node)
        dependency_run = _run_dependency_intelligence(
            self.config,
            self.metadata,
            self.runtime.run.path,
        )
        self.intelligence = list(dependency_run.intelligence)
        self.dependency_intelligence_summary = dependency_run.summary
        records_path = self.runtime.artifacts.write_json(
            "mcp" if self.config.runtime_enabled else "intelligence",
            "dependency-intelligence-records.json",
            [item.to_dict() for item in self.intelligence],
            task,
        )
        summary_path = self.runtime.artifacts.write_json(
            "intelligence",
            "dependency-intelligence-summary.v1.json",
            dependency_run.summary,
            task,
        )
        tool_path = self.runtime.artifacts.write_json(
            "tool_outputs",
            "dependency-intelligence.json",
            dependency_run.tool_result.to_dict(),
            task,
        )
        dependency_run.tool_result.artifact_paths.extend(
            [records_path, summary_path, tool_path]
        )
        self.scan_results = [
            item for item in self.scan_results
            if item.tool_name != "dependency-intelligence"
        ]
        self.scan_results.append(dependency_run.tool_result)
        self.runtime.runtime_refs["mcp_call_refs"].extend(
            item.id or "" for item in self.intelligence
        )
        return GraphNodeResult(
            outputs={"intelligence": self.intelligence},
            artifact_refs=[records_path, summary_path, tool_path],
        )

    def _checkpoint(self, node, inputs: dict[str, Any]) -> GraphNodeResult:
        checkpoint_id = node.lineage.checkpoint_id or ""
        if self.graph.mode != "adaptive-graph":
            return GraphNodeResult(outputs={"checkpoint": "deterministic"})
        source_id = "reconnaissance" if checkpoint_id == "post-recon" else "analysis"
        hints = list(self.next_actions.get(source_id, []))
        model_status = "disabled"
        model_receipt = None
        if self.runtime._decision_enabled("orchestrator") and self.llm_client is not None:
            try:
                model_hints, model_refs, model_receipt = self._graph_model_decision(node, checkpoint_id)
                hints.extend(item for item in model_hints if item not in hints)
                model_status = "accepted"
            except Exception as exc:
                model_status = f"fallback:{type(exc).__name__}"
                model_refs = self._persist_checkpoint_fallback(node, checkpoint_id, exc)
        else:
            model_refs = []
        proposal = translate_next_actions(
            graph_id=self.graph.graph_id,
            revision=self.graph.revision,
            checkpoint_id=checkpoint_id,
            next_actions=hints,
        )
        if not proposal.operations:
            if model_receipt and not model_receipt.terminal_status:
                self.llm_client.record_policy(model_receipt, accepted=True)
                self.llm_client.terminalize(model_receipt, "accepted")
            return GraphNodeResult(
                outputs={"checkpoint": "no-registered-actions", "model_status": model_status},
                artifact_refs=model_refs,
            )
        try:
            outcome = self.policy.evaluate(self.graph, proposal)
        except Exception as exc:
            outcome = GraphMutationOutcome(
                proposal.proposal_id,
                False,
                self.graph,
                [],
                [f"policy exception: {type(exc).__name__}"],
                fallback_reason="policy-exception",
            )
        state_snapshot = {
            "active_graph_ref": self.runtime.run_state.active_graph_ref,
            "graph_revision_refs": list(self.runtime.run_state.graph_revision_refs),
            "mutation_refs": list(self.runtime.run_state.mutation_refs),
            "checkpoint_counts": dict(self.runtime.run_state.checkpoint_counts),
            "graph_fallback_reason": self.runtime.run_state.graph_fallback_reason,
            "message_refs": list(self.runtime.run_state.message_refs),
        }
        try:
            mutation_refs = self.recorder.persist_mutation(proposal, outcome)
        except Exception as exc:
            for key, value in state_snapshot.items():
                setattr(self.runtime.run_state, key, value)
            self.runtime.run_state.graph_fallback_reason = "mutation-persistence-failed"
            if model_receipt and not model_receipt.terminal_status:
                self.llm_client.record_policy(model_receipt, accepted=False, reasons=["mutation-persistence-failed"])
                self.llm_client.record_fallback(model_receipt, "mutation-persistence-failed")
                self.llm_client.terminalize(model_receipt, "fallback")
            return GraphNodeResult(
                outputs={"checkpoint": "fallback", "model_status": model_status},
                artifact_refs=model_refs,
                correlation_refs=[proposal.proposal_id],
            )
        if outcome.committed:
            self._adopt_graph(outcome.graph)
            outcome.graph = self.graph
            self.revision_records.append({"revision": self.graph.revision})
        self.mutation_records.append(outcome.to_dict())
        if model_receipt and not model_receipt.terminal_status:
            self.llm_client.record_policy(
                model_receipt,
                accepted=outcome.committed,
                reasons=list(outcome.candidate_diagnostics),
            )
            if not outcome.committed:
                self.llm_client.record_fallback(
                    model_receipt,
                    outcome.fallback_reason or "policy-denied",
                    refs=mutation_refs,
                )
            self.llm_client.terminalize(
                model_receipt,
                "accepted" if outcome.committed else "fallback",
                decision_refs=mutation_refs,
            )
        return GraphNodeResult(
            outputs={
                "checkpoint": "committed" if outcome.committed else "fallback",
                "model_status": model_status,
            },
            artifact_refs=model_refs + mutation_refs,
            correlation_refs=[proposal.proposal_id],
        )

    def _graph_model_decision(self, node, checkpoint_id: str) -> tuple[list[str], list[str], Any]:
        task = self._task_for(node)
        completed = (
            self.recon.payload if checkpoint_id == "post-recon" and self.recon else {
                "candidate_count": len(self.candidates),
                "candidate_ids": [item.id for item in self.candidates],
            }
        )
        prompt = render_default_prompt(
            "orchestrator",
            "orchestrator.graph-decision",
            {
                "checkpoint_id": checkpoint_id,
                "completed_stage": completed,
                "available_actions": sorted(CHECKPOINT_ACTIONS[checkpoint_id]),
                "remaining_budgets": {
                    "replans": max(0, self.graph.budgets.max_replans - self.graph.global_replan_count),
                    "checkpoints": max(
                        0,
                        self.graph.budgets.max_checkpoints - sum(self.graph.checkpoint_counts.values()),
                    ),
                },
            },
            self.config.prompts,
        )
        prompt_path = self.runtime.artifacts.write_prompt(prompt, task)
        self.runtime.runtime_refs["prompt_refs"].append(prompt.id or "")
        request = LLMRequest(
            role="orchestrator",
            prompt=prompt.rendered,
            model=self.config.llm.model,
            provider=self.config.llm.provider,
            response_schema=prompt.output_schema,
            response_format="auto",
        )
        receipt = self.llm_client.invoke(request, prompt_ref=prompt_path)
        response = receipt.response
        try:
            validate_json_schema(response.parsed_json, prompt.output_schema)
            actions = parse_graph_decision_payload(
                response.parsed_json,
                checkpoint_id=checkpoint_id,
            )
            self.llm_client.record_schema(receipt, valid=True)
        except Exception as exc:
            self.llm_client.record_schema(receipt, valid=False, errors=[str(exc)])
            self.llm_client.record_fallback(receipt, "schema-invalid")
            self.llm_client.terminalize(receipt, "fallback")
            raise
        llm_path = receipt.response_ref or ""
        self.runtime.runtime_refs["llm_response_refs"].append(response.id or "")
        return actions, [prompt_path, llm_path], receipt

    def _persist_checkpoint_fallback(self, node, checkpoint_id: str, exc: Exception) -> list[str]:
        self.runtime.run_state.graph_fallback_reason = f"model-decision-{type(exc).__name__}"
        path = self.runtime.artifacts.write_json(
            "runtime_errors",
            f"graph-decision-{checkpoint_id}.json",
            {
                "schema_version": "graph-decision-fallback.v1",
                "checkpoint_id": checkpoint_id,
                "fallback_reason": type(exc).__name__,
                "message": str(exc),
            },
            self._task_for(node),
        )
        return [path]

    def _adopt_graph(self, candidate) -> None:
        current = {item.node_id: item for item in self.graph.nodes}
        merged = []
        for candidate_node in candidate.nodes:
            existing = current.get(candidate_node.node_id)
            if existing is None:
                merged.append(candidate_node)
                continue
            existing.__dict__.update(candidate_node.__dict__)
            merged.append(existing)
        for field_name in candidate.__dataclass_fields__:
            if field_name == "nodes":
                continue
            setattr(self.graph, field_name, getattr(candidate, field_name))
        self.graph.nodes = merged

    def _validation(self, node, inputs: dict[str, Any]) -> GraphNodeResult:
        self.runtime._emit_phase("verifying")
        task = self._task_for(node)
        verifier = VerificationEngine(
            self.config,
            self.runtime.run.path,
            llm_client=self.llm_client,
            message_bus=self.runtime.bus,
        )
        staged = []
        verifier.begin_validation_phase(self.metadata)
        for decision in self.decisions:
            for key, values in self.runtime.runtime_refs.items():
                decision.finding.metadata.setdefault(key, [])
                for value in values:
                    if value and value not in decision.finding.metadata[key]:
                        decision.finding.metadata[key].append(value)
            staged.append(
                (
                    decision.finding,
                    verifier.verify(decision, self.metadata, self.config.default_validation_level),
                )
            )
        self.validation_results = verifier.finalize_validation_phase(self.metadata, staged)
        refs = list(verifier.integrity_artifact_refs)
        for result in self.validation_results:
            correlated = [
                *result.attempt_refs,
                *result.poc_refs,
                *result.sandbox_result_refs,
                *result.artifacts,
            ]
            refs.extend(correlated)
            for ref in correlated:
                if ref and ref not in task.correlation_refs:
                    task.correlation_refs.append(ref)
        for ref in refs:
            task.record_artifact(ref)
            self.runtime.run_state.record_artifact(ref)
        refs = list(dict.fromkeys(ref for ref in refs if ref))
        return GraphNodeResult(
            outputs={"validations": self.validation_results},
            artifact_refs=refs,
            correlation_refs=list(task.correlation_refs),
        )

    def _evidence_finalization(self, node, inputs: dict[str, Any]) -> GraphNodeResult:
        builder = EvidenceBuilder(self.runtime.run.path / "evidence")
        traces = [item.trace for item in (self.recon, self.analysis, self.verification) if item]
        handoffs = [item.handoff for item in (self.recon, self.analysis, self.verification) if item]
        self.evidence_chains = [
            builder.build(
                finding=decision.finding,
                metadata=self.metadata,
                tool_results=self.scan_results,
                intelligence=self.intelligence,
                verification=decision,
                validation=validation,
                agent_traces=traces,
                handoffs=handoffs,
            )
            for decision, validation in zip(self.decisions, self.validation_results)
        ]
        refs = [item.id or "" for item in self.evidence_chains]
        return GraphNodeResult(outputs={"evidence": self.evidence_chains}, artifact_refs=refs)

    def _report_finalization(self, node, inputs: dict[str, Any]) -> GraphNodeResult:
        self.runtime._emit_phase("reporting")
        task = self._task_for(node)
        status_counts = verification_status_counts(self.validation_results)
        active = [
            decision
            for decision in self.decisions
            if decision.finding.verification_status
            in {
                VerificationStatus.CONFIRMED,
                VerificationStatus.LIKELY,
                VerificationStatus.MANUAL_REQUIRED,
            }
        ]
        runtime_summary = {
            "dependency_intelligence": self.dependency_intelligence_summary,
            "kernel": {
                "name": "AgentRuntime",
                "state_ref": str(self.runtime.run.path / "runtime_state" / "state.json"),
                "task_count": len(self.runtime.run_state.tasks),
                "roles": sorted({item.role for item in self.runtime.run_state.tasks}),
            },
            "graph": {
                "mode": self.graph.mode,
                "graph_id": self.graph.graph_id,
                "schema_version": self.graph.schema_version,
                "template_id": self.graph.template_id,
                "template_version": self.graph.template_version,
                "template_content_hash": self.graph.template_content_hash,
                "revision": self.graph.revision,
                "initial_graph_ref": self.runtime.run_state.initial_graph_ref,
                "mutation_counts": {
                    "committed": sum(bool(item.get("committed")) for item in self.mutation_records),
                    "denied": sum(not bool(item.get("committed")) for item in self.mutation_records),
                },
                "checkpoint_counts": dict(self.graph.checkpoint_counts),
                "checkpoint_total": sum(self.graph.checkpoint_counts.values()),
                "replan_count": self.graph.global_replan_count,
                "execution_path": list(self.scheduler.execution_path if self.scheduler else []),
                "execution_path_summary": {
                    "node_count": len(self.scheduler.execution_path if self.scheduler else []),
                    "agent_nodes": sum(
                        self.graph.node(node_id).executor_kind == "agent"
                        for node_id in (self.scheduler.execution_path if self.scheduler else [])
                    ),
                    "tool_nodes": sum(
                        self.graph.node(node_id).executor_kind == "tool"
                        for node_id in (self.scheduler.execution_path if self.scheduler else [])
                    ),
                    "service_nodes": sum(
                        self.graph.node(node_id).executor_kind == "service"
                        for node_id in (self.scheduler.execution_path if self.scheduler else [])
                    ),
                },
                "fallback_reason": self.runtime.run_state.graph_fallback_reason,
                "artifact_refs": {
                    "initial_graph_ref": self.runtime.run_state.initial_graph_ref,
                    "active_graph_ref": self.runtime.run_state.active_graph_ref,
                    **self.recorder.expected_final_refs(self.graph),
                    "revision_refs": list(self.runtime.run_state.graph_revision_refs),
                    "transition_refs": list(self.runtime.run_state.graph_transition_refs),
                    "mutation_refs": list(self.runtime.run_state.mutation_refs),
                },
                "verification_correlation": {
                    "node_id": "validation",
                    "graph_attempt_count": self.graph.node("validation").attempt_count,
                    "internal_repair_attempt_count": sum(
                        item.repair_attempt_count for item in self.validation_results
                    ),
                    "artifact_refs": list(self.tasks.get("validation").artifact_refs)
                    if self.tasks.get("validation")
                    else [],
                },
            },
        }
        if self.config.runtime_enabled:
            runtime_summary.update(
                {
                    "llm": {
                        "provider": self.config.llm.provider,
                        "model": self.config.llm.model,
                    },
                    "prompts": {
                        "version": self.config.prompts.default_version,
                        "count": len(self.runtime.runtime_refs["prompt_refs"]),
                    },
                    "mcp": {
                        "enabled": self.config.mcp.enabled,
                        "transport": self.config.mcp.transport,
                        "refs": self.runtime.runtime_refs["mcp_call_refs"],
                    },
                    "memory": {
                        "enabled": self.config.memory.enabled,
                        "mode": self.config.memory.mode,
                        "refs": self.runtime.runtime_refs["memory_refs"],
                    },
                    "llm_decisions": {
                        "enabled": self.config.llm_decisions.enabled,
                        "roles": self.config.llm_decisions.roles,
                        "refs": self.runtime.runtime_refs["decision_refs"],
                    },
                    "message_log": str(
                        self.runtime.run.path
                        / "messages"
                        / self.config.message_bus.log_filename
                    )
                    if self.runtime.bus
                    else "",
                    "token_usage": {"mode": "lifecycle-ledger"},
                }
            )
        runtime_summary["llm_accounting"] = reconcile_llm_lifecycle(
            self.runtime.run.path,
            llm_enabled=bool(self.config.runtime_enabled),
            budget_counters=self.runtime.run_state.llm_accounting or None,
        ).to_dict()
        report = ReportGenerator().build(
            self.metadata,
            [item.finding for item in active],
            self.evidence_chains,
            runtime=runtime_summary,
            verification_candidates=[item.finding for item in self.decisions],
        )
        report_path = self.runtime.artifacts.write_json(
            "reports", "report.json", report.to_dict(), task
        )
        markdown_path = self.runtime.artifacts.write_text(
            "reports", "report.md", ReportGenerator().to_markdown(report), task
        )
        accepted = [item for item in self.decisions if item.decision == "accept"]
        resources = build_run_resource_summary(
            run_id=self.runtime.run.run_id,
            run_dir=self.runtime.run.path,
            metadata=self.metadata,
            run_state=self.runtime.run_state,
            config=self.config,
            validation_results=self.validation_results,
            status_counts=status_counts,
            runtime_refs=self.runtime.runtime_refs,
            terminal_status="succeeded",
            tool_calls_used=self.runtime.tool_broker.runtime.budget.total_used,
        )
        resource_path = self.runtime.artifacts.write_json(
            "reports", "run-resource-summary.v1.json", resources.to_dict(), task
        )
        self.summary = {
            "run_dir": str(self.runtime.run.path),
            "candidate_count": len(self.candidates),
            "rejected_count": len([item for item in self.decisions if item.decision == "reject"]),
            "validated_count": len(accepted),
            **status_counts,
            "validation_level_distribution": {
                self.config.default_validation_level: len(accepted)
            },
            "runtime_state_ref": str(self.runtime.run.path / "runtime_state" / "state.json"),
            "resource_summary_ref": resource_path,
            "source_kind": self.metadata.target.kind,
            "requested_revision": self.metadata.target.requested_revision,
            "resolved_commit": self.metadata.commit,
            "acquisition_ref": self.metadata.target.acquisition_ref,
        }
        return GraphNodeResult(
            outputs={"report": report_path},
            artifact_refs=[report_path, markdown_path, resource_path],
        )


def _runner_counts(validation_results) -> dict[str, int]:
    counts: dict[str, int] = {}
    for result in validation_results:
        runner = str((result.environment or {}).get("runner") or "unknown")
        counts[runner] = counts.get(runner, 0) + 1
    return counts


def default_agent_registry(config: AuditConfig | None = None) -> AgentRegistry:
    registry = AgentRegistry()
    registry.register(
        "orchestrator",
        lambda invocation: AgentOutput(
            role="orchestrator",
            payload={"plan": OrchestratorAgent(invocation.config).plan(invocation.inputs["metadata"])},
            next_actions=["recon"],
        ),
        description="Build audit plan.",
    )
    registry.register(
        "recon",
        lambda invocation: AgentOutput(
            role="recon",
            payload={
                "result": ReconAgent(invocation.config).run(
                    invocation.inputs["metadata"], invocation.inputs.get("intelligence", [])
                )
            },
            next_actions=["analysis"],
        ),
        description="Map project and attack surface.",
    )
    registry.register(
        "analysis",
        lambda invocation: AgentOutput(
            role="analysis",
            payload={
                "result": AnalysisAgent(invocation.config).run_with_trace(
                    invocation.inputs["metadata"],
                    invocation.inputs["recon_handoff"],
                    invocation.inputs["tool_results"],
                    invocation.inputs.get("intelligence", []),
                )
            },
            next_actions=["verification"],
        ),
        description="Generate candidate findings.",
    )
    registry.register(
        "verification",
        lambda invocation: AgentOutput(
            role="verification",
            payload={
                "result": VerificationAgent(invocation.config).run_with_trace(
                    invocation.inputs["candidates"],
                    invocation.inputs["metadata"],
                    invocation.inputs.get("intelligence", []),
                )
            },
            next_actions=["reporting"],
        ),
        description="Verify candidate findings.",
    )
    return registry
