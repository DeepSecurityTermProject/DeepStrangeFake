from __future__ import annotations

import json
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
from .evidence import EvidenceBuilder
from .intelligence import CveMcpAdapter, normalize_cve_mcp_output
from .llm import build_llm_client, persist_llm_artifact, validate_json_schema
from .mcp_client import CveMcpClient
from .memory import LexicalMemoryStore, MemoryIndexer, persist_retrievals
from .message_bus import MessageBus
from .models import LLMRequest, ToolCallResult, stable_id, to_plain, utc_now
from .prompts import persist_prompt, render_default_prompt
from .redaction import redact_secrets
from .reporting import ReportGenerator
from .repository import analyze_target
from .storage import RunContext, RunStore, immutable_path
from .tool_protocol import ToolBudget, ToolRuntime, build_default_tool_registry
from .tools import PatternScanner
from .verification import VerificationEngine, VerificationStatus, verification_status_counts


TERMINAL_RUN_STATUSES = {"succeeded", "failed", "cancelled"}
TERMINAL_TASK_STATUSES = {"succeeded", "failed", "skipped", "fallback"}


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

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id("TSK", self.run_id, self.role, self.kind, self.created_at)

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
    def __init__(self, run: RunContext, bus: MessageBus | None = None, run_state: RunState | None = None):
        self.run = run
        self.bus = bus
        self.run_state = run_state

    def write_json(
        self,
        category: str,
        name: str,
        payload: Any,
        task_state: TaskState | None = None,
        redact: bool = True,
    ) -> str:
        value = redact_secrets(to_plain(payload)) if redact else to_plain(payload)
        path = self.run.write_json_artifact(category, name, value)
        self._record_artifact(path, category, task_state)
        return str(path)

    def write_text(self, category: str, name: str, content: str, task_state: TaskState | None = None) -> str:
        target_dir = self.run.path / category
        target_dir.mkdir(parents=True, exist_ok=True)
        path = immutable_path(target_dir / name)
        path.write_text(content, encoding="utf-8")
        self._record_artifact(path, category, task_state)
        return str(path)

    def write_prompt(self, record, task_state: TaskState | None = None) -> str:
        path = persist_prompt(self.run.path / "prompts", record)
        self._record_artifact(path, "prompts", task_state)
        return str(path)

    def write_llm(self, request: LLMRequest, response, task_state: TaskState | None = None) -> str:
        path = persist_llm_artifact(self.run.path / "llm", request, response)
        self._record_artifact(path, "llm", task_state)
        return str(path)

    def write_decision(self, role: str, proposal, gate=None, merged=None, task_state: TaskState | None = None) -> str:
        path = persist_decision_bundle(self.run.path / "decisions", role, proposal, gate, merged)
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
        budget = ToolBudget(per_agent=config.llm_decisions.tool_budget_per_role or config.tools.per_agent_budgets)
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


class AgentRuntime:
    def __init__(
        self,
        config: AuditConfig | None = None,
        output_dir: str | Path = "runs",
        registry: AgentRegistry | None = None,
    ):
        self.config = config or AuditConfig.default()
        self.output_dir = output_dir
        self.registry = registry or default_agent_registry(self.config)
        self.run: RunContext | None = None
        self.run_state: RunState | None = None
        self.artifacts: ArtifactStore | None = None
        self.bus: MessageBus | None = None
        self.tool_broker: ToolBroker | None = None
        self.runtime_refs: dict[str, list[str]] = {
            "prompt_refs": [],
            "llm_response_refs": [],
            "message_refs": [],
            "memory_refs": [],
            "mcp_call_refs": [],
            "tool_call_refs": [],
            "decision_refs": [],
            "runtime_task_refs": [],
        }

    def run_audit(self, target: str) -> dict[str, Any]:
        config = self.config
        metadata = analyze_target(target, audit_scope=config.audit_scope)
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
        self.artifacts = ArtifactStore(self.run, bus=self.bus, run_state=self.run_state)
        self.tool_broker = ToolBroker(config, self.artifacts, bus=self.bus)
        self.artifacts.write_json("metadata", "repository.json", metadata.to_dict())
        llm_client = build_llm_client(config.llm) if config.runtime_enabled else None

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
        if metadata.dependencies:
            mcp_task = self._start_task("recon", "mcp-intelligence")
            first_dep = metadata.dependencies[0]
            if config.runtime_enabled and config.mcp.enabled:
                cve_client = CveMcpClient(
                    config.mcp.command,
                    config.mcp.timeout_seconds,
                    config.mcp.query_budget,
                    allowed_tools=config.mcp.allowed_tools or config.integration.safe_cve_mcp_tools,
                    cwd=config.mcp.working_dir,
                    env=config.mcp.env,
                )
                intel = cve_client.scan_dependency(first_dep.identifiers)
                intelligence.append(intel)
                mcp_path = self.artifacts.write_json("mcp", "cve-mcp-intelligence.json", intel.to_dict(), mcp_task)
                self.runtime_refs["mcp_call_refs"].append(intel.id or "")
                if self.bus:
                    msg = self.bus.publish(
                        "mcp",
                        "recon",
                        "mcp.call",
                        {"dependency": first_dep.name, "degraded": intel.raw.get("degraded", False), "task_id": mcp_task.id},
                        artifact_refs=[mcp_path],
                    )
                    self._record_message(msg.message_id, mcp_task)
            else:
                cve_adapter = CveMcpAdapter(
                    enabled=config.cve_mcp.enabled,
                    command=config.cve_mcp.command,
                    endpoint=config.cve_mcp.endpoint,
                    env=config.cve_mcp.env,
                    timeout=config.cve_mcp.timeout_seconds,
                    query_budget=config.cve_mcp.query_budget,
                    degraded_mode=config.cve_mcp.degraded_mode,
                )
                mcp_observation = cve_adapter.query("scan_dependencies", first_dep.identifiers)
                self.artifacts.write_json("intelligence", "cve-mcp-observation.json", mcp_observation.to_dict(), mcp_task)
                intelligence.append(
                    normalize_cve_mcp_output(
                        {
                            "cwe_ids": ["CWE-89"],
                            "references": [],
                            "risk_score": 0,
                            "mcp_degraded": mcp_observation.degraded,
                        },
                        query={"dependency": first_dep.name},
                    )
                )
            self._finish_task(mcp_task, output_refs=[item.id or "" for item in intelligence])

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

        runtime_summary = {}
        if config.runtime_enabled:
            runtime_summary = {
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
                "token_usage": {"mode": "recorded-per-llm-artifact"},
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
            }

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
        report = ReportGenerator().build(
            metadata,
            [decision.finding for decision in active_decisions],
            evidence_chains,
            runtime=runtime_summary,
            verification_candidates=[decision.finding for decision in decisions],
        )
        report_path = self.artifacts.write_json("reports", "report.json", report.to_dict(), reporting_task)
        markdown_path = self.artifacts.write_text("reports", "report.md", ReportGenerator().to_markdown(report), reporting_task)
        self._finish_task(reporting_task, output_refs=[report_path, markdown_path])

        summary = {
            "run_dir": str(self.run.path),
            "candidate_count": len(candidates),
            "rejected_count": len([decision for decision in decisions if decision.decision == "reject"]),
            "validated_count": len(accepted),
            **status_counts,
            "validation_level_distribution": {config.default_validation_level: len(accepted)},
            "runtime_state_ref": str(self.run.path / "runtime_state" / "state.json"),
        }
        self.run_state.mark_succeeded(summary)
        self.artifacts.persist_state()
        return summary

    def _build_bus(self, target: str) -> MessageBus | None:
        if self.config.runtime_enabled and self.config.message_bus.enabled and self.run:
            bus = MessageBus(self.run.run_id, self.run.path / "messages" / self.config.message_bus.log_filename)
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
        task.mark_succeeded(output_refs=output_refs or [])
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
        prompt_path = self.artifacts.write_prompt(prompt, task)
        self.runtime_refs["prompt_refs"].append(prompt.id or "")
        request = LLMRequest(
            role=role,
            prompt=prompt.rendered,
            model=self.config.llm.model,
            provider=self.config.llm.provider,
            response_schema=prompt.output_schema,
        )
        response = llm_client.complete(request)
        try:
            validate_json_schema(response.parsed_json, prompt.output_schema)
        except Exception as exc:
            if not self._decision_enabled(role):
                raise
            response.validation_errors.append(str(exc))
            task.mark_fallback("schema-invalid")
        llm_path = self.artifacts.write_llm(request, response, task)
        self.runtime_refs["llm_response_refs"].append(response.id or "")
        if self.bus:
            msg = self.bus.publish(
                role,
                "llm",
                "llm.response",
                {"role": role, "response_id": response.id, "task_id": task.id},
                artifact_refs=[prompt_path, llm_path],
            )
            self._record_message(msg.message_id, task)
        return response, prompt_path, llm_path

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
