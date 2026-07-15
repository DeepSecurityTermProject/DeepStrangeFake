from __future__ import annotations

import json
import os
import time
from collections import Counter
from pathlib import Path
from typing import Any

from .agents import AnalysisAgent, ReconAgent, VerificationAgent
from .config import AuditConfig
from .evidence import EvidenceBuilder
from .evidence_gate import EvidenceGate, signal_to_evidence
from .investigation_models import (
    EvidenceItem,
    InvestigationCheckpoint,
    InvestigationHypothesis,
    InvestigationStep,
    InvestigationSummary,
    PRIMITIVES_BY_CLASS,
    SecuritySignal,
    VerificationPlan,
)
from .investigation_tools import InvestigationActionRegistry, InvestigationToolError, RepositoryView
from .models import (
    AgentHandoff,
    AgentTrace,
    Finding,
    ToolCallResult,
    ToolObservation,
    ToolResult,
    ValidationResult,
    VerificationDecision,
    stable_id,
    to_plain,
)
from .reporting import ReportGenerator
from .resource_summary import build_run_resource_summary
from .storage import RunStore, immutable_path
from .verification import VerificationEngine, VerificationStatus, verification_status_counts
from .verification_plans import TrustedVerificationCompiler, plan_from_payload


def provider_is_usable(config: AuditConfig) -> bool:
    provider = str(config.llm.provider or "").strip().lower()
    model = str(config.llm.model or "").strip().lower()
    if not provider or provider in {"disabled", "none", "off"}:
        return False
    if not model or model in {"disabled", "none", "off"}:
        return False
    if provider == "mock":
        return bool(config.investigation.allow_mock_provider)
    if provider not in {"openai-compatible", "openai", "deepseek-compatible", "ollama-compatible"}:
        return False
    return bool(os.environ.get(config.llm.api_key_env))


class InvestigationBudgetTracker:
    def __init__(self, config):
        self.config = config
        self.started = time.monotonic()
        self.hypotheses = 0
        self.tool_calls = 0
        self.candidates = 0
        self.checkpoints = 0

    def timed_out(self) -> bool:
        return time.monotonic() - self.started >= self.config.absolute_timeout_seconds

    def can_add_hypothesis(self) -> bool:
        return not self.timed_out() and self.hypotheses < self.config.max_hypotheses

    def can_promote(self) -> bool:
        return not self.timed_out() and self.candidates < self.config.max_candidates

    def remaining(self, gateway=None) -> dict[str, int | float | None]:
        elapsed = int(time.monotonic() - self.started)
        requests_used = int(getattr(gateway, "requests_used", 0) or 0)
        tokens_used = int(getattr(gateway, "tokens_used", 0) or 0)
        return {
            "hypotheses": max(0, self.config.max_hypotheses - self.hypotheses),
            "tool_calls_global": max(
                0,
                self.config.max_hypotheses * self.config.max_tool_calls_per_hypothesis - self.tool_calls,
            ),
            "candidates": max(0, self.config.max_candidates - self.candidates),
            "requests": max(0, self.config.request_budget - requests_used),
            "tokens": max(0, self.config.token_budget - tokens_used),
            "known_cost_usd": self.config.cost_budget_usd,
            "seconds": max(0, self.config.absolute_timeout_seconds - elapsed),
        }

    def summary(self, gateway=None) -> dict[str, Any]:
        return {
            "limits": {
                "max_hypotheses": self.config.max_hypotheses,
                "max_rounds_per_hypothesis": self.config.max_rounds_per_hypothesis,
                "max_tool_calls_per_hypothesis": self.config.max_tool_calls_per_hypothesis,
                "max_candidates": self.config.max_candidates,
                "token_budget": self.config.token_budget,
                "request_budget": self.config.request_budget,
                "cost_budget_usd": self.config.cost_budget_usd,
                "absolute_timeout_seconds": self.config.absolute_timeout_seconds,
            },
            "used": {
                "hypotheses": self.hypotheses,
                "tool_calls": self.tool_calls,
                "candidates": self.candidates,
                "requests": int(getattr(gateway, "requests_used", 0) or 0),
                "tokens": int(getattr(gateway, "tokens_used", 0) or 0),
                "known_cost_usd": (
                    float(getattr(gateway, "cost_used_usd", 0.0))
                    if gateway is not None and getattr(gateway, "cost_used_usd", None) is not None
                    else None
                ),
                "elapsed_seconds": int(time.monotonic() - self.started),
            },
            "remaining": self.remaining(gateway),
            "cost_accounting": "unknown-when-provider-does-not-report-cost",
        }


class InvestigationCheckpointStore:
    def __init__(self, run_dir: str | Path):
        self.run_dir = Path(run_dir).resolve()
        self.root = Path(run_dir) / "investigations" / "checkpoints"
        self.root.mkdir(parents=True, exist_ok=True)

    def write(self, checkpoint: InvestigationCheckpoint) -> str:
        path = immutable_path(self.root / f"{checkpoint.sequence:04d}-{checkpoint.checkpoint_id}.json")
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_text(json.dumps(checkpoint.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(path)
        return str(path)

    def load_latest(self, run_id: str) -> tuple[InvestigationCheckpoint | None, list[str]]:
        errors: list[str] = []
        paths = sorted(self.root.glob("*.json"), reverse=True)
        for path in paths:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                checkpoint = InvestigationCheckpoint.from_dict(payload)
                if checkpoint.run_id != run_id:
                    raise ValueError("checkpoint run ID mismatch")
                return checkpoint, errors
            except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
                errors.append(f"{path.name}:{type(exc).__name__}")
        return None, errors

    def restore(
        self, run_id: str
    ) -> tuple[InvestigationCheckpoint | None, list[InvestigationHypothesis], list[InvestigationStep], list[str]]:
        checkpoint, errors = self.load_latest(run_id)
        if checkpoint is None:
            return None, [], [], errors
        hypotheses: list[InvestigationHypothesis] = []
        steps: list[InvestigationStep] = []
        try:
            for ref in checkpoint.hypothesis_refs:
                payload = self._read_ref(ref)
                hypothesis = InvestigationHypothesis.from_dict(payload)
                if hypothesis.run_id != run_id:
                    raise ValueError("restored hypothesis run ID mismatch")
                expected_state = checkpoint.hypothesis_states.get(hypothesis.hypothesis_id or "")
                if expected_state != hypothesis.state:
                    raise ValueError("restored hypothesis state mismatch")
                hypotheses.append(hypothesis)
            for ref in checkpoint.step_refs:
                step = InvestigationStep.from_dict(self._read_ref(ref))
                if step.run_id != run_id:
                    raise ValueError("restored step run ID mismatch")
                steps.append(step)
            completed = {item.action_key for item in steps if item.status == "completed"}
            if not set(checkpoint.completed_action_keys).issubset(completed):
                raise ValueError("checkpoint action keys lack committed step records")
            for ref in [
                *checkpoint.evidence_gate_refs,
                *checkpoint.verification_plan_refs,
                *checkpoint.last_evidence_package_refs,
            ]:
                self._read_ref(ref)
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            errors.append(f"checkpoint-restore:{type(exc).__name__}")
            return None, [], [], errors
        return checkpoint, hypotheses, steps, errors

    def _read_ref(self, ref: str) -> dict[str, Any]:
        path = Path(ref).resolve()
        try:
            path.relative_to(self.run_dir)
        except ValueError as exc:
            raise ValueError("checkpoint artifact ref escapes run directory") from exc
        if not path.is_file():
            raise ValueError("checkpoint artifact ref is missing")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("checkpoint artifact ref must contain an object")
        return payload


class AgentLedInvestigationCoordinator:
    def __init__(self, runtime, target: str, prepared_target=None):
        self.runtime = runtime
        self.config: AuditConfig = runtime.config
        self.target = target
        self.prepared_target = prepared_target
        self.metadata = prepared_target.metadata if prepared_target is not None else None
        self.view: RepositoryView | None = None
        self.actions: InvestigationActionRegistry | None = None
        self.budget = InvestigationBudgetTracker(self.config.investigation)
        self.hypotheses: dict[str, InvestigationHypothesis] = {}
        self.hypothesis_refs: dict[str, str] = {}
        self.steps: list[InvestigationStep] = []
        self.step_refs: list[str] = []
        self.gate_refs: list[str] = []
        self.plan_refs: list[str] = []
        self.package_refs: list[str] = []
        self.completed_action_keys: set[str] = set()
        self.checkpoint_refs: list[str] = []
        self.degraded_reasons: list[str] = []
        self.fallback_reason = ""
        self.tool_results: list[ToolResult] = []
        self.signals: list[SecuritySignal] = []
        self.signal_refs: list[str] = []
        self.gateway = None
        self.checkpoints: InvestigationCheckpointStore | None = None
        self.cancelled = False

    def run(self) -> dict[str, Any]:
        from .repository import analyze_target
        from .runtime import ArtifactStore, RunState, ToolBroker

        if self.metadata is None:
            self.metadata = analyze_target(self.target, audit_scope=self.config.audit_scope)
        store = RunStore(self.runtime.output_dir)
        if self.runtime.resume_run_id:
            if not self.config.investigation.resume_from_checkpoint:
                raise ValueError("agent-led checkpoint resume is disabled by configuration")
            self.runtime.run = store.open_run(self.runtime.resume_run_id)
            self.runtime.run_state = self._load_run_state(RunState)
            if self.runtime.run_state.target != self.target:
                raise ValueError("resume target does not match the original run")
            if self.runtime.run_state.requested_mode != "agent-led":
                raise ValueError("only agent-led runs can resume through this coordinator")
            if self.runtime.run_state.status == "succeeded" and self.runtime.run_state.final_summary:
                return dict(self.runtime.run_state.final_summary)
            self.runtime.run_state.status = "running"
            self.runtime.run_state.finished_at = None
            self.runtime.run_state.error = ""
            self.runtime.run_state.final_summary = {}
        else:
            self.runtime.run = store.create_run(
                self.metadata.target.repo or Path(self.metadata.target.path or self.target).name
            )
            self.runtime.run_state = RunState(
                run_id=self.runtime.run.run_id,
                target=self.target,
                graph_mode="agent-led",
                requested_mode="agent-led",
                effective_mode="agent-led",
                config_summary={
                    "runtime_enabled": True,
                    "llm_provider": self.config.llm.provider,
                    "llm_model": self.config.llm.model,
                    "llm_temperature": 0.0,
                    "agent_led": True,
                    "investigation": to_plain(self.config.investigation),
                },
            )
        self.runtime.bus = self.runtime._build_bus(self.target)
        self.runtime.run_state.mark_running()
        self.runtime.artifacts = ArtifactStore(
            self.runtime.run,
            bus=self.runtime.bus,
            run_state=self.runtime.run_state,
            secret_values=[os.environ.get(self.config.llm.api_key_env, "")],
        )
        self.runtime.tool_broker = ToolBroker(self.config, self.runtime.artifacts, bus=self.runtime.bus)
        if self.prepared_target and self.prepared_target.acquisition:
            acquisition_path = self.runtime.artifacts.write_json(
                "metadata", "acquisition.json", self.prepared_target.acquisition.to_dict()
            )
            self.metadata.target.acquisition_ref = acquisition_path
        self.runtime.artifacts.write_json("metadata", "repository.json", self.metadata.to_dict())
        self.view = RepositoryView(
            self.metadata,
            secret_values=[os.environ.get(self.config.llm.api_key_env, "")],
        )
        self.actions = InvestigationActionRegistry(
            self.metadata,
            run_dir=self.runtime.run.path,
            secret_values=[os.environ.get(self.config.llm.api_key_env, "")],
            max_search_results=self.config.investigation.max_search_results,
            max_context_lines=self.config.investigation.max_context_lines,
            external_timeout=self.config.investigation.external_tool_timeout_seconds,
            external_output_limit=self.config.investigation.external_tool_output_bytes,
            cancelled=lambda: self.runtime.cancellation_token.cancelled,
        )
        self.runtime.artifacts.write_json(
            "investigations", "call-graph.v1.json", self.actions.call_graph.to_dict()
        )
        self.checkpoints = InvestigationCheckpointStore(self.runtime.run.path)
        resumed = self._restore_checkpoint() if self.runtime.resume_run_id else False

        self.config.runtime_enabled = True
        self.config.llm_decisions.enabled = True
        for role in ("analysis", "verification"):
            if role not in self.config.llm_decisions.roles:
                self.config.llm_decisions.roles.append(role)
        self.config.llm.temperature = 0.0
        self.config.llm.request_budget = min(
            self.config.llm.request_budget or self.config.investigation.request_budget,
            self.config.investigation.request_budget,
        )
        self.config.llm.token_budget = min(
            self.config.llm.token_budget,
            self.config.investigation.token_budget,
        )
        configured_cost = self.config.llm.cost_budget_usd
        investigation_cost = self.config.investigation.cost_budget_usd
        if investigation_cost is not None:
            self.config.llm.cost_budget_usd = (
                investigation_cost
                if configured_cost is None
                else min(float(configured_cost), float(investigation_cost))
            )
        if resumed:
            pattern_result, pattern_ref = self._restore_signal_seed()
        else:
            scan_task = self.runtime._start_task("analysis", "security-signal-seed")
            pattern_result = self.runtime.tool_broker.dispatch(
                "analysis", "pattern-scan", {}, metadata=self.metadata, task_state=scan_task
            )
            pattern_ref = self.runtime.artifacts.write_json(
                "tool_outputs", "pattern-signals.json", pattern_result.to_dict(), scan_task
            )
            self.tool_results.append(_tool_result_from_call(pattern_result, "pattern-scanner"))
            self._materialize_signals(pattern_result, pattern_ref)
            self.runtime._finish_task(scan_task, output_refs=[pattern_ref, *self.signal_refs])

        if self._check_cancelled():
            self._checkpoint("cancelled-after-signal-seed")
            return self._finalize_report([], [], [], [])

        try:
            self.gateway = self.runtime._build_audited_llm_client()
        except Exception as exc:
            self._degrade(f"provider-initialization-failure:{type(exc).__name__}")
            self.fallback_reason = self.degraded_reasons[-1]
            self._checkpoint("provider-initialization-fallback")
            return self._deterministic_fallback_in_place(pattern_result)

        analysis_task = self.runtime._start_task("analysis", "agent-led-investigation-resume" if resumed else "agent-led-investigation")
        initial_failed = False
        response = None
        if not self.hypotheses:
            try:
                payload, response = self._analysis_call(analysis_task, tool_observations=[])
                if self._check_cancelled():
                    self._terminalize_response(response, False, [], "cancelled")
                    self.runtime._finish_task(analysis_task)
                    self._checkpoint("cancelled-after-model-response")
                    return self._finalize_report([], [], [], [])
                initial_updates = self._accept_new_hypotheses(payload.get("hypotheses", []))
                self._process_updates([*initial_updates, *payload.get("updates", [])], response, analysis_task)
                self._terminalize_response(response, True, self.hypothesis_refs.values())
            except Exception as exc:
                if response is not None:
                    self._terminalize_response(response, False, [], "analysis-response-rejected")
                initial_failed = True
                self._degrade(f"analysis-initial-failure:{type(exc).__name__}")

        if initial_failed and not self.hypotheses:
            if self._check_cancelled():
                self.runtime._finish_task(analysis_task)
                return self._finalize_report([], [], [], [])
            self.fallback_reason = self.degraded_reasons[-1]
            self.runtime._finish_task(analysis_task)
            if resumed:
                return self._finalize_report([], [], [], [])
            return self._deterministic_fallback_in_place(pattern_result)

        while self._active_hypotheses() and not self.budget.timed_out():
            if self._check_cancelled():
                break
            response = None
            try:
                payload, response = self._analysis_call(
                    analysis_task,
                    tool_observations=[self._step_summary(item) for item in self.steps[-20:]],
                )
                if self._check_cancelled():
                    self._terminalize_response(response, False, [], "cancelled")
                    break
                new_updates = self._accept_new_hypotheses(payload.get("hypotheses", []))
                self._process_updates([*new_updates, *payload.get("updates", [])], response, analysis_task)
                self._terminalize_response(response, True, self.step_refs[-20:])
            except Exception as exc:
                if response is not None:
                    self._terminalize_response(response, False, [], "analysis-response-rejected")
                if self._check_cancelled():
                    break
                self._degrade(f"analysis-midrun-failure:{type(exc).__name__}")
                self._converge_committed_evidence()
                break
            if not payload.get("updates") and not payload.get("hypotheses"):
                self._degrade("analysis-no-progress")
                self._converge_committed_evidence()
                break
            active_after_update = self._active_hypotheses()
            if active_after_update and all(
                item.round_count >= self.config.investigation.max_rounds_per_hypothesis
                or item.tool_call_count >= self.config.investigation.max_tool_calls_per_hypothesis
                for item in active_after_update
            ):
                self._degrade("investigation-hypothesis-budget-exhausted")
                self._converge_committed_evidence()
                break

        if self.budget.timed_out():
            self._degrade("investigation-absolute-timeout")
            self._converge_committed_evidence()

        self._persist_all_hypotheses()
        self._checkpoint("analysis-complete")
        self.runtime._finish_task(analysis_task, output_refs=[*self.hypothesis_refs.values(), *self.step_refs])
        return self._verify_and_report()

    def _analysis_call(self, task, tool_observations: list[dict[str, Any]]):
        payload_state = [
            {
                "hypothesis_id": item.hypothesis_id,
                "vulnerability_class": item.vulnerability_class,
                "claim": item.claim,
                "target_paths": item.target_paths,
                "state": item.state,
                "round_count": item.round_count,
                "tool_call_count": item.tool_call_count,
                "evidence_refs": [evidence.evidence_id for evidence in item.evidence],
            }
            for item in self.hypotheses.values()
        ]
        response, _prompt_ref, _llm_ref = self.runtime._run_llm_role(
            task,
            self.gateway,
            "analysis",
            "analysis.investigation",
            {
                "repository_summary": self.metadata.to_dict(),
                "bootstrap_source_context": self.view.bootstrap_context(
                    max_files=self.config.investigation.max_bootstrap_files,
                    max_lines_per_file=self.config.investigation.max_bootstrap_lines_per_file,
                    max_bytes=self.config.investigation.max_bootstrap_bytes,
                ),
                "security_signals": [item.to_dict() for item in self.signals],
                "hypothesis_state": payload_state,
                "tool_observations": tool_observations,
                "remaining_budgets": self.budget.remaining(self.gateway),
                "allowed_actions": self.actions.declarations(),
            },
        )
        try:
            payload = self._parse_analysis_payload(response.parsed_json)
        except Exception:
            self._terminalize_response(response, False, [], "schema-invalid")
            task.mark_fallback("schema-invalid")
            raise
        return payload, response

    def _parse_analysis_payload(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("analysis investigation response must be an object")
        allowed = {"hypotheses", "updates", "rationale"}
        unknown = set(payload) - allowed
        if unknown:
            raise ValueError(f"analysis response contains forbidden/unknown fields: {sorted(unknown)}")
        required = {"hypotheses", "rationale"}
        if not required.issubset(payload):
            raise ValueError("analysis response is missing required fields")
        payload = dict(payload)
        payload.setdefault("updates", [])
        if not isinstance(payload["hypotheses"], list) or not isinstance(payload["updates"], list):
            raise ValueError("analysis hypotheses and updates must be arrays")
        return payload

    def _accept_new_hypotheses(self, proposals: list[dict[str, Any]]) -> list[dict[str, Any]]:
        required_fields = {
            "vulnerability_class",
            "claim",
            "target_paths",
            "confidence",
            "rationale",
            "signal_refs",
        }
        allowed_fields = {*required_fields, "next_action"}
        first_updates: list[dict[str, Any]] = []
        signal_map = {item.signal_id: item for item in self.signals}
        existing_keys = {
            (item.vulnerability_class, item.claim.strip().lower(), tuple(sorted(item.target_paths)))
            for item in self.hypotheses.values()
        }
        for proposal in proposals:
            if not self.budget.can_add_hypothesis():
                self._degrade("investigation-hypothesis-ceiling")
                return first_updates
            if (
                not isinstance(proposal, dict)
                or not required_fields.issubset(proposal)
                or set(proposal) - allowed_fields
            ):
                raise ValueError("hypothesis proposal contains unknown authority or missing fields")
            target_paths = [str(item).replace("\\", "/") for item in proposal["target_paths"]]
            for path in target_paths:
                self.view.resolve(path)
            key = (
                str(proposal["vulnerability_class"]),
                str(proposal["claim"]).strip().lower(),
                tuple(sorted(target_paths)),
            )
            if key in existing_keys:
                continue
            hypothesis = InvestigationHypothesis(
                run_id=self.runtime.run.run_id,
                vulnerability_class=str(proposal["vulnerability_class"]),
                claim=str(proposal["claim"]),
                target_paths=target_paths,
                rationale=str(proposal["rationale"]),
                confidence=float(proposal["confidence"]),
                signal_refs=[str(item) for item in proposal["signal_refs"] if str(item) in signal_map],
            )
            for signal_ref in hypothesis.signal_refs:
                hypothesis.evidence.append(signal_to_evidence(signal_map[signal_ref]))
            hypothesis.transition("investigating")
            self.hypotheses[hypothesis.hypothesis_id or ""] = hypothesis
            existing_keys.add(key)
            self.budget.hypotheses += 1
            hypothesis_ref = self._persist_hypothesis(hypothesis)
            self._publish_investigation_event(
                "investigation.hypothesis",
                {
                    "role": "analysis",
                    "hypothesis_id": hypothesis.hypothesis_id,
                    "vulnerability_class": hypothesis.vulnerability_class,
                    "claim": hypothesis.claim,
                    "rationale_summary": hypothesis.rationale,
                    "target_paths": hypothesis.target_paths,
                    "confidence": hypothesis.confidence,
                    "state": hypothesis.state,
                    "evidence_count": len(hypothesis.evidence),
                },
                [hypothesis_ref],
            )
            self._checkpoint("hypothesis-proposed")
            if "next_action" in proposal:
                action = proposal["next_action"]
                if not isinstance(action, dict) or set(action) != {"action", "arguments"}:
                    raise ValueError("new hypothesis next_action must contain only action and arguments")
                first_updates.append(
                    {
                        "hypothesis_id": hypothesis.hypothesis_id,
                        "assessment": "investigating",
                        "next_action": action,
                        "evidence_refs": [],
                    }
                )
        return first_updates

    def _process_updates(self, updates: list[dict[str, Any]], response, task) -> None:
        update_fields = {"hypothesis_id", "assessment", "next_action", "evidence_refs"}
        for update in updates:
            if not isinstance(update, dict) or set(update) != update_fields:
                raise ValueError("hypothesis update contains unknown authority or missing fields")
            hypothesis = self.hypotheses.get(str(update["hypothesis_id"]))
            if not hypothesis or hypothesis.state not in {"investigating", "refine"}:
                raise ValueError("hypothesis update references unknown or terminal hypothesis")
            if hypothesis.round_count >= self.config.investigation.max_rounds_per_hypothesis:
                self._budget_step(hypothesis, "round-budget-exhausted", task, response)
                continue
            action_payload = update["next_action"]
            if not isinstance(action_payload, dict) or set(action_payload) != {"action", "arguments"}:
                raise ValueError("next_action must contain only action and arguments")
            action = str(action_payload["action"])
            arguments = action_payload["arguments"]
            assessment = str(update["assessment"])
            if assessment not in {"investigating", "supported", "refuted", "inconclusive"}:
                raise ValueError("invalid hypothesis assessment")
            if hypothesis.state == "refine":
                hypothesis.transition("investigating")
            hypothesis.round_count += 1
            if action not in {"submit_gate", "abandon"}:
                if hypothesis.tool_call_count >= self.config.investigation.max_tool_calls_per_hypothesis:
                    self._budget_step(hypothesis, "tool-budget-exhausted", task, response)
                    continue
                output = self.actions.dispatch(action, arguments)
                action_key = output["action_key"]
                if action_key not in self.completed_action_keys:
                    hypothesis.tool_call_count += 1
                    self.budget.tool_calls += 1
                    hypothesis.evidence.extend(self._evidence_from_output(output, hypothesis))
                    self.completed_action_keys.add(action_key)
                step = self._new_step(hypothesis, action, arguments, output, response, "completed")
                self._persist_step(step)
            else:
                action_key = stable_id("ACT", action, hypothesis.hypothesis_id, hypothesis.round_count)
                output = {"action": action, "action_key": action_key, "evidence": [], "control": action}
                step = self._new_step(hypothesis, action, arguments, output, response, "completed")
                self._persist_step(step)
                self.completed_action_keys.add(action_key)

            if assessment == "refuted" or action == "abandon":
                hypothesis.transition("refuted" if hypothesis.state == "investigating" else "rejected")
                if hypothesis.state == "refuted":
                    hypothesis.transition("rejected")
            elif action == "submit_gate":
                if hypothesis.state == "investigating":
                    hypothesis.transition("supported" if assessment == "supported" else "inconclusive")
                if hypothesis.state == "inconclusive" and assessment != "supported":
                    hypothesis.transition("refine")
                else:
                    hypothesis.transition("evidence-gate")
                    self._gate(hypothesis)
            hypothesis_ref = self._persist_hypothesis(hypothesis)
            self._publish_investigation_event(
                "investigation.hypothesis",
                {
                    "role": "analysis",
                    "hypothesis_id": hypothesis.hypothesis_id,
                    "vulnerability_class": hypothesis.vulnerability_class,
                    "claim": hypothesis.claim,
                    "rationale_summary": hypothesis.rationale,
                    "target_paths": hypothesis.target_paths,
                    "confidence": hypothesis.confidence,
                    "state": hypothesis.state,
                    "evidence_count": len(hypothesis.evidence),
                },
                [hypothesis_ref],
            )
            self._checkpoint("investigation-step")

    def _gate(self, hypothesis: InvestigationHypothesis) -> None:
        if not self.budget.can_promote():
            hypothesis.transition("rejected")
            self._degrade("investigation-candidate-ceiling")
            return
        result = EvidenceGate(self.view).evaluate(hypothesis)
        if result.decision.state == "promoted":
            hypothesis.transition("promoted")
            self.budget.candidates += 1
        elif result.decision.state == "refine":
            hypothesis.transition("refine")
        else:
            hypothesis.transition("rejected")
        package_ref = None
        if result.evidence_package:
            result.evidence_package.gate_ref = result.decision.gate_id
            package_ref = self.runtime.artifacts.write_json(
                "evidence-gates",
                f"package-{result.evidence_package.package_id}.json",
                result.evidence_package.to_dict(),
            )
            self.package_refs.append(package_ref)
            result.decision.evidence_package_ref = package_ref
            if result.finding:
                result.finding.metadata["evidence_package_ref"] = package_ref
        gate_ref = self.runtime.artifacts.write_json(
            "evidence-gates", f"gate-{result.decision.gate_id}.json", result.decision.to_dict()
        )
        self.gate_refs.append(gate_ref)
        hypothesis_ref = self._persist_hypothesis(hypothesis)
        self._publish_investigation_event(
            "investigation.evidence-gate",
            {
                "role": "verification",
                "hypothesis_id": hypothesis.hypothesis_id,
                "gate_id": result.decision.gate_id,
                "state": result.decision.state,
                "evidence_count": len(hypothesis.evidence),
            },
            [gate_ref, *([package_ref] if package_ref else [])],
        )
        if result.finding and result.evidence_package:
            result.finding.metadata.update(
                {
                    "evidence_gate_ref": gate_ref,
                    "hypothesis_ref": hypothesis_ref,
                    "normative_package": result.evidence_package,
                }
            )

    def _converge_committed_evidence(self) -> None:
        for hypothesis in list(self.hypotheses.values()):
            if hypothesis.state not in {"investigating", "refine", "inconclusive", "supported"}:
                continue
            if hypothesis.state == "refine":
                hypothesis.transition("investigating")
            if hypothesis.state == "investigating":
                hypothesis.transition("supported" if len(hypothesis.evidence) >= 2 else "inconclusive")
            if hypothesis.state == "inconclusive":
                hypothesis.transition("evidence-gate")
            elif hypothesis.state == "supported":
                hypothesis.transition("evidence-gate")
            self._gate(hypothesis)

    def _verify_and_report(self) -> dict[str, Any]:
        findings: list[Finding] = []
        decisions: list[VerificationDecision] = []
        validations: list[ValidationResult] = []
        evidence_chains = []
        verification_task = self.runtime._start_task("verification", "trusted-plan")
        compiler = TrustedVerificationCompiler(
            self.config, self.view, self.runtime.run.path
        )
        promoted = [item for item in self.hypotheses.values() if item.state == "promoted"]
        if self._check_cancelled():
            promoted = []
        for hypothesis in promoted:
            gate_payload, gate_ref = self._gate_payload_for(hypothesis.hypothesis_id or "")
            package_ref = gate_payload.get("evidence_package_ref")
            if not package_ref or not Path(package_ref).is_file():
                continue
            from .investigation_models import VerificationEvidencePackage

            package = VerificationEvidencePackage.from_dict(
                json.loads(Path(package_ref).read_text(encoding="utf-8"))
            )
            finding = self._finding_for_package(package, gate_ref)
            plan = None
            response = None
            try:
                response, _prompt_ref, _llm_ref = self.runtime._run_llm_role(
                    verification_task,
                    self.gateway,
                    "verification",
                    "verification.plan",
                    {
                        "evidence_package": package.to_dict(),
                        "registered_primitives": {
                            key: sorted(value) for key, value in PRIMITIVES_BY_CLASS.items()
                        },
                    },
                )
                plan = plan_from_payload(
                    response.parsed_json,
                    run_id=self.runtime.run.run_id,
                    candidate_id=package.candidate_id,
                    vulnerability_class=package.vulnerability_class,
                    evidence_package_ref=package_ref,
                )
                if len(plan.primitives) != 1:
                    raise ValueError("phase-one verification requires exactly one primitive")
            except Exception as exc:
                if self._check_cancelled():
                    break
                self._degrade(f"verification-plan-fallback:{type(exc).__name__}")
                plan = compiler.default_plan(package, package_ref)
                if response is not None:
                    self._terminalize_response(response, False, [], "verification-plan-fallback")
            plan_ref = self.runtime.artifacts.write_json(
                "verification-plans", f"plan-{plan.plan_id}.json", plan.to_dict(), verification_task
            )
            self.plan_refs.append(plan_ref)
            if response is not None:
                self._terminalize_response(response, True, [plan_ref])
            try:
                compiled = compiler.compile(plan, package, finding)
                validation = compiler.execute(
                    compiled,
                    package,
                    self.metadata,
                    llm_client=self.gateway if self.config.poc_repair.enabled else None,
                    message_bus=self.runtime.bus,
                    cancellation_token=self.runtime.cancellation_token,
                )
                decision = compiled.decision
            except Exception as exc:
                reason = f"Trusted verification plan denied: {type(exc).__name__}"
                decision = VerificationDecision(
                    finding=finding,
                    decision="reject",
                    reason=reason,
                    confidence=0.0,
                    validation_level="manual",
                    decision_source="trusted-verification-compiler",
                    policy_gate={"status": "denied", "reason": reason},
                )
                validation = ValidationResult(
                    finding_id=finding.id or "",
                    level="manual",
                    status=VerificationStatus.MANUAL_REQUIRED,
                    verification_status=VerificationStatus.MANUAL_REQUIRED,
                    verification_reason=reason,
                    message=reason,
                    artifacts=[plan_ref],
                )
                finding.verification_status = VerificationStatus.MANUAL_REQUIRED
                finding.verification_reason = reason
            if self._check_cancelled():
                break
            findings.append(finding)
            decisions.append(decision)
            validations.append(validation)
            chain = EvidenceBuilder(self.runtime.run.path / "evidence").build(
                finding,
                self.metadata,
                self.tool_results,
                [],
                decision,
                validation,
                [],
                [],
            )
            evidence_chains.append(chain)
        self.runtime._finish_task(verification_task, output_refs=[*self.plan_refs])
        return self._finalize_report(findings, decisions, validations, evidence_chains)

    def _deterministic_fallback_in_place(self, pattern_result_call) -> dict[str, Any]:
        self.runtime.run_state.effective_mode = "deterministic-graph"
        self._emit("scanning")
        scan_task = self.runtime._start_task("analysis", "deterministic-fallback-scan")
        dataflow_call = self.runtime.tool_broker.dispatch(
            "analysis", "dataflow-scan", {}, metadata=self.metadata, task_state=scan_task
        )
        dataflow_result = _tool_result_from_call(dataflow_call, "dataflow-scanner")
        pattern_result = _tool_result_from_call(pattern_result_call, "pattern-scanner")
        self.tool_results.extend([dataflow_result])
        self.runtime._finish_task(scan_task, output_refs=[dataflow_call.id or ""])
        recon = ReconAgent(self.config).run(self.metadata, intelligence=[])
        analysis = AnalysisAgent(self.config).run_with_trace(
            self.metadata, recon.handoff, [dataflow_result, pattern_result], intelligence=[]
        )
        candidates = analysis.payload["candidates"]
        verification = VerificationAgent(self.config).run_with_trace(
            candidates, self.metadata, intelligence=[]
        )
        decisions = verification.decisions
        engine = VerificationEngine(self.config, self.runtime.run.path)
        engine.begin_validation_phase(self.metadata)
        provisional = [
            (decision.finding, engine.verify(decision, self.metadata, decision.validation_level))
            for decision in decisions
        ]
        validations = engine.finalize_validation_phase(self.metadata, provisional)
        chains = []
        for decision, validation in zip(decisions, validations):
            chains.append(
                EvidenceBuilder(self.runtime.run.path / "evidence").build(
                    decision.finding,
                    self.metadata,
                    self.tool_results,
                    [],
                    decision,
                    validation,
                    [recon.trace, analysis.trace, verification.trace],
                    [recon.handoff, analysis.handoff, verification.handoff],
                )
            )
        return self._finalize_report(candidates, decisions, validations, chains)

    def _finalize_report(
        self,
        findings: list[Finding],
        decisions: list[VerificationDecision],
        validations: list[ValidationResult],
        evidence_chains,
    ) -> dict[str, Any]:
        self._emit("reporting")
        if self.checkpoints is not None:
            self._checkpoint("terminal-cancelled" if self.cancelled else "terminal-complete")
        status_counts = verification_status_counts(validations)
        summary_model = InvestigationSummary(
            requested_mode="agent-led",
            effective_mode=self.runtime.run_state.effective_mode,
            hypothesis_counts=dict(Counter(item.state for item in self.hypotheses.values())),
            evidence_gate_counts=self._gate_counts(),
            verification_plan_refs=list(self.plan_refs),
            fallback_reason=self.fallback_reason,
            degraded_reasons=list(self.degraded_reasons),
            investigation_budget=self.budget.summary(self.gateway),
            checkpoint_summary={
                "count": len(self.checkpoint_refs),
                "latest_ref": self.checkpoint_refs[-1] if self.checkpoint_refs else None,
                "completed_action_count": len(self.completed_action_keys),
            },
        )
        self.runtime.run_state.fallback_reason = self.fallback_reason
        self.runtime.run_state.degraded_reasons = list(self.degraded_reasons)
        self.runtime.run_state.hypothesis_counts = summary_model.hypothesis_counts
        self.runtime.run_state.evidence_gate_counts = summary_model.evidence_gate_counts
        self.runtime.run_state.verification_plan_refs = list(self.plan_refs)
        self.runtime.run_state.investigation_budget = summary_model.investigation_budget
        self.runtime.run_state.checkpoint_summary = summary_model.checkpoint_summary
        runtime_summary = {
            "status": "cancelled" if self.cancelled else "degraded" if self.degraded_reasons else "succeeded",
            "investigation": summary_model.to_dict(),
            "llm_accounting": self._reconcile_accounting(),
            "kernel": {
                "name": "AgentLedInvestigationCoordinator",
                "state_ref": str(self.runtime.run.path / "runtime_state" / "state.json"),
                "task_count": len(self.runtime.run_state.tasks),
                "roles": sorted({task.role for task in self.runtime.run_state.tasks}),
            },
        }
        report_task = self.runtime._start_task("reporting", "service")
        report = ReportGenerator().build(
            self.metadata,
            [finding for finding in findings if finding.verification_status != VerificationStatus.REJECTED],
            evidence_chains,
            runtime=runtime_summary,
            verification_candidates=findings,
        )
        report.run_status = "cancelled" if self.cancelled else "degraded" if self.degraded_reasons else "completed"
        report_ref = self.runtime.artifacts.write_json(
            "reports", "report.json", report.to_dict(), report_task
        )
        markdown_ref = self.runtime.artifacts.write_text(
            "reports", "report.md", ReportGenerator().to_markdown(report), report_task
        )
        terminal = "cancelled" if self.cancelled else "degraded" if self.degraded_reasons else "succeeded"
        resource = build_run_resource_summary(
            run_id=self.runtime.run.run_id,
            run_dir=self.runtime.run.path,
            metadata=self.metadata,
            run_state=self.runtime.run_state,
            config=self.config,
            validation_results=validations,
            status_counts=status_counts,
            runtime_refs=self.runtime.runtime_refs,
            terminal_status=terminal,
            tool_calls_used=self.budget.tool_calls,
        )
        resource_ref = self.runtime.artifacts.write_json(
            "reports", "run-resource-summary.v1.json", resource.to_dict(), report_task
        )
        self.runtime._finish_task(report_task, output_refs=[report_ref, markdown_ref, resource_ref])
        summary = {
            "status": terminal,
            "run_dir": str(self.runtime.run.path),
            "candidate_count": len(findings),
            "rejected_count": status_counts.get("rejected_count", 0),
            "validated_count": len(
                [item for item in validations if item.verification_status == VerificationStatus.CONFIRMED]
            ),
            **status_counts,
            "requested_mode": "agent-led",
            "effective_mode": self.runtime.run_state.effective_mode,
            "fallback_reason": self.fallback_reason,
            "degraded_reasons": list(self.degraded_reasons),
            "hypothesis_counts": summary_model.hypothesis_counts,
            "evidence_gate_counts": summary_model.evidence_gate_counts,
            "verification_plan_refs": list(self.plan_refs),
            "investigation_budget": summary_model.investigation_budget,
            "checkpoint_summary": summary_model.checkpoint_summary,
            "runtime_state_ref": str(self.runtime.run.path / "runtime_state" / "state.json"),
            "resource_summary_ref": resource_ref,
            "report_ref": report_ref,
            "source_kind": self.metadata.target.kind,
            "requested_revision": self.metadata.target.requested_revision,
            "resolved_commit": self.metadata.commit,
            "acquisition_ref": self.metadata.target.acquisition_ref,
        }
        if self.cancelled:
            self.runtime.run_state.mark_cancelled(summary)
        elif self.degraded_reasons:
            self.runtime.run_state.mark_degraded(summary, self.degraded_reasons)
        else:
            self.runtime.run_state.mark_succeeded(summary)
        self.runtime.artifacts.persist_state()
        return summary

    def _load_run_state(self, state_type):
        candidates = list((self.runtime.run.path / "runtime_state").glob("state*.json"))
        if not candidates:
            raise ValueError("resume run has no persisted runtime state")
        errors: list[str] = []
        for path in sorted(candidates, key=lambda item: item.stat().st_mtime_ns, reverse=True):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                state = state_type.from_dict(payload)
                if state.run_id != self.runtime.run.run_id:
                    raise ValueError("runtime state run ID mismatch")
                return state
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
                errors.append(f"{path.name}:{type(exc).__name__}")
        raise ValueError(f"resume runtime state is invalid: {','.join(errors)}")

    def _restore_checkpoint(self) -> bool:
        checkpoint, hypotheses, steps, errors = self.checkpoints.restore(self.runtime.run.run_id)
        recovery = {
            "run_id": self.runtime.run.run_id,
            "requested": True,
            "restored": checkpoint is not None,
            "errors": errors,
            "checkpoint_id": checkpoint.checkpoint_id if checkpoint else None,
        }
        self.runtime.artifacts.write_json("investigations", "checkpoint-recovery.json", recovery)
        if checkpoint is None:
            raise ValueError("no valid checkpoint is available for the requested resume")
        self.hypotheses = {item.hypothesis_id or "": item for item in hypotheses}
        self.hypothesis_refs = dict(zip(self.hypotheses, checkpoint.hypothesis_refs))
        self.steps = list(steps)
        self.step_refs = list(checkpoint.step_refs)
        self.gate_refs = list(checkpoint.evidence_gate_refs)
        self.plan_refs = list(checkpoint.verification_plan_refs)
        self.package_refs = list(checkpoint.last_evidence_package_refs)
        self.completed_action_keys = set(checkpoint.completed_action_keys)
        self.checkpoint_refs = [str(item) for item in sorted(self.checkpoints.root.glob("*.json"))]
        self.budget.checkpoints = checkpoint.sequence
        self.budget.hypotheses = self.config.investigation.max_hypotheses - int(
            checkpoint.remaining_budget.get("hypotheses", self.config.investigation.max_hypotheses) or 0
        )
        global_tool_limit = (
            self.config.investigation.max_hypotheses
            * self.config.investigation.max_tool_calls_per_hypothesis
        )
        self.budget.tool_calls = global_tool_limit - int(
            checkpoint.remaining_budget.get("tool_calls_global", global_tool_limit) or 0
        )
        self.budget.candidates = self.config.investigation.max_candidates - int(
            checkpoint.remaining_budget.get("candidates", self.config.investigation.max_candidates) or 0
        )
        self.actions.restore_completed_actions(steps)
        return True

    def _restore_signal_seed(self) -> tuple[ToolCallResult, str]:
        paths = sorted((self.runtime.run.path / "tool_outputs").glob("pattern-signals*.json"))
        if not paths:
            raise ValueError("resume checkpoint lacks its committed signal seed")
        path = paths[0]
        payload = json.loads(path.read_text(encoding="utf-8"))
        observations = [
            ToolObservation(**{
                key: value for key, value in item.items()
                if key in ToolObservation.__dataclass_fields__
            })
            for item in payload.get("observations", [])
            if isinstance(item, dict)
        ]
        values = {
            key: value for key, value in payload.items()
            if key in ToolCallResult.__dataclass_fields__ and key != "observations"
        }
        values["observations"] = observations
        result = ToolCallResult(**values)
        self.tool_results.append(_tool_result_from_call(result, "pattern-scanner"))
        for signal_path in sorted((self.runtime.run.path / "signals").glob("*.json")):
            try:
                signal = SecuritySignal.from_dict(json.loads(signal_path.read_text(encoding="utf-8")))
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
            self.signals.append(signal)
            self.signal_refs.append(str(signal_path))
        return result, str(path)

    def _materialize_signals(self, result, result_ref: str) -> None:
        observations = getattr(result, "observations", [])
        for observation in observations:
            if not observation.path or not observation.line or not observation.vulnerability_class:
                continue
            if observation.vulnerability_class not in {
                "sql-injection", "command-injection", "path-traversal", "hardcoded-secret"
            }:
                continue
            try:
                local = self.view.source_evidence(
                    observation.path,
                    observation.line,
                    origin="source",
                    vulnerability_class=observation.vulnerability_class,
                    message=observation.message,
                )
            except InvestigationToolError:
                continue
            signal = SecuritySignal(
                run_id=self.runtime.run.run_id,
                vulnerability_class=observation.vulnerability_class,
                path=local.path or "",
                line=local.start_line or 1,
                excerpt=local.excerpt,
                content_hash=local.content_hash,
                severity=observation.severity or "medium",
                observation_ref=result_ref,
            )
            ref = self.runtime.artifacts.write_json(
                "signals", f"{signal.signal_id}.json", signal.to_dict()
            )
            self.signals.append(signal)
            self.signal_refs.append(ref)

    def _evidence_from_output(
        self, output: dict[str, Any], hypothesis: InvestigationHypothesis
    ) -> list[EvidenceItem]:
        items: list[EvidenceItem] = []
        for payload in output.get("evidence", []):
            try:
                item = EvidenceItem.from_dict(payload)
            except ValueError:
                continue
            if item.vulnerability_class and item.vulnerability_class != hypothesis.vulnerability_class:
                continue
            if item.path and item.path not in hypothesis.target_paths:
                # Call/dataflow corroboration may legitimately sit on another
                # path only when it carries an explicit edge/trace.
                if item.origin not in {"call-graph", "dataflow"}:
                    continue
            item.vulnerability_class = item.vulnerability_class or hypothesis.vulnerability_class
            items.append(item)
        result = ToolResult(
            tool_name=str(output.get("action") or "investigation-tool"),
            inputs={"action_key": output.get("action_key")},
            success=str(output.get("status") or "ok") in {"", "ok"},
            duration_ms=int(output.get("duration_ms") or 0),
            observations=[
                ToolObservation(
                    tool_name=str(output.get("action") or "investigation-tool"),
                    kind=item.origin,
                    message=item.message,
                    path=item.path,
                    line=item.start_line,
                    vulnerability_class=item.vulnerability_class,
                    evidence=item.excerpt,
                    success=item.success,
                    degraded=str(output.get("status") or "ok") != "ok",
                    raw={"evidence_id": item.evidence_id, **item.raw},
                )
                for item in items
            ],
            message=str(output.get("message") or ""),
        )
        self.tool_results.append(result)
        return items

    def _new_step(self, hypothesis, action, arguments, output, response, status):
        receipt = self.gateway.receipt_for_response(response.id or "") if response else None
        return InvestigationStep(
            run_id=self.runtime.run.run_id,
            hypothesis_id=hypothesis.hypothesis_id or "",
            round_index=hypothesis.round_count,
            action=action,
            arguments=arguments,
            action_key=output["action_key"],
            status=status,
            observation_refs=[item.get("evidence_id", "") for item in output.get("evidence", [])],
            prompt_ref=self.runtime.runtime_refs["prompt_refs"][-1] if self.runtime.runtime_refs["prompt_refs"] else None,
            response_ref=response.id if response else None,
            request_group_id=receipt.request_group_id if receipt else None,
            provider_attempt_ids=list(receipt.provider_attempt_ids) if receipt else [],
            tool_call_ref=stable_id("TCALL", output["action_key"]),
            budget_debit={
                "rounds": 1,
                "tool_calls": (
                    0
                    if action in {"submit_gate", "abandon"} or bool(output.get("cached"))
                    else 1
                ),
            },
            message=str(output.get("message") or ""),
        )

    def _budget_step(self, hypothesis, reason, task, response) -> None:
        step = InvestigationStep(
            run_id=self.runtime.run.run_id,
            hypothesis_id=hypothesis.hypothesis_id or "",
            round_index=hypothesis.round_count,
            action="abandon",
            arguments={"reason": reason},
            action_key=stable_id("ACT", hypothesis.hypothesis_id, reason),
            status="budget-exhausted",
            response_ref=response.id if response else None,
            policy_status="denied",
            message=reason,
        )
        self._persist_step(step)
        if hypothesis.state == "investigating":
            hypothesis.transition("inconclusive")
            hypothesis.transition("rejected")
        self._degrade(reason)

    def _persist_hypothesis(self, hypothesis: InvestigationHypothesis) -> str:
        ref = self.runtime.artifacts.write_json(
            "investigations/hypotheses",
            f"{hypothesis.hypothesis_id}-{hypothesis.state}.json",
            hypothesis.to_dict(),
        )
        self.hypothesis_refs[hypothesis.hypothesis_id or ""] = ref
        return ref

    def _persist_all_hypotheses(self) -> None:
        for hypothesis in self.hypotheses.values():
            self._persist_hypothesis(hypothesis)

    def _persist_step(self, step: InvestigationStep) -> str:
        ref = self.runtime.artifacts.write_json(
            "investigations/steps", f"{step.step_id}.json", step.to_dict()
        )
        self.steps.append(step)
        self.step_refs.append(ref)
        self._publish_investigation_event(
            "investigation.action",
            {
                "role": "analysis",
                "hypothesis_id": step.hypothesis_id,
                "action": step.action,
                "status": step.status,
                "evidence_count": len(step.observation_refs),
                "message": step.message,
            },
            [ref],
        )
        return ref

    def _checkpoint(self, reason: str) -> str:
        self.budget.checkpoints += 1
        checkpoint = InvestigationCheckpoint(
            run_id=self.runtime.run.run_id,
            sequence=self.budget.checkpoints,
            hypothesis_states={key: value.state for key, value in self.hypotheses.items()},
            hypothesis_refs=list(self.hypothesis_refs.values()),
            completed_action_keys=sorted(self.completed_action_keys),
            step_refs=list(self.step_refs),
            evidence_gate_refs=list(self.gate_refs),
            verification_plan_refs=list(self.plan_refs),
            remaining_budget=self.budget.remaining(self.gateway),
            last_evidence_package_refs=list(self.package_refs[-10:]),
            reason=reason,
        )
        ref = self.checkpoints.write(checkpoint)
        self.checkpoint_refs.append(ref)
        self.runtime.run_state.record_artifact(ref)
        # A checkpoint is not resumable through the public entry point unless
        # the matching run/accounting state is durable as well. Persist it at
        # every committed boundary so an abrupt process exit does not require
        # terminal finalization before resume can locate the run state.
        state_path = immutable_path(
            self.runtime.run.path
            / "runtime_state"
            / f"state-checkpoint-{checkpoint.sequence:04d}.json"
        )
        temporary = state_path.with_name(f".{state_path.name}.tmp")
        temporary.write_text(
            json.dumps(to_plain(self.runtime.run_state), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temporary.replace(state_path)
        self.runtime.run_state.record_artifact(state_path)
        self._publish_investigation_event(
            "investigation.budget",
            {
                "role": "orchestrator",
                "checkpoint": checkpoint.sequence,
                "reason": reason,
                "remaining": checkpoint.remaining_budget,
            },
            [ref, str(state_path)],
        )
        return ref

    def _publish_investigation_event(
        self,
        message_type: str,
        payload: dict[str, Any],
        refs: list[str] | None = None,
    ) -> None:
        if self.runtime.bus is None:
            return
        self.runtime.bus.publish(
            "agent-led-investigation",
            "runtime",
            message_type,
            payload,
            artifact_refs=[item for item in (refs or []) if item],
        )

    def _terminalize_response(self, response, accepted: bool, refs, reason: str = "") -> None:
        if not response or not self.gateway:
            return
        receipt = self.gateway.receipt_for_response(response.id or "")
        if not receipt or receipt.terminal_status:
            return
        if reason == "cancelled":
            self.gateway.terminalize(receipt, "cancelled", decision_refs=list(refs))
            return
        self.gateway.record_policy(receipt, accepted=accepted, reasons=[] if accepted else [reason])
        if not accepted:
            self.gateway.record_fallback(receipt, reason or "policy-denied", list(refs))
        self.gateway.terminalize(
            receipt,
            "accepted" if accepted else "fallback",
            decision_refs=list(refs),
        )

    def _active_hypotheses(self) -> list[InvestigationHypothesis]:
        return [item for item in self.hypotheses.values() if item.state in {"investigating", "refine"}]

    def _step_summary(self, step: InvestigationStep) -> dict[str, Any]:
        return {
            "step_id": step.step_id,
            "hypothesis_id": step.hypothesis_id,
            "action": step.action,
            "status": step.status,
            "observation_refs": step.observation_refs,
            "message": step.message,
        }

    def _gate_payload_for(self, hypothesis_id: str) -> tuple[dict[str, Any], str]:
        for ref in reversed(self.gate_refs):
            payload = json.loads(Path(ref).read_text(encoding="utf-8"))
            if payload.get("hypothesis_id") == hypothesis_id:
                return payload, ref
        return {}, ""

    def _finding_for_package(self, package, gate_ref: str) -> Finding:
        hypothesis = self.hypotheses[package.hypothesis_id]
        result = EvidenceGate(self.view).evaluate(hypothesis)
        if not result.finding:
            raise ValueError("promoted package failed deterministic replay")
        result.finding.metadata.update(
            {
                "evidence_package_ref": self._gate_payload_for(package.hypothesis_id)[0].get("evidence_package_ref"),
                "evidence_gate_ref": gate_ref,
                "hypothesis_id": package.hypothesis_id,
            }
        )
        return result.finding

    def _gate_counts(self) -> dict[str, int]:
        counts: Counter[str] = Counter()
        for ref in self.gate_refs:
            try:
                payload = json.loads(Path(ref).read_text(encoding="utf-8"))
                counts[str(payload.get("state") or "unknown")] += 1
            except (OSError, json.JSONDecodeError):
                counts["unreadable"] += 1
        return dict(counts)

    def _reconcile_accounting(self) -> dict[str, Any]:
        from .llm_accounting import reconcile_llm_lifecycle

        result = reconcile_llm_lifecycle(
            self.runtime.run.path,
            llm_enabled=True,
            budget_counters=self.runtime.run_state.llm_accounting or None,
        )
        return result.to_dict()

    def _degrade(self, reason: str) -> None:
        if reason and reason not in self.degraded_reasons:
            self.degraded_reasons.append(reason)
        if not self.fallback_reason:
            self.fallback_reason = reason

    def _check_cancelled(self) -> bool:
        if self.runtime.cancellation_token.cancelled:
            self.cancelled = True
            return True
        return False

    def _emit(self, phase: str) -> None:
        self.runtime._emit_phase(phase)


def _tool_result_from_call(call_result, fallback_name: str) -> ToolResult:
    output = getattr(call_result, "output", {}) or {}
    if isinstance(output, dict) and output.get("tool_name"):
        return ToolResult(
            tool_name=str(output.get("tool_name")),
            inputs=dict(output.get("inputs") or {}),
            success=bool(output.get("success")),
            exit_status=output.get("exit_status"),
            duration_ms=int(output.get("duration_ms") or 0),
            artifact_paths=list(output.get("artifact_paths") or []),
            observations=[
                ToolObservation(**{key: value for key, value in item.items() if key in ToolObservation.__dataclass_fields__})
                for item in output.get("observations", [])
            ],
            message=str(output.get("message") or ""),
            id=output.get("id"),
        )
    return ToolResult(
        tool_name=fallback_name,
        inputs={},
        success=bool(getattr(call_result, "success", False)),
        observations=list(getattr(call_result, "observations", []) or []),
        message=str(getattr(call_result, "message", "")),
        id=getattr(call_result, "id", None),
    )
