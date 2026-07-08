from __future__ import annotations

from pathlib import Path

from .agents import AnalysisAgent, OrchestratorAgent, ReconAgent, VerificationAgent, findings_from_llm_candidates
from .config import AuditConfig
from .decisions import (
    LLMAgentDecision,
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
from .models import LLMRequest
from .prompts import persist_prompt, render_default_prompt
from .reporting import ReportGenerator
from .repository import analyze_target
from .storage import RunStore
from .tool_protocol import ToolBudget, ToolRuntime, build_default_tool_registry
from .tools import PatternScanner
from .validation import Validator


def run_audit(target: str, config: AuditConfig | None = None, output_dir: str | Path = "runs") -> dict:
    config = config or AuditConfig.default()
    metadata = analyze_target(target)
    store = RunStore(output_dir)
    run = store.create_run(metadata.target.repo or Path(metadata.target.path or target).name)
    bus = None
    runtime_refs: dict[str, list[str]] = {
        "prompt_refs": [],
        "llm_response_refs": [],
        "message_refs": [],
        "memory_refs": [],
        "mcp_call_refs": [],
        "tool_call_refs": [],
        "decision_refs": [],
    }
    if config.runtime_enabled and config.message_bus.enabled:
        bus = MessageBus(run.run_id, run.path / "messages" / config.message_bus.log_filename)
        msg = bus.publish("pipeline", "orchestrator", "run.start", {"target": target})
        runtime_refs["message_refs"].append(msg.message_id)
    run.write_json_artifact("metadata", "repository.json", metadata.to_dict())
    llm_client = build_llm_client(config.llm) if config.runtime_enabled else None

    plan = OrchestratorAgent(config).plan(metadata)
    if config.runtime_enabled and llm_client:
        response, _prompt_path, _llm_path = _run_llm_role(
            run,
            bus,
            runtime_refs,
            config,
            llm_client,
            "orchestrator",
            "orchestrator.plan",
            {"repository_summary": metadata.to_dict(), "audit_scope": config.audit_scope.vulnerability_classes},
        )
        if _decision_enabled(config, "orchestrator"):
            proposal = build_decision_from_llm_response(
                "orchestrator",
                response.parsed_json,
                prompt_ref=runtime_refs["prompt_refs"][-1] if runtime_refs["prompt_refs"] else None,
                llm_response_ref=response.id,
                provider=response.provider,
                model=response.model,
                provider_metadata=response.raw_response,
                raw_output=response.text,
                repair_enabled=config.llm_decisions.repair_enabled,
            )
            gate = evaluate_decision_policy("orchestrator", proposal, config)
            plan = _apply_orchestrator_proposal(plan, proposal, gate, config)
            merged = merge_decision(
                "orchestrator",
                {"plan": OrchestratorAgent(config).plan(metadata).to_dict()},
                proposal,
                gate.status,
                gate.reasons,
                final_output={"plan": plan.to_dict()},
            )
            merged.policy_gate_id = gate.id
            path = persist_decision_bundle(run.path / config.llm_decisions.decision_artifact_dir, "orchestrator", proposal, gate, merged)
            _publish_decision_events(bus, runtime_refs, "orchestrator", proposal, gate, merged, [str(path)])
    run.write_json_artifact("metadata", "plan.json", plan.to_dict())
    if bus:
        msg = bus.publish("orchestrator", "pipeline", "agent.plan", plan.to_dict(), artifact_refs=[str(run.path / "metadata" / "plan.json")])
        runtime_refs["message_refs"].append(msg.message_id)

    memory_store = None
    memory_retrievals = []
    if config.runtime_enabled and config.memory.enabled and metadata.root_path:
        memory_store = LexicalMemoryStore(run.path / "memory")
        memory_records = MemoryIndexer(memory_store, config.memory).index_repository(metadata)
        memory_retrievals = memory_store.retrieve("request args os.system select query secret", limit=5)
        retrieval_path = persist_retrievals(run.path / "memory", memory_retrievals, "initial-retrieval")
        runtime_refs["memory_refs"].extend([item.record.id or "" for item in memory_retrievals])
        if bus:
            msg = bus.publish(
                "memory",
                "analysis",
                "memory.retrieved",
                {"record_count": len(memory_records), "retrieval_count": len(memory_retrievals)},
                artifact_refs=[str(retrieval_path)],
            )
            runtime_refs["message_refs"].append(msg.message_id)

    scanner = PatternScanner()
    scan_result = scanner.scan(metadata)
    run.write_json_artifact("tool_outputs", "pattern-scan.json", scan_result.to_dict())
    if bus:
        msg = bus.publish(
            "tool-protocol",
            "analysis",
            "tool.result",
            {"tool": scan_result.tool_name, "observations": len(scan_result.observations)},
        )
        runtime_refs["message_refs"].append(msg.message_id)

    intelligence = []
    if metadata.dependencies:
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
            mcp_path = run.write_json_artifact("mcp", "cve-mcp-intelligence.json", intel.to_dict())
            runtime_refs["mcp_call_refs"].append(intel.id or "")
            if bus:
                msg = bus.publish(
                    "mcp",
                    "recon",
                    "mcp.call",
                    {"dependency": first_dep.name, "degraded": intel.raw.get("degraded", False)},
                    artifact_refs=[str(mcp_path)],
                )
                runtime_refs["message_refs"].append(msg.message_id)
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
            run.write_json_artifact("intelligence", "cve-mcp-observation.json", mcp_observation.to_dict())
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
    recon = ReconAgent(config).run(metadata, intelligence)
    run.write_json_artifact("agent_traces", "recon.json", recon.trace.to_dict())
    run.write_json_artifact("handoffs", "recon-to-analysis.json", recon.handoff.to_dict())
    if config.runtime_enabled and llm_client:
        response, _prompt_path, _llm_path = _run_llm_role(
            run,
            bus,
            runtime_refs,
            config,
            llm_client,
            "recon",
            "recon.summary",
            {
                "repository_metadata": metadata.to_dict(),
                "intelligence_context": [item.to_dict() for item in intelligence],
                "memory_context": [item.to_dict() for item in memory_retrievals],
            },
        )
        if _decision_enabled(config, "recon"):
            proposal = build_decision_from_llm_response(
                "recon",
                response.parsed_json,
                prompt_ref=runtime_refs["prompt_refs"][-1] if runtime_refs["prompt_refs"] else None,
                llm_response_ref=response.id,
                provider=response.provider,
                model=response.model,
                provider_metadata=response.raw_response,
                raw_output=response.text,
                repair_enabled=config.llm_decisions.repair_enabled,
            )
            gate = evaluate_decision_policy("recon", proposal, config)
            if gate.status == "accepted":
                _apply_recon_proposal(recon, proposal)
                _dispatch_recon_tool_requests(run, bus, runtime_refs, config, proposal, metadata, memory_store)
                run.write_json_artifact("agent_traces", "recon.json", recon.trace.to_dict())
                run.write_json_artifact("handoffs", "recon-to-analysis.json", recon.handoff.to_dict())
            merged = merge_decision(
                "recon",
                {"high_risk_areas": recon.payload.get("high_risk_areas", [])},
                proposal,
                gate.status,
                gate.reasons,
                final_output={"handoff": recon.handoff.to_dict(), "payload": recon.payload},
            )
            merged.policy_gate_id = gate.id
            path = persist_decision_bundle(run.path / config.llm_decisions.decision_artifact_dir, "recon", proposal, gate, merged)
            _publish_decision_events(bus, runtime_refs, "recon", proposal, gate, merged, [str(path)])
        elif bus:
            msg = bus.publish("recon", "analysis", "agent.handoff", recon.handoff.to_dict(), artifact_refs=[str(_prompt_path), str(_llm_path)])
            runtime_refs["message_refs"].append(msg.message_id)

    analysis = AnalysisAgent(config).run_with_trace(metadata, recon.handoff, [scan_result], intelligence)
    run.write_json_artifact("agent_traces", "analysis.json", analysis.trace.to_dict())
    run.write_json_artifact("handoffs", "analysis-to-verification.json", analysis.handoff.to_dict())
    candidates = analysis.payload["candidates"]
    deterministic_candidate_count = len(candidates)
    if config.runtime_enabled and llm_client:
        response, _prompt_path, _llm_path = _run_llm_role(
            run,
            bus,
            runtime_refs,
            config,
            llm_client,
            "analysis",
            "analysis.candidates",
            {
                "repository_summary": metadata.to_dict(),
                "tool_outputs": scan_result.to_dict(),
                "memory_context": [item.to_dict() for item in memory_retrievals],
                "intelligence_context": [item.to_dict() for item in intelligence],
            },
        )
        if _decision_enabled(config, "analysis"):
            proposal = build_decision_from_llm_response(
                "analysis",
                response.parsed_json,
                prompt_ref=runtime_refs["prompt_refs"][-1] if runtime_refs["prompt_refs"] else None,
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
                    finding.metadata.setdefault("memory_refs", []).extend(runtime_refs["memory_refs"])
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
            path = persist_decision_bundle(run.path / config.llm_decisions.decision_artifact_dir, "analysis", proposal, gate, merged)
            _publish_decision_events(bus, runtime_refs, "analysis", proposal, gate, merged, [str(path)])
        else:
            llm_candidates = findings_from_llm_candidates(response.parsed_json or {}, metadata)
            for finding in llm_candidates:
                finding.metadata.setdefault("prompt_refs", []).append(runtime_refs["prompt_refs"][-1] if runtime_refs["prompt_refs"] else "")
                finding.metadata.setdefault("llm_response_refs", []).append(response.id or "")
                finding.metadata.setdefault("memory_refs", []).extend(runtime_refs["memory_refs"])
            candidates.extend(llm_candidates)
            if bus:
                msg = bus.publish("analysis", "verification", "agent.handoff", analysis.handoff.to_dict(), artifact_refs=[str(_prompt_path), str(_llm_path)])
                runtime_refs["message_refs"].append(msg.message_id)
    run.write_json_artifact("findings", "candidates.json", [finding.to_dict() for finding in candidates])

    verification = VerificationAgent(config).run_with_trace(candidates, metadata, intelligence)
    run.write_json_artifact("agent_traces", "verification.json", verification.trace.to_dict())
    run.write_json_artifact("handoffs", "verification-to-reporting.json", verification.handoff.to_dict())
    if config.runtime_enabled and llm_client:
        response, _prompt_path, _llm_path = _run_llm_role(
            run,
            bus,
            runtime_refs,
            config,
            llm_client,
            "verification",
            "verification.decision",
            {
                "candidate_json": [finding.to_dict() for finding in candidates],
                "evidence_summary": scan_result.to_dict(),
            },
        )
        if _decision_enabled(config, "verification"):
            proposal = build_decision_from_llm_response(
                "verification",
                response.parsed_json,
                prompt_ref=runtime_refs["prompt_refs"][-1] if runtime_refs["prompt_refs"] else None,
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
                if decision.llm_confidence is not None:
                    decision.finding.metadata["llm_confidence"] = decision.llm_confidence
            path = persist_decision_bundle(run.path / config.llm_decisions.decision_artifact_dir, "verification", proposal, gate, merged)
            _publish_decision_events(bus, runtime_refs, "verification", proposal, gate, merged, [str(path)])
            run.write_json_artifact("findings", "verification-decisions.json", [decision.to_dict() for decision in decisions])
        elif bus:
            msg = bus.publish("verification", "reporting", "agent.handoff", verification.handoff.to_dict(), artifact_refs=[str(_prompt_path), str(_llm_path)])
            runtime_refs["message_refs"].append(msg.message_id)
    decisions = verification.decisions
    for decision in decisions:
        decision.finding.metadata.setdefault("decision_source", decision.decision_source)
    accepted = [decision for decision in decisions if decision.decision == "accept"]
    run.write_json_artifact("findings", "verification.json", [decision.to_dict() for decision in decisions])

    validator = Validator(config)
    evidence_builder = EvidenceBuilder(run.path / "evidence")
    evidence_chains = []
    for decision in accepted:
        for key, values in runtime_refs.items():
            decision.finding.metadata.setdefault(key, [])
            for value in values:
                if value and value not in decision.finding.metadata[key]:
                    decision.finding.metadata[key].append(value)
        validation = validator.validate(decision.finding, metadata, config.default_validation_level)
        evidence_chains.append(
            evidence_builder.build(
                finding=decision.finding,
                metadata=metadata,
                tool_results=[scan_result],
                intelligence=intelligence,
                verification=decision,
                validation=validation,
                agent_traces=[recon.trace, analysis.trace, verification.trace],
                handoffs=[recon.handoff, analysis.handoff, verification.handoff],
            )
        )

    runtime_summary = {}
    if config.runtime_enabled:
        runtime_summary = {
            "llm": {"provider": config.llm.provider, "model": config.llm.model},
            "prompts": {"version": config.prompts.default_version, "count": len(runtime_refs["prompt_refs"])},
            "mcp": {"enabled": config.mcp.enabled, "transport": config.mcp.transport, "refs": runtime_refs["mcp_call_refs"]},
            "memory": {"enabled": config.memory.enabled, "mode": config.memory.mode, "refs": runtime_refs["memory_refs"]},
            "llm_decisions": {
                "enabled": config.llm_decisions.enabled,
                "roles": config.llm_decisions.roles,
                "refs": runtime_refs["decision_refs"],
            },
            "message_log": str(run.path / "messages" / config.message_bus.log_filename) if bus else "",
            "token_usage": {"mode": "recorded-per-llm-artifact"},
        }
        if bus:
            msg = bus.publish("reporting", "pipeline", "report.generate", {"finding_count": len(accepted)})
            runtime_refs["message_refs"].append(msg.message_id)
            for decision in accepted:
                decision.finding.metadata.setdefault("message_refs", []).append(msg.message_id)

    report = ReportGenerator().build(
        metadata,
        [decision.finding for decision in accepted],
        evidence_chains,
        runtime=runtime_summary,
    )
    run.write_json_artifact("reports", "report.json", report.to_dict())
    markdown_path = run.path / "reports" / "report.md"
    markdown_path.write_text(ReportGenerator().to_markdown(report), encoding="utf-8")

    return {
        "run_dir": str(run.path),
        "candidate_count": len(candidates),
        "rejected_count": len([decision for decision in decisions if decision.decision == "reject"]),
        "validated_count": len(accepted),
        "validation_level_distribution": {config.default_validation_level: len(accepted)},
    }


def _run_llm_role(
    run,
    bus,
    runtime_refs: dict[str, list[str]],
    config: AuditConfig,
    llm_client,
    role: str,
    template_id: str,
    variables: dict,
):
    prompt = render_default_prompt(role, template_id, variables, config.prompts)
    prompt_path = persist_prompt(run.path / "prompts", prompt)
    runtime_refs["prompt_refs"].append(prompt.id or "")
    request = LLMRequest(
        role=role,
        prompt=prompt.rendered,
        model=config.llm.model,
        provider=config.llm.provider,
        response_schema=prompt.output_schema,
    )
    response = llm_client.complete(request)
    try:
        validate_json_schema(response.parsed_json, prompt.output_schema)
    except Exception as exc:
        if not _decision_enabled(config, role):
            raise
        response.validation_errors.append(str(exc))
    llm_path = persist_llm_artifact(run.path / "llm", request, response)
    runtime_refs["llm_response_refs"].append(response.id or "")
    if bus:
        msg = bus.publish(
            role,
            "llm",
            "llm.response",
            {"role": role, "response_id": response.id},
            artifact_refs=[str(prompt_path), str(llm_path)],
        )
        runtime_refs["message_refs"].append(msg.message_id)
    return response, prompt_path, llm_path


def _decision_enabled(config: AuditConfig, role: str) -> bool:
    return bool(config.runtime_enabled and config.llm_decisions.enabled and role in set(config.llm_decisions.roles))


def _publish_decision_events(
    bus,
    runtime_refs: dict[str, list[str]],
    role: str,
    proposal,
    gate,
    merged,
    artifact_refs: list[str],
) -> None:
    if proposal.id:
        runtime_refs["decision_refs"].append(proposal.id)
    if not bus:
        return
    events = [
        (
            "llm.decision",
            {
                "role": role,
                "decision_id": proposal.id,
                "confidence": proposal.confidence,
                "fallback_reason": proposal.fallback_reason,
            },
        ),
        (
            "decision.schema",
            {"role": role, "status": proposal.schema_status, "errors": proposal.schema_errors},
        ),
        (
            "decision.policy",
            {"role": role, "status": gate.status, "reasons": gate.reasons, "gate_id": gate.id},
        ),
        (
            "decision.merge",
            {
                "role": role,
                "decision_source": merged.decision_source,
                "merge_id": merged.id,
                "fallback_reason": merged.fallback_reason,
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
                },
            )
        )
    for message_type, payload in events:
        msg = bus.publish(role, "pipeline", message_type, payload, artifact_refs=artifact_refs)
        runtime_refs["message_refs"].append(msg.message_id)


def _apply_orchestrator_proposal(plan, proposal, gate, config: AuditConfig):
    if gate.status != "accepted":
        plan.decision_source = "policy-denied"
        return plan
    payloads = list(proposal.selected_actions)
    if isinstance(proposal.parsed_json.get("plan"), dict):
        payloads.append(proposal.parsed_json["plan"])
    allowed_agents = {"orchestrator", "recon", "analysis", "verification"}
    for payload in payloads:
        classes = payload.get("vulnerability_classes") or []
        accepted_classes = [item for item in classes if item in config.audit_scope.vulnerability_classes]
        if accepted_classes:
            plan.vulnerability_classes = accepted_classes
        focus_areas = payload.get("focus_areas") or []
        for area in focus_areas:
            if area in config.audit_scope.vulnerability_classes and area not in plan.focus_areas:
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


def _apply_recon_proposal(recon, proposal) -> None:
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


def _dispatch_recon_tool_requests(
    run,
    bus,
    runtime_refs: dict[str, list[str]],
    config: AuditConfig,
    proposal,
    metadata,
    memory_store,
) -> None:
    if not proposal.requested_tools:
        return
    budget = ToolBudget(per_agent=config.llm_decisions.tool_budget_per_role or config.tools.per_agent_budgets)
    runtime = ToolRuntime(
        build_default_tool_registry(config),
        artifact_root=run.path / "tool_outputs" / "decision-tool-calls",
        budget=budget,
    )
    for request in proposal.requested_tools:
        tool_name = str(request.get("tool_name") or request.get("name") or "")
        arguments = dict(request.get("arguments") or {})
        arguments = _materialize_tool_arguments(tool_name, arguments, metadata, memory_store)
        if arguments is None:
            continue
        result = runtime.call("recon", tool_name, arguments)
        runtime_refs["tool_call_refs"].append(result.id or "")
        if bus:
            msg = bus.publish(
                "recon",
                "tool-protocol",
                "tool.dispatch",
                {"role": "recon", "tool": tool_name, "status": result.status, "success": result.success},
                artifact_refs=result.artifact_paths,
            )
            runtime_refs["message_refs"].append(msg.message_id)


def _materialize_tool_arguments(tool_name: str, arguments: dict, metadata, memory_store):
    if tool_name in {"pattern-scan", "repository-search", "source-context"}:
        arguments["metadata"] = metadata
    if tool_name == "repository-search":
        arguments.setdefault("pattern", "os\\.system|subprocess|SELECT|secret")
    if tool_name == "source-context":
        arguments.setdefault("path", metadata.file_tree[0] if metadata.file_tree else "")
        arguments.setdefault("start_line", 1)
        arguments.setdefault("end_line", 20)
    if tool_name == "memory.retrieve":
        if memory_store is None:
            return None
        arguments["store"] = memory_store
        arguments.setdefault("query", "request args os.system select secret")
    return arguments
