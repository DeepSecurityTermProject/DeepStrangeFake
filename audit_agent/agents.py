from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .config import AuditConfig
from .models import (
    AgentHandoff,
    AgentTrace,
    AuditPlan,
    Finding,
    ReactResult,
    RepositoryMetadata,
    SourceLocation,
    ToolResult,
    VerificationDecision,
    VulnerabilityIntelligence,
)


@dataclass
class AgentRunResult:
    trace: AgentTrace
    handoff: AgentHandoff
    payload: dict[str, Any]


@dataclass
class VerificationRunResult:
    trace: AgentTrace
    handoff: AgentHandoff
    decisions: list[VerificationDecision]
    payload: dict[str, Any]


class BoundedReActLoop:
    def __init__(self, max_iterations: int = 4, max_tool_calls: int = 8):
        self.max_iterations = max_iterations
        self.max_tool_calls = max_tool_calls

    def run(self, action: Callable[[int], tuple[str, dict[str, Any]]]) -> ReactResult:
        steps: list[dict[str, Any]] = []
        tool_calls = 0
        for index in range(self.max_iterations):
            status, payload = action(index)
            step = {"index": index, "status": status, "payload": payload}
            steps.append(step)
            if payload.get("tool_call"):
                tool_calls += 1
                if tool_calls >= self.max_tool_calls:
                    return ReactResult(stop_reason="max_tool_calls", steps=steps, tool_calls=tool_calls)
            if status in {"stop", "done"}:
                return ReactResult(stop_reason=status, steps=steps, tool_calls=tool_calls)
        return ReactResult(stop_reason="max_iterations", steps=steps, tool_calls=tool_calls)


class OrchestratorAgent:
    def __init__(self, config: AuditConfig):
        self.config = config

    def plan(self, metadata: RepositoryMetadata) -> AuditPlan:
        return AuditPlan(
            target_id=metadata.target.repo or metadata.target.path or metadata.target.source,
            vulnerability_classes=list(self.config.audit_scope.vulnerability_classes),
            validation_level=self.config.default_validation_level,
            budgets={
                "analysis": self.config.audit_scope.analysis_budget,
                "tools": self.config.audit_scope.tool_budget,
                "cve_intelligence": self.config.audit_scope.cve_query_budget,
            },
        )


class ReconAgent:
    def __init__(self, config: AuditConfig):
        self.config = config

    def run(
        self, metadata: RepositoryMetadata, intelligence: list[VulnerabilityIntelligence] | None = None
    ) -> AgentRunResult:
        intelligence = intelligence or []
        high_risk = [
            f"{surface.kind}:{surface.path}:{surface.start_line}" for surface in metadata.attack_surfaces
        ]
        dependency_concerns = [
            f"{item.cve_id or ','.join(item.cwe_ids)} risk={item.risk_score}"
            for item in intelligence
            if item.cve_id or item.cwe_ids
        ]
        trace = AgentTrace(
            agent_name="recon",
            reasoning_summary="Mapped project structure, dependencies, attack surfaces, and contextual CVE intelligence.",
            selected_context_refs=metadata.file_tree[:20],
            model_metadata={"provider": self.config.llm.provider, "model": self.config.llm.model},
            react_steps=[
                {"action": "inspect_metadata", "observed_files": len(metadata.file_tree)},
                {"action": "inspect_attack_surface", "observed_surfaces": len(metadata.attack_surfaces)},
            ],
            tool_calls=[{"tool": "cve-mcp-server", "mode": "contextual", "count": len(intelligence)}],
        )
        handoff = AgentHandoff(
            from_agent="recon",
            to_agent="analysis",
            completed_work="Repository and attack-surface reconnaissance completed.",
            key_findings=high_risk,
            attention_points=dependency_concerns,
            suggested_next_actions=["Prioritize source sinks with local evidence.", "Treat CVE intelligence as context."],
            intelligence_refs=[item.id for item in intelligence],
            trace_id=trace.id,
        )
        return AgentRunResult(
            trace=trace,
            handoff=handoff,
            payload={"high_risk_areas": high_risk, "dependency_concerns": dependency_concerns},
        )


class AnalysisAgent:
    def __init__(self, config: AuditConfig):
        self.config = config

    def run(
        self,
        metadata: RepositoryMetadata,
        recon_handoff: AgentHandoff,
        tool_results: list[ToolResult],
        intelligence: list[VulnerabilityIntelligence] | None = None,
    ) -> list[Finding]:
        return self.run_with_trace(metadata, recon_handoff, tool_results, intelligence).payload["candidates"]

    def run_with_trace(
        self,
        metadata: RepositoryMetadata,
        recon_handoff: AgentHandoff,
        tool_results: list[ToolResult],
        intelligence: list[VulnerabilityIntelligence] | None = None,
    ) -> AgentRunResult:
        intelligence = intelligence or []
        findings: list[Finding] = []
        for tool_result in tool_results:
            for observation in tool_result.observations:
                if not observation.vulnerability_class:
                    continue
                if observation.vulnerability_class not in self.config.audit_scope.vulnerability_classes:
                    continue
                related_intel = _related_intelligence(observation.vulnerability_class, intelligence)
                location = SourceLocation(
                    path=observation.path or "",
                    start_line=observation.line or 1,
                    end_line=observation.line or 1,
                    snippet=observation.evidence,
                )
                finding = Finding(
                    vulnerability_class=observation.vulnerability_class,
                    severity=observation.severity or "medium",
                    confidence=0.72,
                    location=location,
                    title=_title_for(observation.vulnerability_class),
                    description=observation.message,
                    evidence=[observation.evidence or observation.message],
                    remediation=_remediation_for(observation.vulnerability_class),
                    call_path=[f"{observation.path}:{observation.line}", "sink"],
                    tool_refs=[tool_result.id or tool_result.tool_name],
                    intelligence_refs=[item.id for item in related_intel],
                    handoff_refs=[recon_handoff.id or ""],
                    agent_trace_refs=[recon_handoff.trace_id] if recon_handoff.trace_id else [],
                )
                _copy_intelligence_context(finding, related_intel)
                findings.append(finding)
        trace = AgentTrace(
            agent_name="analysis",
            reasoning_summary="Converted deterministic tool observations and contextual CVE/CWE intelligence into candidate findings.",
            selected_context_refs=[finding.location.path for finding in findings],
            model_metadata={"provider": self.config.llm.provider, "model": self.config.llm.model},
            raw_response="deterministic-analysis",
            react_steps=[
                {"action": "consume_recon_handoff", "handoff": recon_handoff.id},
                {"action": "review_tool_results", "tool_result_count": len(tool_results)},
                {"action": "emit_candidates", "candidate_count": len(findings)},
            ],
            tool_calls=[
                {"tool": result.tool_name, "result_id": result.id, "observations": len(result.observations)}
                for result in tool_results
            ],
        )
        intelligence_refs = sorted({ref for finding in findings for ref in finding.intelligence_refs})
        handoff = AgentHandoff(
            from_agent="analysis",
            to_agent="verification",
            completed_work="Candidate findings generated from local tool evidence and contextual intelligence.",
            key_findings=[finding.id or finding.title for finding in findings],
            evidence_refs=sorted({ref for finding in findings for ref in finding.tool_refs}),
            attention_points=["Reject intelligence-only matches without local evidence."],
            suggested_next_actions=["Independently verify local evidence.", "Select safe validation level."],
            intelligence_refs=intelligence_refs,
            trace_id=trace.id,
        )
        for finding in findings:
            if trace.id and trace.id not in finding.agent_trace_refs:
                finding.agent_trace_refs.append(trace.id)
            if handoff.id and handoff.id not in finding.handoff_refs:
                finding.handoff_refs.append(handoff.id)
        return AgentRunResult(trace=trace, handoff=handoff, payload={"candidates": findings})


class VerificationAgent:
    def __init__(self, config: AuditConfig):
        self.config = config

    def run(
        self,
        candidates: list[Finding],
        metadata: RepositoryMetadata,
        intelligence: list[VulnerabilityIntelligence] | None = None,
    ) -> list[VerificationDecision]:
        return self.run_with_trace(candidates, metadata, intelligence).decisions

    def run_with_trace(
        self,
        candidates: list[Finding],
        metadata: RepositoryMetadata,
        intelligence: list[VulnerabilityIntelligence] | None = None,
    ) -> VerificationRunResult:
        intelligence = intelligence or []
        decisions: list[VerificationDecision] = []
        for finding in candidates:
            related = [item for item in intelligence if item.id in finding.intelligence_refs]
            if not finding.evidence and not finding.tool_refs:
                decisions.append(
                    VerificationDecision(
                        finding=finding,
                        decision="reject",
                        reason="Rejected: missing local evidence; intelligence-only matches cannot be promoted.",
                        confidence=0.0,
                        validation_level="manual",
                        priority="low",
                        intelligence_refs=[item.id for item in related],
                    )
                )
                finding.verifier_decision = "reject"
                continue
            if finding.vulnerability_class not in self.config.audit_scope.vulnerability_classes:
                decisions.append(
                    VerificationDecision(
                        finding=finding,
                        decision="reject",
                        reason="Rejected: finding outside configured audit scope.",
                        confidence=min(finding.confidence, 0.4),
                        validation_level="manual",
                    )
                )
                finding.verifier_decision = "reject"
                continue

            priority = _priority(finding, related)
            validation_level = self.config.default_validation_level
            finding.verifier_decision = "accept"
            finding.validation_level = validation_level
            decisions.append(
                VerificationDecision(
                    finding=finding,
                    decision="accept",
                    reason="Accepted: local source evidence and tool output are present.",
                    confidence=min(max(finding.confidence, 0.55), 0.95),
                    validation_level=validation_level,
                    priority=priority,
                    intelligence_refs=[item.id for item in related],
                )
            )
        trace = AgentTrace(
            agent_name="verification",
            reasoning_summary="Independently reviewed candidates, rejected weak evidence, and selected validation levels.",
            selected_context_refs=[decision.finding.location.path for decision in decisions],
            model_metadata={"provider": self.config.llm.provider, "model": self.config.llm.model},
            raw_response="deterministic-verification",
            react_steps=[
                {"action": "review_candidates", "candidate_count": len(candidates)},
                {
                    "action": "emit_decisions",
                    "accepted": len([decision for decision in decisions if decision.decision == "accept"]),
                    "rejected": len([decision for decision in decisions if decision.decision == "reject"]),
                },
            ],
            tool_calls=[{"tool": "cve-mcp-server", "mode": "prioritization", "count": len(intelligence)}],
        )
        handoff = AgentHandoff(
            from_agent="verification",
            to_agent="reporting",
            completed_work="Verification decisions completed with validation-level selection.",
            key_findings=[f"{decision.decision}:{decision.finding_id}" for decision in decisions],
            evidence_refs=[ref for decision in decisions for ref in decision.finding.tool_refs],
            attention_points=[decision.reason for decision in decisions if decision.decision != "accept"],
            suggested_next_actions=["Persist evidence chains.", "Generate structured reports."],
            intelligence_refs=sorted({ref for decision in decisions for ref in decision.intelligence_refs}),
            trace_id=trace.id,
        )
        for decision in decisions:
            finding = decision.finding
            if trace.id and trace.id not in finding.agent_trace_refs:
                finding.agent_trace_refs.append(trace.id)
            if handoff.id and handoff.id not in finding.handoff_refs:
                finding.handoff_refs.append(handoff.id)
        return VerificationRunResult(
            trace=trace,
            handoff=handoff,
            decisions=decisions,
            payload={
                "accepted": len([decision for decision in decisions if decision.decision == "accept"]),
                "rejected": len([decision for decision in decisions if decision.decision == "reject"]),
            },
        )


def _related_intelligence(
    vulnerability_class: str, intelligence: list[VulnerabilityIntelligence]
) -> list[VulnerabilityIntelligence]:
    cwe_by_class = {
        "sql-injection": {"CWE-89"},
        "command-injection": {"CWE-78", "CWE-77"},
        "path-traversal": {"CWE-22"},
        "hardcoded-secret": {"CWE-798", "CWE-259"},
    }
    desired = cwe_by_class.get(vulnerability_class, set())
    related = [item for item in intelligence if desired.intersection(set(item.cwe_ids))]
    return related or list(intelligence[:1])


def findings_from_llm_candidates(payload: dict[str, Any], metadata: RepositoryMetadata) -> list[Finding]:
    findings: list[Finding] = []
    for item in payload.get("candidates", []) if isinstance(payload, dict) else []:
        path = item.get("path") or item.get("file") or ""
        start_line = int(item.get("start_line") or item.get("line") or 1)
        end_line = int(item.get("end_line") or start_line)
        evidence = item.get("evidence") or []
        if isinstance(evidence, str):
            evidence = [evidence]
        finding = Finding(
            vulnerability_class=item.get("vulnerability_class") or item.get("class") or "unknown",
            severity=item.get("severity") or "medium",
            confidence=float(item.get("confidence") or 0.5),
            location=SourceLocation(
                path=path,
                start_line=start_line,
                end_line=end_line,
                snippet=item.get("snippet"),
            ),
            title=item.get("title") or "LLM candidate finding",
            description=item.get("description") or "Candidate generated from schema-valid LLM output.",
            evidence=list(evidence),
            remediation=item.get("remediation") or _remediation_for(item.get("vulnerability_class") or ""),
            call_path=item.get("call_path") or [],
            tool_refs=item.get("tool_refs") or [],
            intelligence_refs=item.get("intelligence_refs") or [],
            agent_trace_refs=item.get("agent_trace_refs") or [],
            handoff_refs=item.get("handoff_refs") or [],
            cve_ids=item.get("cve_ids") or [],
            cwe_ids=item.get("cwe_ids") or [],
            metadata={
                "source": "llm",
                "target": metadata.target.source,
                "memory_refs": item.get("memory_refs") or [],
                "prompt_refs": item.get("prompt_refs") or [],
                "llm_response_refs": item.get("llm_response_refs") or [],
                "message_refs": item.get("message_refs") or [],
            },
        )
        findings.append(finding)
    return findings


def _copy_intelligence_context(finding: Finding, intelligence: list[VulnerabilityIntelligence]) -> None:
    for item in intelligence:
        if item.cve_id and item.cve_id not in finding.cve_ids:
            finding.cve_ids.append(item.cve_id)
        for cwe in item.cwe_ids:
            if cwe not in finding.cwe_ids:
                finding.cwe_ids.append(cwe)
        finding.cvss = item.cvss if item.cvss is not None else finding.cvss
        finding.epss = item.epss if item.epss is not None else finding.epss
        finding.kev = item.kev if item.kev is not None else finding.kev
        finding.public_poc_available = (
            item.public_poc_available if item.public_poc_available is not None else finding.public_poc_available
        )
        finding.risk_score = item.risk_score if item.risk_score is not None else finding.risk_score


def _priority(finding: Finding, intelligence: list[VulnerabilityIntelligence]) -> str:
    if finding.kev or any(item.kev for item in intelligence):
        return "urgent"
    if finding.epss and finding.epss >= 0.5:
        return "high"
    if any(item.epss and item.epss >= 0.5 for item in intelligence):
        return "high"
    if finding.severity in {"critical", "high"}:
        return "high"
    return "normal"


def _title_for(vulnerability_class: str) -> str:
    return {
        "sql-injection": "Potential SQL injection",
        "command-injection": "Potential command injection",
        "path-traversal": "Potential path traversal",
        "hardcoded-secret": "Potential hardcoded secret",
    }.get(vulnerability_class, f"Potential {vulnerability_class}")


def _remediation_for(vulnerability_class: str) -> str:
    return {
        "sql-injection": "Use parameterized queries and avoid string interpolation for SQL.",
        "command-injection": "Use fixed command argument arrays and strict allowlists for user input.",
        "path-traversal": "Normalize paths, enforce a safe base directory, and reject traversal tokens.",
        "hardcoded-secret": "Move secrets into a managed secret store and rotate exposed credentials.",
    }.get(vulnerability_class, "Review the affected code path and add targeted controls.")
