from __future__ import annotations

import json
from typing import Any

from .models import EvidenceChain, Finding, Report, RepositoryMetadata
from .repository import source_category
from .verification import VerificationStatus, verification_status_counts


REMEDIATION = {
    "sql-injection": "Use parameterized queries, query builders with bound variables, and input allowlists.",
    "command-injection": "Avoid shell invocation; use fixed argument arrays and strict allowlists.",
    "path-traversal": "Canonicalize paths, enforce a safe root, and reject traversal sequences.",
    "hardcoded-secret": "Move secrets to a secret manager or environment variables and rotate exposed values.",
}


class ReportGenerator:
    def build(
        self,
        metadata: RepositoryMetadata,
        findings: list[Finding],
        evidence_chains: list[EvidenceChain],
        runtime: dict[str, Any] | None = None,
        verification_candidates: list[Finding] | None = None,
    ) -> Report:
        evidence_by_finding = {chain.finding_id: chain for chain in evidence_chains}
        source_category_distribution: dict[str, int] = {}
        report_findings = [
            self._finding_item(finding, metadata, evidence_by_finding, source_category_distribution)
            for finding in findings
        ]
        candidate_items = [
            self._finding_item(finding, metadata, evidence_by_finding, None)
            for finding in (verification_candidates or findings)
        ]
        status_counts = verification_status_counts(candidate_items)
        summary = {
            "target": metadata.target.source,
            "finding_count": len(report_findings),
            "verification_candidate_count": len(candidate_items),
            "validated_count": sum(1 for item in candidate_items if item.get("verifier_decision") == "accept"),
            **status_counts,
            "languages": metadata.languages,
            "source_category_distribution": source_category_distribution,
        }
        return Report(
            target_metadata=metadata.to_dict(),
            executive_summary=summary,
            findings=report_findings,
            verification_candidates=candidate_items,
            evidence_chains=[chain.to_dict() for chain in evidence_chains],
            runtime=runtime or {},
        )

    def _finding_item(
        self,
        finding: Finding,
        metadata: RepositoryMetadata,
        evidence_by_finding: dict[str, EvidenceChain],
        source_category_distribution: dict[str, int] | None,
    ) -> dict[str, Any]:
        chain = evidence_by_finding.get(finding.id or "")
        item = finding.to_dict()
        category = finding.metadata.get("source_category") or metadata.file_categories.get(
            finding.location.path,
            source_category(finding.location.path),
        )
        item["source_category"] = category
        if source_category_distribution is not None:
            source_category_distribution[category] = source_category_distribution.get(category, 0) + 1
        item["remediation"] = item.get("remediation") or REMEDIATION.get(
            finding.vulnerability_class, "Review and fix the affected code path."
        )
        item["evidence_chain_id"] = chain.id if chain else None
        item["agent_traces"] = chain.agent_traces if chain else []
        item["handoffs"] = chain.handoffs if chain else []
        item["validation"] = chain.validation if chain else finding.metadata.get("validation_summary", {})
        validation = item["validation"]
        item["repair_summary"] = {
            "attempt_count": validation.get("repair_attempt_count", 0),
            "classifications": [
                {
                    "attempt_index": entry.get("attempt_index"),
                    "failure_class": entry.get("failure_class"),
                    "eligible": entry.get("eligible"),
                    "reason": entry.get("reason"),
                }
                for entry in validation.get("classifications", [])
            ],
            "timeline": validation.get("repair_timeline", []),
            "semantic_integrity_status": validation.get("semantic_integrity_status", ""),
            "safety_status": validation.get("safety_status", ""),
            "provisional_status": validation.get("provisional_status"),
            "final_status": validation.get("final_status"),
            "integrity": validation.get("integrity_summary", {}),
            "final_stop_reason": validation.get("final_stop_reason", ""),
        }
        item["verification_status"] = _verification_status(finding, item["validation"])
        item["verification_reason"] = (
            finding.verification_reason
            or finding.metadata.get("verification_reason")
            or item["validation"].get("verification_reason")
            or item["validation"].get("message")
            or ""
        )
        item["vulnerability_intelligence"] = _intelligence_context(finding, chain)
        for key in (
            "prompt_refs",
            "llm_response_refs",
            "message_refs",
            "memory_refs",
            "mcp_call_refs",
            "tool_call_refs",
            "decision_refs",
            "runtime_task_refs",
            "dataflow_trace_refs",
        ):
            item[key] = finding.metadata.get(
                key,
                chain.dataflow_trace_refs if key == "dataflow_trace_refs" and chain else [],
            )
        item["dataflow_summary"] = finding.metadata.get("dataflow_summary", {})
        item["dataflow_status"] = finding.metadata.get("dataflow_status", "")
        item["dataflow_rule_ids"] = finding.metadata.get("dataflow_rule_ids", [])
        item["decision_source"] = finding.metadata.get("decision_source", "deterministic")
        item["llm_confidence"] = finding.metadata.get("llm_confidence")
        item["policy_gate"] = finding.metadata.get("policy_gate", {})
        item["fallback_reason"] = finding.metadata.get("fallback_reason", "")
        item["local_evidence_refs"] = finding.metadata.get("local_evidence_refs", list(finding.tool_refs))
        item["contextual_intelligence_refs"] = finding.metadata.get(
            "contextual_intelligence_refs",
            list(finding.intelligence_refs) + finding.metadata.get("memory_refs", []),
        )
        return item

    def to_json(self, report: Report) -> str:
        return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)

    def to_markdown(self, report: Report) -> str:
        lines = [
            "# Agentic Security Audit Report",
            "",
            "## Executive Summary",
            "",
            f"- Target: {report.executive_summary.get('target')}",
            f"- Findings: {report.executive_summary.get('finding_count')}",
            f"- Validated/accepted: {report.executive_summary.get('validated_count')}",
            f"- Confirmed: {report.executive_summary.get('confirmed_count', 0)}",
            f"- Likely: {report.executive_summary.get('likely_count', 0)}",
            f"- Rejected: {report.executive_summary.get('rejected_count', 0)}",
            f"- Manual required: {report.executive_summary.get('manual_required_count', 0)}",
            "",
        ]
        graph = report.runtime.get("graph") if isinstance(report.runtime, dict) else None
        if isinstance(graph, dict):
            mutation_counts = graph.get("mutation_counts") or {}
            path_summary = graph.get("execution_path_summary") or {}
            artifact_refs = graph.get("artifact_refs") or {}
            lines.extend(
                [
                    "## Execution Graph",
                    "",
                    f"- Mode: {graph.get('mode', 'unknown')}",
                    f"- Schema: {graph.get('schema_version', 'unknown')}",
                    f"- Template: {graph.get('template_id', 'unknown')}@{graph.get('template_version', 'unknown')}",
                    f"- Revision: {graph.get('revision', 0)}",
                    f"- Mutations: {mutation_counts.get('committed', 0)} committed, {mutation_counts.get('denied', 0)} denied",
                    f"- Checkpoints: {graph.get('checkpoint_total', 0)}",
                    f"- Replans: {graph.get('replan_count', 0)}",
                    f"- Execution path nodes: {path_summary.get('node_count', 0)}",
                    f"- Execution path: {', '.join(graph.get('execution_path') or [])}",
                    f"- Fallback reason: {graph.get('fallback_reason') or 'none'}",
                    f"- Initial graph: {artifact_refs.get('initial_graph_ref', '')}",
                    f"- Final graph: {artifact_refs.get('final_graph_ref', '')}",
                    f"- Replay: {artifact_refs.get('replay_ref', '')}",
                    "",
                ]
            )
        lines.extend(["## Verification Evidence", ""])
        for candidate in report.verification_candidates:
            validation = candidate.get("validation") or {}
            lines.extend(
                [
                    f"### {candidate['title']}",
                    "",
                    f"- ID: {candidate['id']}",
                    f"- Status: {candidate.get('verification_status', 'unknown')}",
                    f"- Reason: {candidate.get('verification_reason', '')}",
                    f"- Class: {candidate['vulnerability_class']}",
                    f"- Location: {candidate['location']['path']}:{candidate['location']['start_line']}",
                    f"- Validation level: {validation.get('level', candidate.get('validation_level'))}",
                ]
            )
            if validation.get("exit_code") is not None:
                lines.append(f"- Exit code: {validation.get('exit_code')}")
            environment = validation.get("environment") or {}
            if environment.get("runner"):
                lines.append(f"- Runner: {environment.get('runner')}")
            if environment.get("docker_image"):
                lines.append(f"- Docker image: {environment.get('docker_image')}")
            if validation.get("timed_out") is not None:
                lines.append(f"- Timed out: {validation.get('timed_out')}")
            if validation.get("judge_reason"):
                lines.append(f"- Judge reason: {validation.get('judge_reason')}")
            if validation.get("repair_attempt_count") is not None:
                lines.append(f"- Repair attempts: {validation.get('repair_attempt_count', 0)}")
            if validation.get("semantic_integrity_status"):
                lines.append(f"- Semantic integrity: {validation.get('semantic_integrity_status')}")
            if validation.get("safety_status"):
                lines.append(f"- Safety gate: {validation.get('safety_status')}")
            if validation.get("provisional_status"):
                lines.append(f"- Provisional status: {validation.get('provisional_status')}")
            if validation.get("final_status"):
                lines.append(f"- Final status: {validation.get('final_status')}")
            if validation.get("final_stop_reason"):
                lines.append(f"- Repair stop reason: {validation.get('final_stop_reason')}")
            integrity = validation.get("integrity_summary") or {}
            if integrity:
                lines.append(
                    "- Target integrity: "
                    + ("unchanged" if integrity.get("unchanged") else "changed")
                    + f" (changed={integrity.get('changed_count', 0)}, added={integrity.get('added_count', 0)}, removed={integrity.get('removed_count', 0)})"
                )
            repair_timeline = validation.get("repair_timeline") or []
            if repair_timeline:
                lines.extend(["", "#### PoC Repair Timeline"])
                for event in repair_timeline:
                    details = [
                        f"attempt={event.get('attempt_index', '?')}",
                        f"stage={event.get('stage', 'unknown')}",
                        f"status={event.get('status', 'unknown')}",
                    ]
                    if event.get("edit_hash"):
                        details.append(f"edit_hash={event.get('edit_hash')}")
                    if event.get("script_hash"):
                        details.append(f"script_hash={event.get('script_hash')}")
                    if event.get("rule_ids"):
                        details.append("rules=" + ",".join(event.get("rule_ids") or []))
                    lines.append("- " + "; ".join(details))
            if validation.get("stdout_preview") is not None:
                lines.append(f"- stdout: {validation.get('stdout_preview')}")
            if validation.get("stderr_preview") is not None:
                lines.append(f"- stderr: {validation.get('stderr_preview')}")
            refs: list[str] = []
            for key in ("poc_refs", "sandbox_result_refs", "attempt_refs", "artifacts"):
                refs.extend(validation.get(key) or [])
            if refs:
                lines.append(f"- Artifact refs: {', '.join(refs)}")
            lines.append("")

        lines.extend(["## Findings", ""])
        for finding in report.findings:
            lines.extend(
                [
                    f"### {finding['title']}",
                    "",
                    f"- ID: {finding['id']}",
                    f"- Class: {finding['vulnerability_class']}",
                    f"- Severity: {finding['severity']}",
                    f"- Confidence: {finding['confidence']}",
                    f"- Location: {finding['location']['path']}:{finding['location']['start_line']}",
                    f"- Source category: {finding.get('source_category', 'product-code')}",
                    f"- Verification status: {finding.get('verification_status', 'unknown')}",
                    f"- Validation: {finding.get('validation', {}).get('level', finding.get('validation_level'))}",
                    f"- Remediation: {finding['remediation']}",
                ]
            )
            cves = finding.get("cve_ids") or [
                item.get("payload", {}).get("cve_id")
                for item in finding.get("vulnerability_intelligence", [])
                if item.get("payload", {}).get("cve_id")
            ]
            if cves:
                lines.append(f"- CVE context: {', '.join(cves)}")
            cwes = finding.get("cwe_ids") or []
            if cwes:
                lines.append(f"- CWE context: {', '.join(cwes)}")
            if finding.get("prompt_refs"):
                lines.append(f"- Prompt refs: {', '.join(finding['prompt_refs'])}")
            if finding.get("memory_refs"):
                lines.append(f"- Memory refs: {', '.join(finding['memory_refs'])}")
            if finding.get("message_refs"):
                lines.append(f"- Message refs: {', '.join(finding['message_refs'])}")
            if finding.get("runtime_task_refs"):
                lines.append(f"- Runtime task refs: {', '.join(finding['runtime_task_refs'])}")
            if finding.get("dataflow_trace_refs"):
                summary = finding.get("dataflow_summary") or {}
                source = summary.get("source", {})
                sink = summary.get("sink", {})
                lines.extend(
                    [
                        "",
                        "#### Dataflow Evidence",
                        f"- Source: {source.get('path', finding['location']['path'])}:{source.get('line', finding['location']['start_line'])} {source.get('expression', '')}".rstrip(),
                        f"- Sink: {sink.get('path', finding['location']['path'])}:{sink.get('line', finding['location']['start_line'])} {sink.get('expression', '')}".rstrip(),
                        f"- Sanitizer: {summary.get('sanitizer_status', finding.get('dataflow_status') or 'unknown')}",
                        f"- Trace refs: {', '.join(finding['dataflow_trace_refs'])}",
                    ]
                )
            lines.extend(
                [
                    "",
                    "#### LLM Influence",
                    f"- Decision source: {finding.get('decision_source', 'deterministic')}",
                ]
            )
            if finding.get("llm_confidence") is not None:
                lines.append(f"- LLM confidence: {finding['llm_confidence']}")
            gate = finding.get("policy_gate") or {}
            if gate:
                lines.append(f"- Policy gate: {gate.get('status', 'unknown')}")
            contextual = finding.get("contextual_intelligence_refs") or []
            if contextual:
                lines.append(f"- Contextual intelligence only: {', '.join(contextual)}")
            if finding.get("fallback_reason"):
                lines.append(f"- Fallback: {finding['fallback_reason']}")
            lines.append("")
        return "\n".join(lines)


def _intelligence_context(finding: Finding, chain: EvidenceChain | None) -> list[dict[str, Any]]:
    if chain:
        return chain.intelligence_refs
    return [{"id": ref, "contextual": True, "validation_evidence": False} for ref in finding.intelligence_refs]


def _verification_status(finding: Finding, validation: dict[str, Any]) -> str:
    status = (
        finding.verification_status
        or finding.metadata.get("verification_status")
        or validation.get("verification_status")
        or validation.get("status")
    )
    if status in {
        VerificationStatus.CONFIRMED,
        VerificationStatus.LIKELY,
        VerificationStatus.REJECTED,
        VerificationStatus.MANUAL_REQUIRED,
    }:
        return str(status)
    if finding.verifier_decision == "reject":
        return VerificationStatus.REJECTED
    if finding.verifier_decision == "accept":
        return VerificationStatus.LIKELY
    return VerificationStatus.MANUAL_REQUIRED
