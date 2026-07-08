from __future__ import annotations

import json
from typing import Any

from .models import EvidenceChain, Finding, Report, RepositoryMetadata


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
    ) -> Report:
        evidence_by_finding = {chain.finding_id: chain for chain in evidence_chains}
        report_findings: list[dict[str, Any]] = []
        for finding in findings:
            chain = evidence_by_finding.get(finding.id or "")
            item = finding.to_dict()
            item["remediation"] = item.get("remediation") or REMEDIATION.get(
                finding.vulnerability_class, "Review and fix the affected code path."
            )
            item["evidence_chain_id"] = chain.id if chain else None
            item["agent_traces"] = chain.agent_traces if chain else []
            item["handoffs"] = chain.handoffs if chain else []
            item["validation"] = chain.validation if chain else {}
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
            ):
                item[key] = finding.metadata.get(key, [])
            item["decision_source"] = finding.metadata.get("decision_source", "deterministic")
            item["llm_confidence"] = finding.metadata.get("llm_confidence")
            item["policy_gate"] = finding.metadata.get("policy_gate", {})
            item["fallback_reason"] = finding.metadata.get("fallback_reason", "")
            item["local_evidence_refs"] = finding.metadata.get("local_evidence_refs", list(finding.tool_refs))
            item["contextual_intelligence_refs"] = finding.metadata.get(
                "contextual_intelligence_refs",
                list(finding.intelligence_refs) + finding.metadata.get("memory_refs", []),
            )
            report_findings.append(item)
        summary = {
            "target": metadata.target.source,
            "finding_count": len(report_findings),
            "validated_count": sum(1 for item in report_findings if item.get("verifier_decision") == "accept"),
            "languages": metadata.languages,
        }
        return Report(
            target_metadata=metadata.to_dict(),
            executive_summary=summary,
            findings=report_findings,
            evidence_chains=[chain.to_dict() for chain in evidence_chains],
            runtime=runtime or {},
        )

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
            "",
            "## Findings",
            "",
        ]
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
