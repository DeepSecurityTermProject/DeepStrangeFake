from __future__ import annotations

import json
from pathlib import Path

from .models import (
    AgentHandoff,
    AgentTrace,
    EvidenceChain,
    Finding,
    RepositoryMetadata,
    ToolResult,
    ValidationResult,
    VerificationDecision,
    VulnerabilityIntelligence,
    to_plain,
)
from .storage import immutable_path


class EvidenceBuilder:
    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def build(
        self,
        finding: Finding,
        metadata: RepositoryMetadata,
        tool_results: list[ToolResult],
        intelligence: list[VulnerabilityIntelligence],
        verification: VerificationDecision,
        validation: ValidationResult,
        agent_traces: list[AgentTrace],
        handoffs: list[AgentHandoff],
    ) -> EvidenceChain:
        tool_refs = [self._persist("tool", result.id or result.tool_name, result.to_dict()) for result in tool_results]
        intelligence_refs = [
            self._persist("intelligence", item.id or item.tool_name, item.to_dict()) for item in intelligence
        ]
        trace_refs = [trace.to_dict() for trace in agent_traces]
        handoff_refs = [handoff.to_dict() for handoff in handoffs]
        dataflow_trace_refs = list(finding.metadata.get("dataflow_trace_refs", []))
        source_locations = _source_locations_with_dataflow(finding)
        artifact_refs = list(validation.artifacts)
        for ref in dataflow_trace_refs:
            if ref and ref not in artifact_refs:
                artifact_refs.append(ref)
        chain = EvidenceChain(
            finding_id=finding.id or "",
            source_locations=source_locations,
            vulnerability_class=finding.vulnerability_class,
            analysis_rationale=finding.description or finding.title,
            verification=verification.to_dict(),
            validation=validation.to_dict(),
            intelligence_refs=intelligence_refs,
            artifact_refs=artifact_refs,
            tool_refs=tool_refs,
            dataflow_trace_refs=dataflow_trace_refs,
            agent_traces=trace_refs,
            handoffs=handoff_refs,
            call_path=finding.call_path,
        )
        self._persist("evidence-chain", chain.id or finding.id or "finding", chain.to_dict())
        return chain

    def _persist(self, category: str, name: str, payload: dict) -> dict:
        safe_name = "".join(char if char.isalnum() or char in "-_." else "-" for char in name)
        path = immutable_path(self.root / f"{category}-{safe_name}.json")
        path.write_text(json.dumps(to_plain(payload), ensure_ascii=False, indent=2), encoding="utf-8")
        return {"kind": category, "path": str(path), "payload": payload}


def _source_locations_with_dataflow(finding: Finding):
    locations = [finding.location]
    seen = {(finding.location.path, finding.location.start_line, finding.location.end_line)}
    for item in finding.metadata.get("dataflow_locations", []):
        path = item.get("path")
        start = item.get("start_line")
        end = item.get("end_line") or start
        if not path or not start:
            continue
        key = (path, int(start), int(end))
        if key in seen:
            continue
        seen.add(key)
        locations.append(
            type(finding.location)(
                path=path,
                start_line=int(start),
                end_line=int(end),
                symbol=item.get("symbol"),
                snippet=item.get("snippet"),
            )
        )
    return locations
