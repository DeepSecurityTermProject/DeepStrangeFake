from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .graph_models import (
    ExecutionGraph,
    GraphBudget,
    GraphEdge,
    GraphInputRef,
    GraphNode,
    GraphNodeBudget,
    NodeLineage,
    RetryPolicy,
)
from .models import stable_id, to_plain


DETERMINISTIC_TEMPLATE_ID = "audit.deterministic.v1"
DETERMINISTIC_TEMPLATE_VERSION = "v1"
REQUIRED_TEMPLATE_IDS = {
    "agent.orchestrator",
    "tool.static-scan",
    "agent.recon",
    "agent.analysis",
    "agent.verification",
    "service.validation",
    "service.evidence-finalization",
    "service.report-finalization",
}


@dataclass(frozen=True)
class NodeTemplate:
    template_id: str
    executor_kind: str
    executor_ref: str
    priority: int
    required: bool = False
    input_refs: tuple[GraphInputRef, ...] = ()
    output_types: dict[str, str] = field(default_factory=dict)
    budget: GraphNodeBudget = field(default_factory=GraphNodeBudget)
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    checkpoint_id: str | None = None
    mutable: bool = True
    allowed_parameters: tuple[str, ...] = ()

    def instantiate(
        self,
        node_id: str,
        *,
        iteration: int = 0,
        parent_node_id: str | None = None,
        checkpoint_id: str | None = None,
        proposal_ref: str | None = None,
    ) -> GraphNode:
        return GraphNode(
            node_id=node_id,
            template_id=self.template_id,
            executor_kind=self.executor_kind,
            executor_ref=self.executor_ref,
            priority=self.priority,
            required=self.required,
            input_refs=list(self.input_refs),
            output_types=dict(self.output_types),
            budget=GraphNodeBudget.from_dict(self.budget.to_dict()),
            retry_policy=RetryPolicy.from_dict(self.retry_policy.to_dict()),
            lineage=NodeLineage(
                parent_node_id=parent_node_id,
                iteration=iteration,
                checkpoint_id=checkpoint_id or self.checkpoint_id,
                proposal_ref=proposal_ref,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


class NodeTemplateCatalog:
    def __init__(self) -> None:
        self._templates: dict[str, NodeTemplate] = {}

    def register(self, template: NodeTemplate) -> None:
        if template.template_id in self._templates:
            raise ValueError(f"duplicate node template: {template.template_id}")
        if template.executor_kind not in {"agent", "tool", "service"}:
            raise ValueError(f"invalid template executor kind: {template.executor_kind}")
        self._templates[template.template_id] = template

    def get(self, template_id: str) -> NodeTemplate:
        try:
            return self._templates[template_id]
        except KeyError as exc:
            raise KeyError(f"node template is not registered: {template_id}") from exc

    def template_ids(self) -> set[str]:
        return set(self._templates)

    def to_dict(self) -> dict[str, Any]:
        return {key: self._templates[key].to_dict() for key in sorted(self._templates)}


def build_default_template_catalog() -> NodeTemplateCatalog:
    catalog = NodeTemplateCatalog()
    templates = [
        NodeTemplate("agent.orchestrator", "agent", "orchestrator", 10, True, output_types={"plan": "audit-plan"}, mutable=False),
        NodeTemplate("service.memory-context", "service", "memory-context", 20, False, output_types={"context": "memory-context"}),
        NodeTemplate("tool.static-scan", "tool", "static-scan", 30, True, output_types={"scan_results": "tool-result-list"}, mutable=False),
        NodeTemplate("service.intelligence", "service", "intelligence", 40, False, output_types={"intelligence": "intelligence-list"}),
        NodeTemplate("agent.recon", "agent", "recon", 50, True, output_types={"recon": "recon-result"}, mutable=False),
        NodeTemplate("checkpoint.post-recon", "service", "post-recon-checkpoint", 55, False, output_types={"checkpoint": "checkpoint-result"}, checkpoint_id="post-recon"),
        NodeTemplate("agent.analysis", "agent", "analysis", 60, True, output_types={"candidates": "finding-list"}, mutable=False),
        NodeTemplate("checkpoint.post-analysis", "service", "post-analysis-checkpoint", 65, False, output_types={"checkpoint": "checkpoint-result"}, checkpoint_id="post-analysis"),
        NodeTemplate("agent.verification", "agent", "verification", 70, True, output_types={"decisions": "verification-decision-list"}, mutable=False),
        NodeTemplate("service.validation", "service", "validation", 80, True, output_types={"validations": "validation-result-list"}, mutable=False),
        NodeTemplate("service.evidence-finalization", "service", "evidence-finalization", 90, True, output_types={"evidence": "evidence-chain-list"}, mutable=False),
        NodeTemplate("service.report-finalization", "service", "report-finalization", 100, True, output_types={"report": "report-ref"}, mutable=False),
        NodeTemplate("service.local-context-refinement", "service", "local-context-refinement", 57, False, output_types={"context": "memory-context"}, allowed_parameters=("focus_refs",)),
        NodeTemplate("tool.scan-refinement", "tool", "static-scan", 58, False, output_types={"scan_results": "tool-result-list"}, allowed_parameters=("focus_refs",)),
        NodeTemplate("agent.evidence-refinement", "agent", "analysis", 66, False, output_types={"candidates": "finding-list"}, allowed_parameters=("focus_refs",)),
        NodeTemplate("agent.analysis-refinement", "agent", "analysis", 67, False, output_types={"candidates": "finding-list"}, allowed_parameters=("focus_refs",)),
        NodeTemplate("service.verification-routing", "service", "verification-routing", 68, False, output_types={"candidates": "finding-list"}, allowed_parameters=("focus_refs",)),
    ]
    for template in templates:
        catalog.register(template)
    return catalog


def build_deterministic_audit_graph(
    run_id: str,
    *,
    mode: str = "deterministic-graph",
    budgets: GraphBudget | None = None,
) -> ExecutionGraph:
    catalog = build_default_template_catalog()
    node_specs = [
        ("orchestrator-plan", "agent.orchestrator"),
        ("memory-context", "service.memory-context"),
        ("static-scan", "tool.static-scan"),
        ("intelligence", "service.intelligence"),
        ("reconnaissance", "agent.recon"),
        ("post-recon-checkpoint", "checkpoint.post-recon"),
        ("analysis", "agent.analysis"),
        ("post-analysis-checkpoint", "checkpoint.post-analysis"),
        ("verification", "agent.verification"),
        ("validation", "service.validation"),
        ("evidence-finalization", "service.evidence-finalization"),
        ("report-finalization", "service.report-finalization"),
    ]
    nodes = [catalog.get(template_id).instantiate(node_id) for node_id, template_id in node_specs]
    edges = [
        GraphEdge("plan-memory", "orchestrator-plan", "memory-context"),
        GraphEdge("memory-scan", "memory-context", "static-scan"),
        GraphEdge("scan-intelligence", "static-scan", "intelligence"),
        GraphEdge("scan-recon", "static-scan", "reconnaissance"),
        GraphEdge("intelligence-recon", "intelligence", "reconnaissance"),
        GraphEdge("recon-checkpoint", "reconnaissance", "post-recon-checkpoint"),
        GraphEdge("recon-analysis", "reconnaissance", "analysis"),
        GraphEdge("checkpoint-recon-analysis", "post-recon-checkpoint", "analysis"),
        GraphEdge("analysis-checkpoint", "analysis", "post-analysis-checkpoint"),
        GraphEdge("analysis-verification", "analysis", "verification"),
        GraphEdge("checkpoint-analysis-verification", "post-analysis-checkpoint", "verification"),
        GraphEdge("verification-validation", "verification", "validation"),
        GraphEdge("validation-evidence", "validation", "evidence-finalization"),
        GraphEdge("evidence-report", "evidence-finalization", "report-finalization"),
    ]
    template_payload = {
        "template_id": DETERMINISTIC_TEMPLATE_ID,
        "template_version": DETERMINISTIC_TEMPLATE_VERSION,
        "nodes": [item.to_dict() for item in nodes],
        "edges": [item.to_dict() for item in edges],
    }
    template_hash = hashlib.sha256(
        json.dumps(template_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return ExecutionGraph(
        graph_id=stable_id("GR", run_id, DETERMINISTIC_TEMPLATE_ID),
        run_id=run_id,
        revision=0,
        mode=mode,
        template_id=DETERMINISTIC_TEMPLATE_ID,
        template_version=DETERMINISTIC_TEMPLATE_VERSION,
        template_content_hash=template_hash,
        nodes=nodes,
        edges=edges,
        budgets=budgets or GraphBudget(),
        required_terminal_nodes=["report-finalization"],
    )
