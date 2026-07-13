from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .graph_models import ExecutionGraph, GraphEdge, GraphInputRef, stable_topological_order, validate_graph
from .graph_templates import NodeTemplateCatalog
from .models import stable_id, to_plain, utc_now


MUTATION_SCHEMA_VERSION = "graph-mutation-proposal.v1"
MUTATION_OPERATIONS = {
    "insert-template",
    "route-edge",
    "skip-optional",
    "adjust-budget",
    "attach-context",
}
IMMUTABLE_NODE_STATUSES = {"running", "succeeded", "failed", "skipped", "blocked"}
CHECKPOINT_ACTIONS = {
    "post-recon": {"gather-more-local-context", "refine-static-scan"},
    "post-analysis": {
        "refine-evidence",
        "repeat-analysis",
        "route-verification",
        "skip-optional",
    },
}


@dataclass
class GraphMutationOperation:
    operation_id: str
    op: str
    target_node_id: str | None = None
    template_id: str | None = None
    after_node_id: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    budget_delta: dict[str, int] = field(default_factory=dict)
    reason: str = ""

    def __post_init__(self) -> None:
        if not self.operation_id:
            raise ValueError("mutation operation ID is required")
        if self.op not in MUTATION_OPERATIONS:
            raise ValueError(f"unregistered mutation operation: {self.op}")

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class GraphMutationProposal:
    proposal_id: str
    checkpoint_id: str
    graph_id: str
    base_revision: int
    operations: list[GraphMutationOperation]
    schema_version: str = MUTATION_SCHEMA_VERSION
    correlation_refs: list[str] = field(default_factory=list)
    ignored_hints: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if self.schema_version != MUTATION_SCHEMA_VERSION:
            raise ValueError(f"unsupported mutation schema: {self.schema_version}")
        if not self.proposal_id or not self.checkpoint_id or not self.graph_id:
            raise ValueError("mutation proposal identity is required")
        if self.base_revision < 0:
            raise ValueError("mutation base revision must be non-negative")
        operation_ids = [item.operation_id for item in self.operations]
        if len(set(operation_ids)) != len(operation_ids):
            raise ValueError("duplicate mutation operation ID")

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class MutationOperationDecision:
    operation_id: str
    status: str
    reasons: list[str] = field(default_factory=list)
    budget_delta: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class GraphMutationOutcome:
    proposal_id: str
    committed: bool
    graph: ExecutionGraph
    decisions: list[MutationOperationDecision]
    candidate_diagnostics: list[str] = field(default_factory=list)
    committed_revision_ref: str | None = None
    fallback_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = to_plain(self)
        payload["graph"] = self.graph.to_dict()
        return payload


@dataclass
class GraphCheckpointState:
    max_global_replans: int = 2
    per_checkpoint_ceiling: int = 1
    counts: dict[str, int] = field(default_factory=dict)
    global_replans: int = 0

    def consume(self, checkpoint_id: str) -> bool:
        if self.global_replans >= self.max_global_replans:
            return False
        count = self.counts.get(checkpoint_id, 0)
        if count >= self.per_checkpoint_ceiling:
            return False
        self.counts[checkpoint_id] = count + 1
        self.global_replans += 1
        return True


def parse_graph_decision_payload(
    payload: Any,
    *,
    checkpoint_id: str,
) -> list[str]:
    """Parse model output without aliases, coercion, or guessed field names."""
    if not isinstance(payload, dict):
        raise ValueError("graph decision must be a JSON object")
    if set(payload) != {"checkpoint_id", "next_actions", "rationale"}:
        raise ValueError("graph decision fields do not match the strict contract")
    if payload.get("checkpoint_id") != checkpoint_id:
        raise ValueError("graph decision checkpoint does not match the active checkpoint")
    actions = payload.get("next_actions")
    if not isinstance(actions, list) or len(actions) > 3:
        raise ValueError("graph decision next_actions must be an array of at most three items")
    allowed = CHECKPOINT_ACTIONS.get(checkpoint_id, set())
    if not all(isinstance(item, str) and item in allowed for item in actions):
        raise ValueError("graph decision contains an action unavailable at this checkpoint")
    if not isinstance(payload.get("rationale"), str):
        raise ValueError("graph decision rationale must be a string")
    return list(dict.fromkeys(actions))


class GraphMutationPolicy:
    def __init__(
        self,
        catalog: NodeTemplateCatalog,
        required_template_ids: set[str],
        *,
        allow_network: bool = False,
        allow_target_writes: bool = False,
        issued_artifact_refs: set[str] | None = None,
        artifact_ref_validator: Callable[[str], bool] | None = None,
    ) -> None:
        self.catalog = catalog
        self.required_template_ids = set(required_template_ids)
        self.allow_network = allow_network
        self.allow_target_writes = allow_target_writes
        self.issued_artifact_refs = set(issued_artifact_refs or ())
        self.artifact_ref_validator = artifact_ref_validator

    def evaluate(
        self,
        graph: ExecutionGraph,
        proposal: GraphMutationProposal,
    ) -> GraphMutationOutcome:
        if proposal.graph_id != graph.graph_id or proposal.base_revision != graph.revision:
            return GraphMutationOutcome(
                proposal.proposal_id,
                False,
                graph,
                [],
                ["proposal graph or revision mismatch"],
                fallback_reason="proposal-identity-mismatch",
            )
        if graph.global_replan_count >= graph.budgets.max_replans:
            return GraphMutationOutcome(
                proposal.proposal_id,
                False,
                graph,
                [],
                ["graph replan ceiling exceeded"],
                fallback_reason="replan-ceiling-exceeded",
            )
        if sum(graph.checkpoint_counts.values()) >= graph.budgets.max_checkpoints:
            return GraphMutationOutcome(
                proposal.proposal_id,
                False,
                graph,
                [],
                ["graph checkpoint ceiling exceeded"],
                fallback_reason="checkpoint-ceiling-exceeded",
            )
        if graph.checkpoint_counts.get(proposal.checkpoint_id, 0) >= 1:
            return GraphMutationOutcome(
                proposal.proposal_id,
                False,
                graph,
                [],
                ["checkpoint is single use"],
                fallback_reason="checkpoint-ceiling-exceeded",
            )
        candidate = ExecutionGraph.from_dict(graph.to_dict())
        decisions: list[MutationOperationDecision] = []
        accepted = 0
        for operation in proposal.operations:
            reasons = self._apply_operation(candidate, proposal, operation)
            status = "denied" if reasons else "accepted"
            if not reasons:
                accepted += 1
            decisions.append(
                MutationOperationDecision(
                    operation.operation_id,
                    status,
                    reasons,
                    dict(operation.budget_delta),
                )
            )
        if not accepted:
            return GraphMutationOutcome(
                proposal.proposal_id,
                False,
                graph,
                decisions,
                fallback_reason="no-accepted-operations",
            )
        try:
            validate_graph(
                candidate,
                self.catalog.template_ids(),
                required_template_ids=self.required_template_ids,
            )
            _validate_executable_reachability(candidate)
            _validate_aggregate_budgets(candidate)
        except ValueError as exc:
            return GraphMutationOutcome(
                proposal.proposal_id,
                False,
                graph,
                decisions,
                [str(exc)],
                fallback_reason="candidate-graph-invalid",
            )
        candidate.parent_revision_ref = f"revision:{graph.revision}"
        candidate.revision = graph.revision + 1
        candidate.global_replan_count = graph.global_replan_count + 1
        candidate.checkpoint_counts[proposal.checkpoint_id] = (
            candidate.checkpoint_counts.get(proposal.checkpoint_id, 0) + 1
        )
        return GraphMutationOutcome(
            proposal.proposal_id,
            True,
            candidate,
            decisions,
            committed_revision_ref=f"revision:{candidate.revision}",
        )

    def _apply_operation(
        self,
        graph: ExecutionGraph,
        proposal: GraphMutationProposal,
        operation: GraphMutationOperation,
    ) -> list[str]:
        if operation.op == "insert-template":
            return self._insert_template(graph, proposal, operation)
        if operation.op == "route-edge":
            return self._route_edge(graph, proposal, operation)
        if operation.op == "skip-optional":
            node, reasons = self._future_node(graph, operation.target_node_id)
            if reasons:
                return reasons
            if node.required:
                return ["required nodes cannot be skipped"]
            node.status = "skipped"
            graph.edges = [
                edge
                for edge in graph.edges
                if edge.source_node_id != node.node_id
                or not any(
                    alternate.target_node_id == edge.target_node_id
                    and alternate.source_node_id != node.node_id
                    for alternate in graph.edges
                )
            ]
            return []
        if operation.op == "adjust-budget":
            node, reasons = self._future_node(graph, operation.target_node_id)
            if reasons:
                return reasons
            allowed = {"tool_calls", "llm_tokens", "sandbox_attempts"}
            if not operation.budget_delta or set(operation.budget_delta) - allowed:
                return ["budget adjustment contains unsupported fields"]
            ceilings = {
                "tool_calls": graph.budgets.max_tool_calls,
                "llm_tokens": graph.budgets.max_llm_tokens,
                "sandbox_attempts": graph.budgets.max_sandbox_attempts,
            }
            for key, delta in operation.budget_delta.items():
                if isinstance(delta, bool) or not isinstance(delta, int) or delta < 0:
                    return ["budget delta must be a non-negative integer"]
                current_total = sum(getattr(item.budget, key) for item in graph.nodes)
                if current_total + delta > ceilings[key]:
                    return [f"{key} budget ceiling exceeded"]
            for key, delta in operation.budget_delta.items():
                setattr(node.budget, key, getattr(node.budget, key) + delta)
            return []
        if operation.op == "attach-context":
            node, reasons = self._future_node(graph, operation.target_node_id)
            if reasons:
                return reasons
            refs = operation.parameters.get("context_refs")
            if operation.parameters.get("target_writes") and not self.allow_target_writes:
                return ["target writes are not allowed"]
            if not isinstance(refs, list) or not all(self._approved_context_ref(item) for item in refs):
                return ["context refs must be approved local artifact refs"]
            for ref in refs:
                if ref not in node.artifact_refs:
                    node.artifact_refs.append(ref)
            return []
        return ["unregistered mutation operation"]

    def _insert_template(self, graph, proposal, operation):
        if len(graph.nodes) >= graph.budgets.max_nodes:
            return ["graph node ceiling exceeded"]
        if not operation.template_id:
            return ["insert-template requires template_id"]
        try:
            template = self.catalog.get(operation.template_id)
        except KeyError:
            return [f"unregistered template: {operation.template_id}"]
        parent, reasons = self._insertion_anchor(graph, proposal, operation.after_node_id)
        if reasons:
            return reasons
        node_id = operation.parameters.get("node_id")
        if not isinstance(node_id, str) or not node_id:
            return ["insert-template requires a node_id parameter"]
        if any(item.node_id == node_id for item in graph.nodes):
            return [f"duplicate node ID: {node_id}"]
        extra = set(operation.parameters) - {"node_id"} - set(template.allowed_parameters)
        if extra:
            return [f"template parameters are not allowed: {sorted(extra)}"]
        node = template.instantiate(
            node_id,
            iteration=parent.lineage.iteration + 1,
            parent_node_id=parent.node_id,
            checkpoint_id=proposal.checkpoint_id,
            proposal_ref=proposal.proposal_id,
        )
        focus_refs = operation.parameters.get("focus_refs", [])
        if not isinstance(focus_refs, list) or not all(self._approved_context_ref(ref) for ref in focus_refs):
            return ["focus refs must be approved local artifact refs"]
        node.artifact_refs.extend(focus_refs)
        outgoing = [item for item in graph.edges if item.source_node_id == parent.node_id]
        for edge in outgoing:
            target = graph.node(edge.target_node_id)
            if target.status in IMMUTABLE_NODE_STATUSES:
                return [f"cannot insert before immutable successor: {target.node_id}"]
        graph.edges = [item for item in graph.edges if item not in outgoing]
        graph.nodes.append(node)
        graph.edges.append(
            GraphEdge(
                stable_id("GE", graph.graph_id, parent.node_id, node_id),
                parent.node_id,
                node_id,
            )
        )
        for edge in outgoing:
            graph.edges.append(
                GraphEdge(
                    edge.edge_id,
                    node_id,
                    edge.target_node_id,
                    dependency_type=edge.dependency_type,
                    terminal_outcome=edge.terminal_outcome,
                    condition=edge.condition,
                )
            )
            target = graph.node(edge.target_node_id)
            for output_key, value_type in node.output_types.items():
                ref = GraphInputRef(node_id, output_key, value_type, required=node.required)
                if not any(
                    existing.source_node_id == node_id and existing.output_key == output_key
                    for existing in target.input_refs
                ):
                    target.input_refs.append(ref)
        return []

    def _route_edge(self, graph, proposal, operation):
        params = operation.parameters
        source_id = params.get("source_node_id")
        target_id = params.get("target_node_id")
        edge_id = params.get("edge_id")
        source, source_reasons = self._insertion_anchor(graph, proposal, source_id)
        target, target_reasons = self._future_node(graph, target_id)
        reasons = source_reasons + target_reasons
        if reasons:
            return reasons
        if not isinstance(edge_id, str) or not edge_id:
            return ["route-edge requires edge_id"]
        if any(item.edge_id == edge_id for item in graph.edges):
            return [f"duplicate edge ID: {edge_id}"]
        graph.edges.append(GraphEdge(edge_id, source.node_id, target.node_id))
        return []

    @staticmethod
    def _future_node(graph: ExecutionGraph, node_id: str | None):
        if not node_id:
            return None, ["operation requires target future node"]
        try:
            node = graph.node(node_id)
        except KeyError:
            return None, [f"unknown target node: {node_id}"]
        if node.status in IMMUTABLE_NODE_STATUSES:
            return None, [f"node is no longer mutable: {node_id}"]
        if not node.required and node.status == "skipped":
            return None, [f"node is no longer mutable: {node_id}"]
        return node, []

    def _insertion_anchor(
        self,
        graph: ExecutionGraph,
        proposal: GraphMutationProposal,
        node_id: str | None,
    ):
        if not node_id:
            return None, ["operation requires target future node"]
        try:
            node = graph.node(node_id)
        except KeyError:
            return None, [f"unknown target node: {node_id}"]
        is_active_checkpoint = (
            node.status == "running"
            and node.template_id.startswith("checkpoint.")
            and node.lineage.checkpoint_id == proposal.checkpoint_id
        )
        if node.status in IMMUTABLE_NODE_STATUSES and not is_active_checkpoint:
            return None, [f"node is no longer mutable: {node_id}"]
        return node, []

    def _approved_context_ref(self, value: Any) -> bool:
        if not isinstance(value, str) or not value or "://" in value:
            return False
        issued = value in self.issued_artifact_refs
        if self.artifact_ref_validator is not None:
            try:
                issued = issued or bool(self.artifact_ref_validator(value))
            except Exception:
                return False
        return issued


def translate_next_actions(
    *,
    graph_id: str,
    revision: int,
    checkpoint_id: str,
    next_actions: list[str],
) -> GraphMutationProposal:
    mappings = {
        "gather-more-local-context": "service.local-context-refinement",
        "refine-static-scan": "tool.scan-refinement",
        "refine-evidence": "agent.evidence-refinement",
        "repeat-analysis": "agent.analysis-refinement",
        "route-verification": "service.verification-routing",
    }
    operations = []
    ignored = []
    last_inserted_node_id = None
    for index, hint in enumerate(next_actions):
        if hint == "skip-optional":
            if last_inserted_node_id is None:
                ignored.append(hint)
                continue
            checkpoint_node_id = (
                "post-recon-checkpoint" if checkpoint_id == "post-recon" else "post-analysis-checkpoint"
            )
            successor_id = "analysis" if checkpoint_id == "post-recon" else "verification"
            operations.extend(
                [
                    GraphMutationOperation(
                        operation_id=stable_id("GMO", graph_id, revision, checkpoint_id, index, hint, "bypass"),
                        op="route-edge",
                        parameters={
                            "edge_id": stable_id("GE", graph_id, checkpoint_node_id, successor_id, revision),
                            "source_node_id": checkpoint_node_id,
                            "target_node_id": successor_id,
                        },
                        reason="translated-next-action:skip-optional-bypass",
                    ),
                    GraphMutationOperation(
                        operation_id=stable_id("GMO", graph_id, revision, checkpoint_id, index, hint, "skip"),
                        op="skip-optional",
                        target_node_id=last_inserted_node_id,
                        reason="translated-next-action:skip-optional",
                    ),
                ]
            )
            continue
        template_id = mappings.get(hint)
        if not template_id:
            ignored.append(hint)
            continue
        node_id = f"{hint}-{revision + 1}-{index}"
        operations.append(
            GraphMutationOperation(
                operation_id=stable_id("GMO", graph_id, revision, checkpoint_id, index, hint),
                op="insert-template",
                template_id=template_id,
                after_node_id=(
                    "post-recon-checkpoint"
                    if checkpoint_id == "post-recon"
                    else "post-analysis-checkpoint"
                ),
                parameters={"node_id": node_id},
                reason=f"translated-next-action:{hint}",
            )
        )
        last_inserted_node_id = node_id
    return GraphMutationProposal(
        proposal_id=stable_id("GMP", graph_id, revision, checkpoint_id, next_actions),
        checkpoint_id=checkpoint_id,
        graph_id=graph_id,
        base_revision=revision,
        operations=operations,
        ignored_hints=ignored,
    )


def _validate_executable_reachability(graph: ExecutionGraph) -> None:
    order = stable_topological_order(graph)
    incoming = {item.node_id: [] for item in graph.nodes}
    for edge in graph.edges:
        incoming[edge.target_node_id].append(edge)
    reachable: set[str] = set()
    unavailable = {"failed", "skipped", "blocked"}
    already_reached = {"runnable", "running", "succeeded", "fallback"}
    for node_id in order:
        node = graph.node(node_id)
        if node.status in unavailable:
            continue
        if node.status in already_reached:
            reachable.add(node_id)
            continue
        edges = incoming[node_id]
        normal_edges = [item for item in edges if item.dependency_type != "fallback"]
        fallback_edges = [item for item in edges if item.dependency_type == "fallback"]
        active_normal_edges = [
            item
            for item in normal_edges
            if not (
                graph.node(item.source_node_id).status == "skipped"
                and not graph.node(item.source_node_id).required
            )
        ]
        normal_reachable = (
            not normal_edges
            or bool(active_normal_edges)
            and all(item.source_node_id in reachable for item in active_normal_edges)
        )
        fallback_reachable = not fallback_edges or any(
            item.source_node_id in reachable for item in fallback_edges
        )
        if normal_reachable and fallback_reachable:
            reachable.add(node_id)
    unreachable = [
        item.node_id for item in graph.nodes if item.required and item.node_id not in reachable
    ]
    if unreachable:
        raise ValueError(f"required nodes unreachable after mutation: {sorted(unreachable)}")


def _validate_aggregate_budgets(graph: ExecutionGraph) -> None:
    fields = {
        "tool_calls": graph.budgets.max_tool_calls,
        "llm_tokens": graph.budgets.max_llm_tokens,
        "sandbox_attempts": graph.budgets.max_sandbox_attempts,
    }
    for name, ceiling in fields.items():
        total = sum(getattr(item.budget, name) for item in graph.nodes)
        if total > ceiling:
            raise ValueError(f"aggregate {name} budget ceiling exceeded")
