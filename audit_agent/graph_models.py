from __future__ import annotations

import hashlib
import json
from dataclasses import MISSING, dataclass, field, fields
from typing import Any

from .models import to_plain, utc_now


GRAPH_SCHEMA_VERSION = "agent-execution-graph.v1"
GRAPH_MODES = {"agent-led", "legacy", "deterministic-graph", "adaptive-graph"}
NODE_STATUSES = {
    "pending",
    "runnable",
    "running",
    "succeeded",
    "failed",
    "skipped",
    "fallback",
    "blocked",
}
EXECUTOR_KINDS = {"agent", "tool", "service"}
EDGE_TYPES = {"required", "conditional", "fallback"}
PREDICATE_PARAMETERS = {
    "always": set(),
    "status-equals": {"status"},
    "output-present": {"key"},
    "finding-count-gte": {"minimum"},
    "verification-status-in": {"statuses"},
}


class GraphModel:
    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)

    @classmethod
    def _values(cls, payload: dict[str, Any]) -> dict[str, Any]:
        allowed = {item.name for item in fields(cls)}
        unknown = set(payload) - allowed
        if unknown:
            raise ValueError(f"{cls.__name__} has unknown fields: {sorted(unknown)}")
        required = {
            item.name
            for item in fields(cls)
            if item.default is MISSING and item.default_factory is MISSING
        }
        missing = required - set(payload)
        if missing:
            raise ValueError(f"{cls.__name__} is missing fields: {sorted(missing)}")
        return dict(payload)


@dataclass
class GraphNodeBudget(GraphModel):
    tool_calls: int = 0
    llm_tokens: int = 0
    sandbox_attempts: int = 0

    def __post_init__(self) -> None:
        _validate_non_negative(self, ("tool_calls", "llm_tokens", "sandbox_attempts"))

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "GraphNodeBudget":
        return cls(**cls._values(payload))


@dataclass
class GraphBudget(GraphModel):
    max_nodes: int = 64
    max_scheduler_iterations: int = 256
    max_node_attempts: int = 2
    max_replans: int = 2
    max_checkpoints: int = 2
    max_llm_tokens: int = 200000
    max_tool_calls: int = 1000
    max_sandbox_attempts: int = 20

    def __post_init__(self) -> None:
        _validate_non_negative(
            self,
            (
                "max_nodes",
                "max_scheduler_iterations",
                "max_node_attempts",
                "max_replans",
                "max_checkpoints",
                "max_llm_tokens",
                "max_tool_calls",
                "max_sandbox_attempts",
            ),
        )

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "GraphBudget":
        return cls(**cls._values(payload))


@dataclass
class RetryPolicy(GraphModel):
    max_attempts: int = 1
    fallback_node_id: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.max_attempts, bool) or not isinstance(self.max_attempts, int) or self.max_attempts < 1:
            raise ValueError("retry max_attempts must be a positive integer")

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RetryPolicy":
        return cls(**cls._values(payload))


@dataclass
class NodeLineage(GraphModel):
    parent_node_id: str | None = None
    iteration: int = 0
    checkpoint_id: str | None = None
    proposal_ref: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.iteration, bool) or not isinstance(self.iteration, int) or self.iteration < 0:
            raise ValueError("lineage iteration must be a non-negative integer")

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "NodeLineage":
        return cls(**cls._values(payload))


@dataclass
class GraphInputRef(GraphModel):
    source_node_id: str
    output_key: str
    value_type: str
    required: bool = True

    def __post_init__(self) -> None:
        if not self.source_node_id or not self.output_key or not self.value_type:
            raise ValueError("graph input ref requires source node, output key, and value type")

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "GraphInputRef":
        return cls(**cls._values(payload))


@dataclass
class GraphCondition(GraphModel):
    predicate: str = "always"
    parameters: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.predicate not in PREDICATE_PARAMETERS:
            raise ValueError(f"unregistered graph predicate: {self.predicate}")
        expected = PREDICATE_PARAMETERS[self.predicate]
        if set(self.parameters) != expected:
            raise ValueError(
                f"invalid parameters for predicate {self.predicate}: expected {sorted(expected)}"
            )
        if self.predicate == "status-equals" and self.parameters["status"] not in NODE_STATUSES:
            raise ValueError("status-equals predicate has invalid status")
        if self.predicate == "finding-count-gte":
            minimum = self.parameters["minimum"]
            if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 0:
                raise ValueError("finding-count-gte minimum must be non-negative")
        if self.predicate == "verification-status-in":
            statuses = self.parameters["statuses"]
            if not isinstance(statuses, list) or not all(isinstance(item, str) for item in statuses):
                raise ValueError("verification-status-in statuses must be a string list")

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "GraphCondition":
        return cls(**cls._values(payload))


@dataclass
class GraphNode(GraphModel):
    node_id: str
    template_id: str
    executor_kind: str
    executor_ref: str
    priority: int
    required: bool = True
    input_refs: list[GraphInputRef] = field(default_factory=list)
    output_types: dict[str, str] = field(default_factory=dict)
    budget: GraphNodeBudget = field(default_factory=GraphNodeBudget)
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    lineage: NodeLineage = field(default_factory=NodeLineage)
    status: str = "pending"
    attempt_count: int = 0
    output_refs: dict[str, Any] = field(default_factory=dict)
    artifact_refs: list[str] = field(default_factory=list)
    transition_refs: list[str] = field(default_factory=list)
    started_at: str | None = None
    finished_at: str | None = None

    def __post_init__(self) -> None:
        if not self.node_id or not self.template_id or not self.executor_ref:
            raise ValueError("graph node identity and executor are required")
        if self.executor_kind not in EXECUTOR_KINDS:
            raise ValueError(f"invalid executor kind: {self.executor_kind}")
        if self.status not in NODE_STATUSES:
            raise ValueError(f"invalid graph node status: {self.status}")
        if isinstance(self.priority, bool) or not isinstance(self.priority, int):
            raise ValueError("graph node priority must be an integer")
        if isinstance(self.attempt_count, bool) or not isinstance(self.attempt_count, int) or self.attempt_count < 0:
            raise ValueError("graph node attempt_count must be non-negative")

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "GraphNode":
        values = cls._values(payload)
        values["input_refs"] = [GraphInputRef.from_dict(item) for item in values.get("input_refs", [])]
        values["budget"] = GraphNodeBudget.from_dict(values.get("budget", {}))
        values["retry_policy"] = RetryPolicy.from_dict(values.get("retry_policy", {}))
        values["lineage"] = NodeLineage.from_dict(values.get("lineage", {}))
        return cls(**values)


@dataclass
class GraphEdge(GraphModel):
    edge_id: str
    source_node_id: str
    target_node_id: str
    dependency_type: str = "required"
    terminal_outcome: str | None = None
    condition: GraphCondition = field(default_factory=GraphCondition)

    def __post_init__(self) -> None:
        if not self.edge_id or not self.source_node_id or not self.target_node_id:
            raise ValueError("graph edge identity and endpoints are required")
        if self.dependency_type not in EDGE_TYPES:
            raise ValueError(f"invalid edge dependency type: {self.dependency_type}")

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "GraphEdge":
        values = cls._values(payload)
        values["condition"] = GraphCondition.from_dict(values.get("condition", {}))
        return cls(**values)


@dataclass
class ExecutionGraph(GraphModel):
    graph_id: str
    run_id: str
    revision: int
    mode: str
    template_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    budgets: GraphBudget
    required_terminal_nodes: list[str]
    schema_version: str = GRAPH_SCHEMA_VERSION
    template_version: str = "v1"
    template_content_hash: str = ""
    checkpoint_counts: dict[str, int] = field(default_factory=dict)
    global_replan_count: int = 0
    artifact_refs: list[str] = field(default_factory=list)
    parent_revision_ref: str | None = None
    status: str = "pending"
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if self.schema_version != GRAPH_SCHEMA_VERSION:
            raise ValueError(f"unsupported graph schema: {self.schema_version}")
        if self.mode not in {"deterministic-graph", "adaptive-graph"}:
            raise ValueError(f"invalid graph execution mode: {self.mode}")
        if not self.graph_id or not self.run_id or not self.template_id:
            raise ValueError("graph, run, and template identity are required")
        _validate_non_negative(self, ("revision", "global_replan_count"))

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ExecutionGraph":
        values = cls._values(payload)
        values["nodes"] = [GraphNode.from_dict(item) for item in values.get("nodes", [])]
        values["edges"] = [GraphEdge.from_dict(item) for item in values.get("edges", [])]
        values["budgets"] = GraphBudget.from_dict(values.get("budgets", {}))
        return cls(**values)

    def node(self, node_id: str) -> GraphNode:
        for item in self.nodes:
            if item.node_id == node_id:
                return item
        raise KeyError(f"graph node not found: {node_id}")

    def content_hash(self) -> str:
        payload = self.to_dict()
        payload.pop("artifact_refs", None)
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()


@dataclass(frozen=True)
class GraphTransition(GraphModel):
    graph_id: str
    revision: int
    node_id: str
    old_status: str
    new_status: str
    cause: str
    correlation_refs: tuple[str, ...] = ()
    causation_refs: tuple[str, ...] = ()
    timestamp: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if self.old_status not in NODE_STATUSES or self.new_status not in NODE_STATUSES:
            raise ValueError("graph transition has invalid status")


@dataclass(frozen=True)
class GraphRevision(GraphModel):
    graph_id: str
    revision: int
    parent_revision: int | None
    content_hash: str
    proposal_ref: str | None = None
    policy_ref: str | None = None
    graph_ref: str | None = None
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if self.revision < 0 or (self.parent_revision is not None and self.parent_revision < 0):
            raise ValueError("graph revision values must be non-negative")
        if len(self.content_hash) != 64:
            raise ValueError("graph revision content_hash must be sha256")


def validate_graph(
    graph: ExecutionGraph,
    registered_templates: set[str],
    *,
    required_template_ids: set[str] | None = None,
) -> list[str]:
    node_ids = [item.node_id for item in graph.nodes]
    if len(set(node_ids)) != len(node_ids):
        raise ValueError("duplicate node ID")
    if len(graph.nodes) > graph.budgets.max_nodes:
        raise ValueError("graph node ceiling exceeded")
    nodes = {item.node_id: item for item in graph.nodes}
    for item in graph.nodes:
        if item.template_id not in registered_templates:
            raise ValueError(f"unregistered template: {item.template_id}")
    present_templates = {item.template_id for item in graph.nodes}
    missing_templates = set(required_template_ids or ()) - present_templates
    if missing_templates:
        raise ValueError(f"required template missing: {sorted(missing_templates)}")
    edge_ids = [item.edge_id for item in graph.edges]
    if len(set(edge_ids)) != len(edge_ids):
        raise ValueError("duplicate edge ID")
    outgoing: dict[str, list[str]] = {node_id: [] for node_id in node_ids}
    for edge in graph.edges:
        if edge.source_node_id not in nodes or edge.target_node_id not in nodes:
            raise ValueError(
                f"edge {edge.edge_id} references missing node: "
                f"{edge.source_node_id}->{edge.target_node_id}"
            )
        if edge.source_node_id == edge.target_node_id:
            raise ValueError("graph cycle detected")
        outgoing[edge.source_node_id].append(edge.target_node_id)
    for item in graph.nodes:
        for ref in item.input_refs:
            source = nodes.get(ref.source_node_id)
            if source is None:
                raise ValueError(f"input ref references missing node: {ref.source_node_id}")
            actual_type = source.output_types.get(ref.output_key)
            if actual_type != ref.value_type:
                raise ValueError(
                    f"incompatible input ref {item.node_id}.{ref.output_key}: "
                    f"expected {ref.value_type}, got {actual_type}"
                )
            if ref.required and not _is_upstream_dependency(
                outgoing,
                ref.source_node_id,
                item.node_id,
            ):
                raise ValueError(
                    f"required input source is not upstream: "
                    f"{ref.source_node_id}->{item.node_id}"
                )
    order = stable_topological_order(graph)
    incoming: dict[str, list[str]] = {node_id: [] for node_id in node_ids}
    for edge in graph.edges:
        incoming[edge.target_node_id].append(edge.source_node_id)
    for terminal in graph.required_terminal_nodes:
        if terminal not in nodes or not incoming.get(terminal):
            raise ValueError(f"unreachable required terminal node: {terminal}")
        if not nodes[terminal].required:
            raise ValueError(f"required terminal node is optional: {terminal}")
    return order


def _is_upstream_dependency(
    outgoing: dict[str, list[str]],
    source_node_id: str,
    target_node_id: str,
) -> bool:
    pending = list(outgoing.get(source_node_id, ()))
    visited: set[str] = set()
    while pending:
        node_id = pending.pop()
        if node_id == target_node_id:
            return True
        if node_id in visited:
            continue
        visited.add(node_id)
        pending.extend(outgoing.get(node_id, ()))
    return False


def stable_topological_order(graph: ExecutionGraph) -> list[str]:
    nodes = {item.node_id: item for item in graph.nodes}
    indegree = {node_id: 0 for node_id in nodes}
    outgoing: dict[str, list[str]] = {node_id: [] for node_id in nodes}
    for edge in graph.edges:
        if edge.source_node_id not in nodes or edge.target_node_id not in nodes:
            raise ValueError("graph contains edge with missing node")
        indegree[edge.target_node_id] += 1
        outgoing[edge.source_node_id].append(edge.target_node_id)
    ready = [node_id for node_id, count in indegree.items() if count == 0]
    order: list[str] = []
    while ready:
        ready.sort(key=lambda node_id: (nodes[node_id].priority, node_id))
        node_id = ready.pop(0)
        order.append(node_id)
        for target in sorted(outgoing[node_id]):
            indegree[target] -= 1
            if indegree[target] == 0:
                ready.append(target)
    if len(order) != len(nodes):
        raise ValueError("graph cycle detected")
    return order


def evaluate_condition(condition: GraphCondition, source: GraphNode) -> bool:
    if condition.predicate == "always":
        return True
    if condition.predicate == "status-equals":
        return source.status == condition.parameters["status"]
    if condition.predicate == "output-present":
        return condition.parameters["key"] in source.output_refs
    if condition.predicate == "finding-count-gte":
        value = source.output_refs.get("finding_count", 0)
        try:
            return int(value) >= int(condition.parameters["minimum"])
        except (TypeError, ValueError):
            return False
    if condition.predicate == "verification-status-in":
        return source.output_refs.get("verification_status") in condition.parameters["statuses"]
    return False


def _validate_non_negative(instance: Any, names: tuple[str, ...]) -> None:
    for name in names:
        value = getattr(instance, name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer")
