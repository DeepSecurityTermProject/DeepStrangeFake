from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .graph_models import (
    ExecutionGraph,
    GraphEdge,
    GraphInputRef,
    GraphNode,
    GraphTransition,
    evaluate_condition,
    validate_graph,
)


NodeHandler = Callable[[GraphNode, dict[str, Any]], "GraphNodeResult"]
ExecutorHandler = Callable[[str, GraphNode, dict[str, Any]], "GraphNodeResult"]
TransitionSink = Callable[[list[GraphTransition]], None]
TERMINAL_NODE_STATUSES = {"succeeded", "failed", "skipped", "fallback", "blocked"}


@dataclass
class GraphNodeResult:
    outputs: dict[str, Any] = field(default_factory=dict)
    artifact_refs: list[str] = field(default_factory=list)
    correlation_refs: list[str] = field(default_factory=list)


@dataclass
class GraphRunResult:
    status: str
    execution_path: list[str]
    transitions: list[GraphTransition]
    failure_reason: str = ""
    scheduler_iterations: int = 0


class GraphScheduler:
    def __init__(
        self,
        graph: ExecutionGraph,
        *,
        registered_templates: set[str],
        service_handlers: dict[str, NodeHandler] | None = None,
        agent_executor: ExecutorHandler | None = None,
        tool_executor: ExecutorHandler | None = None,
        transition_sink: TransitionSink | None = None,
        required_template_ids: set[str] | None = None,
    ) -> None:
        self.graph = graph
        self.registered_templates = set(registered_templates)
        self.service_handlers = service_handlers or {}
        self.agent_executor = agent_executor
        self.tool_executor = tool_executor
        self.transition_sink = transition_sink
        self.required_template_ids = required_template_ids
        self.transitions: list[GraphTransition] = []
        self.execution_path: list[str] = []
        self.results: dict[str, GraphNodeResult] = {}
        self.failure_reason = ""
        self.iterations = 0

    def run(self) -> GraphRunResult:
        validate_graph(
            self.graph,
            self.registered_templates,
            required_template_ids=self.required_template_ids,
        )
        for node in self.graph.nodes:
            fallback_id = node.retry_policy.fallback_node_id
            if fallback_id:
                try:
                    self.graph.node(fallback_id)
                except KeyError as exc:
                    raise ValueError(
                        f"registered fallback node is missing: {node.node_id}->{fallback_id}"
                    ) from exc
        self.graph.status = "running"
        while True:
            required_failure = next(
                (
                    item
                    for item in self.graph.nodes
                    if item.required
                    and item.status in {"failed", "blocked"}
                    and self._required_failure_is_unhandled(item)
                ),
                None,
            )
            if required_failure:
                self.graph.status = "failed"
                return self._result("failed")
            if all(item.status in TERMINAL_NODE_STATUSES for item in self.graph.nodes):
                terminals_ok = all(
                    self.graph.node(node_id).status == "succeeded"
                    for node_id in self.graph.required_terminal_nodes
                )
                self.graph.status = "succeeded" if terminals_ok else "failed"
                if not terminals_ok and not self.failure_reason:
                    self.failure_reason = "required-terminal-not-succeeded"
                return self._result(self.graph.status)
            if self.iterations >= self.graph.budgets.max_scheduler_iterations:
                self.failure_reason = "scheduler-iteration-ceiling"
                self.graph.status = "bounded-termination"
                return self._result("bounded-termination")

            runnable = self._derive_runnable()
            if not runnable:
                self._finalize_unreachable_nodes()
                runnable = self._derive_runnable()
            if not runnable:
                if all(item.status in TERMINAL_NODE_STATUSES for item in self.graph.nodes):
                    continue
                self.failure_reason = self.failure_reason or "scheduler-deadlock"
                self.graph.status = "failed"
                return self._result("failed")

            runnable.sort(key=lambda item: (item.priority, item.node_id))
            node = runnable[0]
            self.iterations += 1
            self._execute(node)

    def _derive_runnable(self) -> list[GraphNode]:
        runnable: list[GraphNode] = [
            node for node in self.graph.nodes if node.status == "runnable"
        ]
        incoming = self._incoming_edges()
        for node in self.graph.nodes:
            if node.status != "pending":
                continue
            edges = incoming[node.node_id]
            if not edges:
                self._transition(node, "runnable", "dependencies-satisfied")
                runnable.append(node)
                continue
            sources = [self.graph.node(edge.source_node_id) for edge in edges]
            if not all(source.status in TERMINAL_NODE_STATUSES for source in sources):
                continue
            active = []
            for edge, source in zip(edges, sources):
                if edge.dependency_type == "fallback":
                    active.append(source.status in {"failed", "blocked"} and evaluate_condition(edge.condition, source))
                else:
                    active.append(source.status == "succeeded" and evaluate_condition(edge.condition, source))
            if all(active):
                self._transition(node, "runnable", "dependencies-satisfied", [edge.edge_id for edge in edges])
                runnable.append(node)
            elif node.required:
                self.failure_reason = f"required node {node.node_id} has unsatisfied dependency or condition"
                self._transition(node, "blocked", "required-dependency-unsatisfied", [edge.edge_id for edge in edges])
            else:
                self._transition(node, "skipped", "optional-condition-unsatisfied", [edge.edge_id for edge in edges])
        return runnable

    def _execute(self, node: GraphNode) -> None:
        attempt_limit = min(
            node.retry_policy.max_attempts,
            self.graph.budgets.max_node_attempts,
        )
        if node.attempt_count >= attempt_limit:
            self.failure_reason = f"node {node.node_id} reached graph node-attempt ceiling"
            self._transition(node, "failed", "node-attempt-ceiling")
            return
        while node.attempt_count < attempt_limit:
            node.attempt_count += 1
            self._transition(node, "running", "scheduler-selected")
            if node.node_id not in self.execution_path:
                self.execution_path.append(node.node_id)
            try:
                inputs = self._resolve_inputs(node)
                result = self._invoke(node, inputs)
                self.results[node.node_id] = result
                node.output_refs = dict(result.outputs)
                for ref in result.artifact_refs:
                    if ref not in node.artifact_refs:
                        node.artifact_refs.append(ref)
                self._transition(
                    node,
                    "succeeded",
                    "executor-succeeded",
                    result.correlation_refs,
                )
                self._recover_fallback_sources(node)
                return
            except Exception as exc:
                if node.attempt_count < attempt_limit:
                    self._transition(node, "fallback", f"retry:{type(exc).__name__}")
                    self._transition(node, "runnable", "retry-approved")
                    continue
                self.failure_reason = f"node {node.node_id} failed: {type(exc).__name__}: {exc}"
                self._transition(node, "failed", f"executor-failed:{type(exc).__name__}")
                return

    def _resolve_inputs(self, node: GraphNode) -> dict[str, Any]:
        values: dict[str, Any] = {}
        for ref in node.input_refs:
            source_result = self.results.get(ref.source_node_id)
            if source_result is None or ref.output_key not in source_result.outputs:
                if ref.required:
                    raise ValueError(
                        f"missing required input {ref.source_node_id}.{ref.output_key} for {node.node_id}"
                    )
                continue
            value = source_result.outputs[ref.output_key]
            if not _value_matches_type(value, ref.value_type):
                raise TypeError(
                    f"incompatible runtime input {ref.source_node_id}.{ref.output_key}: {ref.value_type}"
                )
            values[ref.output_key] = value
        return values

    def _invoke(self, node: GraphNode, inputs: dict[str, Any]) -> GraphNodeResult:
        if node.executor_kind == "service":
            handler = self.service_handlers.get(node.executor_ref)
            if handler is None:
                raise KeyError(f"runtime service handler is not registered: {node.executor_ref}")
            value = handler(node, inputs)
        elif node.executor_kind == "agent":
            if self.agent_executor is None:
                raise KeyError("agent executor is not registered")
            value = self.agent_executor(node.executor_ref, node, inputs)
        elif node.executor_kind == "tool":
            if self.tool_executor is None:
                raise KeyError("tool executor is not registered")
            value = self.tool_executor(node.executor_ref, node, inputs)
        else:  # structural validation normally prevents this
            raise ValueError(f"unsupported executor kind: {node.executor_kind}")
        if isinstance(value, GraphNodeResult):
            return value
        if isinstance(value, dict):
            return GraphNodeResult(outputs=value)
        raise TypeError("graph node executor must return GraphNodeResult or dict")

    def _finalize_unreachable_nodes(self) -> None:
        incoming = self._incoming_edges()
        for node in self.graph.nodes:
            if node.status != "pending":
                continue
            edges = incoming[node.node_id]
            edges = [
                edge
                for edge in edges
                if not (
                    self.graph.node(edge.source_node_id).status == "skipped"
                    and not self.graph.node(edge.source_node_id).required
                )
            ]
            if not edges:
                if incoming[node.node_id]:
                    continue
            sources = [self.graph.node(edge.source_node_id) for edge in edges]
            if all(source.status in TERMINAL_NODE_STATUSES for source in sources):
                if node.required:
                    self.failure_reason = f"required node {node.node_id} is unreachable"
                    self._transition(node, "blocked", "required-node-unreachable")
                else:
                    self._transition(node, "skipped", "optional-node-unreachable")

    def _incoming_edges(self):
        incoming = {item.node_id: [] for item in self.graph.nodes}
        for edge in self.graph.edges:
            incoming[edge.target_node_id].append(edge)
        for source in self.graph.nodes:
            target_id = source.retry_policy.fallback_node_id
            if not target_id or target_id not in incoming:
                continue
            if any(
                edge.source_node_id == source.node_id
                and edge.target_node_id == target_id
                and edge.dependency_type == "fallback"
                for edge in incoming[target_id]
            ):
                continue
            incoming[target_id].append(
                GraphEdge(
                    f"retry-fallback:{source.node_id}:{target_id}",
                    source.node_id,
                    target_id,
                    dependency_type="fallback",
                )
            )
        for edges in incoming.values():
            edges.sort(key=lambda item: item.edge_id)
        return incoming

    def _fallback_targets(self, source: GraphNode) -> list[GraphNode]:
        target_ids = {
            edge.target_node_id
            for edge in self.graph.edges
            if edge.source_node_id == source.node_id and edge.dependency_type == "fallback"
        }
        if source.retry_policy.fallback_node_id:
            target_ids.add(source.retry_policy.fallback_node_id)
        targets = []
        for target_id in sorted(target_ids):
            try:
                targets.append(self.graph.node(target_id))
            except KeyError:
                continue
        return targets

    def _required_failure_is_unhandled(self, source: GraphNode) -> bool:
        targets = self._fallback_targets(source)
        if not targets:
            return True
        return all(target.status in {"failed", "skipped", "blocked"} for target in targets)

    def _recover_fallback_sources(self, fallback_node: GraphNode) -> None:
        for source in self.graph.nodes:
            if source.status not in {"failed", "blocked"}:
                continue
            if fallback_node not in self._fallback_targets(source):
                continue
            self._transition(
                source,
                "fallback",
                f"fallback-succeeded:{fallback_node.node_id}",
                [fallback_node.node_id],
            )
        if not any(
            item.required
            and item.status in {"failed", "blocked"}
            and self._required_failure_is_unhandled(item)
            for item in self.graph.nodes
        ):
            self.failure_reason = ""

    def _transition(
        self,
        node: GraphNode,
        new_status: str,
        cause: str,
        causation_refs: list[str] | None = None,
    ) -> None:
        transition = GraphTransition(
            graph_id=self.graph.graph_id,
            revision=self.graph.revision,
            node_id=node.node_id,
            old_status=node.status,
            new_status=new_status,
            cause=cause,
            correlation_refs=tuple(node.artifact_refs),
            causation_refs=tuple(causation_refs or ()),
        )
        node.status = new_status
        self.transitions.append(transition)
        node.transition_refs.append(f"transition:{len(self.transitions)}")
        if self.transition_sink:
            self.transition_sink([transition])

    def _result(self, status: str) -> GraphRunResult:
        return GraphRunResult(
            status=status,
            execution_path=list(self.execution_path),
            transitions=list(self.transitions),
            failure_reason=self.failure_reason,
            scheduler_iterations=self.iterations,
        )


def _value_matches_type(value: Any, value_type: str) -> bool:
    primitive = {
        "text": str,
        "integer": int,
        "boolean": bool,
        "number": (int, float),
    }
    expected = primitive.get(value_type)
    if expected is None:
        return True
    if value_type in {"integer", "number"} and isinstance(value, bool):
        return False
    return isinstance(value, expected)
