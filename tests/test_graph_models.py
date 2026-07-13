import json
import unittest
from dataclasses import FrozenInstanceError

from audit_agent.graph_models import (
    ExecutionGraph,
    GraphBudget,
    GraphCondition,
    GraphEdge,
    GraphInputRef,
    GraphNode,
    GraphNodeBudget,
    GraphRevision,
    GraphTransition,
    NodeLineage,
    RetryPolicy,
    stable_topological_order,
    validate_graph,
)


REGISTERED_TEMPLATES = {
    "agent.orchestrator",
    "service.scan",
    "service.report",
}


def node(
    node_id: str,
    template_id: str,
    priority: int,
    *,
    required: bool = True,
    inputs: list[GraphInputRef] | None = None,
    outputs: dict[str, str] | None = None,
) -> GraphNode:
    return GraphNode(
        node_id=node_id,
        template_id=template_id,
        executor_kind="service" if template_id.startswith("service.") else "agent",
        executor_ref="runtime" if template_id.startswith("service.") else "orchestrator",
        priority=priority,
        required=required,
        input_refs=inputs or [],
        output_types=outputs or {},
        budget=GraphNodeBudget(tool_calls=2, llm_tokens=10, sandbox_attempts=0),
        retry_policy=RetryPolicy(max_attempts=1),
        lineage=NodeLineage(iteration=0),
    )


def graph() -> ExecutionGraph:
    return ExecutionGraph(
        graph_id="graph-1",
        run_id="run-1",
        revision=0,
        mode="deterministic-graph",
        template_id="audit.deterministic.v1",
        nodes=[
            node("plan", "agent.orchestrator", 10, outputs={"plan": "audit-plan"}),
            node(
                "scan",
                "service.scan",
                20,
                inputs=[GraphInputRef("plan", "plan", "audit-plan")],
                outputs={"findings": "finding-list"},
            ),
            node(
                "report",
                "service.report",
                100,
                inputs=[GraphInputRef("scan", "findings", "finding-list")],
                outputs={"report": "report-ref"},
            ),
        ],
        edges=[
            GraphEdge("edge-plan-scan", "plan", "scan"),
            GraphEdge(
                "edge-scan-report",
                "scan",
                "report",
                condition=GraphCondition("status-equals", {"status": "succeeded"}),
            ),
        ],
        budgets=GraphBudget(max_nodes=10, max_scheduler_iterations=30, max_replans=2),
        required_terminal_nodes=["report"],
    )


class GraphModelTests(unittest.TestCase):
    def test_graph_round_trip_preserves_nested_schema(self):
        original = graph()
        payload = original.to_dict()
        restored = ExecutionGraph.from_dict(json.loads(json.dumps(payload)))

        self.assertEqual(restored.to_dict(), payload)
        self.assertEqual(payload["schema_version"], "agent-execution-graph.v1")
        self.assertEqual(restored.nodes[1].input_refs[0].value_type, "audit-plan")
        self.assertEqual(restored.edges[1].condition.predicate, "status-equals")

    def test_conditions_reject_arbitrary_expressions_and_unknown_parameters(self):
        with self.assertRaisesRegex(ValueError, "predicate"):
            GraphCondition("python-eval", {"expression": "__import__('os')"})
        with self.assertRaisesRegex(ValueError, "parameters"):
            GraphCondition("status-equals", {"status": "succeeded", "expression": "x"})

    def test_transition_and_revision_records_are_immutable(self):
        transition = GraphTransition(
            graph_id="graph-1",
            revision=1,
            node_id="scan",
            old_status="runnable",
            new_status="running",
            cause="scheduler-selected",
            correlation_refs=("task-1",),
            causation_refs=("edge-plan-scan",),
        )
        revision = GraphRevision(
            graph_id="graph-1",
            revision=1,
            parent_revision=0,
            content_hash="a" * 64,
            proposal_ref="proposal-1",
            policy_ref="policy-1",
        )
        with self.assertRaises(FrozenInstanceError):
            transition.new_status = "succeeded"
        with self.assertRaises(FrozenInstanceError):
            revision.revision = 2

    def test_validator_rejects_duplicate_missing_cycle_and_unreachable_terminal(self):
        duplicate = graph()
        duplicate.nodes.append(node("scan", "service.scan", 30))
        with self.assertRaisesRegex(ValueError, "duplicate node"):
            validate_graph(duplicate, REGISTERED_TEMPLATES)

        missing = graph()
        missing.edges.append(GraphEdge("missing", "absent", "report"))
        with self.assertRaisesRegex(ValueError, "missing node"):
            validate_graph(missing, REGISTERED_TEMPLATES)

        cyclic = graph()
        cyclic.edges.append(GraphEdge("back", "report", "plan"))
        with self.assertRaisesRegex(ValueError, "cycle"):
            validate_graph(cyclic, REGISTERED_TEMPLATES)

        unreachable = graph()
        unreachable.edges = [GraphEdge("edge-plan-scan", "plan", "scan")]
        unreachable.nodes[2].input_refs = []
        with self.assertRaisesRegex(ValueError, "required terminal"):
            validate_graph(unreachable, REGISTERED_TEMPLATES)

    def test_validator_rejects_unregistered_template_and_incompatible_input_ref(self):
        unknown = graph()
        unknown.nodes[1].template_id = "service.model-authored-command"
        with self.assertRaisesRegex(ValueError, "unregistered template"):
            validate_graph(unknown, REGISTERED_TEMPLATES)

        incompatible = graph()
        incompatible.nodes[1].input_refs[0] = GraphInputRef("plan", "plan", "finding-list")
        with self.assertRaisesRegex(ValueError, "incompatible input ref"):
            validate_graph(incompatible, REGISTERED_TEMPLATES)

    def test_required_input_source_must_be_a_structural_upstream_dependency(self):
        missing_dependency = graph()
        missing_dependency.edges = [
            edge for edge in missing_dependency.edges if edge.edge_id != "edge-plan-scan"
        ]

        with self.assertRaisesRegex(ValueError, "required input source is not upstream"):
            validate_graph(missing_dependency, REGISTERED_TEMPLATES)

        transitive_dependency = graph()
        transitive_dependency.nodes[2].input_refs = [
            GraphInputRef("plan", "plan", "audit-plan")
        ]
        self.assertEqual(
            validate_graph(transitive_dependency, REGISTERED_TEMPLATES),
            ["plan", "scan", "report"],
        )

    def test_topological_order_uses_priority_then_stable_node_id(self):
        value = graph()
        value.nodes.insert(1, node("context-b", "service.scan", 15, required=False))
        value.nodes.insert(1, node("context-a", "service.scan", 15, required=False))
        value.edges.extend(
            [
                GraphEdge("plan-context-a", "plan", "context-a"),
                GraphEdge("plan-context-b", "plan", "context-b"),
            ]
        )

        self.assertEqual(
            stable_topological_order(value),
            ["plan", "context-a", "context-b", "scan", "report"],
        )


if __name__ == "__main__":
    unittest.main()
