import unittest

from audit_agent.graph_models import (
    ExecutionGraph,
    GraphBudget,
    GraphCondition,
    GraphEdge,
    GraphInputRef,
    GraphNode,
    RetryPolicy,
)
from audit_agent.graph_scheduler import GraphNodeResult, GraphScheduler


def service_node(
    node_id: str,
    priority: int,
    *,
    required: bool = True,
    inputs: list[GraphInputRef] | None = None,
    outputs: dict[str, str] | None = None,
    attempts: int = 1,
) -> GraphNode:
    return GraphNode(
        node_id=node_id,
        template_id=f"service.{node_id}",
        executor_kind="service",
        executor_ref=node_id,
        priority=priority,
        required=required,
        input_refs=inputs or [],
        output_types=outputs or {},
        retry_policy=RetryPolicy(max_attempts=attempts),
    )


def make_graph(nodes, edges, *, iterations=30, terminals=None):
    return ExecutionGraph(
        graph_id="graph-scheduler",
        run_id="run-scheduler",
        revision=0,
        mode="deterministic-graph",
        template_id="test.scheduler.v1",
        nodes=nodes,
        edges=edges,
        budgets=GraphBudget(max_nodes=20, max_scheduler_iterations=iterations),
        required_terminal_nodes=terminals or [nodes[-1].node_id],
    )


class GraphSchedulerTests(unittest.TestCase):
    def test_scheduler_runs_ready_nodes_with_stable_tie_breaking_and_typed_inputs(self):
        nodes = [
            service_node("start", 10, outputs={"seed": "text"}),
            service_node("branch-b", 20, inputs=[GraphInputRef("start", "seed", "text")]),
            service_node("branch-a", 20, inputs=[GraphInputRef("start", "seed", "text")]),
            service_node("finish", 30),
        ]
        edges = [
            GraphEdge("start-a", "start", "branch-a"),
            GraphEdge("start-b", "start", "branch-b"),
            GraphEdge("a-finish", "branch-a", "finish"),
            GraphEdge("b-finish", "branch-b", "finish"),
        ]
        invoked = []

        def handler(node, inputs):
            invoked.append((node.node_id, dict(inputs)))
            return GraphNodeResult(outputs={"seed": "local"} if node.node_id == "start" else {})

        scheduler = GraphScheduler(
            make_graph(nodes, edges),
            registered_templates={item.template_id for item in nodes},
            service_handlers={item.executor_ref: handler for item in nodes},
        )
        result = scheduler.run()

        self.assertEqual(result.status, "succeeded")
        self.assertEqual([item[0] for item in invoked], ["start", "branch-a", "branch-b", "finish"])
        self.assertEqual(invoked[1][1], {"seed": "local"})
        self.assertEqual(result.execution_path, ["start", "branch-a", "branch-b", "finish"])

    def test_unsatisfied_condition_skips_optional_node(self):
        nodes = [
            service_node("start", 10, outputs={"finding_count": "integer"}),
            service_node("optional", 20, required=False),
            service_node("finish", 30),
        ]
        edges = [
            GraphEdge(
                "start-optional",
                "start",
                "optional",
                dependency_type="conditional",
                condition=GraphCondition("finding-count-gte", {"minimum": 1}),
            ),
            GraphEdge("start-finish", "start", "finish"),
        ]
        scheduler = GraphScheduler(
            make_graph(nodes, edges),
            registered_templates={item.template_id for item in nodes},
            service_handlers={
                "start": lambda node, inputs: GraphNodeResult(outputs={"finding_count": 0}),
                "optional": lambda node, inputs: self.fail("unreachable optional node executed"),
                "finish": lambda node, inputs: GraphNodeResult(),
            },
        )

        result = scheduler.run()

        self.assertEqual(result.status, "succeeded")
        self.assertEqual(nodes[1].status, "skipped")
        self.assertNotIn("optional", result.execution_path)
        self.assertTrue(any(item.node_id == "optional" and item.new_status == "skipped" for item in result.transitions))

    def test_missing_required_typed_output_fails_dependent_node(self):
        nodes = [
            service_node("start", 10, outputs={"seed": "text"}),
            service_node("finish", 20, inputs=[GraphInputRef("start", "seed", "text")]),
        ]
        scheduler = GraphScheduler(
            make_graph(nodes, [GraphEdge("start-finish", "start", "finish")]),
            registered_templates={item.template_id for item in nodes},
            service_handlers={
                "start": lambda node, inputs: GraphNodeResult(outputs={}),
                "finish": lambda node, inputs: GraphNodeResult(),
            },
        )

        result = scheduler.run()

        self.assertEqual(result.status, "failed")
        self.assertEqual(nodes[1].status, "failed")
        self.assertIn("missing required input", result.failure_reason)

    def test_retry_is_bounded_and_transitions_are_persisted(self):
        nodes = [service_node("flaky", 10, outputs={"ok": "boolean"}, attempts=2), service_node("finish", 20)]
        calls = []
        persisted = []

        def flaky(node, inputs):
            calls.append(node.attempt_count)
            if len(calls) == 1:
                raise RuntimeError("transient")
            return GraphNodeResult(outputs={"ok": True})

        scheduler = GraphScheduler(
            make_graph(nodes, [GraphEdge("flaky-finish", "flaky", "finish")]),
            registered_templates={item.template_id for item in nodes},
            service_handlers={"flaky": flaky, "finish": lambda node, inputs: GraphNodeResult()},
            transition_sink=persisted.extend,
        )
        result = scheduler.run()

        self.assertEqual(result.status, "succeeded")
        self.assertEqual(len(calls), 2)
        self.assertEqual(nodes[0].attempt_count, 2)
        self.assertEqual(persisted, result.transitions)
        self.assertTrue(any(item.new_status == "fallback" for item in result.transitions))

    def test_graph_node_attempt_ceiling_caps_larger_node_retry_policy(self):
        flaky = service_node("flaky", 10, attempts=3)
        finish = service_node("finish", 20)
        graph = make_graph([flaky, finish], [GraphEdge("flaky-finish", "flaky", "finish")])
        graph.budgets.max_node_attempts = 1
        calls = []

        def succeeds_only_on_third_attempt(node, inputs):
            calls.append(node.attempt_count)
            if len(calls) < 3:
                raise RuntimeError("synthetic transient failure")
            return GraphNodeResult()

        scheduler = GraphScheduler(
            graph,
            registered_templates={flaky.template_id, finish.template_id},
            service_handlers={
                "flaky": succeeds_only_on_third_attempt,
                "finish": lambda node, inputs: GraphNodeResult(),
            },
        )

        result = scheduler.run()

        self.assertEqual(result.status, "failed")
        self.assertEqual(calls, [1])
        self.assertEqual(flaky.attempt_count, 1)
        self.assertFalse(any(item.cause == "retry-approved" for item in result.transitions))

    def test_scheduler_iteration_ceiling_terminates_deterministically(self):
        nodes = [service_node("start", 10), service_node("finish", 20)]
        scheduler = GraphScheduler(
            make_graph(nodes, [GraphEdge("start-finish", "start", "finish")], iterations=1),
            registered_templates={item.template_id for item in nodes},
            service_handlers={"start": lambda node, inputs: GraphNodeResult(), "finish": lambda node, inputs: GraphNodeResult()},
        )

        result = scheduler.run()

        self.assertEqual(result.status, "bounded-termination")
        self.assertEqual(result.failure_reason, "scheduler-iteration-ceiling")

    def test_required_failure_executes_registered_fallback_before_termination(self):
        primary = service_node("primary", 10)
        fallback = service_node("fallback-handler", 20)
        finish = service_node("finish", 30)
        nodes = [primary, fallback, finish]
        edges = [
            GraphEdge(
                "primary-fallback",
                "primary",
                "fallback-handler",
                dependency_type="fallback",
            ),
            GraphEdge("fallback-finish", "fallback-handler", "finish"),
        ]
        invoked = []

        def primary_handler(node, inputs):
            invoked.append(node.node_id)
            raise RuntimeError("synthetic failure")

        def success_handler(node, inputs):
            invoked.append(node.node_id)
            return GraphNodeResult()

        scheduler = GraphScheduler(
            make_graph(nodes, edges),
            registered_templates={item.template_id for item in nodes},
            service_handlers={
                "primary": primary_handler,
                "fallback-handler": success_handler,
                "finish": success_handler,
            },
        )

        result = scheduler.run()

        self.assertEqual(result.status, "succeeded")
        self.assertEqual(invoked, ["primary", "fallback-handler", "finish"])
        self.assertEqual(primary.status, "fallback")
        self.assertTrue(
            any(
                item.node_id == "primary"
                and item.old_status == "failed"
                and item.new_status == "fallback"
                for item in result.transitions
            )
        )

    def test_retry_policy_fallback_node_runs_without_explicit_fallback_edge(self):
        primary = service_node("primary", 10)
        fallback = service_node("fallback-handler", 20)
        finish = service_node("finish", 30)
        primary.retry_policy.fallback_node_id = fallback.node_id
        invoked = []

        def handler(node, inputs):
            invoked.append(node.node_id)
            if node.node_id == "primary":
                raise RuntimeError("synthetic failure")
            return GraphNodeResult()

        scheduler = GraphScheduler(
            make_graph(
                [primary, fallback, finish],
                [GraphEdge("fallback-finish", "fallback-handler", "finish")],
            ),
            registered_templates={primary.template_id, fallback.template_id, finish.template_id},
            service_handlers={
                "primary": handler,
                "fallback-handler": handler,
                "finish": handler,
            },
        )

        result = scheduler.run()

        self.assertEqual(result.status, "succeeded")
        self.assertEqual(invoked, ["primary", "fallback-handler", "finish"])


if __name__ == "__main__":
    unittest.main()
