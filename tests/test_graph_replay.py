import unittest

from audit_agent.graph_models import GraphTransition
from audit_agent.graph_replay import replay_graph
from audit_agent.graph_templates import build_deterministic_audit_graph


class GraphReplayTests(unittest.TestCase):
    def test_replay_reconstructs_revision_order_path_skips_retries_and_fallbacks(self):
        graph = build_deterministic_audit_graph("run-1")
        transitions = [
            GraphTransition(graph.graph_id, 0, "orchestrator-plan", "pending", "runnable", "ready"),
            GraphTransition(graph.graph_id, 0, "orchestrator-plan", "runnable", "running", "selected"),
            GraphTransition(graph.graph_id, 0, "orchestrator-plan", "running", "fallback", "retry:RuntimeError"),
            GraphTransition(graph.graph_id, 0, "orchestrator-plan", "fallback", "running", "retry-approved"),
            GraphTransition(graph.graph_id, 0, "orchestrator-plan", "running", "succeeded", "done"),
            GraphTransition(graph.graph_id, 1, "memory-context", "pending", "skipped", "optional-condition-unsatisfied"),
            GraphTransition(graph.graph_id, 1, "static-scan", "pending", "running", "selected"),
            GraphTransition(graph.graph_id, 1, "static-scan", "running", "succeeded", "done"),
        ]
        summary = replay_graph(
            graph.to_dict(),
            [item.to_dict() for item in transitions],
            revisions=[{"revision": 0}, {"revision": 1, "parent_revision": 0}],
            mutation_records=[{"proposal_id": "p1", "committed": True}],
        )

        self.assertTrue(summary.complete)
        self.assertEqual(summary.revision_order, [0, 1])
        self.assertEqual(summary.execution_path, ["orchestrator-plan", "static-scan"])
        self.assertEqual(summary.skipped_nodes, ["memory-context"])
        self.assertEqual(summary.retry_counts, {"orchestrator-plan": 1})
        self.assertEqual(summary.fallback_nodes, ["orchestrator-plan"])
        self.assertEqual(summary.committed_mutation_count, 1)

    def test_replay_marks_missing_and_inconsistent_data_without_execution(self):
        graph = build_deterministic_audit_graph("run-1")
        summary = replay_graph(
            graph.to_dict(),
            [
                {
                    "graph_id": "different-graph",
                    "revision": 0,
                    "node_id": "missing-node",
                    "old_status": "pending",
                    "new_status": "running",
                    "cause": "bad",
                    "correlation_refs": [],
                    "causation_refs": [],
                    "timestamp": "2026-07-13T00:00:00+00:00",
                }
            ],
            revisions=[],
            mutation_records=[],
        )

        self.assertFalse(summary.complete)
        self.assertIn("revision:0", summary.missing_refs)
        self.assertTrue(summary.inconsistencies)
        self.assertEqual(summary.execution_path, [])

    def test_replay_reconstructs_skip_written_directly_by_committed_mutation(self):
        graph = build_deterministic_audit_graph("run-mutation-skip")
        graph.node("memory-context").status = "skipped"
        mutation_record = {
            "proposal_id": "skip-memory",
            "committed": True,
            "graph": graph.to_dict(),
        }

        summary = replay_graph(
            graph.to_dict(),
            [],
            revisions=[{"revision": 0}],
            mutation_records=[mutation_record],
        )

        self.assertTrue(summary.complete, summary.inconsistencies)
        self.assertEqual(summary.final_node_statuses["memory-context"], "skipped")
        self.assertEqual(summary.skipped_nodes, ["memory-context"])

    def test_replay_marks_unexplained_mutation_status_incomplete(self):
        graph = build_deterministic_audit_graph("run-unexplained-skip")
        graph.node("memory-context").status = "skipped"

        summary = replay_graph(
            graph.to_dict(),
            [],
            revisions=[{"revision": 0}],
            mutation_records=[],
        )

        self.assertFalse(summary.complete)
        self.assertIn(
            "final-status-unexplained:memory-context:skipped",
            summary.inconsistencies,
        )

    def test_replay_does_not_double_apply_transition_skip_carried_by_mutation_graph(self):
        graph = build_deterministic_audit_graph("run-transition-skip")
        graph.node("memory-context").status = "skipped"
        transition = GraphTransition(
            graph.graph_id,
            0,
            "memory-context",
            "pending",
            "skipped",
            "optional-condition-unsatisfied",
        )

        summary = replay_graph(
            graph.to_dict(),
            [transition.to_dict()],
            revisions=[{"revision": 0}],
            mutation_records=[{"committed": True, "graph": graph.to_dict()}],
        )

        self.assertTrue(summary.complete, summary.inconsistencies)
        self.assertEqual(summary.skipped_nodes, ["memory-context"])


if __name__ == "__main__":
    unittest.main()
