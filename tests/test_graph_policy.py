import unittest

from audit_agent.graph_models import GraphBudget, GraphEdge
from audit_agent.graph_policy import (
    GraphCheckpointState,
    GraphMutationOperation,
    GraphMutationPolicy,
    GraphMutationProposal,
    parse_graph_decision_payload,
    translate_next_actions,
)
from audit_agent.graph_templates import (
    REQUIRED_TEMPLATE_IDS,
    build_default_template_catalog,
    build_deterministic_audit_graph,
)
from audit_agent.graph_scheduler import GraphNodeResult, GraphScheduler


class GraphMutationPolicyTests(unittest.TestCase):
    def setUp(self):
        self.catalog = build_default_template_catalog()
        self.policy = GraphMutationPolicy(
            self.catalog,
            REQUIRED_TEMPLATE_IDS,
            issued_artifact_refs={"metadata/repository.json"},
        )

    def test_registered_insert_commits_one_new_revision(self):
        graph = build_deterministic_audit_graph("run-1", mode="adaptive-graph")
        proposal = GraphMutationProposal(
            proposal_id="proposal-1",
            checkpoint_id="post-recon",
            graph_id=graph.graph_id,
            base_revision=0,
            operations=[
                GraphMutationOperation(
                    operation_id="operation-1",
                    op="insert-template",
                    template_id="service.local-context-refinement",
                    after_node_id="post-recon-checkpoint",
                    parameters={"node_id": "local-context-1", "focus_refs": ["metadata/repository.json"]},
                )
            ],
        )

        outcome = self.policy.evaluate(graph, proposal)

        self.assertTrue(outcome.committed)
        self.assertEqual(outcome.graph.revision, 1)
        self.assertEqual(outcome.graph.parent_revision_ref, "revision:0")
        self.assertEqual(outcome.decisions[0].status, "accepted")
        self.assertEqual(outcome.graph.node("local-context-1").lineage.parent_node_id, "post-recon-checkpoint")
        self.assertEqual(graph.revision, 0)
        self.assertNotIn("local-context-1", {item.node_id for item in graph.nodes})

    def test_unregistered_completed_unsafe_and_over_budget_operations_are_denied(self):
        graph = build_deterministic_audit_graph("run-1", mode="adaptive-graph", budgets=GraphBudget(max_nodes=12))
        graph.node("analysis").status = "succeeded"
        proposal = GraphMutationProposal(
            proposal_id="proposal-denied",
            checkpoint_id="post-analysis",
            graph_id=graph.graph_id,
            base_revision=0,
            operations=[
                GraphMutationOperation("unknown", "insert-template", template_id="agent.shell", after_node_id="analysis", parameters={"node_id": "shell"}),
                GraphMutationOperation("completed", "adjust-budget", target_node_id="analysis", budget_delta={"tool_calls": 1}),
                GraphMutationOperation("unsafe", "attach-context", target_node_id="verification", parameters={"context_refs": ["https://live-target.example"], "target_writes": True}),
                GraphMutationOperation("too-many", "insert-template", template_id="agent.analysis-refinement", after_node_id="post-analysis-checkpoint", parameters={"node_id": "repeat-analysis"}),
            ],
        )

        outcome = self.policy.evaluate(graph, proposal)

        self.assertFalse(outcome.committed)
        self.assertEqual([item.status for item in outcome.decisions], ["denied"] * 4)
        self.assertEqual(outcome.graph.revision, 0)

    def test_candidate_cycle_rolls_back_all_accepted_operations(self):
        graph = build_deterministic_audit_graph("run-1", mode="adaptive-graph")
        proposal = GraphMutationProposal(
            proposal_id="proposal-cycle",
            checkpoint_id="post-analysis",
            graph_id=graph.graph_id,
            base_revision=0,
            operations=[
                GraphMutationOperation(
                    "back-edge",
                    "route-edge",
                    parameters={
                        "edge_id": "report-back-analysis",
                        "source_node_id": "report-finalization",
                        "target_node_id": "analysis",
                    },
                )
            ],
        )

        outcome = self.policy.evaluate(graph, proposal)

        self.assertFalse(outcome.committed)
        self.assertTrue(outcome.candidate_diagnostics)
        self.assertEqual(outcome.graph.to_dict(), graph.to_dict())

    def test_checkpoint_is_single_use_and_global_replan_bounded(self):
        state = GraphCheckpointState(max_global_replans=1, per_checkpoint_ceiling=1)
        self.assertTrue(state.consume("post-recon"))
        self.assertFalse(state.consume("post-recon"))
        self.assertFalse(state.consume("post-analysis"))
        self.assertEqual(state.counts, {"post-recon": 1})

    def test_known_next_actions_translate_and_unknown_hints_do_not_execute(self):
        proposal = translate_next_actions(
            graph_id="graph-1",
            revision=2,
            checkpoint_id="post-analysis",
            next_actions=["gather-more-local-context", "run-shell-command", "repeat-analysis"],
        )

        self.assertEqual(
            [item.template_id for item in proposal.operations],
            ["service.local-context-refinement", "agent.analysis-refinement"],
        )
        self.assertEqual(proposal.ignored_hints, ["run-shell-command"])

    def test_registered_checkpoint_actions_cover_recon_and_analysis_refinement_paths(self):
        recon = translate_next_actions(
            graph_id="graph-recon",
            revision=0,
            checkpoint_id="post-recon",
            next_actions=["gather-more-local-context", "refine-static-scan"],
        )
        analysis = translate_next_actions(
            graph_id="graph-analysis",
            revision=0,
            checkpoint_id="post-analysis",
            next_actions=["refine-evidence", "repeat-analysis", "route-verification"],
        )

        self.assertEqual(
            [item.template_id for item in recon.operations],
            ["service.local-context-refinement", "tool.scan-refinement"],
        )
        self.assertEqual(
            [item.template_id for item in analysis.operations],
            ["agent.evidence-refinement", "agent.analysis-refinement", "service.verification-routing"],
        )

        skipped = translate_next_actions(
            graph_id="graph-skip",
            revision=0,
            checkpoint_id="post-analysis",
            next_actions=["route-verification", "skip-optional"],
        )
        self.assertEqual([item.op for item in skipped.operations], ["insert-template", "route-edge", "skip-optional"])

    def test_post_analysis_skip_optional_keeps_required_verification_path_reachable(self):
        graph = build_deterministic_audit_graph("run-skip-route", mode="adaptive-graph")
        graph.node("post-analysis-checkpoint").status = "running"
        proposal = translate_next_actions(
            graph_id=graph.graph_id,
            revision=0,
            checkpoint_id="post-analysis",
            next_actions=["route-verification", "skip-optional"],
        )

        outcome = self.policy.evaluate(graph, proposal)

        self.assertTrue(outcome.committed, outcome.candidate_diagnostics)
        routing_id = proposal.operations[0].parameters["node_id"]
        self.assertEqual(outcome.graph.node(routing_id).status, "skipped")
        self.assertIn(
            ("post-analysis-checkpoint", "verification"),
            {(item.source_node_id, item.target_node_id) for item in outcome.graph.edges},
        )

    def test_post_analysis_skip_optional_executes_verification_through_scheduler(self):
        graph = build_deterministic_audit_graph("run-skip-scheduler", mode="adaptive-graph")
        graph.node("post-analysis-checkpoint").status = "running"
        proposal = translate_next_actions(
            graph_id=graph.graph_id,
            revision=graph.revision,
            checkpoint_id="post-analysis",
            next_actions=["route-verification", "skip-optional"],
        )

        outcome = self.policy.evaluate(graph, proposal)

        self.assertTrue(outcome.committed, outcome.candidate_diagnostics)
        routing_id = proposal.operations[0].parameters["node_id"]
        outcome.graph.node("post-analysis-checkpoint").status = "pending"
        invoked = []

        def execute(executor_ref, node, inputs):
            invoked.append(node.node_id)
            return GraphNodeResult()

        def service(node, inputs):
            invoked.append(node.node_id)
            return GraphNodeResult()

        scheduler = GraphScheduler(
            outcome.graph,
            registered_templates=self.catalog.template_ids(),
            required_template_ids=REQUIRED_TEMPLATE_IDS,
            service_handlers={
                item.executor_ref: service
                for item in outcome.graph.nodes
                if item.executor_kind == "service"
            },
            agent_executor=execute,
            tool_executor=execute,
        )

        result = scheduler.run()

        self.assertEqual(result.status, "succeeded", result.failure_reason)
        self.assertEqual(outcome.graph.node(routing_id).status, "skipped")
        self.assertEqual(outcome.graph.node("verification").status, "succeeded")
        self.assertNotIn(routing_id, invoked)
        self.assertIn("verification", invoked)
        self.assertNotIn(
            (routing_id, "verification"),
            {(item.source_node_id, item.target_node_id) for item in outcome.graph.edges},
        )

    def test_policy_enforces_checkpoint_and_replan_ceilings(self):
        graph = build_deterministic_audit_graph(
            "run-ceilings",
            mode="adaptive-graph",
            budgets=GraphBudget(max_replans=1, max_checkpoints=1),
        )
        graph.global_replan_count = 1
        proposal = translate_next_actions(
            graph_id=graph.graph_id,
            revision=graph.revision,
            checkpoint_id="post-analysis",
            next_actions=["repeat-analysis"],
        )

        outcome = self.policy.evaluate(graph, proposal)

        self.assertFalse(outcome.committed)
        self.assertEqual(outcome.fallback_reason, "replan-ceiling-exceeded")
        self.assertEqual(outcome.graph.revision, 0)

        graph.global_replan_count = 0
        graph.checkpoint_counts = {"post-recon": 1}
        checkpoint_outcome = self.policy.evaluate(graph, proposal)
        self.assertFalse(checkpoint_outcome.committed)
        self.assertEqual(checkpoint_outcome.fallback_reason, "checkpoint-ceiling-exceeded")

    def test_graph_decision_parser_is_fail_closed(self):
        self.assertEqual(
            parse_graph_decision_payload(
                {
                    "checkpoint_id": "post-analysis",
                    "next_actions": ["repeat-analysis"],
                    "rationale": "one bounded pass",
                },
                checkpoint_id="post-analysis",
            ),
            ["repeat-analysis"],
        )
        invalid = [
            {"checkpoint_id": "post-analysis", "actions": ["repeat-analysis"], "rationale": "x"},
            {"checkpoint_id": "post-recon", "next_actions": ["repeat-analysis"], "rationale": "x"},
            {"checkpoint_id": "post-analysis", "next_actions": ["run-shell"], "rationale": "x"},
        ]
        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                parse_graph_decision_payload(payload, checkpoint_id="post-analysis")

    def test_skip_optional_is_rejected_when_it_breaks_required_execution_path(self):
        graph = build_deterministic_audit_graph("run-skip", mode="adaptive-graph")
        proposal = GraphMutationProposal(
            proposal_id="proposal-skip-memory",
            checkpoint_id="post-recon",
            graph_id=graph.graph_id,
            base_revision=0,
            operations=[
                GraphMutationOperation(
                    "skip-memory",
                    "skip-optional",
                    target_node_id="memory-context",
                    reason="not-needed",
                )
            ],
        )

        outcome = self.policy.evaluate(graph, proposal)

        self.assertFalse(outcome.committed)
        self.assertEqual(outcome.graph.node("memory-context").status, "pending")
        self.assertTrue(
            any("required" in diagnostic and "unreachable" in diagnostic for diagnostic in outcome.candidate_diagnostics),
            outcome.candidate_diagnostics,
        )

    def test_context_refs_must_be_issued_by_artifact_store(self):
        graph = build_deterministic_audit_graph("run-refs", mode="adaptive-graph")
        proposal = GraphMutationProposal(
            proposal_id="proposal-context-refs",
            checkpoint_id="post-analysis",
            graph_id=graph.graph_id,
            base_revision=0,
            operations=[
                GraphMutationOperation(
                    "windows-path",
                    "attach-context",
                    target_node_id="verification",
                    parameters={"context_refs": [r"C:\Users\example\.env"]},
                ),
                GraphMutationOperation(
                    "unissued-local",
                    "attach-context",
                    target_node_id="verification",
                    parameters={"context_refs": ["evidence/unissued.json"]},
                ),
                GraphMutationOperation(
                    "issued-local",
                    "attach-context",
                    target_node_id="verification",
                    parameters={"context_refs": ["metadata/repository.json"]},
                ),
            ],
        )

        outcome = self.policy.evaluate(graph, proposal)

        self.assertTrue(outcome.committed)
        self.assertEqual([item.status for item in outcome.decisions], ["denied", "denied", "accepted"])
        self.assertEqual(outcome.graph.node("verification").artifact_refs, ["metadata/repository.json"])

    def test_budget_adjustments_are_checked_against_graph_aggregate(self):
        graph = build_deterministic_audit_graph(
            "run-budget",
            mode="adaptive-graph",
            budgets=GraphBudget(max_tool_calls=5),
        )
        proposal = GraphMutationProposal(
            proposal_id="proposal-budget",
            checkpoint_id="post-analysis",
            graph_id=graph.graph_id,
            base_revision=0,
            operations=[
                GraphMutationOperation(
                    "analysis-budget",
                    "adjust-budget",
                    target_node_id="analysis",
                    budget_delta={"tool_calls": 5},
                ),
                GraphMutationOperation(
                    "verification-budget",
                    "adjust-budget",
                    target_node_id="verification",
                    budget_delta={"tool_calls": 5},
                ),
            ],
        )

        outcome = self.policy.evaluate(graph, proposal)

        self.assertTrue(outcome.committed)
        self.assertEqual([item.status for item in outcome.decisions], ["accepted", "denied"])
        self.assertEqual(
            sum(item.budget.tool_calls for item in outcome.graph.nodes),
            5,
        )

    def test_token_and_sandbox_allocations_share_graph_wide_ceilings(self):
        graph = build_deterministic_audit_graph(
            "run-token-sandbox-budget",
            mode="adaptive-graph",
            budgets=GraphBudget(max_llm_tokens=5, max_sandbox_attempts=1),
        )
        proposal = GraphMutationProposal(
            proposal_id="proposal-token-sandbox-budget",
            checkpoint_id="post-analysis",
            graph_id=graph.graph_id,
            base_revision=0,
            operations=[
                GraphMutationOperation(
                    "analysis-token",
                    "adjust-budget",
                    target_node_id="analysis",
                    budget_delta={"llm_tokens": 5, "sandbox_attempts": 1},
                ),
                GraphMutationOperation(
                    "verification-overflow",
                    "adjust-budget",
                    target_node_id="verification",
                    budget_delta={"llm_tokens": 1, "sandbox_attempts": 1},
                ),
            ],
        )

        outcome = self.policy.evaluate(graph, proposal)

        self.assertTrue(outcome.committed)
        self.assertEqual([item.status for item in outcome.decisions], ["accepted", "denied"])
        self.assertEqual(sum(item.budget.llm_tokens for item in outcome.graph.nodes), 5)
        self.assertEqual(sum(item.budget.sandbox_attempts for item in outcome.graph.nodes), 1)

    def test_active_checkpoint_can_insert_refinement_into_future_main_path(self):
        graph = build_deterministic_audit_graph("run-checkpoint", mode="adaptive-graph")
        graph.node("post-analysis-checkpoint").status = "running"
        proposal = translate_next_actions(
            graph_id=graph.graph_id,
            revision=graph.revision,
            checkpoint_id="post-analysis",
            next_actions=["repeat-analysis"],
        )

        outcome = self.policy.evaluate(graph, proposal)

        self.assertTrue(outcome.committed, outcome.candidate_diagnostics)
        refinement_id = proposal.operations[0].parameters["node_id"]
        edges = {(item.source_node_id, item.target_node_id) for item in outcome.graph.edges}
        self.assertIn(("post-analysis-checkpoint", refinement_id), edges)
        self.assertIn((refinement_id, "verification"), edges)
        self.assertNotIn(("post-analysis-checkpoint", "verification"), edges)


if __name__ == "__main__":
    unittest.main()
