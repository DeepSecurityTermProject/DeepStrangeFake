import json
import tempfile
import unittest
from pathlib import Path

from audit_agent.graph_artifacts import GraphArtifactRecorder
from audit_agent.graph_models import GraphTransition
from audit_agent.graph_policy import GraphMutationOperation, GraphMutationOutcome, GraphMutationProposal, MutationOperationDecision
from audit_agent.graph_replay import GraphReplaySummary
from audit_agent.graph_scheduler import GraphRunResult
from audit_agent.graph_templates import build_deterministic_audit_graph
from audit_agent.message_bus import MessageBus, replay_summary
from audit_agent.runtime import ArtifactStore, RunState
from audit_agent.storage import RunStore


class GraphArtifactRecorderTests(unittest.TestCase):
    def test_recorder_persists_redacted_graph_lifecycle_and_correlated_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = RunStore(Path(tmp)).create_run("fixture")
            state = RunState(run.run_id, "fixture", graph_mode="adaptive-graph")
            bus = MessageBus(run.run_id, run.path / "messages" / "messages.jsonl")
            artifacts = ArtifactStore(run, bus=bus, run_state=state)
            recorder = GraphArtifactRecorder(artifacts, bus, state)
            graph = build_deterministic_audit_graph(run.run_id, mode="adaptive-graph")
            initial_ref = recorder.persist_initial(graph)
            transition = GraphTransition(graph.graph_id, 0, "orchestrator-plan", "pending", "running", "selected", ("Bearer secret-value",), ())
            transition_ref = recorder.persist_transitions(graph, [transition])
            proposal = GraphMutationProposal(
                "proposal-1",
                "post-recon",
                graph.graph_id,
                0,
                [GraphMutationOperation("operation-1", "skip-optional", target_node_id="memory-context")],
                correlation_refs=["Bearer secret-value"],
            )
            candidate = build_deterministic_audit_graph(run.run_id, mode="adaptive-graph")
            candidate.revision = 1
            outcome = GraphMutationOutcome(
                "proposal-1",
                True,
                candidate,
                [MutationOperationDecision("operation-1", "accepted")],
                committed_revision_ref="revision:1",
            )
            mutation_refs = recorder.persist_mutation(proposal, outcome)
            final_refs = recorder.persist_final(
                candidate,
                GraphRunResult("succeeded", ["orchestrator-plan"], [transition]),
                GraphReplaySummary(candidate.graph_id, True, revision_order=[0, 1], execution_path=["orchestrator-plan"]),
            )

            persisted = "\n".join(path.read_text(encoding="utf-8") for path in (run.path / "graphs").glob("*.json"))
            messages = replay_summary(run.path / "messages" / "messages.jsonl")
            self.assertTrue(Path(initial_ref).is_file())
            self.assertTrue(Path(transition_ref).is_file())
            self.assertTrue(all(Path(ref).is_file() for ref in mutation_refs + final_refs))
            self.assertNotIn("secret-value", persisted)
            self.assertEqual(state.initial_graph_ref, initial_ref)
            self.assertEqual(state.active_graph_ref, final_refs[0])
            self.assertIn(mutation_refs[-1], state.graph_revision_refs)
            self.assertEqual(state.execution_path, ["orchestrator-plan"])
            self.assertIn("graph.created", messages["types"])
            self.assertIn("graph.mutation.committed", messages["types"])
            self.assertIn("graph.finalized", messages["types"])


if __name__ == "__main__":
    unittest.main()
