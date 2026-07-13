from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .graph_models import ExecutionGraph, GraphTransition
from .graph_policy import GraphMutationOutcome, GraphMutationProposal
from .graph_replay import GraphReplaySummary
from .graph_scheduler import GraphRunResult
from .message_bus import MessageBus
from .redaction import redact_secrets

if TYPE_CHECKING:
    from .runtime import ArtifactStore, RunState


class GraphArtifactRecorder:
    def __init__(
        self,
        artifacts: ArtifactStore,
        bus: MessageBus | None,
        run_state: RunState,
    ) -> None:
        self.artifacts = artifacts
        self.bus = bus
        self.run_state = run_state

    def expected_final_refs(self, graph: ExecutionGraph) -> dict[str, str]:
        root = self.artifacts.run.path / "graphs"
        return {
            "final_graph_ref": str(root / f"final-{graph.graph_id}.json"),
            "execution_summary_ref": str(root / f"summary-{graph.graph_id}.json"),
            "replay_ref": str(root / f"replay-{graph.graph_id}.json"),
        }

    def persist_initial(self, graph: ExecutionGraph) -> str:
        ref = self.artifacts.write_json(
            "graphs",
            f"initial-{graph.graph_id}.json",
            graph.to_dict(),
        )
        graph.artifact_refs.append(ref)
        self.run_state.initial_graph_ref = ref
        self.run_state.active_graph_ref = ref
        self.run_state.graph_revision_refs.append(ref)
        self._publish(
            "graph.created",
            graph,
            {"template_id": graph.template_id, "template_version": graph.template_version},
            [ref],
        )
        return ref

    def persist_transitions(
        self,
        graph: ExecutionGraph,
        transitions: list[GraphTransition],
    ) -> str:
        ref = self.artifacts.write_json(
            "graphs",
            f"transitions-r{graph.revision}.json",
            {
                "schema_version": "graph-transition-batch.v1",
                "graph_id": graph.graph_id,
                "revision": graph.revision,
                "transitions": [item.to_dict() for item in transitions],
            },
        )
        self.run_state.graph_transition_refs.append(ref)
        for transition in transitions:
            self._publish(
                "graph.node.transition",
                graph,
                {
                    "node_id": transition.node_id,
                    "old_status": transition.old_status,
                    "new_status": transition.new_status,
                    "cause": transition.cause,
                    "correlation_refs": list(transition.correlation_refs),
                    "causation_refs": list(transition.causation_refs),
                },
                [ref],
            )
        return ref

    def persist_mutation(
        self,
        proposal: GraphMutationProposal,
        outcome: GraphMutationOutcome,
    ) -> list[str]:
        graph = outcome.graph
        proposal_ref = self.artifacts.write_json(
            "graphs", f"mutation-{proposal.proposal_id}.json", proposal.to_dict()
        )
        policy_ref = self.artifacts.write_json(
            "graphs", f"mutation-policy-{proposal.proposal_id}.json", outcome.to_dict()
        )
        refs = [proposal_ref, policy_ref]
        event = "graph.mutation.denied"
        if outcome.committed:
            graph_ref = self.artifacts.write_json(
                "graphs", f"revision-{graph.revision}-{graph.graph_id}.json", graph.to_dict()
            )
            refs.append(graph_ref)
            event = "graph.mutation.committed"
        self._publish(
            event,
            graph,
            {
                "checkpoint_id": proposal.checkpoint_id,
                "proposal_id": proposal.proposal_id,
                "committed": outcome.committed,
                "decision_count": len(outcome.decisions),
                "fallback_reason": outcome.fallback_reason,
            },
            refs,
        )
        self.run_state.mutation_refs.extend(refs[:2])
        if outcome.committed:
            self.run_state.graph_revision_refs.append(refs[2])
            self.run_state.active_graph_ref = refs[2]
            self.run_state.checkpoint_counts = dict(graph.checkpoint_counts)
        else:
            self.run_state.graph_fallback_reason = outcome.fallback_reason
        return refs

    def persist_final(
        self,
        graph: ExecutionGraph,
        result: GraphRunResult,
        replay: GraphReplaySummary,
    ) -> list[str]:
        graph_ref = self.artifacts.write_json(
            "graphs", f"final-{graph.graph_id}.json", graph.to_dict()
        )
        summary_ref = self.artifacts.write_json(
            "graphs",
            f"summary-{graph.graph_id}.json",
            {
                "schema_version": "graph-execution-summary.v1",
                "graph_id": graph.graph_id,
                "revision": graph.revision,
                "mode": graph.mode,
                "status": result.status,
                "execution_path": result.execution_path,
                "scheduler_iterations": result.scheduler_iterations,
                "failure_reason": result.failure_reason,
                "fallback_reason": self.run_state.graph_fallback_reason,
            },
        )
        replay_ref = self.artifacts.write_json(
            "graphs", f"replay-{graph.graph_id}.json", replay.to_dict()
        )
        refs = [graph_ref, summary_ref, replay_ref]
        self.run_state.final_graph_ref = graph_ref
        self.run_state.active_graph_ref = graph_ref
        self.run_state.execution_path = list(result.execution_path)
        self._publish(
            "graph.finalized",
            graph,
            {
                "status": result.status,
                "execution_path": result.execution_path,
                "replay_complete": replay.complete,
            },
            refs,
        )
        return refs

    def _publish(
        self,
        message_type: str,
        graph: ExecutionGraph,
        payload: dict[str, Any],
        artifact_refs: list[str],
    ) -> None:
        if not self.bus:
            return
        message = self.bus.publish(
            "graph-runtime",
            "runtime",
            message_type,
            redact_secrets(
                {
                    "graph_id": graph.graph_id,
                    "revision": graph.revision,
                    "mode": graph.mode,
                    **payload,
                }
            ),
            correlation_id=graph.graph_id,
            causation_id=payload.get("proposal_id"),
            artifact_refs=artifact_refs,
        )
        self.run_state.record_message(message.message_id)
