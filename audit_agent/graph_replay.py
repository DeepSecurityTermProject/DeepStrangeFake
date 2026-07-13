from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .graph_models import ExecutionGraph
from .models import to_plain


@dataclass
class GraphReplaySummary:
    graph_id: str
    complete: bool
    revision_order: list[int] = field(default_factory=list)
    execution_path: list[str] = field(default_factory=list)
    skipped_nodes: list[str] = field(default_factory=list)
    retry_counts: dict[str, int] = field(default_factory=dict)
    fallback_nodes: list[str] = field(default_factory=list)
    final_node_statuses: dict[str, str] = field(default_factory=dict)
    committed_mutation_count: int = 0
    denied_mutation_count: int = 0
    missing_refs: list[str] = field(default_factory=list)
    inconsistencies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


def replay_graph(
    graph_payload: dict[str, Any],
    transition_payloads: list[dict[str, Any]],
    *,
    revisions: list[dict[str, Any]],
    mutation_records: list[dict[str, Any]],
) -> GraphReplaySummary:
    graph = ExecutionGraph.from_dict(graph_payload)
    node_ids = {item.node_id for item in graph.nodes}
    revision_ids = sorted(
        {
            int(item["revision"])
            for item in revisions
            if isinstance(item, dict) and isinstance(item.get("revision"), int)
        }
    )
    missing_refs = []
    referenced_revisions = {graph.revision}
    for payload in transition_payloads:
        if isinstance(payload.get("revision"), int):
            referenced_revisions.add(int(payload["revision"]))
    for revision in sorted(referenced_revisions):
        if revision not in revision_ids:
            missing_refs.append(f"revision:{revision}")

    inconsistencies = []
    execution_path = []
    skipped = []
    retries: dict[str, int] = {}
    fallback_nodes = []
    statuses = {item.node_id: "pending" for item in graph.nodes}
    transition_skips = {
        str(payload.get("node_id"))
        for payload in transition_payloads
        if payload.get("new_status") == "skipped"
        and payload.get("node_id") in node_ids
    }
    mutation_skips = set()
    for record in mutation_records:
        if not bool(record.get("committed")):
            continue
        candidate_graph = record.get("graph")
        if not isinstance(candidate_graph, dict):
            continue
        candidate_nodes = candidate_graph.get("nodes")
        if not isinstance(candidate_nodes, list):
            continue
        for node_payload in candidate_nodes:
            if not isinstance(node_payload, dict):
                continue
            node_id = node_payload.get("node_id")
            if (
                node_id in node_ids
                and node_id not in transition_skips
                and node_payload.get("status") == "skipped"
            ):
                mutation_skips.add(str(node_id))
    for node in graph.nodes:
        if node.node_id in mutation_skips:
            statuses[node.node_id] = "skipped"
            skipped.append(node.node_id)
    for index, payload in enumerate(transition_payloads):
        graph_id = payload.get("graph_id")
        node_id = payload.get("node_id")
        old_status = payload.get("old_status")
        new_status = payload.get("new_status")
        if graph_id != graph.graph_id:
            inconsistencies.append(f"transition:{index}:graph-id-mismatch")
            continue
        if node_id not in node_ids:
            inconsistencies.append(f"transition:{index}:unknown-node:{node_id}")
            continue
        current = statuses.get(node_id, "pending")
        if current != old_status and not (current == "fallback" and old_status in {"fallback", "runnable"}):
            inconsistencies.append(
                f"transition:{index}:status-mismatch:{node_id}:{current}!={old_status}"
            )
        statuses[node_id] = str(new_status)
        if new_status == "running" and node_id not in execution_path:
            execution_path.append(node_id)
        if new_status == "skipped" and node_id not in skipped:
            skipped.append(node_id)
        if new_status == "fallback":
            retries[node_id] = retries.get(node_id, 0) + 1
            if node_id not in fallback_nodes:
                fallback_nodes.append(node_id)

    for node in graph.nodes:
        if node.status == "skipped" and statuses[node.node_id] != "skipped":
            inconsistencies.append(
                f"final-status-unexplained:{node.node_id}:skipped"
            )

    committed = sum(bool(item.get("committed")) for item in mutation_records)
    denied = sum(not bool(item.get("committed")) for item in mutation_records)
    return GraphReplaySummary(
        graph_id=graph.graph_id,
        complete=not missing_refs and not inconsistencies,
        revision_order=revision_ids,
        execution_path=execution_path,
        skipped_nodes=skipped,
        retry_counts=retries,
        fallback_nodes=fallback_nodes,
        final_node_statuses=statuses,
        committed_mutation_count=committed,
        denied_mutation_count=denied,
        missing_refs=missing_refs,
        inconsistencies=inconsistencies,
    )
