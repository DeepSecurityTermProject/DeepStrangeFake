import unittest

from audit_agent.graph_models import GraphBudget, validate_graph
from audit_agent.graph_templates import (
    DETERMINISTIC_TEMPLATE_ID,
    DETERMINISTIC_TEMPLATE_VERSION,
    REQUIRED_TEMPLATE_IDS,
    NodeTemplate,
    NodeTemplateCatalog,
    build_default_template_catalog,
    build_deterministic_audit_graph,
)


class GraphTemplateTests(unittest.TestCase):
    def test_catalog_is_closed_and_rejects_duplicate_templates(self):
        catalog = NodeTemplateCatalog()
        template = NodeTemplate(
            template_id="service.example",
            executor_kind="service",
            executor_ref="example",
            priority=10,
            output_types={"result": "example-result"},
        )
        catalog.register(template)
        self.assertEqual(catalog.get("service.example"), template)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            catalog.register(template)
        with self.assertRaisesRegex(KeyError, "not registered"):
            catalog.get("service.model-authored")

    def test_deterministic_template_maps_required_audit_lifecycle(self):
        catalog = build_default_template_catalog()
        graph = build_deterministic_audit_graph(
            "run-1",
            mode="deterministic-graph",
            budgets=GraphBudget(max_nodes=32, max_scheduler_iterations=128),
        )
        order = validate_graph(
            graph,
            catalog.template_ids(),
            required_template_ids=REQUIRED_TEMPLATE_IDS,
        )
        self.assertEqual(graph.template_id, DETERMINISTIC_TEMPLATE_ID)
        self.assertEqual(graph.template_version, DETERMINISTIC_TEMPLATE_VERSION)
        self.assertEqual(len(graph.template_content_hash), 64)
        self.assertEqual(order[0], "orchestrator-plan")
        self.assertEqual(order[-1], "report-finalization")

    def test_required_evidence_template_cannot_be_removed(self):
        catalog = build_default_template_catalog()
        graph = build_deterministic_audit_graph("run-1", mode="adaptive-graph")
        graph.nodes = [item for item in graph.nodes if item.template_id != "service.evidence-finalization"]
        graph.edges = [edge for edge in graph.edges if "evidence-finalization" not in {edge.source_node_id, edge.target_node_id}]
        with self.assertRaisesRegex(ValueError, "required template"):
            validate_graph(graph, catalog.template_ids(), required_template_ids=REQUIRED_TEMPLATE_IDS)

    def test_template_hash_is_stable_for_same_registered_content(self):
        first = build_deterministic_audit_graph("run-1")
        second = build_deterministic_audit_graph("run-2")
        self.assertEqual(first.template_content_hash, second.template_content_hash)
        self.assertNotEqual(first.graph_id, second.graph_id)


if __name__ == "__main__":
    unittest.main()
