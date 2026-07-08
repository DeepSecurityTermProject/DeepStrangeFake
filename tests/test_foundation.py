import json
import tempfile
import unittest
from pathlib import Path

from audit_agent.config import AuditConfig
from audit_agent.models import Finding, SourceLocation
from audit_agent.storage import RunStore


class FoundationTests(unittest.TestCase):
    def test_default_config_contains_core_runtime_choices(self):
        config = AuditConfig.default()

        self.assertEqual(
            config.validation_levels,
            ["static-only", "poc-generate", "sandbox", "manual"],
        )
        self.assertIn("sql-injection", config.audit_scope.vulnerability_classes)
        self.assertIn("command-injection", config.audit_scope.vulnerability_classes)
        self.assertEqual(config.cve_mcp.name, "mukul975/cve-mcp-server")
        self.assertTrue(config.cve_mcp.degraded_mode)
        self.assertGreater(config.cve_mcp.query_budget, 0)
        self.assertFalse(config.sandbox.allow_live_targets)

    def test_finding_serialization_has_stable_id_and_json_shape(self):
        finding = Finding(
            vulnerability_class="command-injection",
            severity="high",
            confidence=0.82,
            location=SourceLocation(path="app.py", start_line=12, end_line=14),
            title="User input reaches os.system",
            evidence=["request.args['cmd'] reaches os.system"],
            remediation="Use subprocess with fixed argument lists and strict allowlists.",
        )

        serialized = finding.to_dict()

        self.assertTrue(serialized["id"].startswith("F-"))
        self.assertEqual(serialized["location"]["path"], "app.py")
        self.assertEqual(serialized["location"]["start_line"], 12)
        self.assertEqual(serialized["vulnerability_class"], "command-injection")
        json.dumps(serialized)

    def test_run_store_creates_expected_layout_and_immutable_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RunStore(Path(tmp))
            run = store.create_run("demo-target")

            expected_dirs = {
                "metadata",
                "logs",
                "tool_outputs",
                "intelligence",
                "agent_traces",
                "handoffs",
                "findings",
                "evidence",
                "poc",
                "reports",
            }
            self.assertTrue(expected_dirs.issubset({p.name for p in run.path.iterdir()}))

            first = run.write_json_artifact("tool_outputs", "scan.json", {"value": 1})
            second = run.write_json_artifact("tool_outputs", "scan.json", {"value": 2})

            self.assertNotEqual(first, second)
            self.assertEqual(first.name, "scan.json")
            self.assertTrue(second.name.startswith("scan-"))
            self.assertEqual(json.loads(first.read_text(encoding="utf-8"))["value"], 1)
            self.assertEqual(json.loads(second.read_text(encoding="utf-8"))["value"], 2)


if __name__ == "__main__":
    unittest.main()
