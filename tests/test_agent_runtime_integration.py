import json
import tempfile
import unittest
from pathlib import Path

from audit_agent.config import AuditConfig
from audit_agent.pipeline import run_audit

from tests.test_repository_analysis import create_vulnerable_fixture


class AgentRuntimeIntegrationTests(unittest.TestCase):
    def test_mock_runtime_audit_generates_prompts_llm_memory_messages_and_report_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            output = Path(tmp) / "runs"
            config = AuditConfig.default()
            config.runtime_enabled = True
            config.llm.provider = "mock"
            config.memory.enabled = True
            config.message_bus.enabled = True
            config.mcp.enabled = True
            config.mcp.command = ["definitely-missing-mcp"]

            result = run_audit(str(project), config=config, output_dir=output)
            run_dir = Path(result["run_dir"])

            self.assertTrue((run_dir / "prompts").exists())
            self.assertTrue((run_dir / "llm").exists())
            self.assertTrue((run_dir / "memory").exists())
            self.assertTrue((run_dir / "mcp").exists())
            self.assertTrue((run_dir / "messages" / "messages.jsonl").exists())
            self.assertTrue(list((run_dir / "prompts").glob("*.json")))
            self.assertTrue(list((run_dir / "llm").glob("*.json")))
            self.assertTrue(list((run_dir / "memory").glob("*.json")))
            self.assertTrue(list((run_dir / "mcp").glob("*.json")))

            report = json.loads((run_dir / "reports" / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["runtime"]["llm"]["provider"], "mock")
            self.assertEqual(report["runtime"]["memory"]["mode"], "lexical")
            self.assertTrue(report["runtime"]["message_log"].endswith("messages.jsonl"))
            self.assertIn("prompt_refs", report["findings"][0])
            self.assertIn("message_refs", report["findings"][0])
            self.assertIn("memory_refs", report["findings"][0])

    def test_verification_rejects_memory_only_findings(self):
        from audit_agent.agents import VerificationAgent
        from audit_agent.models import Finding, SourceLocation
        from audit_agent.repository import analyze_target

        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            metadata = analyze_target(str(project))
            finding = Finding(
                vulnerability_class="sql-injection",
                severity="high",
                confidence=0.9,
                location=SourceLocation(path="app.py", start_line=1, end_line=1),
                title="Memory-only SQL injection",
                evidence=[],
                tool_refs=[],
                metadata={"memory_refs": ["MEM-1"]},
            )

            decisions = VerificationAgent(AuditConfig.default()).run([finding], metadata, intelligence=[])

            self.assertEqual(decisions[0].decision, "reject")
            self.assertIn("local evidence", decisions[0].reason)

    def test_analysis_can_parse_schema_valid_llm_candidates_with_local_evidence(self):
        from audit_agent.agents import findings_from_llm_candidates
        from audit_agent.repository import analyze_target

        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            metadata = analyze_target(str(project))
            payload = {
                "candidates": [
                    {
                        "vulnerability_class": "command-injection",
                        "severity": "high",
                        "confidence": 0.83,
                        "title": "LLM identified command injection",
                        "path": "app.py",
                        "start_line": 9,
                        "end_line": 9,
                        "evidence": ["os.system uses request args"],
                        "tool_refs": ["TR-local"],
                        "memory_refs": ["MEM-local"],
                        "prompt_refs": ["PR-local"],
                    }
                ]
            }

            findings = findings_from_llm_candidates(payload, metadata)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].vulnerability_class, "command-injection")
            self.assertEqual(findings[0].location.path, "app.py")
            self.assertIn("TR-local", findings[0].tool_refs)
            self.assertIn("MEM-local", findings[0].metadata["memory_refs"])


if __name__ == "__main__":
    unittest.main()
