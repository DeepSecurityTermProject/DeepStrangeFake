import json
import tempfile
import unittest
from pathlib import Path

from audit_agent.agents import (
    AnalysisAgent,
    BoundedReActLoop,
    OrchestratorAgent,
    ReconAgent,
    VerificationAgent,
)
from audit_agent.benchmark import BenchmarkConfig, BenchmarkRunner
from audit_agent.config import AuditConfig
from audit_agent.evidence import EvidenceBuilder
from audit_agent.intelligence import CveMcpAdapter, normalize_cve_mcp_output
from audit_agent.models import Finding, SourceLocation
from audit_agent.reporting import ReportGenerator
from audit_agent.repository import analyze_target
from audit_agent.tools import PatternScanner
from audit_agent.validation import Validator

from tests.test_repository_analysis import create_vulnerable_fixture


class ToolAgentReportingTests(unittest.TestCase):
    def test_pattern_scanner_and_four_agent_pipeline_generate_traceable_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            metadata = analyze_target(str(project))
            config = AuditConfig.default()
            scan_result = PatternScanner().scan(metadata)

            intelligence = normalize_cve_mcp_output(
                {
                    "cve_id": "CVE-2099-0001",
                    "cwe_ids": ["CWE-89", "CWE-78"],
                    "cvss": 9.1,
                    "epss": 0.73,
                    "kev": True,
                    "public_poc_available": True,
                    "risk_score": 95,
                    "references": ["https://example.test/advisory"],
                },
                query={"dependency": "Flask"},
                tool_name="cve-mcp-server",
            )

            plan = OrchestratorAgent(config).plan(metadata)
            recon = ReconAgent(config).run(metadata, [intelligence])
            candidates = AnalysisAgent(config).run(
                metadata=metadata,
                recon_handoff=recon.handoff,
                tool_results=[scan_result],
                intelligence=[intelligence],
            )

            intel_only = Finding(
                vulnerability_class="dependency-cve",
                severity="critical",
                confidence=0.99,
                location=SourceLocation(path="requirements.txt", start_line=1, end_line=1),
                title="Intelligence-only finding",
                evidence=[],
                intelligence_refs=[intelligence.id],
            )
            decisions = VerificationAgent(config).run(
                candidates=candidates + [intel_only],
                metadata=metadata,
                intelligence=[intelligence],
            )
            accepted = [decision for decision in decisions if decision.decision == "accept"]
            rejected = [decision for decision in decisions if decision.decision == "reject"]

            self.assertIn("sql-injection", plan.vulnerability_classes)
            self.assertTrue(candidates)
            self.assertTrue(accepted)
            self.assertEqual(rejected[0].finding_id, intel_only.id)
            self.assertIn("local evidence", rejected[0].reason)

            validator = Validator(config)
            validation = validator.validate(accepted[0].finding, metadata, level="poc-generate")
            evidence = EvidenceBuilder(Path(tmp) / "evidence").build(
                finding=accepted[0].finding,
                metadata=metadata,
                tool_results=[scan_result],
                intelligence=[intelligence],
                verification=accepted[0],
                validation=validation,
                agent_traces=[recon.trace],
                handoffs=[recon.handoff],
            )
            report = ReportGenerator().build(metadata, [accepted[0].finding], [evidence])
            markdown = ReportGenerator().to_markdown(report)
            report_json = json.loads(ReportGenerator().to_json(report))

            self.assertEqual(evidence.finding_id, accepted[0].finding.id)
            self.assertIn("poc", validation.artifacts[0])
            self.assertIn("CVE-2099-0001", markdown)
            self.assertIn("agent_traces", report_json["findings"][0])
            self.assertIn("remediation", report_json["findings"][0])

    def test_cve_mcp_adapter_degrades_when_server_is_unavailable(self):
        adapter = CveMcpAdapter(enabled=True, command=["definitely-missing-cve-mcp"])

        observation = adapter.query("lookup_cve", {"cve_id": "CVE-2099-0001"})

        self.assertFalse(observation.success)
        self.assertTrue(observation.degraded)
        self.assertEqual(observation.tool_name, "cve-mcp-server")
        self.assertIn("unavailable", observation.message.lower())

    def test_react_loop_respects_iteration_limit(self):
        loop = BoundedReActLoop(max_iterations=2, max_tool_calls=1)
        result = loop.run(lambda step: ("continue", {"step": step}))

        self.assertEqual(result.stop_reason, "max_iterations")
        self.assertEqual(len(result.steps), 2)

    def test_benchmark_config_and_runner_aggregate_partial_failures(self):
        config = BenchmarkConfig.load_default()
        self.assertGreaterEqual(len(config.targets), 20)
        self.assertIn("openvpn", {target.name for target in config.targets})
        self.assertIn("maccms-v10", {target.name for target in config.targets})

        runner = BenchmarkRunner(config.targets[:2])
        summary = runner.run(lambda target: {"candidate_count": 1, "validated_count": 0})

        self.assertEqual(summary.total_projects, 2)
        self.assertEqual(summary.completed_projects, 2)
        self.assertEqual(summary.candidate_count, 2)


if __name__ == "__main__":
    unittest.main()
