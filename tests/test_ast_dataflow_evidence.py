import json
import tempfile
import unittest
from pathlib import Path

from audit_agent.agents import AnalysisAgent, ReconAgent, VerificationAgent
from audit_agent.config import AuditConfig
from audit_agent.evidence import EvidenceBuilder
from audit_agent.pipeline import run_audit
from audit_agent.reporting import ReportGenerator
from audit_agent.repository import analyze_target
from audit_agent.tool_protocol import ToolRuntime, build_default_tool_registry


def create_dataflow_fixture(root: Path) -> Path:
    project = root / "dataflow-app"
    project.mkdir()
    (project / "app.py").write_text(
        "\n".join(
            [
                "import os",
                "import subprocess",
                "from flask import Flask, request, send_file",
                "app = Flask(__name__)",
                "@app.route('/user')",
                "def user():",
                "    name = request.args.get('name')",
                "    query = \"select * from users where name='%s'\" % name",
                "    cursor.execute(query)",
                "    return 'ok'",
                "@app.route('/cmd')",
                "def cmd():",
                "    cmd_value = request.args.get('cmd')",
                "    subprocess.run('ls ' + cmd_value, shell=True)",
                "    return 'ok'",
                "@app.route('/download/<filename>')",
                "def download(filename):",
                "    return open('/srv/files/' + filename).read()",
                "@app.route('/safe')",
                "def safe():",
                "    safe_name = request.args.get('name')",
                "    cursor.execute('select * from users where name=?', (safe_name,))",
                "    return 'ok'",
            ]
        ),
        encoding="utf-8",
    )
    (project / "server.js").write_text(
        "\n".join(
            [
                "const express = require('express');",
                "const child_process = require('child_process');",
                "const fs = require('fs');",
                "const app = express();",
                "app.get('/search', (req, res) => {",
                "  const term = req.query.term;",
                "  db.query(`select * from users where name='${term}'`);",
                "});",
                "app.get('/run', (req, res) => {",
                "  const cmd = req.query.cmd;",
                "  child_process.exec('ls ' + cmd);",
                "});",
                "app.get('/file', (req, res) => {",
                "  const file = req.query.file;",
                "  fs.readFile('/srv/files/' + file, () => {});",
                "});",
            ]
        ),
        encoding="utf-8",
    )
    return project


class AstDataflowEvidenceTests(unittest.TestCase):
    def test_dataflow_scanner_detects_python_and_js_source_to_sink_traces_and_artifacts(self):
        from audit_agent.dataflow.scanner import DataflowScanner

        with tempfile.TemporaryDirectory() as tmp:
            project = create_dataflow_fixture(Path(tmp))
            metadata = analyze_target(str(project))
            artifact_root = Path(tmp) / "traces"

            result = DataflowScanner().scan(metadata, artifact_root=artifact_root)

            self.assertTrue(result.success)
            classes = {observation.vulnerability_class for observation in result.observations}
            self.assertIn("sql-injection", classes)
            self.assertIn("command-injection", classes)
            self.assertIn("path-traversal", classes)
            self.assertTrue(result.artifact_paths)
            first_trace = json.loads(Path(result.artifact_paths[0]).read_text(encoding="utf-8"))
            self.assertIn("source", first_trace)
            self.assertIn("sink", first_trace)
            self.assertIn("steps", first_trace)
            self.assertEqual(first_trace["status"], "complete-flow")
            self.assertNotIn("steps", json.dumps(result.observations[0].raw.get("dataflow_summary", {})))

    def test_dataflow_scan_is_declared_and_dispatched_through_tool_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = create_dataflow_fixture(Path(tmp))
            metadata = analyze_target(str(project))
            registry = build_default_tool_registry(AuditConfig.default())
            names = {declaration.name for declaration in registry.declarations()}

            self.assertIn("dataflow-scan", names)
            result = ToolRuntime(registry, artifact_root=Path(tmp) / "tool-results").call(
                "analysis",
                "dataflow-scan",
                {"metadata": metadata, "artifact_root": Path(tmp) / "dataflow"},
            )

            self.assertTrue(result.success)
            self.assertTrue(result.observations)
            self.assertTrue(any("dataflow" in path for path in result.artifact_paths))

    def test_dataflow_scan_tool_respects_max_trace_argument(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = create_dataflow_fixture(Path(tmp))
            metadata = analyze_target(str(project))
            registry = build_default_tool_registry(AuditConfig.default())

            result = ToolRuntime(registry, artifact_root=Path(tmp) / "tool-results").call(
                "analysis",
                "dataflow-scan",
                {
                    "metadata": metadata,
                    "artifact_root": Path(tmp) / "dataflow",
                    "max_traces": 1,
                },
            )

            self.assertTrue(result.success)
            self.assertEqual(1, len(result.observations))
            self.assertEqual(1, result.output["inputs"]["max_traces"])

    def test_sanitized_dataflow_observation_reaches_verification_rejection(self):
        from audit_agent.dataflow.scanner import DataflowScanner

        with tempfile.TemporaryDirectory() as tmp:
            project = create_dataflow_fixture(Path(tmp))
            metadata = analyze_target(str(project))
            config = AuditConfig.default()
            dataflow_result = DataflowScanner().scan(metadata, artifact_root=Path(tmp) / "traces")
            recon = ReconAgent(config).run(metadata)

            sanitized_observations = [
                observation
                for observation in dataflow_result.observations
                if observation.raw.get("dataflow_status") == "sanitized-flow"
            ]
            self.assertTrue(sanitized_observations)
            self.assertEqual("sql-injection", sanitized_observations[0].vulnerability_class)

            candidates = AnalysisAgent(config).run(metadata, recon.handoff, [dataflow_result], [])
            sanitized_candidates = [
                candidate
                for candidate in candidates
                if candidate.metadata.get("dataflow_status") == "sanitized-flow"
            ]
            self.assertTrue(sanitized_candidates)

            decisions = VerificationAgent(config).run(candidates, metadata)
            sanitized_decisions = [
                decision
                for decision in decisions
                if decision.finding.metadata.get("dataflow_status") == "sanitized-flow"
            ]
            self.assertTrue(sanitized_decisions)
            self.assertEqual("reject", sanitized_decisions[0].decision)
            self.assertIn("sanitizer", sanitized_decisions[0].reason.lower())

    def test_js_ts_frontend_uses_tree_sitter_parser_when_available(self):
        from audit_agent.dataflow.js_ts_frontend import JsTsDataflowFrontend

        class FakeNode:
            def __init__(self, kind: str, start: int, end: int, text: str, children=None):
                self.type = kind
                self.start_byte = start
                self.end_byte = end
                self.start_point = (text[:start].count("\n"), 0)
                self.end_point = (text[:end].count("\n"), 0)
                self.children = children or []

        class FakeTree:
            def __init__(self, root_node):
                self.root_node = root_node

        class FakeParser:
            def parse(self, source_bytes):
                text = source_bytes.decode("utf-8")

                def node(kind: str, segment: str) -> FakeNode:
                    start = text.index(segment)
                    return FakeNode(kind, start, start + len(segment), text)

                children = [
                    node("variable_declarator", "const term = req.query.term"),
                    node("call_expression", "db.query(`select * from users where name='${term}'`)"),
                ]
                return FakeTree(FakeNode("program", 0, len(text), text, children))

        frontend = JsTsDataflowFrontend(parser_provider=lambda _language: FakeParser())
        traces = frontend.analyze(
            "server.ts",
            "\n".join(
                [
                    "const term = req.query.term;",
                    "db.query(`select * from users where name='${term}'`);",
                ]
            ),
        )

        self.assertEqual("tree-sitter", frontend.last_parse_backend)
        self.assertEqual(1, len(traces))
        self.assertEqual("tree-sitter", traces[0].metadata["parse_backend"])

    def test_analysis_finding_keeps_summary_refs_not_full_trace_payload(self):
        from audit_agent.dataflow.scanner import DataflowScanner

        with tempfile.TemporaryDirectory() as tmp:
            project = create_dataflow_fixture(Path(tmp))
            metadata = analyze_target(str(project))
            config = AuditConfig.default()
            dataflow_result = DataflowScanner().scan(metadata, artifact_root=Path(tmp) / "traces")
            recon = ReconAgent(config).run(metadata)

            candidates = AnalysisAgent(config).run(
                metadata=metadata,
                recon_handoff=recon.handoff,
                tool_results=[dataflow_result],
                intelligence=[],
            )

            dataflow_candidates = [item for item in candidates if item.metadata.get("dataflow_trace_refs")]
            self.assertTrue(dataflow_candidates)
            finding = dataflow_candidates[0]
            self.assertTrue(finding.call_path)
            self.assertIn("dataflow_summary", finding.metadata)
            self.assertIn("dataflow_trace_refs", finding.metadata)
            self.assertNotIn("steps", finding.metadata)
            self.assertNotIn("source", finding.metadata)
            self.assertTrue(Path(finding.metadata["dataflow_trace_refs"][0]).exists())

    def test_evidence_and_report_reference_full_dataflow_trace_artifacts(self):
        from audit_agent.dataflow.scanner import DataflowScanner
        from audit_agent.validation import Validator

        with tempfile.TemporaryDirectory() as tmp:
            project = create_dataflow_fixture(Path(tmp))
            metadata = analyze_target(str(project))
            config = AuditConfig.default()
            dataflow_result = DataflowScanner().scan(metadata, artifact_root=Path(tmp) / "traces")
            recon = ReconAgent(config).run(metadata)
            candidates = AnalysisAgent(config).run(metadata, recon.handoff, [dataflow_result], [])
            decisions = VerificationAgent(config).run(candidates, metadata)
            accepted = [decision for decision in decisions if decision.decision == "accept"]

            validation = Validator(config).validate(accepted[0].finding, metadata, level="static-only")
            evidence = EvidenceBuilder(Path(tmp) / "evidence").build(
                finding=accepted[0].finding,
                metadata=metadata,
                tool_results=[dataflow_result],
                intelligence=[],
                verification=accepted[0],
                validation=validation,
                agent_traces=[recon.trace],
                handoffs=[recon.handoff],
            )
            report = ReportGenerator().build(metadata, [accepted[0].finding], [evidence])
            report_json = json.loads(ReportGenerator().to_json(report))
            markdown = ReportGenerator().to_markdown(report)

            self.assertTrue(evidence.dataflow_trace_refs)
            self.assertIn("dataflow_trace_refs", report_json["findings"][0])
            self.assertTrue(report_json["findings"][0]["dataflow_trace_refs"])
            self.assertIn("Dataflow Evidence", markdown)

    def test_runtime_audit_persists_dataflow_traces_and_report_refs(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = create_dataflow_fixture(Path(tmp))
            config = AuditConfig.default()
            config.runtime_enabled = True
            config.llm.provider = "mock"
            config.memory.enabled = False
            config.mcp.enabled = False

            result = run_audit(str(project), config=config, output_dir=Path(tmp) / "runs")
            run_dir = Path(result["run_dir"])
            report = json.loads((run_dir / "reports" / "report.json").read_text(encoding="utf-8"))

            self.assertTrue(list((run_dir / "dataflow" / "traces").glob("*.json")))
            self.assertTrue(any(item.get("dataflow_trace_refs") for item in report["findings"]))
            self.assertIn("dataflow-scan", (run_dir / "runtime_state" / "state.json").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
