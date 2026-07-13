import json
import tempfile
import unittest
from pathlib import Path

from audit_agent.config import AuditConfig
from audit_agent.models import Finding, SourceLocation, VerificationDecision
from audit_agent.pipeline import run_audit
from audit_agent.repository import analyze_target
from audit_agent.verification import (
    VerificationEngine,
    VerificationJudge,
    VerificationStatus,
    artifact_refs_under_run,
    verification_status_counts,
)

from tests.test_ast_dataflow_evidence import create_dataflow_fixture


def create_sqli_fixture(root: Path) -> Path:
    project = root / "sqli-app"
    project.mkdir()
    (project / "app.py").write_text(
        "\n".join(
            [
                "from flask import Flask, request",
                "app = Flask(__name__)",
                "@app.route('/raw')",
                "def raw_user():",
                "    name = request.args.get('name')",
                "    query = \"select id, name, role from users where name='%s'\" % name",
                "    cursor.execute(query)",
                "    return 'ok'",
                "@app.route('/param')",
                "def param_user():",
                "    safe_name = request.args.get('name')",
                "    cursor.execute('select id, name, role from users where name=?', (safe_name,))",
                "    return 'ok'",
            ]
        ),
        encoding="utf-8",
    )
    return project


def create_unsupported_sqli_fixture(root: Path) -> Path:
    project = root / "unsupported-sqli-app"
    project.mkdir()
    (project / "app.py").write_text(
        "\n".join(
            [
                "from flask import Flask, request",
                "app = Flask(__name__)",
                "@app.route('/orm')",
                "def orm_user():",
                "    name = request.args.get('name')",
                "    query = \"select id, name from users where name='%s'\" % name",
                "    session.execute(query)",
                "    return 'ok'",
                "@app.route('/delete')",
                "def delete_user():",
                "    name = request.args.get('name')",
                "    query = \"delete from users where name='%s'\" % name",
                "    cursor.execute(query)",
                "    return 'ok'",
            ]
        ),
        encoding="utf-8",
    )
    (project / "server.js").write_text(
        "\n".join(
            [
                "const express = require('express');",
                "const app = express();",
                "app.get('/search', (req, res) => {",
                "  const term = req.query.term;",
                "  db.query(`select * from users where name='${term}'`);",
                "});",
            ]
        ),
        encoding="utf-8",
    )
    return project


def write_sqli_trace(
    root: Path,
    *,
    language: str = "python",
    path: str = "app.py",
    sink_expression: str,
    step_expression: str | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    trace = {
        "id": f"DFT-test-sqli-{language}",
        "vulnerability_class": "sql-injection",
        "language": language,
        "path": path,
        "status": "complete-flow",
        "source": {
            "path": path,
            "start_line": 4,
            "end_line": 4,
            "expression": "request.args.get('name')",
            "language": language,
            "kind": "source",
            "symbol": "name",
        },
        "sink": {
            "path": path,
            "start_line": 6,
            "end_line": 6,
            "expression": sink_expression,
            "language": language,
            "kind": "sink",
            "symbol": "cursor.execute",
            "vulnerability_class": "sql-injection",
        },
        "steps": [
            {
                "path": path,
                "start_line": 5,
                "end_line": 5,
                "expression": step_expression or sink_expression,
                "step_type": "assignment",
                "language": language,
            }
        ],
        "sanitizers": [],
        "rule_ids": ["TEST.SQL.RAW"],
        "metadata": {},
    }
    trace_path = root / f"{language}-sqli-trace.json"
    trace_path.write_text(json.dumps(trace, ensure_ascii=False, indent=2), encoding="utf-8")
    return trace_path


def decision_for_trace(project: Path, trace_ref: Path, *, sink_path: str = "app.py") -> tuple[VerificationDecision, object]:
    metadata = analyze_target(str(project))
    finding = Finding(
        vulnerability_class="sql-injection",
        severity="high",
        confidence=0.95,
        location=SourceLocation(path=sink_path, start_line=6, end_line=6),
        title="SQL injection candidate",
        evidence=["dataflow-backed SQL injection"],
        tool_refs=["TR-sqli"],
        metadata={
            "dataflow_status": "complete-flow",
            "dataflow_trace_refs": [str(trace_ref)],
            "local_evidence_refs": [str(trace_ref)],
        },
    )
    return (
        VerificationDecision(
            finding=finding,
            decision="accept",
            reason="Exercise SQLi verification.",
            confidence=0.9,
            validation_level="sandbox",
        ),
        metadata,
    )


class SQLInjectionPoCGeneratorTests(unittest.TestCase):
    def test_raw_sqli_fixture_runs_poc_and_reports_openable_confirmation_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = create_sqli_fixture(Path(tmp))
            config = AuditConfig.default()
            config.runtime_enabled = True
            config.llm.provider = "mock"
            config.memory.enabled = False
            config.mcp.enabled = False
            config.sandbox.enabled = True
            config.default_validation_level = "sandbox"

            result = run_audit(str(project), config=config, output_dir=Path(tmp) / "runs")
            run_dir = Path(result["run_dir"])
            report = json.loads((run_dir / "reports" / "report.json").read_text(encoding="utf-8"))
            raw = [
                item
                for item in report["verification_candidates"]
                if item["vulnerability_class"] == "sql-injection"
                and item.get("dataflow_status") == "complete-flow"
            ][0]

            self.assertEqual(VerificationStatus.CONFIRMED, raw["verification_status"])
            self.assertEqual("sandbox", raw["validation"]["level"])
            self.assertEqual(0, raw["validation"]["exit_code"])
            self.assertIn("SQL injection semantic widening", raw["validation"]["judge_reason"])
            refs = raw["validation"]["poc_refs"] + raw["validation"]["sandbox_result_refs"] + raw["validation"]["attempt_refs"] + raw["validation"]["artifacts"]
            self.assertTrue(refs)
            self.assertTrue(artifact_refs_under_run(refs, run_dir))
            sqli_refs = [Path(ref) for ref in raw["validation"]["artifacts"] if str(ref).endswith("sqli-result.json")]
            self.assertTrue(sqli_refs)
            sqli_result = json.loads(sqli_refs[0].read_text(encoding="utf-8"))
            self.assertEqual("confirmed", sqli_result["status"])
            self.assertGreater(sqli_result["attack_count"], sqli_result["baseline_count"])
            self.assertTrue(sqli_result["marker_seen"])
            self.assertGreaterEqual(report["executive_summary"]["confirmed_count"], 1)
            poc_payload = json.loads(Path(raw["validation"]["poc_refs"][0]).read_text(encoding="utf-8"))
            manifest = json.loads(Path(poc_payload["repair_manifest_ref"]).read_text(encoding="utf-8"))
            categories = {node["category"] for node in manifest["protected_nodes"]}
            self.assertIn("measurement", categories)
            self.assertIn("result-writer", categories)
            self.assertEqual("sqli-result.json", manifest["protected_result_filenames"][0])

    def test_parameterized_sqli_fixture_runs_poc_and_reports_rejection_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = create_sqli_fixture(Path(tmp))
            config = AuditConfig.default()
            config.runtime_enabled = True
            config.llm.provider = "mock"
            config.memory.enabled = False
            config.mcp.enabled = False
            config.sandbox.enabled = True
            config.default_validation_level = "sandbox"

            result = run_audit(str(project), config=config, output_dir=Path(tmp) / "runs")
            run_dir = Path(result["run_dir"])
            report = json.loads((run_dir / "reports" / "report.json").read_text(encoding="utf-8"))
            parameterized = [
                item
                for item in report["verification_candidates"]
                if item["vulnerability_class"] == "sql-injection"
                and item.get("dataflow_status") == "sanitized-flow"
            ][0]

            self.assertEqual(VerificationStatus.REJECTED, parameterized["verification_status"])
            self.assertEqual(0, parameterized["validation"]["exit_code"])
            self.assertIn("parameter binding", parameterized["validation"]["judge_reason"].lower())
            self.assertTrue(parameterized["validation"]["poc_refs"])
            sqli_refs = [Path(ref) for ref in parameterized["validation"]["artifacts"] if str(ref).endswith("sqli-result.json")]
            self.assertTrue(sqli_refs)
            sqli_result = json.loads(sqli_refs[0].read_text(encoding="utf-8"))
            self.assertEqual("rejected", sqli_result["status"])
            self.assertFalse(sqli_result["marker_seen"])
            self.assertTrue(artifact_refs_under_run(parameterized["validation"]["artifacts"], run_dir))

    def test_forged_sqli_trace_cannot_generate_poc_or_confirm(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = create_sqli_fixture(Path(tmp))
            trace_ref = write_sqli_trace(
                Path(tmp),
                sink_expression='cursor.execute("select id from missing where name=\'%s\'" % name)',
            )
            decision, metadata = decision_for_trace(project, trace_ref)
            config = AuditConfig.default()
            config.sandbox.enabled = True

            result = VerificationEngine(config, run_dir=Path(tmp) / "run").verify(decision, metadata, level="sandbox")

            self.assertNotEqual(VerificationStatus.CONFIRMED, result.status)
            self.assertEqual(0, verification_status_counts([result])["confirmed_count"])
            self.assertFalse(result.poc_refs)
            self.assertIn("target", result.reason.lower())

    def test_unsupported_orm_js_and_non_select_sqli_degrade_without_poc(self):
        cases = [
            ("orm", "app.py", "python", "session.execute(query)", "orm"),
            ("js", "server.js", "javascript", "db.query(`select * from users where name='${term}'`)", "language"),
            ("non_select", "app.py", "python", "cursor.execute(query)", "non-select"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            project = create_unsupported_sqli_fixture(Path(tmp))
            config = AuditConfig.default()
            config.sandbox.enabled = True
            for name, path, language, sink_expression, reason_token in cases:
                with self.subTest(name=name):
                    trace_ref = write_sqli_trace(
                        Path(tmp) / name,
                        language=language,
                        path=path,
                        sink_expression=sink_expression,
                        step_expression=(
                            "query = \"delete from users where name='%s'\" % name"
                            if name == "non_select"
                            else "query = \"select id, name from users where name='%s'\" % name"
                        ),
                    )
                    decision, metadata = decision_for_trace(project, trace_ref, sink_path=path)

                    result = VerificationEngine(config, run_dir=Path(tmp) / f"run-{name}").verify(
                        decision,
                        metadata,
                        level="sandbox",
                    )

                    self.assertIn(result.status, {VerificationStatus.LIKELY, VerificationStatus.MANUAL_REQUIRED})
                    self.assertFalse(result.poc_refs)
                    self.assertIn(reason_token, result.reason.lower())

    def test_sqli_judge_requires_result_json_not_return_code_or_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            stdout = run_dir / "stdout.txt"
            stderr = run_dir / "stderr.txt"
            stdout.write_text("SQLI_CONFIRMED but no semantic artifact", encoding="utf-8")
            stderr.write_text("", encoding="utf-8")
            poc = {
                "expected_signal": {
                    "kind": "sqli-semantic-result",
                    "result_filename": "sqli-result.json",
                }
            }
            sandbox_result = {
                "status": "completed",
                "exit_code": 0,
                "stdout_ref": str(stdout),
                "stderr_ref": str(stderr),
                "stdout_preview": stdout.read_text(encoding="utf-8"),
                "stderr_preview": "",
                "artifact_refs": [],
            }

            result = VerificationJudge().judge(poc, sandbox_result)

            self.assertNotEqual(VerificationStatus.CONFIRMED, result.status)
            self.assertIn("sqli-result.json", result.reason)

    def test_path_traversal_validation_still_confirms_after_generator_routing(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = create_dataflow_fixture(Path(tmp))
            config = AuditConfig.default()
            config.runtime_enabled = True
            config.llm.provider = "mock"
            config.memory.enabled = False
            config.mcp.enabled = False
            config.sandbox.enabled = True
            config.default_validation_level = "sandbox"

            result = run_audit(str(project), config=config, output_dir=Path(tmp) / "runs")
            report = json.loads((Path(result["run_dir"]) / "reports" / "report.json").read_text(encoding="utf-8"))
            path_candidates = [
                item for item in report["verification_candidates"] if item["vulnerability_class"] == "path-traversal"
            ]

            self.assertTrue(path_candidates)
            self.assertTrue(any(item["verification_status"] == VerificationStatus.CONFIRMED for item in path_candidates))


if __name__ == "__main__":
    unittest.main()
