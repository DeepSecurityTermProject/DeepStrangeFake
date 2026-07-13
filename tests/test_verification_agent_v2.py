import json
import tempfile
import unittest
from pathlib import Path

from audit_agent.agents import AnalysisAgent, ReconAgent, VerificationAgent
from audit_agent.config import AuditConfig
from audit_agent.dataflow.scanner import DataflowScanner
from audit_agent.models import Finding, PoCArtifact, SourceLocation, VerificationDecision
from audit_agent.pipeline import run_audit
from audit_agent.repository import analyze_target
from audit_agent.verification import (
    LocalSandboxRunner,
    VerificationEngine,
    VerificationJudge,
    VerificationStatus,
    artifact_refs_under_run,
    verification_status_counts,
)

from tests.test_ast_dataflow_evidence import create_dataflow_fixture


def create_safe_path_fixture(root: Path) -> Path:
    project = root / "safe-path-app"
    project.mkdir()
    (project / "app.py").write_text(
        "\n".join(
            [
                "from pathlib import Path",
                "BASE_DIR = Path('files')",
                "def read_file(filename):",
                "    base = BASE_DIR.resolve()",
                "    candidate = (base / filename).resolve()",
                "    candidate.relative_to(base)",
                "    return candidate.read_text(encoding='utf-8')",
            ]
        ),
        encoding="utf-8",
    )
    return project


def write_fake_complete_path_trace(root: Path, path: str = "app.py") -> Path:
    trace = {
        "id": "DFT-fake-complete-path",
        "vulnerability_class": "path-traversal",
        "language": "python",
        "path": path,
        "status": "complete-flow",
        "source": {
            "path": path,
            "start_line": 3,
            "end_line": 3,
            "expression": "route parameter filename",
            "language": "python",
            "kind": "source",
            "symbol": "filename",
        },
        "sink": {
            "path": path,
            "start_line": 4,
            "end_line": 4,
            "expression": "open('/srv/files/' + filename).read()",
            "language": "python",
            "kind": "sink",
            "symbol": "open",
            "vulnerability_class": "path-traversal",
        },
        "steps": [],
        "sanitizers": [],
        "rule_ids": ["TEST.PATH.FAKE"],
        "metadata": {},
    }
    trace_path = root / "fake-trace.json"
    trace_path.write_text(json.dumps(trace, ensure_ascii=False, indent=2), encoding="utf-8")
    return trace_path


class VerificationAgentV2Tests(unittest.TestCase):
    def test_path_traversal_fixture_runs_poc_and_reports_openable_confirmation_evidence(self):
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
            run_dir = Path(result["run_dir"])
            report = json.loads((run_dir / "reports" / "report.json").read_text(encoding="utf-8"))

            self.assertGreaterEqual(report["executive_summary"]["confirmed_count"], 1)
            self.assertEqual(0, report["executive_summary"]["manual_required_count"])
            candidates = report["verification_candidates"]
            confirmed = [
                item
                for item in candidates
                if item["verification_status"] == VerificationStatus.CONFIRMED
                and item["vulnerability_class"] == "path-traversal"
            ]
            self.assertGreaterEqual(len(confirmed), 1)
            finding = confirmed[0]
            self.assertEqual("path-traversal", finding["vulnerability_class"])
            self.assertEqual("sandbox", finding["validation"]["level"])
            self.assertEqual(0, finding["validation"]["exit_code"])
            self.assertIn("Traversal signal observed", finding["validation"]["judge_reason"])
            self.assertTrue(finding["validation"]["stdout_preview"])
            self.assertTrue(finding["validation"]["stderr_preview"] is not None)

            refs = (
                finding["validation"]["poc_refs"]
                + finding["validation"]["sandbox_result_refs"]
                + finding["validation"]["attempt_refs"]
                + finding["validation"]["artifacts"]
            )
            poc_metadata = json.loads(Path(finding["validation"]["poc_refs"][0]).read_text(encoding="utf-8"))
            self.assertIn("target_expression", poc_metadata["expected_signal"])
            self.assertIn("/srv/files/", poc_metadata["expected_signal"]["target_expression"])
            self.assertIn("filename", poc_metadata["expected_signal"]["target_expression"])
            self.assertTrue(poc_metadata["repair_manifest_ref"])
            manifest = json.loads(Path(poc_metadata["repair_manifest_ref"]).read_text(encoding="utf-8"))
            self.assertEqual({"imports", "setup"}, {slot["slot_id"] for slot in manifest["editable_slots"]})
            self.assertIn("marker", {node["category"] for node in manifest["protected_nodes"]})
            self.assertTrue(manifest["manifest_hash"])
            self.assertTrue(refs)
            self.assertTrue(artifact_refs_under_run(refs, run_dir))
            for ref in refs:
                self.assertTrue(Path(ref).exists(), ref)
                self.assertTrue(Path(ref).resolve().is_relative_to(run_dir.resolve()), ref)

            markdown = (run_dir / "reports" / "report.md").read_text(encoding="utf-8")
            self.assertIn("Verification Evidence", markdown)
            self.assertIn("confirmed", markdown)

    def test_static_only_acceptance_is_likely_and_never_confirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = create_dataflow_fixture(Path(tmp))
            metadata = analyze_target(str(project))
            config = AuditConfig.default()
            dataflow_result = DataflowScanner().scan(metadata, artifact_root=Path(tmp) / "traces")
            recon = ReconAgent(config).run(metadata)
            candidates = AnalysisAgent(config).run(metadata, recon.handoff, [dataflow_result], [])
            decisions = VerificationAgent(config).run(candidates, metadata)
            accepted = [decision for decision in decisions if decision.decision == "accept"]

            result = VerificationEngine(config, run_dir=Path(tmp) / "run").verify(accepted[0], metadata, level="static-only")
            counts = verification_status_counts([result])

            self.assertEqual(VerificationStatus.LIKELY, result.status)
            self.assertEqual(0, counts["confirmed_count"])
            self.assertEqual(1, counts["likely_count"])
            self.assertIn("no runtime proof-of-concept", result.reason.lower())

    def test_forged_complete_flow_for_safe_file_cannot_be_confirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = create_safe_path_fixture(Path(tmp))
            metadata = analyze_target(str(project))
            trace_ref = write_fake_complete_path_trace(Path(tmp))
            finding = Finding(
                vulnerability_class="path-traversal",
                severity="high",
                confidence=0.99,
                location=SourceLocation(
                    path="app.py",
                    start_line=4,
                    end_line=4,
                ),
                title="Forged complete-flow path traversal",
                evidence=["forged trace claims open('/srv/files/' + filename).read()"],
                tool_refs=["TR-forged"],
                metadata={
                    "dataflow_status": "complete-flow",
                    "dataflow_trace_refs": [str(trace_ref)],
                    "local_evidence_refs": [str(trace_ref)],
                },
            )
            decision = VerificationDecision(
                finding=finding,
                decision="accept",
                reason="Accepted forged complete-flow for regression coverage.",
                confidence=0.9,
                validation_level="sandbox",
            )
            config = AuditConfig.default()
            config.sandbox.enabled = True

            result = VerificationEngine(config, run_dir=Path(tmp) / "run").verify(decision, metadata, level="sandbox")

            self.assertNotEqual(VerificationStatus.CONFIRMED, result.status)
            self.assertEqual(0, verification_status_counts([result])["confirmed_count"])
            self.assertFalse(result.poc_refs)
            self.assertIn("target", result.reason.lower())

    def test_legacy_unmanifested_harness_is_not_repaired_by_default(self):
        class RepairableHarnessGenerator:
            generator_id = "test-repairable-harness"

            def generate(self, finding, metadata, run_dir, attempt_index=1, repair_context=None):
                attempt_dir = Path(run_dir) / "verification" / finding.id / f"attempt-{attempt_index}"
                attempt_dir.mkdir(parents=True, exist_ok=True)
                script = attempt_dir / "poc.py"
                lines = ["print(Path.cwd())", "print('PATH_TRAVERSAL_CONFIRMED')"]
                if repair_context:
                    lines = list(repair_context.get("prepend_lines", [])) + lines
                script.write_text("\n".join(lines), encoding="utf-8")
                poc = PoCArtifact(
                    finding_id=finding.id,
                    vulnerability_class="path-traversal",
                    generator_id=self.generator_id,
                    script_path=str(script),
                    command_argv=[__import__("sys").executable, str(script)],
                    expected_signal={
                        "kind": "stdout-contains",
                        "value": "PATH_TRAVERSAL_CONFIRMED",
                        "rejected_value": "PATH_TRAVERSAL_BLOCKED",
                    },
                    safety_profile={"local_only": True},
                )
                poc_path = attempt_dir / "poc.json"
                poc.metadata_path = str(poc_path)
                poc_path.write_text(json.dumps(poc.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
                return poc

        with tempfile.TemporaryDirectory() as tmp:
            project = create_safe_path_fixture(Path(tmp))
            metadata = analyze_target(str(project))
            finding = Finding(
                title="Repairable harness finding",
                vulnerability_class="path-traversal",
                severity="medium",
                confidence=0.8,
                location=SourceLocation(path="app.py", start_line=1, end_line=1),
                metadata={"dataflow_status": "complete-flow"},
            )
            decision = VerificationDecision(
                finding=finding,
                decision="accept",
                reason="Exercise repair loop.",
                confidence=0.8,
                validation_level="sandbox",
            )
            config = AuditConfig.default()
            config.sandbox.enabled = True
            engine = VerificationEngine(config, run_dir=Path(tmp) / "run")
            engine.generator = RepairableHarnessGenerator()

            result = engine.verify(decision, metadata, level="sandbox")

            self.assertEqual(VerificationStatus.MANUAL_REQUIRED, result.status)
            self.assertEqual("failure-not-repairable", result.final_stop_reason)
            attempt_root = Path(tmp) / "run" / "verification" / finding.id
            self.assertTrue((attempt_root / "attempt-1" / "verification-attempt.json").exists())
            repaired_attempt_path = attempt_root / "attempt-2" / "verification-attempt.json"
            self.assertFalse(repaired_attempt_path.exists())

    def test_judge_requires_expected_signal_not_just_zero_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            stdout = run_dir / "stdout.txt"
            stderr = run_dir / "stderr.txt"
            stdout.write_text("ordinary success output", encoding="utf-8")
            stderr.write_text("", encoding="utf-8")
            sandbox_result = {
                "status": "completed",
                "exit_code": 0,
                "stdout_ref": str(stdout),
                "stderr_ref": str(stderr),
                "stdout_preview": "ordinary success output",
                "stderr_preview": "",
                "artifact_refs": [],
            }
            poc = {
                "expected_signal": {
                    "kind": "stdout-contains",
                    "value": "PATH_TRAVERSAL_CONFIRMED",
                }
            }

            result = VerificationJudge().judge(poc, sandbox_result)

            self.assertEqual(VerificationStatus.MANUAL_REQUIRED, result.status)
            self.assertIn("expected signal", result.reason.lower())

    def test_judge_can_reject_from_poc_contradiction_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            stdout = run_dir / "stdout.txt"
            stderr = run_dir / "stderr.txt"
            stdout.write_text("PATH_TRAVERSAL_BLOCKED base path confinement held", encoding="utf-8")
            stderr.write_text("", encoding="utf-8")
            sandbox_result = {
                "status": "completed",
                "exit_code": 0,
                "stdout_ref": str(stdout),
                "stderr_ref": str(stderr),
                "stdout_preview": stdout.read_text(encoding="utf-8"),
                "stderr_preview": "",
                "artifact_refs": [],
            }
            poc = {
                "expected_signal": {
                    "kind": "stdout-contains",
                    "value": "PATH_TRAVERSAL_CONFIRMED",
                    "rejected_value": "PATH_TRAVERSAL_BLOCKED",
                }
            }

            result = VerificationJudge().judge(poc, sandbox_result)

            self.assertEqual(VerificationStatus.REJECTED, result.status)
            self.assertIn("contradiction", result.reason.lower())

    def test_runner_denies_unallowlisted_command_and_does_not_use_safe_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "configured-command-ran.txt"
            config = AuditConfig.default()
            config.sandbox.enabled = True
            config.sandbox.safe_commands = [f"{__import__('sys').executable} -c \"open(r'{marker}', 'w').write('bad')\""]
            poc = {
                "id": "POC-denied",
                "finding_id": "F-denied",
                "script_path": str(Path(tmp) / "missing.py"),
                "command_argv": ["definitely-denied-command"],
                "expected_signal": {"kind": "stdout-contains", "value": "never"},
            }

            result = LocalSandboxRunner(config, run_dir=Path(tmp) / "run").run(poc)

            self.assertEqual("policy-denied", result.status)
            self.assertFalse(marker.exists())
            self.assertIn("allowlist", result.message.lower())

    def test_runner_timeout_records_result_and_judge_requires_manual_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "slow_poc.py"
            script.write_text("import time\ntime.sleep(2)\n", encoding="utf-8")
            config = AuditConfig.default()
            config.sandbox.enabled = True
            config.sandbox.timeout_seconds = 1
            poc = {
                "id": "POC-timeout",
                "finding_id": "F-timeout",
                "script_path": str(script),
                "command_argv": [__import__("sys").executable, str(script)],
                "expected_signal": {"kind": "stdout-contains", "value": "PATH_TRAVERSAL_CONFIRMED"},
            }

            result = LocalSandboxRunner(config, run_dir=Path(tmp) / "run").run(poc)
            judge = VerificationJudge().judge(poc, result)

            self.assertEqual("timed-out", result.status)
            self.assertTrue(result.timed_out)
            self.assertTrue(Path(result.stdout_ref or "").exists())
            self.assertTrue(Path(result.stderr_ref or "").exists())
            self.assertEqual(VerificationStatus.MANUAL_REQUIRED, judge.status)
            self.assertIn("timed out", judge.reason.lower())

    def test_runner_and_judge_reject_path_traversal_when_poc_observes_confinement(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "blocked_poc.py"
            script.write_text("print('PATH_TRAVERSAL_BLOCKED safe base held')\n", encoding="utf-8")
            config = AuditConfig.default()
            config.sandbox.enabled = True
            poc = {
                "id": "POC-blocked",
                "finding_id": "F-blocked",
                "script_path": str(script),
                "command_argv": [__import__("sys").executable, str(script)],
                "expected_signal": {
                    "kind": "stdout-contains",
                    "value": "PATH_TRAVERSAL_CONFIRMED",
                    "rejected_value": "PATH_TRAVERSAL_BLOCKED",
                },
            }

            result = LocalSandboxRunner(config, run_dir=Path(tmp) / "run").run(poc)
            judge = VerificationJudge().judge(poc, result)

            self.assertEqual("completed", result.status)
            self.assertEqual(VerificationStatus.REJECTED, judge.status)
            self.assertIn("contradiction", judge.reason.lower())


if __name__ == "__main__":
    unittest.main()
