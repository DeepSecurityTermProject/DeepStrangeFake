import json
import sys
import tempfile
import unittest
from pathlib import Path

from audit_agent.config import AuditConfig
from audit_agent.llm import LLMProviderError, MockLLMClient
from audit_agent.message_bus import MessageBus, replay_summary
from audit_agent.models import (
    Finding,
    PoCArtifact,
    PoCEditableSlot,
    PoCFailureClass,
    RepositoryMetadata,
    SandboxRunResult,
    SourceLocation,
    AuditTarget,
    VerificationDecision,
)
from audit_agent.poc_repair import (
    IMPORT_SLOT_BEGIN,
    IMPORT_SLOT_END,
    SETUP_SLOT_BEGIN,
    SETUP_SLOT_END,
    PoCFailureClassifier,
    PoCRepairContractError,
    PoCSafetyGate,
    PoCSemanticIntegrityGate,
    TrustedPoCAssembler,
    build_and_persist_repair_manifest,
    build_target_manifest,
    compare_target_manifests,
    load_repair_manifest,
    parse_poc_repair_response,
    persist_execution_envelope,
    sha256_text,
)
from audit_agent.redaction import REDACTION_MARKER, redact_text
from audit_agent.reporting import ReportGenerator
from audit_agent.verification import LocalSandboxRunner, VerificationEngine, VerificationStatus


class RecordingMockLLMClient(MockLLMClient):
    def __init__(self, payload):
        super().__init__({"poc-repair": payload})
        self.calls = []

    def complete(self, request):
        self.calls.append(request)
        return super().complete(request)


class FakeDockerRunner:
    runner_type = "docker"

    def __init__(self):
        self.starts = []

    def run(self, poc, attempt_index=1):
        self.starts.append((attempt_index, poc.script_hash))
        attempt_dir = Path(poc.script_path).parent
        script = Path(poc.script_path).read_text(encoding="utf-8")
        repaired = "from pathlib import Path" in script
        stdout = "PATH_TRAVERSAL_CONFIRMED synthetic-evidence\n" if repaired else ""
        stderr = "" if repaired else "NameError: name 'Path' is not defined\n"
        stdout_path = attempt_dir / "stdout.txt"
        stderr_path = attempt_dir / "stderr.txt"
        stdout_path.write_text(stdout, encoding="utf-8")
        stderr_path.write_text(stderr, encoding="utf-8")
        result = SandboxRunResult(
            poc_id=poc.id or "poc",
            finding_id=poc.finding_id,
            attempt_id=f"attempt-{attempt_index}",
            status="completed",
            cwd=str(attempt_dir),
            argv=["python", "/attempt/poc.py"],
            timeout_seconds=10,
            environment={"runner": "docker", "network": "none", "docker_image": "fake-python"},
            exit_code=0 if repaired else 1,
            stdout_ref=str(stdout_path),
            stderr_ref=str(stderr_path),
            stdout_preview=stdout,
            stderr_preview=stderr,
            artifact_refs=[str(stdout_path), str(stderr_path)],
            policy={"allowed": True, "network": "none", "read_only_root": True},
            message="Synthetic fake-runner result.",
        )
        metadata_path = attempt_dir / "sandbox-result.json"
        result.metadata_path = str(metadata_path)
        metadata_path.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        result.artifact_refs.append(str(metadata_path))
        return result


class FixtureMismatchRunner(FakeDockerRunner):
    def run(self, poc, attempt_index=1):
        self.starts.append((attempt_index, poc.script_hash))
        attempt_dir = Path(poc.script_path).parent
        script = Path(poc.script_path).read_text(encoding="utf-8")
        repaired = "fixture_name = 'expected'" in script
        stdout = "PATH_TRAVERSAL_CONFIRMED synthetic-evidence\n" if repaired else ""
        stderr = "" if repaired else "NameError: synthetic fixture name mismatch\n"
        stdout_path = attempt_dir / "stdout.txt"
        stderr_path = attempt_dir / "stderr.txt"
        stdout_path.write_text(stdout, encoding="utf-8")
        stderr_path.write_text(stderr, encoding="utf-8")
        result = SandboxRunResult(
            poc_id=poc.id or "poc",
            finding_id=poc.finding_id,
            attempt_id=f"attempt-{attempt_index}",
            status="completed",
            cwd=str(attempt_dir),
            argv=["python", "/attempt/poc.py"],
            timeout_seconds=10,
            environment={"runner": "docker", "network": "none", "docker_image": "fake-python"},
            exit_code=0 if repaired else 1,
            stdout_ref=str(stdout_path),
            stderr_ref=str(stderr_path),
            stdout_preview=stdout,
            stderr_preview=stderr,
            artifact_refs=[str(stdout_path), str(stderr_path)],
            policy={"allowed": True, "network": "none", "read_only_root": True},
            message="Synthetic fixture-mismatch result.",
        )
        metadata_path = attempt_dir / "sandbox-result.json"
        result.metadata_path = str(metadata_path)
        metadata_path.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        result.artifact_refs.append(str(metadata_path))
        return result


class AlwaysFailDockerRunner(FakeDockerRunner):
    def run(self, poc, attempt_index=1):
        self.starts.append((attempt_index, poc.script_hash))
        attempt_dir = Path(poc.script_path).parent
        stdout_path = attempt_dir / "stdout.txt"
        stderr_path = attempt_dir / "stderr.txt"
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text("NameError: name 'Path' is not defined\n", encoding="utf-8")
        result = SandboxRunResult(
            poc_id=poc.id or "poc",
            finding_id=poc.finding_id,
            attempt_id=f"attempt-{attempt_index}",
            status="completed",
            cwd=str(attempt_dir),
            argv=["python", "/attempt/poc.py"],
            timeout_seconds=10,
            environment={"runner": "docker", "network": "none"},
            exit_code=1,
            stdout_ref=str(stdout_path),
            stderr_ref=str(stderr_path),
            stderr_preview="NameError: name 'Path' is not defined",
            artifact_refs=[str(stdout_path), str(stderr_path)],
            policy={"allowed": True, "network": "none"},
            message="Synthetic persistent harness failure.",
        )
        metadata_path = attempt_dir / "sandbox-result.json"
        result.metadata_path = str(metadata_path)
        metadata_path.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        result.artifact_refs.append(str(metadata_path))
        return result


class EnvironmentFailureRunner(FakeDockerRunner):
    def run(self, poc, attempt_index=1):
        self.starts.append((attempt_index, poc.script_hash))
        attempt_dir = Path(poc.script_path).parent
        result = SandboxRunResult(
            poc_id=poc.id or "poc",
            finding_id=poc.finding_id,
            attempt_id=f"attempt-{attempt_index}",
            status="environment-unavailable",
            cwd=str(attempt_dir),
            argv=[],
            timeout_seconds=10,
            environment={"runner": "docker", "network": "none"},
            message="Synthetic Docker daemon unavailable.",
        )
        metadata_path = attempt_dir / "sandbox-result.json"
        result.metadata_path = str(metadata_path)
        metadata_path.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        result.artifact_refs.append(str(metadata_path))
        return result


class TargetMutatingRunner(FakeDockerRunner):
    def __init__(self, target_root):
        super().__init__()
        self.target_root = Path(target_root)

    def run(self, poc, attempt_index=1):
        result = super().run(poc, attempt_index)
        if result.exit_code == 0:
            (self.target_root / "unexpected-added.txt").write_text("synthetic mutation", encoding="utf-8")
        return result


class FindingScopedMutatingRunner(FakeDockerRunner):
    def __init__(self, target_root, mutating_finding_id):
        super().__init__()
        self.target_root = Path(target_root)
        self.mutating_finding_id = mutating_finding_id

    def run(self, poc, attempt_index=1):
        result = super().run(poc, attempt_index)
        if poc.finding_id == self.mutating_finding_id and result.exit_code == 0:
            (self.target_root / "changed-during-finding-b.txt").write_text(
                "authorized synthetic mutation",
                encoding="utf-8",
            )
        return result


class RejectedMutatingRunner(FakeDockerRunner):
    def __init__(self, target_root):
        super().__init__()
        self.target_root = Path(target_root)

    def run(self, poc, attempt_index=1):
        self.starts.append((attempt_index, poc.script_hash))
        attempt_dir = Path(poc.script_path).parent
        stdout_path = attempt_dir / "stdout.txt"
        stderr_path = attempt_dir / "stderr.txt"
        stdout_path.write_text("PATH_TRAVERSAL_BLOCKED synthetic-contradiction\n", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        (self.target_root / "unexpected-added.txt").write_text("synthetic mutation", encoding="utf-8")
        result = SandboxRunResult(
            poc_id=poc.id or "poc",
            finding_id=poc.finding_id,
            attempt_id=f"attempt-{attempt_index}",
            status="completed",
            cwd=str(attempt_dir),
            argv=["python", "/attempt/poc.py"],
            timeout_seconds=10,
            environment={"runner": "docker", "network": "none"},
            exit_code=0,
            stdout_ref=str(stdout_path),
            stderr_ref=str(stderr_path),
            stdout_preview="PATH_TRAVERSAL_BLOCKED synthetic-contradiction",
            artifact_refs=[str(stdout_path), str(stderr_path)],
            policy={"allowed": True, "network": "none"},
        )
        metadata_path = attempt_dir / "sandbox-result.json"
        result.metadata_path = str(metadata_path)
        metadata_path.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        result.artifact_refs.append(str(metadata_path))
        return result


class FailingLLMClient:
    def __init__(self):
        self.calls = []

    def complete(self, request):
        self.calls.append(request)
        raise LLMProviderError(
            message="Synthetic provider failure",
            error_type="network",
            provider="mock",
            model="synthetic",
            attempts=1,
        )


class MissingImportGenerator:
    generator_id = "synthetic-missing-import-v1"

    def __init__(self, setup_lines=None):
        self.setup_lines = setup_lines or ["fixture_name = 'authorized-synthetic'"]

    def generate(self, finding, metadata, run_dir, attempt_index=1, repair_context=None):
        attempt_dir = Path(run_dir) / "verification" / finding.id / f"attempt-{attempt_index}"
        attempt_dir.mkdir(parents=True, exist_ok=True)
        script_text = "\n".join(
            [
                IMPORT_SLOT_BEGIN,
                IMPORT_SLOT_END,
                SETUP_SLOT_BEGIN,
                *self.setup_lines,
                SETUP_SLOT_END,
                "print(Path.cwd())",
                "print('PATH_TRAVERSAL_CONFIRMED synthetic-evidence')",
            ]
        )
        script_path = attempt_dir / "poc.py"
        script_path.write_text(script_text, encoding="utf-8")
        expected = {
            "kind": "stdout-contains",
            "value": "PATH_TRAVERSAL_CONFIRMED",
            "rejected_value": "PATH_TRAVERSAL_BLOCKED",
        }
        poc = PoCArtifact(
            finding_id=finding.id,
            vulnerability_class="path-traversal",
            generator_id=self.generator_id,
            script_path=str(script_path),
            command_argv=["python", str(script_path)],
            expected_signal=expected,
            safety_profile={"local_only": True, "writes_under_attempt_dir": True},
            dataflow_trace_refs=list(finding.metadata.get("dataflow_trace_refs", [])),
            target_file_refs=[finding.location.path],
            script_hash=sha256_text(script_text),
            attempt_index=attempt_index,
        )
        manifest = build_and_persist_repair_manifest(
            finding_id=finding.id,
            generator_id=self.generator_id,
            script_text=script_text,
            attempt_dir=attempt_dir,
            expected_signal=expected,
        )
        poc.repair_manifest_ref = manifest.metadata_path
        poc.repair_manifest_hash = manifest.manifest_hash
        poc.protected_node_hashes = {item.node_id: item.ast_hash for item in manifest.protected_nodes}
        persist_execution_envelope(poc, attempt_dir)
        poc_path = attempt_dir / "poc.json"
        poc.metadata_path = str(poc_path)
        poc_path.write_text(json.dumps(poc.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        return poc


def synthetic_case(root: Path):
    project = root / "authorized-fixture"
    project.mkdir()
    (project / "app.py").write_text(
        'api_key = "synthetic-source-secret"\ndef read_fixture(name):\n    return name\n',
        encoding="utf-8",
    )
    trace = project / "trace.json"
    trace.write_text(
        json.dumps(
            {
                "vulnerability_class": "path-traversal",
                "language": "python",
                "source": {"path": "app.py", "line": 1},
                "sink": {"path": "app.py", "line": 2},
            }
        ),
        encoding="utf-8",
    )
    metadata = RepositoryMetadata(
        target=AuditTarget(source=str(project), kind="local", path=str(project)),
        root_path=str(project),
        file_tree=["app.py", "trace.json"],
    )
    finding = Finding(
        title="Authorized synthetic repair fixture",
        vulnerability_class="path-traversal",
        severity="medium",
        confidence=0.8,
        location=SourceLocation(path="app.py", start_line=1, end_line=2),
        metadata={"dataflow_status": "complete-flow", "dataflow_trace_refs": [str(trace)]},
    )
    decision = VerificationDecision(
        finding=finding,
        decision="accept",
        reason="Exercise only the synthetic repair state machine.",
        confidence=0.8,
        validation_level="sandbox",
    )
    return metadata, decision


def repair_config():
    config = AuditConfig.default()
    config.sandbox.enabled = True
    config.sandbox.runner = "docker"
    config.runtime_enabled = True
    config.poc_repair.enabled = True
    config.poc_repair.max_repair_attempts = 1
    config.poc_repair.effective_source = "explicit"
    return config


class PoCRepairCoreTests(unittest.TestCase):
    def test_exact_parser_accepts_only_manifest_declared_typed_edits(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = "\n".join([IMPORT_SLOT_BEGIN, IMPORT_SLOT_END, "print('safe')"])
            manifest = build_and_persist_repair_manifest(
                finding_id="F-test",
                generator_id="synthetic",
                script_text=script,
                attempt_dir=tmp,
                expected_signal={"kind": "stdout-contains", "value": "SAFE"},
            )
            parsed = parse_poc_repair_response(
                {
                    "diagnosis": "Missing Path import.",
                    "edits": [{"op": "add_import", "slot_id": "imports", "module": "pathlib", "name": "Path"}],
                    "changes": ["Add Path import."],
                },
                manifest,
            )
            self.assertEqual("add_import", parsed.edits[0].op)
            self.assertTrue(parsed.edit_hash)

            invalid_payloads = [
                {"diagnosis": "x", "edits": [], "changes": ["x"]},
                {"diagnosis": "x", "edits": [{"op": "add_import", "slot_id": "missing", "module": "pathlib"}], "changes": ["x"]},
                {"diagnosis": "x", "edits": [{"op": "add_import", "slot_id": "imports", "module": "subprocess"}], "changes": ["x"]},
                {"diagnosis": "x", "edits": [{"op": "add_import", "slot_id": "imports", "module": "pathlib"}], "changes": ["x"], "verdict": "confirmed"},
                {"diagnosis": "x", "edits": [{"op": "add_import", "slot_id": "imports", "module": "pathlib", "command": "python poc.py"}], "changes": ["x"]},
                {"diagnosis": "x", "edits": "not-a-list", "changes": ["x"]},
                {"diagnosis": "x", "edits": [{"op": "add_import", "slot_id": "imports", "module": "pathlib", "name": ["Path"]}], "changes": ["x"]},
                {"diagnosis": "x", "edits": [{"op": "unknown", "slot_id": "imports", "value": "x"}], "changes": ["x"]},
                {"diagnosis": "x" * 2001, "edits": [{"op": "add_import", "slot_id": "imports", "module": "pathlib"}], "changes": ["x"]},
                {"diagnosis": "x", "edits": [{"op": "add_import", "slot_id": "imports", "module": "pathlib"}, {"op": "add_import", "slot_id": "imports", "module": "os"}], "changes": ["x"]},
                {"diagnosis": "x", "edits": [{"op": "add_import", "slot_id": "imports", "module": "pathlib"}], "changes": [1]},
                {
                    "diagnosis": "Correct diagnosis but wrong provider-shaped fields.",
                    "edits": [
                        {
                            "operation": "add_import",
                            "slot_id": "imports",
                            "value": "from pathlib import Path",
                        }
                    ],
                    "changes": "Added the import.",
                },
            ]
            for payload in invalid_payloads:
                with self.subTest(payload=payload):
                    with self.assertRaises(PoCRepairContractError):
                        parse_poc_repair_response(payload, manifest)

    def test_manifest_reopens_and_trusted_assembly_preserves_protected_nodes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata, decision = synthetic_case(root)
            original = MissingImportGenerator().generate(decision.finding, metadata, root / "run")
            manifest = load_repair_manifest(original.repair_manifest_ref)
            envelope = json.loads(Path(original.immutable_envelope_ref).read_text(encoding="utf-8"))
            self.assertEqual(manifest.manifest_hash, envelope["repair_manifest_hash"])
            self.assertEqual(original.immutable_envelope_hash, envelope["envelope_hash"])
            proposal = parse_poc_repair_response(
                {
                    "diagnosis": "Missing import.",
                    "edits": [{"op": "add_import", "slot_id": "imports", "module": "pathlib", "name": "Path"}],
                    "changes": ["Add import."],
                },
                manifest,
            )
            repaired = TrustedPoCAssembler().assemble(
                original_poc=original,
                manifest=manifest,
                edits=proposal.edits,
                attempt_dir=root / "run" / "verification" / decision.finding.id / "attempt-2",
                attempt_index=2,
            )
            semantic = PoCSemanticIntegrityGate().evaluate(
                original_poc=original,
                candidate_poc=repaired,
                manifest=manifest,
                attempt_index=2,
            )
            safety = PoCSafetyGate().evaluate(poc=repaired, attempt_index=2, repaired=True)
            self.assertTrue(semantic.allowed, semantic.rule_ids)
            self.assertTrue(safety.allowed, safety.rule_ids)
            self.assertNotEqual(original.script_hash, repaired.script_hash)
            self.assertTrue(Path(original.script_path).read_text(encoding="utf-8").startswith(IMPORT_SLOT_BEGIN))

    def test_semantic_and_safety_gates_deny_forgery_and_process_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata, decision = synthetic_case(root)
            original = MissingImportGenerator().generate(decision.finding, metadata, root / "run")
            manifest = load_repair_manifest(original.repair_manifest_ref)
            cases = [
                ("print('PATH_TRAVERSAL_CONFIRMED forged')", "semantic"),
                ("Path('sqli-result.json').write_text('{}')", "semantic"),
                ("baseline_count = 0\nattack_count = 99\nmarker_seen = True", "semantic"),
                ("import subprocess\nsubprocess.run(['echo', 'x'])", "safety"),
                ("import socket\nsocket.socket()", "safety"),
                ("exec('value = 1')", "safety"),
                ("Path('/etc/passwd').write_text('x')", "safety"),
                ("getattr(Path('.'), 'write_text')('x')", "safety"),
                ("installer = 'pip install unsafe-package'", "safety"),
                ("endpoint = 'unix:///var/run/docker.sock'", "safety"),
            ]
            for index, (value, expected_gate) in enumerate(cases, 2):
                with self.subTest(value=value):
                    proposal = parse_poc_repair_response(
                        {
                            "diagnosis": "synthetic adversarial output",
                            "edits": [{"op": "replace_slot", "slot_id": "setup", "value": value}],
                            "changes": ["synthetic change"],
                        },
                        manifest,
                    )
                    repaired = TrustedPoCAssembler().assemble(
                        original_poc=original,
                        manifest=manifest,
                        edits=proposal.edits,
                        attempt_dir=root / "run" / f"case-{index}",
                        attempt_index=index,
                    )
                    semantic = PoCSemanticIntegrityGate().evaluate(
                        original_poc=original,
                        candidate_poc=repaired,
                        manifest=manifest,
                        attempt_index=index,
                    )
                    safety = PoCSafetyGate().evaluate(poc=repaired, attempt_index=index, repaired=True)
                    if expected_gate == "semantic":
                        self.assertFalse(semantic.allowed)
                    else:
                        self.assertTrue(semantic.allowed, semantic.rule_ids)
                        self.assertFalse(safety.allowed)

            safe = parse_poc_repair_response(
                {
                    "diagnosis": "Valid import edit.",
                    "edits": [{"op": "add_import", "slot_id": "imports", "module": "pathlib", "name": "Path"}],
                    "changes": ["Add import."],
                },
                manifest,
            )
            changed = TrustedPoCAssembler().assemble(
                original_poc=original,
                manifest=manifest,
                edits=safe.edits,
                attempt_dir=root / "run" / "protected-change",
                attempt_index=20,
            )
            changed_text = Path(changed.script_path).read_text(encoding="utf-8").replace(
                "print('PATH_TRAVERSAL_CONFIRMED synthetic-evidence')",
                "print('PATH_TRAVERSAL_BLOCKED changed-protected-code')",
            )
            Path(changed.script_path).write_text(changed_text, encoding="utf-8")
            protected_change = PoCSemanticIntegrityGate().evaluate(
                original_poc=original,
                candidate_poc=changed,
                manifest=manifest,
                attempt_index=20,
            )
            self.assertFalse(protected_change.allowed)
            self.assertIn("semantic-protected-node-changed", protected_change.rule_ids)

    def test_closed_loop_repairs_missing_import_with_fake_docker_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata, decision = synthetic_case(root)
            client = RecordingMockLLMClient(
                {
                    "diagnosis": "The synthetic harness is missing pathlib.Path; token=\"synthetic-model-secret\".",
                    "edits": [{"op": "add_import", "slot_id": "imports", "module": "pathlib", "name": "Path"}],
                    "changes": ["Add the allowlisted import."],
                }
            )
            runner = FakeDockerRunner()
            bus = MessageBus("synthetic-run", root / "run" / "messages" / "messages.jsonl")
            engine = VerificationEngine(repair_config(), root / "run", llm_client=client, message_bus=bus)
            engine.generator = MissingImportGenerator()
            engine.runner = runner
            result = engine.verify_and_finalize_single(decision, metadata, level="sandbox")

            self.assertEqual(VerificationStatus.CONFIRMED, result.status)
            self.assertEqual(1, result.repair_attempt_count)
            self.assertEqual(2, len(runner.starts))
            self.assertEqual(1, len(client.calls))
            self.assertTrue(result.integrity_summary["unchanged"])
            self.assertTrue(any(item["stage"] == "trusted-assembly" for item in result.repair_timeline))
            replay = replay_summary(root / "run" / "messages" / "messages.jsonl")
            self.assertEqual(1, replay["repair_lifecycle"]["repair_requests"])
            self.assertEqual(2, replay["repair_lifecycle"]["runner_starts"])
            self.assertEqual(1, replay["repair_lifecycle"]["judge_results"]["confirmed"])

            report = ReportGenerator().build(
                metadata,
                [decision.finding],
                [],
                verification_candidates=[decision.finding],
            )
            report_json = json.loads(ReportGenerator().to_json(report))
            markdown = ReportGenerator().to_markdown(report)
            summary = report_json["verification_candidates"][0]["repair_summary"]
            self.assertEqual(1, summary["attempt_count"])
            self.assertEqual("allowed", summary["semantic_integrity_status"])
            self.assertTrue(summary["integrity"]["unchanged"])
            self.assertIn("PoC Repair Timeline", markdown)
            self.assertNotIn("raw_response", json.dumps(report_json).lower())
            standard_artifacts = [
                *list((root / "run" / "prompts").glob("*.json")),
                *list((root / "run" / "llm").glob("*.json")),
                *list((root / "run" / "verification").rglob("repair-record*.json")),
            ]
            persisted = "\n".join(path.read_text(encoding="utf-8") for path in standard_artifacts)
            self.assertNotIn("synthetic-source-secret", persisted)
            self.assertNotIn("synthetic-model-secret", persisted)

    def test_nontrivial_target_derived_setup_slot_repair_is_grounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata, decision = synthetic_case(root)
            client = RecordingMockLLMClient(
                {
                    "diagnosis": "The synthetic fixture name does not match the expected target-derived name.",
                    "edits": [{"op": "replace_slot", "slot_id": "setup", "value": "fixture_name = 'expected'"}],
                    "changes": ["Align the declared setup slot with the synthetic target fixture name."],
                }
            )
            runner = FixtureMismatchRunner()
            engine = VerificationEngine(repair_config(), root / "run", llm_client=client)
            engine.generator = MissingImportGenerator(setup_lines=["fixture_name = 'wrong'"])
            engine.runner = runner
            result = engine.verify_and_finalize_single(decision, metadata, level="sandbox")
            self.assertEqual(VerificationStatus.CONFIRMED, result.status)
            self.assertEqual(2, len(runner.starts))
            self.assertTrue(result.integrity_summary["unchanged"])
            assembled = [item for item in result.repair_timeline if item["stage"] == "trusted-assembly"]
            self.assertIn("Align the declared setup slot", assembled[0]["changes"][0])

    def test_repair_disabled_and_policy_denial_never_start_second_container(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata, decision = synthetic_case(root)
            disabled = repair_config()
            disabled.poc_repair.enabled = False
            client = RecordingMockLLMClient({})
            runner = FakeDockerRunner()
            engine = VerificationEngine(disabled, root / "disabled-run", llm_client=client)
            engine.generator = MissingImportGenerator()
            engine.runner = runner
            result = engine.verify_and_finalize_single(decision, metadata, level="sandbox")
            self.assertEqual(VerificationStatus.MANUAL_REQUIRED, result.status)
            self.assertEqual("repair-disabled", result.final_stop_reason)
            self.assertEqual(1, len(runner.starts))
            self.assertEqual(0, len(client.calls))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata, decision = synthetic_case(root)
            client = RecordingMockLLMClient(
                {
                    "diagnosis": "Try to forge evidence.",
                    "edits": [{"op": "replace_slot", "slot_id": "setup", "value": "print('PATH_TRAVERSAL_CONFIRMED forged')"}],
                    "changes": ["forged marker"],
                }
            )
            runner = FixtureMismatchRunner()
            engine = VerificationEngine(repair_config(), root / "denied-run", llm_client=client)
            engine.generator = MissingImportGenerator(setup_lines=["fixture_name = 'wrong'"])
            engine.runner = runner
            result = engine.verify_and_finalize_single(decision, metadata, level="sandbox")
            self.assertEqual(VerificationStatus.MANUAL_REQUIRED, result.status)
            self.assertEqual("semantic-integrity-denied", result.final_stop_reason)
            self.assertEqual(1, len(runner.starts))

    def test_duplicate_budget_environment_and_provider_stops_are_monotonic(self):
        payload = {
            "diagnosis": "The synthetic harness is missing pathlib.Path.",
            "edits": [{"op": "add_import", "slot_id": "imports", "module": "pathlib", "name": "Path"}],
            "changes": ["Add import."],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata, decision = synthetic_case(root)
            config = repair_config()
            config.poc_repair.max_repair_attempts = 0
            client = RecordingMockLLMClient(payload)
            runner = AlwaysFailDockerRunner()
            engine = VerificationEngine(config, root / "budget-zero", llm_client=client)
            engine.generator = MissingImportGenerator()
            engine.runner = runner
            result = engine.verify(decision, metadata, level="sandbox")
            self.assertEqual("repair-budget-exhausted", result.final_stop_reason)
            self.assertEqual(1, len(runner.starts))
            self.assertEqual(0, len(client.calls))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata, decision = synthetic_case(root)
            config = repair_config()
            config.poc_repair.max_repair_attempts = 2
            client = RecordingMockLLMClient(payload)
            runner = AlwaysFailDockerRunner()
            engine = VerificationEngine(config, root / "duplicate", llm_client=client)
            engine.generator = MissingImportGenerator()
            engine.runner = runner
            result = engine.verify(decision, metadata, level="sandbox")
            self.assertEqual("duplicate-edit", result.final_stop_reason)
            self.assertEqual(2, len(runner.starts))
            self.assertEqual(2, len(client.calls))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata, decision = synthetic_case(root)
            client = RecordingMockLLMClient(payload)
            runner = EnvironmentFailureRunner()
            engine = VerificationEngine(repair_config(), root / "environment", llm_client=client)
            engine.generator = MissingImportGenerator()
            engine.runner = runner
            result = engine.verify(decision, metadata, level="sandbox")
            self.assertEqual("failure-not-repairable", result.final_stop_reason)
            self.assertEqual("environment-error", result.classifications[-1]["failure_class"])
            self.assertEqual(0, len(client.calls))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata, decision = synthetic_case(root)
            client = FailingLLMClient()
            runner = AlwaysFailDockerRunner()
            engine = VerificationEngine(repair_config(), root / "provider", llm_client=client)
            engine.generator = MissingImportGenerator()
            engine.runner = runner
            result = engine.verify(decision, metadata, level="sandbox")
            self.assertEqual("provider-failure", result.final_stop_reason)
            self.assertEqual("harness-error", result.classifications[-1]["failure_class"])
            self.assertEqual(1, len(client.calls))

    def test_target_integrity_downgrades_confirmation_and_preserves_rejection(self):
        payload = {
            "diagnosis": "The synthetic harness is missing pathlib.Path.",
            "edits": [{"op": "add_import", "slot_id": "imports", "module": "pathlib", "name": "Path"}],
            "changes": ["Add import."],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata, decision = synthetic_case(root)
            runner = TargetMutatingRunner(metadata.root_path)
            engine = VerificationEngine(repair_config(), root / "run", llm_client=RecordingMockLLMClient(payload))
            engine.generator = MissingImportGenerator()
            engine.runner = runner
            result = engine.verify_and_finalize_single(decision, metadata, level="sandbox")
            self.assertEqual(VerificationStatus.MANUAL_REQUIRED, result.status)
            self.assertEqual("confirmed", result.provisional_status)
            self.assertEqual("target-integrity-changed", result.final_stop_reason)
            self.assertFalse(result.integrity_summary["unchanged"])
            self.assertIn("unexpected-added.txt", result.integrity_summary["added_files"])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata, decision = synthetic_case(root)
            runner = RejectedMutatingRunner(metadata.root_path)
            config = repair_config()
            config.poc_repair.enabled = False
            engine = VerificationEngine(config, root / "run")
            engine.generator = MissingImportGenerator()
            engine.runner = runner
            result = engine.verify_and_finalize_single(decision, metadata, level="sandbox")
            self.assertEqual(VerificationStatus.REJECTED, result.status)
            self.assertEqual("rejected", result.provisional_status)
            self.assertEqual("target-integrity-changed", result.final_stop_reason)
            self.assertIn("integrity changed", result.verification_reason.lower())

    def test_run_level_integrity_finalization_downgrades_all_provisional_confirmations(self):
        payload = {
            "diagnosis": "The synthetic harness is missing pathlib.Path.",
            "edits": [{"op": "add_import", "slot_id": "imports", "module": "pathlib", "name": "Path"}],
            "changes": ["Add import."],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata, decision_a = synthetic_case(root)
            finding_b = Finding(
                title="Authorized synthetic repair fixture B",
                vulnerability_class="path-traversal",
                severity="medium",
                confidence=0.8,
                location=SourceLocation(path="app.py", start_line=2, end_line=2),
                metadata={
                    "dataflow_status": "complete-flow",
                    "dataflow_trace_refs": list(decision_a.finding.metadata["dataflow_trace_refs"]),
                },
            )
            decision_b = VerificationDecision(
                finding=finding_b,
                decision="accept",
                reason="Exercise the second synthetic provisional confirmation.",
                confidence=0.8,
                validation_level="sandbox",
            )
            run_dir = root / "run"
            bus = MessageBus("synthetic-multi-finding-run", run_dir / "messages" / "messages.jsonl")
            engine = VerificationEngine(
                repair_config(),
                run_dir,
                llm_client=RecordingMockLLMClient(payload),
                message_bus=bus,
            )
            engine.generator = MissingImportGenerator()
            engine.runner = FindingScopedMutatingRunner(metadata.root_path, finding_b.id)

            engine.begin_validation_phase(metadata)
            provisional_a = engine.verify(decision_a, metadata, level="sandbox")
            provisional_b = engine.verify(decision_b, metadata, level="sandbox")

            self.assertEqual(VerificationStatus.CONFIRMED, provisional_a.provisional_status)
            self.assertEqual(VerificationStatus.CONFIRMED, provisional_b.provisional_status)
            self.assertIsNone(provisional_a.final_status)
            self.assertIsNone(provisional_b.final_status)
            self.assertIsNone(decision_a.finding.verification_status)
            self.assertIsNone(decision_b.finding.verification_status)

            finalized = engine.finalize_validation_phase(
                metadata,
                [
                    (decision_a.finding, provisional_a),
                    (decision_b.finding, provisional_b),
                ],
            )

            self.assertEqual(
                [VerificationStatus.MANUAL_REQUIRED, VerificationStatus.MANUAL_REQUIRED],
                [result.final_status for result in finalized],
            )
            self.assertEqual(
                [VerificationStatus.MANUAL_REQUIRED, VerificationStatus.MANUAL_REQUIRED],
                [decision_a.finding.verification_status, decision_b.finding.verification_status],
            )
            self.assertEqual(
                finalized[0].integrity_summary["comparison_ref"],
                finalized[1].integrity_summary["comparison_ref"],
            )
            self.assertIn("changed-during-finding-b.txt", finalized[0].integrity_summary["added_files"])
            self.assertEqual(1, len(list((run_dir / "verification").glob("target-manifest-before*.json"))))
            self.assertEqual(1, len(list((run_dir / "verification").glob("target-manifest-after*.json"))))
            replay = replay_summary(run_dir / "messages" / "messages.jsonl")
            integrity_events = [
                event
                for event in replay["repair_lifecycle"]["events"]
                if event["type"] == "poc.target-integrity"
            ]
            self.assertEqual(1, len(integrity_events))
            self.assertEqual(1, replay["repair_lifecycle"]["target_integrity_changes"])

    def test_classifier_target_manifest_and_credential_redaction_fail_closed(self):
        classifier = PoCFailureClassifier()
        environment = SandboxRunResult(
            poc_id="poc",
            finding_id="F-test",
            attempt_id="attempt-1",
            status="environment-unavailable",
            cwd=".",
            argv=[],
            timeout_seconds=1,
            message="Docker daemon unavailable",
        )
        classification = classifier.classify(
            finding_id="F-test",
            attempt_index=1,
            stage="runner",
            sandbox_result=environment,
            compatible_slot_ids=["imports"],
        )
        self.assertEqual(PoCFailureClass.ENVIRONMENT_ERROR, classification.failure_class)
        self.assertFalse(classification.eligible)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.txt").write_text("one", encoding="utf-8")
            (root / "removed.txt").write_text("remove", encoding="utf-8")
            before = build_target_manifest(root, "before")
            (root / "a.txt").write_text("two", encoding="utf-8")
            (root / "b.txt").write_text("new", encoding="utf-8")
            (root / "removed.txt").unlink()
            after = build_target_manifest(root, "after")
            comparison = compare_target_manifests(before, after)
            self.assertFalse(comparison.unchanged)
            self.assertEqual(["a.txt"], comparison.changed_files)
            self.assertEqual(["b.txt"], comparison.added_files)
            self.assertEqual(["removed.txt"], comparison.removed_files)

        redacted = redact_text('password = "synthetic-secret" token="abc123456789xyz" sk-exampletoken123456')
        self.assertIn(REDACTION_MARKER, redacted)
        self.assertNotIn("synthetic-secret", redacted)
        self.assertNotIn("abc123456789xyz", redacted)

    def test_local_runner_redacts_credential_shaped_stdout_and_stderr_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attempt = root / "run" / "verification" / "F-redact" / "attempt-1"
            attempt.mkdir(parents=True)
            script = attempt / "poc.py"
            script.write_text(
                'print(\'password="synthetic-stdout-secret"\')\n'
                'print(\'token="synthetic-stderr-secret"\', file=__import__("sys").stderr)\n',
                encoding="utf-8",
            )
            poc = PoCArtifact(
                finding_id="F-redact",
                vulnerability_class="path-traversal",
                generator_id="synthetic-redaction",
                script_path=str(script),
                command_argv=[sys.executable, str(script)],
                expected_signal={"kind": "stdout-contains", "value": "never"},
            )
            result = LocalSandboxRunner(AuditConfig.default(), root / "run").run(poc)
            persisted = Path(result.stdout_ref).read_text(encoding="utf-8") + Path(result.stderr_ref).read_text(encoding="utf-8")
            self.assertIn(REDACTION_MARKER, persisted)
            self.assertNotIn("synthetic-stdout-secret", persisted)
            self.assertNotIn("synthetic-stderr-secret", persisted)

    def test_repair_configuration_defaults_range_and_guarded_legacy_migration(self):
        default = AuditConfig.default()
        self.assertFalse(default.poc_repair.enabled)
        self.assertEqual(2, default.poc_repair.total_execution_attempts)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy_off = root / "legacy-off.json"
            legacy_off.write_text(
                json.dumps({"llm_decisions": {"enabled": False, "repair_enabled": True, "max_repair_attempts": 2}}),
                encoding="utf-8",
            )
            config = AuditConfig.from_json(legacy_off)
            self.assertFalse(config.poc_repair.enabled)
            self.assertEqual("default", config.poc_repair.effective_source)

            legacy_on = root / "legacy-on.json"
            legacy_on.write_text(
                json.dumps({"llm_decisions": {"enabled": True, "repair_enabled": True, "max_repair_attempts": 2}}),
                encoding="utf-8",
            )
            config = AuditConfig.from_json(legacy_on)
            self.assertTrue(config.poc_repair.enabled)
            self.assertEqual("legacy", config.poc_repair.effective_source)
            self.assertEqual(2, config.poc_repair.max_repair_attempts)

            explicit = root / "explicit.json"
            explicit.write_text(
                json.dumps(
                    {
                        "llm_decisions": {"enabled": True, "repair_enabled": True, "max_repair_attempts": 2},
                        "poc_repair": {"enabled": False, "max_repair_attempts": 0},
                    }
                ),
                encoding="utf-8",
            )
            config = AuditConfig.from_json(explicit)
            self.assertFalse(config.poc_repair.enabled)
            self.assertEqual("explicit", config.poc_repair.effective_source)
            self.assertEqual(0, config.poc_repair.max_repair_attempts)

            invalid = root / "invalid.json"
            invalid.write_text(json.dumps({"poc_repair": {"enabled": True, "max_repair_attempts": 3}}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "0..2"):
                AuditConfig.from_json(invalid)


if __name__ == "__main__":
    unittest.main()
