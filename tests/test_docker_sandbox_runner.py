import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from audit_agent.config import AuditConfig
from audit_agent.message_bus import MessageBus, replay_summary
from audit_agent.models import Finding, PoCArtifact, SourceLocation, VerificationDecision
from audit_agent.reporting import ReportGenerator
from audit_agent.repository import analyze_target
from audit_agent.verification import (
    DockerSandboxRunner,
    VerificationEngine,
    VerificationJudge,
    VerificationStatus,
    artifact_refs_under_run,
    create_sandbox_runner,
)


def create_minimal_project(root: Path) -> Path:
    project = root / "project"
    project.mkdir()
    (project / "app.py").write_text("def read_file(name):\n    return name\n", encoding="utf-8")
    return project


def write_fake_docker(root: Path, mode: str = "success") -> Path:
    log_path = root / "docker-args.jsonl"
    fake_py = root / "fake_docker.py"
    fake_py.write_text(
        "\n".join(
            [
                "import json, os, sys",
                f"MODE = {mode!r}",
                f"LOG = {str(log_path)!r}",
                "args = sys.argv[1:]",
                "with open(LOG, 'a', encoding='utf-8') as handle:",
                "    handle.write(json.dumps({'args': args, 'docker_host': os.environ.get('DOCKER_HOST', '')}) + '\\n')",
                "if args[:2] == ['--context', 'desktop-linux']:",
                "    args = args[2:]",
                "if args[:1] == ['info']:",
                "    if MODE == 'daemon_unavailable':",
                "        print('permission denied while trying to connect to docker', file=sys.stderr)",
                "        sys.exit(1)",
                "    print('29.6.1')",
                "    sys.exit(0)",
                "if args[:2] == ['image', 'inspect']:",
                "    if MODE == 'missing_image':",
                "        print('Error response from daemon: No such image: ' + (args[2] if len(args) > 2 else '<missing>'), file=sys.stderr)",
                "        sys.exit(1)",
                "    print('[]')",
                "    sys.exit(0)",
                "if args[:1] == ['run']:",
                "    if MODE == 'run_failure':",
                "        print('container startup failed', file=sys.stderr)",
                "        sys.exit(125)",
                "    print('fake docker stdout')",
                "    print('fake docker stderr', file=sys.stderr)",
                "    sys.exit(0)",
                "print('unknown fake docker command: ' + ' '.join(args), file=sys.stderr)",
                "sys.exit(2)",
            ]
        ),
        encoding="utf-8",
    )
    if os.name == "nt":
        wrapper = root / "docker.cmd"
        wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{fake_py}" %*\r\n', encoding="utf-8")
    else:
        wrapper = root / "docker"
        wrapper.write_text(f'#!/bin/sh\n"{sys.executable}" "{fake_py}" "$@"\n', encoding="utf-8")
        wrapper.chmod(0o755)
    return wrapper


def read_fake_docker_args(fake_binary: Path) -> list[list[str]]:
    log_path = fake_binary.parent / "docker-args.jsonl"
    if not log_path.exists():
        return []
    calls = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [call["args"] if isinstance(call, dict) else call for call in calls]


def read_fake_docker_calls(fake_binary: Path) -> list[dict]:
    log_path = fake_binary.parent / "docker-args.jsonl"
    if not log_path.exists():
        return []
    calls = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        if isinstance(payload, list):
            payload = {"args": payload, "docker_host": ""}
        calls.append(payload)
    return calls


def make_poc(run_dir: Path, finding_id: str = "F-docker", vulnerability_class: str = "path-traversal") -> PoCArtifact:
    attempt_dir = run_dir / "verification" / finding_id / "attempt-1"
    attempt_dir.mkdir(parents=True, exist_ok=True)
    script = attempt_dir / "poc.py"
    script.write_text("print('PATH_TRAVERSAL_CONFIRMED')\n", encoding="utf-8")
    poc = PoCArtifact(
        finding_id=finding_id,
        vulnerability_class=vulnerability_class,
        generator_id="test-docker-poc",
        script_path=str(script),
        command_argv=[sys.executable, str(script)],
        expected_signal={
            "kind": "stdout-contains",
            "value": "PATH_TRAVERSAL_CONFIRMED",
        },
        safety_profile={"local_only": True, "writes_under_attempt_dir": True},
    )
    poc_path = attempt_dir / "poc.json"
    poc.metadata_path = str(poc_path)
    poc_path.write_text(json.dumps(poc.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return poc


class StaticPathPoCGenerator:
    generator_id = "test-static-path-poc"

    def __init__(self, vulnerability_class: str = "path-traversal") -> None:
        self.vulnerability_class = vulnerability_class

    def generate(self, finding, metadata, run_dir, attempt_index=1, repair_context=None):
        return make_poc(Path(run_dir), finding.id, self.vulnerability_class)


def accepted_path_decision() -> VerificationDecision:
    finding = Finding(
        title="Docker runner candidate",
        vulnerability_class="path-traversal",
        severity="high",
        confidence=0.9,
        location=SourceLocation(path="app.py", start_line=1, end_line=1),
        metadata={"dataflow_status": "complete-flow"},
    )
    return VerificationDecision(
        finding=finding,
        decision="accept",
        reason="exercise docker runner",
        confidence=0.9,
        validation_level="sandbox",
    )


class DockerSandboxRunnerTests(unittest.TestCase):
    def test_sandbox_config_defaults_and_factory_select_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = AuditConfig.default()

            self.assertEqual("local", config.sandbox.runner)
            self.assertEqual("docker", config.sandbox.docker_binary)
            self.assertEqual("python:3.12-slim", config.sandbox.docker_image)
            self.assertIsNone(config.sandbox.docker_context)
            self.assertIsNone(config.sandbox.docker_host)
            self.assertEqual("none", config.sandbox.network)
            self.assertTrue(config.sandbox.memory_limit)
            self.assertTrue(config.sandbox.cpu_limit)
            self.assertTrue(config.sandbox.pids_limit)
            self.assertEqual("local", create_sandbox_runner(config, Path(tmp)).runner_type)

            config.sandbox.runner = "docker"
            self.assertEqual("docker", create_sandbox_runner(config, Path(tmp)).runner_type)

    def test_docker_runner_uses_explicit_context_for_all_cli_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_docker = write_fake_docker(root, mode="success")
            run_dir = root / "run"
            config = AuditConfig.default()
            config.sandbox.runner = "docker"
            config.sandbox.docker_binary = str(fake_docker)
            config.sandbox.docker_context = "desktop-linux"
            config.sandbox.docker_host = "npipe:////./pipe/ignored"
            poc = make_poc(run_dir)

            result = DockerSandboxRunner(config, run_dir).run(poc)

            self.assertEqual("completed", result.status)
            self.assertEqual("desktop-linux", result.environment["docker_context"])
            self.assertEqual("", result.environment.get("docker_host", ""))
            for call in read_fake_docker_calls(fake_docker):
                self.assertEqual(["--context", "desktop-linux"], call["args"][:2])
                self.assertEqual("", call["docker_host"])

    def test_docker_runner_uses_explicit_host_env_without_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_docker = write_fake_docker(root, mode="success")
            run_dir = root / "run"
            config = AuditConfig.default()
            config.sandbox.runner = "docker"
            config.sandbox.docker_binary = str(fake_docker)
            config.sandbox.docker_host = "npipe:////./pipe/dockerDesktopLinuxEngine"
            poc = make_poc(run_dir)

            result = DockerSandboxRunner(config, run_dir).run(poc)

            self.assertEqual("completed", result.status)
            self.assertEqual("npipe:////./pipe/dockerDesktopLinuxEngine", result.environment["docker_host"])
            calls = read_fake_docker_calls(fake_docker)
            self.assertTrue(calls)
            self.assertTrue(all(call["docker_host"] == "npipe:////./pipe/dockerDesktopLinuxEngine" for call in calls))
            self.assertTrue(all(call["args"][:1] != ["--context"] for call in calls))

    def test_docker_runner_uses_secure_argv_and_records_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_docker = write_fake_docker(root, mode="success")
            run_dir = root / "run"
            config = AuditConfig.default()
            config.sandbox.runner = "docker"
            config.sandbox.docker_binary = str(fake_docker)
            config.sandbox.docker_image = "python:3.12-slim"
            config.sandbox.network = "none"
            poc = make_poc(run_dir)

            result = DockerSandboxRunner(config, run_dir).run(poc)

            self.assertEqual("completed", result.status)
            self.assertEqual("docker", result.environment["runner"])
            self.assertEqual("python:3.12-slim", result.environment["docker_image"])
            self.assertEqual(str(fake_docker), result.environment["docker_binary"])
            self.assertEqual("none", result.policy["network"])
            self.assertFalse(result.policy["privileged"])
            self.assertTrue(result.policy["read_only_root"])
            self.assertEqual(["ALL"], result.policy["cap_drop"])
            self.assertTrue(result.policy["no_new_privileges"])
            self.assertTrue(artifact_refs_under_run(result.artifact_refs, run_dir))

            docker_calls = read_fake_docker_args(fake_docker)
            run_calls = [args for args in docker_calls if args and args[0] == "run"]
            self.assertEqual(1, len(run_calls))
            run_argv = run_calls[0]
            self.assertIn("--network", run_argv)
            self.assertIn("none", run_argv)
            self.assertIn("--read-only", run_argv)
            self.assertIn("--cap-drop", run_argv)
            self.assertIn("ALL", run_argv)
            self.assertIn("--security-opt", run_argv)
            self.assertIn("no-new-privileges", run_argv)
            self.assertIn("--pids-limit", run_argv)
            self.assertIn("--memory", run_argv)
            self.assertIn("--cpus", run_argv)
            self.assertIn("--workdir", run_argv)
            self.assertIn("/attempt", run_argv)
            self.assertNotIn("--privileged", run_argv)
            self.assertIn("python:3.12-slim", run_argv)
            self.assertIn("python", run_argv)
            self.assertIn("/attempt/poc.py", run_argv)

    def test_missing_docker_image_degrades_to_manual_required_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_docker = write_fake_docker(root, mode="missing_image")
            run_dir = root / "run"
            config = AuditConfig.default()
            config.sandbox.runner = "docker"
            config.sandbox.docker_binary = str(fake_docker)
            config.sandbox.docker_image = "python:3.12-slim"
            poc = make_poc(run_dir)

            sandbox_result = DockerSandboxRunner(config, run_dir).run(poc)
            judge = VerificationJudge().judge(poc, sandbox_result)

            self.assertEqual("image-unavailable", sandbox_result.status)
            self.assertEqual("docker", sandbox_result.environment["runner"])
            self.assertIn("docker pull python:3.12-slim", sandbox_result.message)
            self.assertTrue(Path(sandbox_result.metadata_path or "").exists())
            self.assertEqual(VerificationStatus.MANUAL_REQUIRED, judge.status)
            self.assertNotEqual(VerificationStatus.CONFIRMED, judge.status)

    def test_docker_unavailable_closed_loop_returns_manual_required_with_persisted_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = create_minimal_project(root)
            metadata = analyze_target(str(project))
            config = AuditConfig.default()
            config.sandbox.enabled = True
            config.sandbox.runner = "docker"
            config.sandbox.docker_binary = str(root / "missing-docker")
            decision = accepted_path_decision()
            engine = VerificationEngine(config, run_dir=root / "run")
            engine.generator = StaticPathPoCGenerator()

            result = engine.verify(decision, metadata, level="sandbox")

            self.assertEqual(VerificationStatus.MANUAL_REQUIRED, result.status)
            self.assertEqual(0, result.exit_code or 0)
            self.assertTrue(result.sandbox_result_refs)
            sandbox_payload = json.loads(Path(result.sandbox_result_refs[0]).read_text(encoding="utf-8"))
            self.assertEqual("docker", sandbox_payload["environment"]["runner"])
            self.assertIn("docker", result.reason.lower())

    def test_docker_run_failure_cannot_confirm_closed_loop(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_docker = write_fake_docker(root, mode="run_failure")
            project = create_minimal_project(root)
            metadata = analyze_target(str(project))
            config = AuditConfig.default()
            config.sandbox.enabled = True
            config.sandbox.runner = "docker"
            config.sandbox.docker_binary = str(fake_docker)
            decision = accepted_path_decision()
            engine = VerificationEngine(config, run_dir=root / "run")
            engine.generator = StaticPathPoCGenerator()

            result = engine.verify(decision, metadata, level="sandbox")

            self.assertEqual(VerificationStatus.MANUAL_REQUIRED, result.status)
            self.assertNotEqual(VerificationStatus.CONFIRMED, result.status)
            self.assertIn("docker", result.reason.lower())
            self.assertIn("container startup failed", result.stderr_preview)

    def test_docker_sqli_judge_requires_structured_result_not_zero_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stdout = root / "stdout.txt"
            stderr = root / "stderr.txt"
            stdout.write_text("SQLI_CONFIRMED text without JSON", encoding="utf-8")
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
                "environment": {"runner": "docker", "docker_image": "python:3.12-slim"},
            }

            outcome = VerificationJudge().judge(poc, sandbox_result)

            self.assertEqual(VerificationStatus.MANUAL_REQUIRED, outcome.status)
            self.assertNotEqual(VerificationStatus.CONFIRMED, outcome.status)
            self.assertIn("sqli-result.json", outcome.reason)

    def test_report_markdown_and_replay_expose_docker_runner_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = create_minimal_project(root)
            metadata = analyze_target(str(project))
            finding = Finding(
                title="Docker-backed candidate",
                vulnerability_class="path-traversal",
                severity="high",
                confidence=0.8,
                location=SourceLocation(path="app.py", start_line=1, end_line=1),
                metadata={
                    "validation_summary": {
                        "level": "sandbox",
                        "verification_status": "manual-required",
                        "verification_reason": "Docker daemon is unavailable.",
                        "environment": {
                            "runner": "docker",
                            "docker_image": "python:3.12-slim",
                        },
                        "sandbox_result_refs": [str(root / "sandbox-result.json")],
                        "attempt_refs": [str(root / "verification-attempt.json")],
                        "stdout_preview": "",
                        "stderr_preview": "permission denied",
                    }
                },
            )
            finding.verifier_decision = "accept"
            finding.verification_status = VerificationStatus.MANUAL_REQUIRED
            finding.verification_reason = "Docker daemon is unavailable."

            report = ReportGenerator().build(metadata, [], [], verification_candidates=[finding])
            markdown = ReportGenerator().to_markdown(report)

            self.assertIn("Runner: docker", markdown)
            self.assertIn("Docker image: python:3.12-slim", markdown)
            self.assertEqual(1, report.executive_summary["manual_required_count"])

            bus = MessageBus("run-1", root / "messages.jsonl")
            bus.publish(
                "validation",
                "verification",
                "verification.attempt",
                {
                    "finding_id": finding.id,
                    "status": "manual-required",
                    "level": "sandbox",
                    "runner": "docker",
                    "docker_image": "python:3.12-slim",
                    "blocking_reason": "Docker daemon is unavailable.",
                },
            )
            replay = replay_summary(root / "messages.jsonl")

            self.assertEqual(1, replay["sandbox_lifecycle"]["attempts"])
            self.assertEqual(1, replay["sandbox_lifecycle"]["runner_counts"]["docker"])
            self.assertEqual(1, replay["sandbox_lifecycle"]["docker_images"]["python:3.12-slim"])
            self.assertEqual(1, replay["sandbox_lifecycle"]["environment_failures"])

    def test_live_docker_runner_executes_path_poc_when_enabled(self):
        if os.environ.get("AUDIT_AGENT_RUN_DOCKER_TESTS") != "1":
            self.skipTest("Set AUDIT_AGENT_RUN_DOCKER_TESTS=1 to run live Docker smoke tests.")
        if not shutil.which("docker"):
            self.skipTest("Docker CLI is not available.")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "run"
            config = AuditConfig.default()
            config.sandbox.runner = "docker"
            config.sandbox.docker_image = os.environ.get("AUDIT_AGENT_DOCKER_IMAGE", "python:3.12-slim")
            poc = make_poc(run_dir)

            result = DockerSandboxRunner(config, run_dir).run(poc)

            if result.status == "image-unavailable":
                self.skipTest(result.message)
            self.assertEqual("docker", result.environment["runner"])
            self.assertEqual("completed", result.status)
            self.assertEqual(0, result.exit_code)


if __name__ == "__main__":
    unittest.main()
