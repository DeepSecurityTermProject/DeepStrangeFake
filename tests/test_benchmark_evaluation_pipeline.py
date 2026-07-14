import json
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from audit_agent.benchmark import BenchmarkConfig, build_engine_identity, load_corpus, readiness_for_profile, run_benchmark
from audit_agent.benchmark_acquisition import CommandResult, RepositoryAcquirer, normalize_source_identity
from audit_agent.benchmark_evaluation import (
    AdjudicationRecord,
    FindingMatcher,
    TruthRecord,
    compare_reports,
    aggregate_repetitions,
    compute_macro_metrics,
    compute_metrics,
    finding_group_id,
    promotion_readiness,
    render_markdown,
)
from audit_agent.benchmark_models import (
    AcquisitionRecord,
    BenchmarkCase,
    CaseState,
    RunResourceSummary,
    canonical_digest,
    contained_path,
)
from audit_agent.benchmark_runtime import (
    AtomicJsonStore,
    BenchmarkCoordinator,
    DockerLabelCleaner,
    ProcessResult,
    ProcessTreeRunner,
    build_child_audit_config,
    validate_case_completion,
)
from audit_agent.models import BenchmarkTarget
from audit_agent.models import LLMRequest
from audit_agent.llm import BudgetedLLMClient, LLMBudgetExceeded, MockLLMClient
from audit_agent.redaction import redact_secrets
from audit_agent.resource_summary import build_run_resource_summary
from audit_agent.config import AuditConfig
from audit_agent.repository import analyze_target
from audit_agent.tool_protocol import ToolBudget
from audit_agent.verification import DockerSandboxRunner
from audit_agent.cli import main as cli_main


ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "benchmarks" / "corpus.v1.json"
TRUTH = ROOT / "benchmarks" / "truth.v1.json"
ADJUDICATIONS = ROOT / "benchmarks" / "adjudications.v1.json"


class RecordingGit:
    def __init__(self, responses=None):
        self.calls = []
        self.responses = responses or {}

    def __call__(self, argv, cwd, env, timeout):
        self.calls.append({"argv": list(argv), "cwd": cwd, "env": env, "timeout": timeout})
        key = tuple(argv[-3:])
        return self.responses.get(key, CommandResult(list(argv), 0, "", ""))


class RecordingProcessRunner:
    def __init__(self, result=None):
        self.calls = []
        self.result = result or ProcessResult(0, "", "", False, {"success": True})

    def run(self, argv, **kwargs):
        self.calls.append({"argv": list(argv), **kwargs})
        return self.result


class RecordingDockerCleaner(DockerLabelCleaner):
    def __init__(self):
        super().__init__()
        self.calls = []

    def cleanup(self, benchmark_id, run_id, case_id):
        self.calls.append((benchmark_id, run_id, case_id))
        return super().cleanup(benchmark_id, run_id, case_id)


class BenchmarkPipelineTests(unittest.TestCase):
    def test_legacy_remote_download_skip_is_not_completed_and_values_are_null(self):
        from audit_agent.benchmark import BenchmarkRunner

        target = BenchmarkTarget(name="remote", source="https://github.com/example/example.git")
        summary = BenchmarkRunner([target]).run(
            lambda _: {
                "candidate_count": 0,
                "validated_count": 0,
                "rejected_count": 0,
                "setup_status": "remote-download-skipped",
            }
        )

        self.assertEqual(summary.completed_projects, 0)
        self.assertEqual(summary.failed_projects, 1)
        result = summary.project_results[0]
        self.assertEqual(result["status"], "not-run")
        self.assertIsNone(result["metrics"]["candidate_count"])
        self.assertEqual(result["metrics"]["unavailable_reason"], "remote-download-skipped")

    def test_strict_corpus_models_and_cardinality(self):
        corpus = load_corpus(CORPUS)
        profile, cases = corpus.select("fixture")
        self.assertEqual(profile.kind, "fixture")
        self.assertEqual(len(cases), 3)
        self.assertEqual(len({case.project_id for case in cases}), 2)
        self.assertEqual(canonical_digest(corpus.to_dict()), corpus.digest)
        with self.assertRaises(ValueError):
            BenchmarkCase.from_dict({**cases[0].to_dict(), "unknown": True})
        with self.assertRaises(ValueError):
            contained_path(ROOT / "benchmarks", "..", "outside")

    def test_effective_case_config_enforces_all_declared_limits_and_docker_runner(self):
        corpus = load_corpus(CORPUS)
        _, cases = corpus.select("fixture")
        case = BenchmarkCase.from_dict(
            {
                **cases[0].to_dict(),
                "validation_level": "sandbox",
                "budgets": {"llm_requests": 2, "llm_tokens": 100, "tool_calls": 3, "docker_starts": 1, "repair_attempts": 1},
                "safety": {**cases[0].safety, "docker": True, "secret_env_names": ["LLM_API_KEY"]},
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            coordinator = BenchmarkCoordinator(
                corpus, profile_id="fixture", case_ids=[case.case_id], output_root=root / "runs",
                cache_root=root / "cache", allow_docker=True,
                engine_identity={"provider": "openai-compatible", "model": "synthetic-model"},
            )
            effective = coordinator._effective_case_config(case, str(root / "source"), root / "case")
            self.assertEqual(effective["budgets"], case.budgets)
            self.assertEqual(effective["validation_level"], "sandbox")
            self.assertEqual(effective["sandbox_runner"], "docker")
            self.assertTrue(effective["sandbox_enabled"])
            self.assertEqual(effective["max_files"], case.scope["max_files"])
            self.assertEqual(effective["max_bytes"], case.scope["max_bytes"])

            (root / ".env").write_text(
                "LLM_API_KEY=synthetic-alias-value\nAUDIT_AGENT_LLM_BASE_URL=https://provider.invalid/v1\n",
                encoding="utf-8",
            )
            config, secrets = build_child_audit_config(
                effective, environment={"SENTINEL": "1"}, environment_root=root
            )
            self.assertEqual(config.default_validation_level, "sandbox")
            self.assertEqual(config.sandbox.runner, "docker")
            self.assertEqual(config.sandbox.max_starts, 1)
            self.assertEqual(config.audit_scope.tool_budget, 3)
            self.assertEqual(config.llm.request_budget, 2)
            self.assertEqual(config.llm.token_budget, 100)
            self.assertEqual(config.poc_repair.max_repair_attempts, 1)
            self.assertTrue(config.poc_repair.enabled)
            self.assertEqual(config.llm.api_key_env, "LLM_API_KEY")
            self.assertEqual(secrets, {"LLM_API_KEY": "synthetic-alias-value"})

    def test_real_provider_requires_a_non_placeholder_model(self):
        corpus = load_corpus(CORPUS)
        _, cases = corpus.select("fixture")
        case = BenchmarkCase.from_dict(
            {
                **cases[0].to_dict(),
                "budgets": {"llm_requests": 1, "llm_tokens": 100, "tool_calls": 1, "docker_starts": 0, "repair_attempts": 0},
                "safety": {**cases[0].safety, "secret_env_names": ["LLM_API_KEY"]},
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            coordinator = BenchmarkCoordinator(
                corpus,
                profile_id="fixture",
                case_ids=[case.case_id],
                output_root=root / "runs",
                cache_root=root / "cache",
                engine_identity={"provider": "openai-compatible", "model": "valid-real-model"},
            )
            effective = coordinator._effective_case_config(case, str(root / "source"), root / "case")
            environment = {"LLM_API_KEY": "synthetic-provider-key"}
            for invalid_model in (None, "", "disabled", "mock", " DISABLED ", " Mock "):
                with self.subTest(model=invalid_model):
                    with self.assertRaisesRegex(ValueError, "real provider requires a non-placeholder model"):
                        build_child_audit_config(
                            {**effective, "model": invalid_model},
                            environment=environment,
                            environment_root=root,
                        )

    def test_benchmark_cli_loads_dotenv_model_instead_of_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text(
                "LLM_API_KEY=synthetic-provider-key\nLLM_MODEL=synthetic-real-model\n",
                encoding="utf-8",
            )
            captured: dict[str, object] = {}

            def capture_identity(**kwargs):
                captured.update(kwargs)
                return {"provider": kwargs["provider"], "model": kwargs["model"]}

            previous_cwd = Path.cwd()
            try:
                os.chdir(root)
                with patch("audit_agent.cli.build_engine_identity", side_effect=capture_identity), patch(
                    "audit_agent.cli.run_benchmark", return_value=({"status": "configuration-smoke"}, 0)
                ), patch("builtins.print"):
                    exit_code = cli_main(
                        [
                            "benchmark",
                            "--benchmark-config",
                            str(CORPUS),
                            "--provider",
                            "openai-compatible",
                        ]
                    )
            finally:
                os.chdir(previous_cwd)

            self.assertEqual(exit_code, 0)
            self.assertEqual(captured["provider"], "openai-compatible")
            self.assertEqual(captured["model"], "synthetic-real-model")

    def test_pilot_workflow_requires_and_forwards_model_input(self):
        workflow = (ROOT / ".github" / "workflows" / "benchmark-pilot.yml").read_text(encoding="utf-8")
        model_input = workflow.split("      model:", 1)[1].split("      docker:", 1)[0]
        self.assertIn("required: true", model_input)
        self.assertIn('--provider "${{ inputs.provider }}"', workflow)
        self.assertIn('--model "${{ inputs.model }}"', workflow)

    def test_runtime_budget_guards_stop_tool_llm_and_docker_overuse(self):
        tool_budget = ToolBudget(total_limit=1)
        self.assertTrue(tool_budget.consume("analysis"))
        self.assertFalse(tool_budget.consume("verification"))
        client = BudgetedLLMClient(MockLLMClient(), request_budget=1, token_budget=10_000)
        request = LLMRequest(role="analysis", prompt="test", model="mock")
        client.complete(request)
        with self.assertRaises(LLMBudgetExceeded):
            client.complete(request)
        config = AuditConfig.default()
        config.sandbox.enabled = True
        config.sandbox.runner = "docker"
        config.sandbox.max_starts = 0
        with tempfile.TemporaryDirectory() as tmp:
            result = DockerSandboxRunner(config, tmp).run(
                {"id": "poc", "finding_id": "finding", "command_argv": ["python", "poc.py"]}
            )
            self.assertEqual(result.status, "policy-denied")
            self.assertIn("budget", result.message.lower())

    def test_scope_file_and_byte_bounds_are_enforced_before_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_text("a = 1\n", encoding="utf-8")
            (root / "b.py").write_text("b = 2\n", encoding="utf-8")
            config = AuditConfig.default()
            config.audit_scope.max_files = 1
            config.audit_scope.max_bytes = 100
            metadata = analyze_target(str(root), audit_scope=config.audit_scope)
            self.assertEqual(metadata.file_tree, ["a.py"])

    def test_engine_and_prompt_content_changes_change_reuse_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = root / "audit_agent"
            prompts = engine / "prompt_templates"
            prompts.mkdir(parents=True)
            source = engine / "module.py"
            prompt = prompts / "role.v1.json"
            source.write_text("VALUE = 1\n", encoding="utf-8")
            prompt.write_text('{"template":"one"}', encoding="utf-8")
            first = build_engine_identity(root=root, template_dir=prompts, prompt_version="v1")
            source.write_text("VALUE = 2\n", encoding="utf-8")
            second = build_engine_identity(root=root, template_dir=prompts, prompt_version="v1")
            self.assertNotEqual(first["engine_worktree_digest"], second["engine_worktree_digest"])
            self.assertEqual(first["prompt_content_digest"], second["prompt_content_digest"])
            prompt.write_text('{"template":"two"}', encoding="utf-8")
            third = build_engine_identity(root=root, template_dir=prompts, prompt_version="v1")
            self.assertNotEqual(second["prompt_content_digest"], third["prompt_content_digest"])

    def test_truth_content_change_invalidates_comparison_protocol(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            truth_path = root / "truth.json"
            truth_payload = json.loads(TRUTH.read_text(encoding="utf-8"))
            truth_path.write_text(json.dumps(truth_payload), encoding="utf-8")
            kwargs = {
                "corpus_path": CORPUS,
                "profile_id": "fixture",
                "cache_root": root / "cache",
                "truth_path": truth_path,
                "adjudication_path": ADJUDICATIONS,
                "case_ids": ["fixture-safe-negative"],
                "engine_identity": {"engine": "same", "prompt": "same", "model": "disabled"},
            }
            before, before_code = run_benchmark(output_root=root / "before", **kwargs)
            truth_payload["records"][0]["evidence_refs"].append("same-path-content-change")
            truth_path.write_text(json.dumps(truth_payload), encoding="utf-8")
            after, after_code = run_benchmark(output_root=root / "after", **kwargs)
            self.assertEqual((before_code, after_code), (0, 0))
            self.assertNotEqual(
                before["fingerprints"]["comparison_protocol_fingerprint"],
                after["fingerprints"]["comparison_protocol_fingerprint"],
            )

    def test_truth_change_resume_preserves_stale_result_and_reruns_same_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            truth_path = root / "truth.json"
            truth_payload = json.loads(TRUTH.read_text(encoding="utf-8"))
            truth_path.write_text(json.dumps(truth_payload), encoding="utf-8")
            kwargs = {
                "corpus_path": CORPUS,
                "profile_id": "fixture",
                "case_ids": ["fixture-safe-negative"],
                "output_root": root / "runs",
                "cache_root": root / "cache",
                "truth_path": truth_path,
                "adjudication_path": ADJUDICATIONS,
                "allow_network": False,
                "comparison_dimensions": ["engine"],
                "engine_identity": {"engine": "same", "prompt": "same", "model": "disabled"},
            }
            first, first_code = run_benchmark(**kwargs)
            run_dir = root / "runs" / first["run_id"]
            original_manifest = AtomicJsonStore.read(run_dir / "resolved-manifest.json")

            truth_payload["records"][0]["evidence_refs"].append("resume-truth-change")
            truth_path.write_text(json.dumps(truth_payload), encoding="utf-8")
            resumed, resumed_code = run_benchmark(**kwargs, resume_run_id=first["run_id"])

            case_dir = run_dir / "cases" / "fixture-safe-negative"
            resume_requests = list(run_dir.glob("resume-request-*.json"))
            self.assertEqual((first_code, resumed_code), (0, 0))
            self.assertEqual(
                AtomicJsonStore.read(run_dir / "resolved-manifest.json")["truth_identity"],
                original_manifest["truth_identity"],
            )
            self.assertEqual(len(resume_requests), 1)
            self.assertNotEqual(
                AtomicJsonStore.read(resume_requests[0])["requested"]["truth_identity"]["content_digest"],
                original_manifest["truth_identity"]["content_digest"],
            )
            self.assertTrue((case_dir / "stale-result-1.json").is_file())
            self.assertTrue((case_dir / "source-attempt-2").is_dir())
            self.assertNotEqual(
                first["fingerprints"]["comparison_protocol_fingerprint"],
                resumed["fingerprints"]["comparison_protocol_fingerprint"],
            )

    def test_adjudication_change_reuses_scan_but_invalidates_comparison_protocol(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            adjudication_path = root / "adjudications.json"
            adjudication_payload = {
                "schema_version": "benchmark-adjudication.v1",
                "records": [],
            }
            adjudication_path.write_text(json.dumps(adjudication_payload), encoding="utf-8")
            kwargs = {
                "corpus_path": CORPUS,
                "profile_id": "fixture",
                "case_ids": ["fixture-safe-negative"],
                "output_root": root / "runs",
                "cache_root": root / "cache",
                "truth_path": TRUTH,
                "adjudication_path": adjudication_path,
                "allow_network": False,
                "comparison_dimensions": ["engine"],
                "engine_identity": {"engine": "same", "prompt": "same", "model": "disabled"},
            }
            first, first_code = run_benchmark(**kwargs)
            case_dir = root / "runs" / first["run_id"] / "cases" / "fixture-safe-negative"
            marker = case_dir / "source" / "adjudication-resume-marker.txt"
            marker.write_text("preserve", encoding="utf-8")

            adjudication_payload["records"].append(
                {
                    "adjudication_id": "adj-synthetic-1",
                    "case_id": "fixture-safe-negative",
                    "finding_id": "synthetic-nonexistent-finding",
                    "finding_group_id": "synthetic-nonexistent-group",
                    "decision": "unresolved",
                    "reviewer": "fixture-reviewer",
                    "rationale": "Identity-only synthetic adjudication fixture.",
                    "timestamp": "2026-07-13T00:00:00+00:00",
                    "evidence_refs": ["fixture://adjudication-identity"],
                    "match_refs": [],
                }
            )
            adjudication_path.write_text(json.dumps(adjudication_payload), encoding="utf-8")
            resumed, resumed_code = run_benchmark(**kwargs, resume_run_id=first["run_id"])

            self.assertEqual((first_code, resumed_code), (0, 0))
            self.assertTrue(marker.exists())
            self.assertEqual(resumed["cases"][0]["reuse_decision"], "reused-compatible-completed-result")
            self.assertFalse((case_dir / "stale-result-1.json").exists())
            self.assertEqual(resumed["corpus"]["adjudication"]["schema_version"], "benchmark-adjudication.v1")
            self.assertEqual(resumed["corpus"]["adjudication"]["record_count"], 1)
            self.assertNotEqual(
                first["fingerprints"]["comparison_protocol_fingerprint"],
                resumed["fingerprints"]["comparison_protocol_fingerprint"],
            )
            with self.assertRaisesRegex(ValueError, "comparison_protocol_fingerprint mismatch"):
                compare_reports(first, resumed, ["engine"])

    def test_benchmark_operator_guide_covers_safe_operation_and_troubleshooting(self):
        guide = ROOT / "docs" / "benchmark-operator-guide.md"
        content = guide.read_text(encoding="utf-8")
        for required_topic in (
            "cache",
            "resume",
            "truth",
            "adjudication",
            "comparison_dimensions",
            "Windows Job Object",
            "POSIX process group",
            "remote-download-skipped",
            "troubleshooting",
        ):
            self.assertIn(required_topic, content)

    def test_legacy_conversion_is_non_executable(self):
        converted = BenchmarkConfig.load(ROOT / "benchmarks" / "projects.json").to_unresolved_corpus()
        self.assertEqual(len(converted.parsed_cases()), 20)
        self.assertTrue(all(not item.executable for item in converted.parsed_cases()))
        self.assertTrue(all(not item.effectiveness_eligible for item in converted.parsed_cases()))

    def test_source_identity_rejects_credentials_protocols_and_local_remote(self):
        with self.assertRaises(ValueError):
            normalize_source_identity("https://user:password@github.com/o/r.git", remote_profile=True)
        with self.assertRaises(ValueError):
            normalize_source_identity("file:///tmp/repo", remote_profile=True)
        with self.assertRaises(ValueError):
            normalize_source_identity(str(ROOT), remote_profile=True)
        self.assertEqual(
            normalize_source_identity("https://github.com/o/r.git", remote_profile=True),
            "https://github.com/o/r.git",
        )

    def test_offline_cache_miss_never_invokes_scan_or_fabricates_counts(self):
        corpus = load_corpus(CORPUS)
        _, cases = corpus.select("fixture")
        remote_case = BenchmarkCase.from_dict(
            {
                **cases[0].to_dict(),
                "case_id": "remote-case",
                "source": "https://github.com/example/example.git",
                "commit": "a" * 40,
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            record = RepositoryAcquirer(Path(tmp) / "cache", allow_network=False).acquire(
                remote_case, Path(tmp) / "source", profile_kind="pilot"
            )
        self.assertEqual(record.status, "not-run")
        self.assertEqual(record.failure_reason, "acquisition-cache-miss")
        self.assertEqual(record.commands, [])

    def test_cached_remote_wrong_origin_and_commit_mismatch_fail_closed(self):
        corpus = load_corpus(CORPUS)
        _, cases = corpus.select("fixture")
        case = BenchmarkCase.from_dict({**cases[0].to_dict(), "source": "https://github.com/example/example.git", "commit": "a" * 40})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            identity = normalize_source_identity(case.source, remote_profile=True)
            from audit_agent.benchmark_acquisition import source_cache_key
            mirror = root / "cache" / "mirrors" / f"{source_cache_key(identity)}.git"
            mirror.mkdir(parents=True)

            def wrong_origin(argv, cwd, env, timeout):
                if argv[-3:] == ["remote", "get-url", "origin"]:
                    return CommandResult(argv, 0, "https://github.com/other/repo.git\n", "")
                return CommandResult(argv, 0, "", "")

            record = RepositoryAcquirer(root / "cache", command_runner=wrong_origin).acquire(case, root / "out", profile_kind="pilot")
            self.assertNotEqual(record.status, "ready")
            self.assertIn("remote identity mismatch", record.failure_reason)

            def wrong_commit(argv, cwd, env, timeout):
                if argv[-3:] == ["remote", "get-url", "origin"]:
                    return CommandResult(argv, 0, case.source + "\n", "")
                if "rev-parse" in argv:
                    return CommandResult(argv, 0, "b" * 40 + "\n", "")
                return CommandResult(argv, 0, "", "")

            record = RepositoryAcquirer(root / "cache", command_runner=wrong_commit).acquire(case, root / "out-2", profile_kind="pilot")
            self.assertNotEqual(record.status, "ready")
            self.assertIn("resolved commit", record.failure_reason)

    def test_authorized_fetch_uses_fixed_argv_and_safe_archive(self):
        corpus = load_corpus(CORPUS)
        _, cases = corpus.select("fixture")
        case = BenchmarkCase.from_dict({**cases[0].to_dict(), "source": "https://github.com/example/example.git", "commit": "a" * 40})
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def fake_git(argv, cwd, env, timeout):
                calls.append(list(argv))
                if argv[:3] == ["git", "clone", "--mirror"]:
                    Path(argv[-1]).mkdir(parents=True)
                if "cat-file" in argv:
                    return CommandResult(argv, 1, "", "missing")
                if "rev-parse" in argv:
                    return CommandResult(argv, 0, case.commit + "\n", "")
                if "archive" in argv:
                    archive_path = Path(argv[argv.index("-o") + 1])
                    source_file = root / "app.py"
                    source_file.write_text("print('fixture')", encoding="utf-8")
                    with tarfile.open(archive_path, "w") as handle:
                        handle.add(source_file, arcname="app.py")
                return CommandResult(argv, 0, "", "")

            record = RepositoryAcquirer(root / "cache", allow_network=True, command_runner=fake_git).acquire(
                case, root / "export", profile_kind="pilot"
            )
            self.assertEqual(record.status, "ready")
            self.assertTrue((root / "export" / "app.py").is_file())
            self.assertTrue(any(call[1] == "clone" for call in calls))
            self.assertTrue(any("fetch" in call for call in calls))
            self.assertTrue(all(isinstance(call, list) for call in calls))
            self.assertTrue(record.safety_checks["submodules_disabled"])
            self.assertTrue(record.safety_checks["lfs_smudge_disabled"])
            self.assertTrue(record.safety_checks["external_filters_disabled"])

    def test_cached_archive_reuse_corruption_and_traversal_are_covered(self):
        from audit_agent.benchmark_acquisition import source_cache_key
        corpus = load_corpus(CORPUS)
        _, cases = corpus.select("fixture")
        case = BenchmarkCase.from_dict({**cases[0].to_dict(), "source": "https://github.com/example/example.git", "commit": "a" * 40})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mirror = root / "cache" / "mirrors" / f"{source_cache_key(case.source)}.git"
            mirror.mkdir(parents=True)
            calls = []

            def cached_git(argv, cwd, env, timeout):
                calls.append(list(argv))
                if argv[-3:] == ["remote", "get-url", "origin"]:
                    return CommandResult(argv, 0, case.source + "\n", "")
                if "rev-parse" in argv:
                    return CommandResult(argv, 0, case.commit + "\n", "")
                if "archive" in argv:
                    archive_path = Path(argv[argv.index("-o") + 1])
                    fixture = root / "fixture.py"
                    fixture.write_text("pass", encoding="utf-8")
                    with tarfile.open(archive_path, "w") as handle:
                        handle.add(fixture, arcname="fixture.py")
                return CommandResult(argv, 0, "", "")

            record = RepositoryAcquirer(root / "cache", command_runner=cached_git).acquire(
                case, root / "cached-export", profile_kind="pilot"
            )
            self.assertEqual(record.cache_status, "hit")
            self.assertFalse(any("clone" in call or "fetch" in call for call in calls))

            def corrupt_git(argv, cwd, env, timeout):
                return CommandResult(argv, 1, "", "corrupt mirror")

            corrupt = RepositoryAcquirer(root / "cache", command_runner=corrupt_git).acquire(
                case, root / "corrupt-export", profile_kind="pilot"
            )
            self.assertNotEqual(corrupt.status, "ready")

            traversal_tar = root / "traversal.tar"
            with tarfile.open(traversal_tar, "w") as handle:
                info = tarfile.TarInfo("../escape.py")
                info.size = 0
                handle.addfile(info)
            destination = root / "traversal-output"
            destination.mkdir()
            with self.assertRaises(ValueError):
                RepositoryAcquirer._safe_extract(traversal_tar, destination)

    def test_local_acquisition_denies_escaping_symlink(self):
        if not hasattr(Path, "symlink_to"):
            self.skipTest("symlinks unavailable")
        corpus = load_corpus(CORPUS)
        _, cases = corpus.select("fixture")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "app.py").write_text("print('safe')", encoding="utf-8")
            try:
                (source / "escape").symlink_to(root.parent, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation unavailable")
            case = BenchmarkCase.from_dict({**cases[0].to_dict(), "source": str(source)})
            record = RepositoryAcquirer(root / "cache").acquire(case, root / "export", profile_kind="fixture")
            self.assertNotEqual(record.status, "ready")
            self.assertIn("policy-denied", record.failure_reason)

    def test_atomic_state_rejects_partial_and_transition_contract_is_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            AtomicJsonStore.write(state_path, {"schema_version": "v1", "status": "pending"})
            self.assertEqual(AtomicJsonStore.read(state_path)["status"], "pending")
            partial = Path(tmp) / ".state.json.1.tmp"
            partial.write_text("{", encoding="utf-8")
            self.assertIn(partial.name, AtomicJsonStore.recover(tmp))
            state_path.write_text("{", encoding="utf-8")
            with self.assertRaises(ValueError):
                AtomicJsonStore.read(state_path)

    def test_completion_requires_scan_runtime_report_resource_identity_and_cleanup(self):
        corpus = load_corpus(CORPUS)
        _, cases = corpus.select("fixture")
        case = cases[2]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "report.json"
            runtime = root / "state.json"
            resource = root / "resource.json"
            for path in (report, runtime, resource):
                path.write_text("{}", encoding="utf-8")
            resource_payload = _resource(case.case_id, case.commit, scanned_files=1)
            result = {
                "status": "pending-validation",
                "acquisition": {"status": "ready", "resolved_commit": case.commit},
                "runtime": {"status": "succeeded"},
                "resources": resource_payload,
                "cleanup": {"success": True},
                "artifact_refs": {"report": str(report), "runtime_state": str(runtime), "resource_summary": str(resource)},
            }
            self.assertEqual(validate_case_completion(case, result), (True, None))
            result["resources"] = _resource("wrong-case", case.commit, scanned_files=1)
            self.assertEqual(validate_case_completion(case, result)[1], "resource-identity-mismatch")
            result["resources"] = _resource(case.case_id, case.commit, scanned_files=0)
            self.assertEqual(validate_case_completion(case, result)[1], "empty-scan-scope")
            result["resources"] = _resource(case.case_id, case.commit, scanned_files=1)
            result["cleanup"] = {"success": False}
            self.assertEqual(validate_case_completion(case, result)[1], "cleanup-failed")
            result["cleanup"] = {"success": True}
            result["resources"] = _resource(case.case_id, case.commit, scanned_files=1)
            result["resources"]["tool_calls"] = case.budgets["tool_calls"] + 1
            self.assertEqual(validate_case_completion(case, result)[1], "budget-exceeded:tool_calls")

    def test_numeric_token_accounting_is_preserved_but_secret_value_is_redacted(self):
        value = redact_secrets(
            {"llm_tokens": 123, "total_tokens": 123, "api_key": "secret-value", "secret_env_names": ["LLM_API_KEY"]}
        )
        self.assertEqual(value["llm_tokens"], 123)
        self.assertEqual(value["total_tokens"], 123)
        self.assertEqual(value["api_key"], "[REDACTED]")
        self.assertEqual(value["secret_env_names"], ["LLM_API_KEY"])

    def test_resource_summary_handles_provider_usage_docker_repair_and_missing_accounting(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            (run_dir / "llm").mkdir(parents=True)
            llm_path = run_dir / "llm" / "provider.json"
            llm_path.write_text(json.dumps({"response": {"usage": {"prompt_tokens": 4, "completion_tokens": 5, "total_tokens": 9}}}), encoding="utf-8")
            metadata = analyze_target(str(ROOT / "benchmarks" / "fixtures" / "fixture-negative"))
            config = AuditConfig.default()
            config.runtime_enabled = True
            config.llm.provider = "openai-compatible"
            config.llm.model = "provider-shaped"
            state = SimpleNamespace(
                started_at="2026-07-13T00:00:00+00:00",
                finished_at="2026-07-13T00:00:02.500000+00:00",
                tasks=[SimpleNamespace(kind="tool", role="analysis", started_at=None, finished_at=None)],
            )
            validation = SimpleNamespace(environment={"runner": "docker", "docker_started": True}, repair_attempt_count=1, timed_out=True)
            summary = build_run_resource_summary(
                run_id="run", run_dir=run_dir, metadata=metadata, run_state=state, config=config,
                validation_results=[validation], status_counts={"confirmed_count": 0}, runtime_refs={}, terminal_status="succeeded",
            )
            self.assertEqual(summary.llm_tokens, 9)
            self.assertEqual(summary.llm_requests, 1)
            self.assertEqual(summary.docker_starts, 1)
            self.assertEqual(summary.repair_attempts, 1)
            self.assertEqual(summary.timeouts, 1)
            self.assertEqual(summary.elapsed_seconds, 2.5)
            llm_path.write_text("{}", encoding="utf-8")
            missing = build_run_resource_summary(
                run_id="run", run_dir=run_dir, metadata=metadata, run_state=state, config=config,
                validation_results=[], status_counts={}, runtime_refs={}, terminal_status="succeeded",
            )
            self.assertIsNone(missing.llm_tokens)
            self.assertIn("llm_tokens", {item["field"] for item in missing.accounting_gaps})

    def test_child_output_redacts_configured_secret_and_uses_no_shell(self):
        secret = "sk-benchmark-secret-123456789"
        runner = ProcessTreeRunner()
        result = runner.run(
            [sys.executable, "-c", "import os; print(os.environ['BENCH_SECRET'])"],
            env={**os.environ, "BENCH_SECRET": secret}, cwd=ROOT, timeout_seconds=10,
            secret_values=[secret],
        )
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(secret, result.stdout)
        self.assertIn("[REDACTED]", result.stdout)
        with tempfile.TemporaryDirectory() as tmp:
            process_path = AtomicJsonStore.write(Path(tmp) / "process.json", result.__dict__)
            self.assertNotIn(secret, process_path.read_text(encoding="utf-8"))

    def test_coordinator_passes_only_allowlisted_secret_values_to_process_redaction(self):
        corpus = load_corpus(CORPUS)
        process = RecordingProcessRunner(ProcessResult(-1, "", "", True, {"success": True, "method": "double"}))
        secret = "synthetic-allowlisted-secret"
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"BENCH_SECRET": secret}):
            coordinator = BenchmarkCoordinator(
                corpus, profile_id="fixture", case_ids=["fixture-safe-negative"],
                output_root=Path(tmp) / "runs", cache_root=Path(tmp) / "cache",
                process_runner=process,
            )
            coordinator.cases[0].safety["secret_env_names"] = ["BENCH_SECRET"]
            coordinator.run()
            self.assertEqual(process.calls[0]["secret_values"], [secret])
            persisted = "\n".join(path.read_text(encoding="utf-8") for path in coordinator.run_dir.rglob("*.json"))
            self.assertNotIn(secret, persisted)

    def test_timeout_result_and_docker_cleanup_are_case_scoped(self):
        corpus = load_corpus(CORPUS)
        process = RecordingProcessRunner(ProcessResult(-1, "", "", True, {"success": True, "method": "double"}))
        docker = RecordingDockerCleaner()
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = BenchmarkCoordinator(
                corpus, profile_id="fixture", case_ids=["fixture-safe-negative"],
                output_root=Path(tmp) / "runs", cache_root=Path(tmp) / "cache",
                process_runner=process, docker_cleaner=docker,
            )
            results, code = coordinator.run()
            self.assertEqual(code, 2)
            self.assertEqual(results[0]["status"], "timed-out")
            self.assertEqual(results[0]["counts"], None)
            self.assertEqual(docker.calls, [(corpus.corpus_id, coordinator.run_id, "fixture-safe-negative")])
            labels = results[0]["cleanup"]["labels"]
            self.assertEqual(labels["audit.benchmark_case_id"], "fixture-safe-negative")

    @unittest.skipUnless(
        os.getenv("AUDIT_AGENT_RUN_PROCESS_TREE_TESTS") == "1",
        "Set AUDIT_AGENT_RUN_PROCESS_TREE_TESTS=1 for the opt-in process-tree smoke.",
    )
    def test_live_safe_timeout_terminates_spawned_process_tree(self):
        runner = ProcessTreeRunner()
        with tempfile.TemporaryDirectory() as tmp:
            pid_dir = Path(tmp) / "pids"
            result = runner.run(
                [sys.executable, str(ROOT / "tests" / "process_tree_worker.py"), str(pid_dir), "2"],
                env=dict(os.environ), cwd=ROOT, timeout_seconds=1,
            )
            pids = [int((pid_dir / f"{depth}.pid").read_text(encoding="utf-8")) for depth in range(3)]
            self.assertTrue(result.timed_out)
            self.assertTrue(result.cleanup["success"])
            self.assertTrue(result.cleanup["descendants_verified_gone"])
            self.assertIn(result.cleanup["method"], {"windows-job-object", "process-group"})
            self.assertTrue(all(not _pid_is_running(pid) for pid in pids))

    def test_enabled_docker_cleaner_uses_exact_conjunctive_labels(self):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(list(argv))
            stdout = "container-1\n" if argv[1:3] == ["ps", "-aq"] else "container-1\n"
            return subprocess_completed(argv, stdout)

        cleaner = DockerLabelCleaner(enabled=True, command_runner=fake_run)
        result = cleaner.cleanup("bench", "run", "case")
        self.assertTrue(result.success)
        self.assertEqual(calls[1], ["docker", "rm", "-f", "container-1"])
        list_argv = calls[0]
        self.assertIn("label=audit.benchmark_id=bench", list_argv)
        self.assertIn("label=audit.benchmark_run_id=run", list_argv)
        self.assertIn("label=audit.benchmark_case_id=case", list_argv)

    def test_match_dedup_adjudication_and_metrics(self):
        truth = TruthRecord(
            truth_id="truth-1", project_id="p", case_id="c", expected_presence=True,
            vulnerability_class="CWE-89", path="src/app.py", evidence_refs=["review"],
            source="synthetic", reviewed_by="reviewer", reviewed_at="2026-07-13T00:00:00+00:00",
            start_line=10, end_line=12,
        )
        truth.validate()
        finding = {
            "id": "f-1", "vulnerability_class": "sqli", "verification_status": "confirmed",
            "location": {"path": "src\\app.py", "start_line": 13, "end_line": 13},
        }
        duplicate = {**finding, "id": "f-2"}
        matches = FindingMatcher(line_drift=3).match_case("c", [finding, duplicate], [truth])
        self.assertEqual([item["outcome"] for item in matches], ["matched", "duplicate"])
        group = finding_group_id("c", finding)
        adjudication = AdjudicationRecord(
            adjudication_id="a-1", case_id="c", finding_id="f-1", finding_group_id=group,
            decision="true-positive", reviewer="reviewer", rationale="local evidence", timestamp="2026-07-13T00:00:00+00:00",
            evidence_refs=["evidence"], match_refs=[matches[0]["match_id"]],
        )
        metrics = compute_metrics(
            [{"case_id": "c", "project_id": "p", "status": "completed", "variant": "vulnerable", "effectiveness_eligible": True, "findings": [finding, duplicate]}],
            [truth], matches, [adjudication],
        )
        values = {item.metric_id: item.value for item in metrics}
        self.assertEqual(values["candidate-recall"], 1.0)
        self.assertEqual(values["confirmed-recall"], 1.0)
        self.assertEqual(values["adjudicated-confirmed-precision"], 1.0)

    def test_adjudicated_confirmed_precision_excludes_non_confirmed_groups(self):
        likely = {"id": "likely", "verification_status": "likely", "location": {"path": "likely.py"}}
        confirmed = {"id": "confirmed", "verification_status": "confirmed", "location": {"path": "confirmed.py"}}
        cases = [
            {
                "case_id": "positive",
                "project_id": "project",
                "status": "completed",
                "variant": "vulnerable",
                "effectiveness_eligible": True,
                "findings": [likely, confirmed],
            }
        ]
        adjudications = [
            AdjudicationRecord("a-likely", "positive", "likely", finding_group_id("positive", likely), "true-positive", "r", "review", "2026-07-13T00:00:00+00:00", ["e"]),
            AdjudicationRecord("a-confirmed", "positive", "confirmed", finding_group_id("positive", confirmed), "false-positive", "r", "review", "2026-07-13T00:00:00+00:00", ["e"]),
        ]
        metrics = {item.metric_id: item for item in compute_metrics(cases, [], [], adjudications)}
        precision = metrics["adjudicated-confirmed-precision"]
        self.assertEqual((precision.value, precision.numerator, precision.denominator), (0.0, 0, 1))
        self.assertEqual(precision.metric_version, "benchmark-metrics.v2")

    def test_unadjudicated_confirmed_safe_negative_counts_as_false_positive_case(self):
        finding = {"id": "confirmed", "verification_status": "confirmed", "location": {"path": "safe.py"}}
        cases = [
            {
                "case_id": "negative",
                "project_id": "project",
                "status": "completed",
                "variant": "safe-negative",
                "effectiveness_eligible": True,
                "findings": [finding],
            }
        ]
        metrics = {item.metric_id: item for item in compute_metrics(cases, [], [], [])}
        fpr = metrics["negative-control-false-positive-rate"]
        self.assertEqual((fpr.value, fpr.numerator, fpr.denominator), (1.0, 1, 1))

    def test_same_finding_id_in_different_cases_does_not_overwrite_status(self):
        positive = TruthRecord("positive", "p", "vuln", True, "sql-injection", "app.py", ["e"], "synthetic", "r", "2026-07-13T00:00:00+00:00")
        negative = TruthRecord("negative", "p", "fixed", False, "sql-injection", "app.py", ["e"], "synthetic", "r", "2026-07-13T00:00:00+00:00")
        shared_id = "F-shared"
        cases = [
            {"case_id": "vuln", "project_id": "p", "status": "completed", "variant": "vulnerable", "effectiveness_eligible": True, "findings": [{"id": shared_id, "verification_status": "confirmed"}]},
            {"case_id": "fixed", "project_id": "p", "status": "completed", "variant": "fixed", "effectiveness_eligible": True, "findings": [{"id": shared_id, "verification_status": "rejected"}]},
        ]
        matches = [
            {"case_id": "vuln", "finding_id": shared_id, "outcome": "matched", "truth_ids": ["positive"]},
            {"case_id": "fixed", "finding_id": shared_id, "outcome": "unexpected", "truth_ids": ["negative"]},
        ]
        metrics = {item.metric_id: item.value for item in compute_metrics(cases, [positive, negative], matches, [])}
        self.assertEqual(metrics["confirmed-recall"], 1.0)
        self.assertEqual(metrics["negative-location-rejection-accuracy"], 1.0)

    def test_matching_reports_ambiguous_out_of_scope_and_unresolved(self):
        truths = [
            TruthRecord("t1", "p", "c", True, "sql-injection", "app.py", ["e"], "synthetic", "r", "2026-07-13T00:00:00+00:00", start_line=5, end_line=8),
            TruthRecord("t2", "p", "c", True, "CWE-89", "app.py", ["e"], "synthetic", "r", "2026-07-13T00:00:00+00:00", start_line=5, end_line=8),
        ]
        finding = {"id": "f", "vulnerability_class": "sqli", "location": {"path": "app.py", "start_line": 6, "end_line": 6}}
        out = FindingMatcher().match_case("c", [finding], truths)
        self.assertEqual(out[0]["outcome"], "ambiguous")
        unresolved = FindingMatcher().match_case(
            "c", [{"id": "u", "vulnerability_class": "path-traversal", "location": {"path": "other.py", "start_line": 1}, "in_scope": False}], truths
        )
        self.assertEqual(unresolved[0]["outcome"], "out-of-scope")
        self.assertEqual({item["outcome"] for item in unresolved[1:]}, {"missed"})

    def test_comparison_allows_declared_engine_and_rejects_undeclared_scope(self):
        base = _report("base", engine="old")
        candidate = _report("candidate", engine="new")
        comparison = compare_reports(base, candidate, ["engine"])
        self.assertTrue(comparison["compatible"])
        candidate["provenance"]["scope"] = "different"
        with self.assertRaisesRegex(ValueError, "undeclared"):
            compare_reports(base, candidate, ["engine"])
        base = _report("base-identity", engine="same")
        candidate = _report("candidate-identity", engine="same")
        base["provenance"].update({"engine_commit": "a", "engine_worktree_digest": "one", "prompt_content_digest": "prompt"})
        candidate["provenance"].update({"engine_commit": "b", "engine_worktree_digest": "two", "prompt_content_digest": "prompt"})
        self.assertTrue(compare_reports(base, candidate, ["engine"])["compatible"])
        candidate["provenance"]["prompt_content_digest"] = "changed"
        with self.assertRaisesRegex(ValueError, "prompt_content_digest"):
            compare_reports(base, candidate, ["engine"])

    def test_comparison_emits_case_resource_deltas_and_hard_gates(self):
        base = _report("base", engine="old")
        candidate = _report("candidate", engine="new")
        base["cases"][0]["resources"]["elapsed_seconds"] = 1.0
        candidate["cases"][0]["resources"]["elapsed_seconds"] = 2.5
        candidate["cases"][0]["resources"]["llm_tokens"] = 20
        candidate["cases"][0]["counts"] = {"confirmed": 1}
        comparison = compare_reports(base, candidate, ["engine"])
        self.assertIn("llm_tokens", comparison["case_deltas"]["c"]["resources"])
        self.assertEqual(comparison["case_deltas"]["c"]["resources"]["elapsed_seconds"]["absolute"], 1.5)
        self.assertEqual(comparison["aggregate_resource_deltas"]["elapsed_seconds"]["candidate"], 2.5)
        self.assertFalse(comparison["gates"]["passed"])
        self.assertIn("false-confirmed-safe-negative", {item["gate"] for item in comparison["gates"]["failures"]})

    def test_macro_metrics_and_compatible_repetitions_do_not_pool_findings(self):
        truth = TruthRecord("t", "p", "c", True, "sql-injection", "app.py", ["e"], "synthetic", "r", "2026-07-13T00:00:00+00:00")
        finding = {"id": "f", "vulnerability_class": "sql-injection", "verification_status": "confirmed", "location": {"path": "app.py", "start_line": 1}}
        cases = [{"case_id": "c", "project_id": "p", "status": "completed", "variant": "vulnerable", "effectiveness_eligible": True, "findings": [finding]}]
        matches = FindingMatcher().match_case("c", [finding], [truth])
        macro = compute_macro_metrics(cases, [truth], matches, [])
        self.assertEqual(next(item for item in macro if item["metric_id"] == "candidate-recall")["value"], 1.0)
        first = _report("r1", engine="same")
        second = _report("r2", engine="same")
        first["provenance"]["repetition"] = "1"
        second["provenance"]["repetition"] = "2"
        aggregate = aggregate_repetitions([first, second])
        self.assertFalse(aggregate["pooled_findings"])
        self.assertEqual(aggregate["metrics"][0]["repetition_count"], 2)

    def test_markdown_is_derived_from_json_and_promotion_is_fail_closed(self):
        report = _report("run", engine="same")
        report["cases"][0]["resources"].update(
            {
                "accounting_source": "lifecycle-ledger",
                "llm_reconciliation_status": "incomplete",
                "llm_gap_ids": ["LLMGAP-fixture"],
                "llm_tokens": None,
            }
        )
        markdown = render_markdown(report)
        self.assertIn("# Benchmark Report", markdown)
        self.assertIn("candidate-recall", markdown)
        self.assertIn("lifecycle-ledger", markdown)
        self.assertIn("LLMGAP-fixture", markdown)
        self.assertIn("| N/A |", markdown)
        readiness = promotion_readiness(report, profile_kind="pilot")
        self.assertFalse(readiness["ready"])
        self.assertIn("requires-3-eligible-projects", {item["reason"] for item in readiness["blockers"]})

    def test_golden_json_markdown_and_comparison_digests_are_stable(self):
        report = _report("run", engine="same")
        comparison = compare_reports(_report("base", engine="old"), _report("candidate", engine="new"), ["engine"])
        self.assertEqual(canonical_digest(report), "f982c18cd1fe224fbe95d3f038921b4ab4f0b39505ef4729090510ca46dd6806")
        self.assertEqual(canonical_digest(render_markdown(report)), "9053b06bbe347a65e4495ec94a0b94d2f0c2936558f3e3862c1d013a1a3fab8f")
        self.assertEqual(canonical_digest(comparison), "829a25d53902d0b2ec65f22c8ef75cedb18297f6656271fd0cbc4c869688f001")

    def test_full_profile_readiness_never_counts_placeholders(self):
        readiness = readiness_for_profile(CORPUS, "full-readiness")
        self.assertFalse(readiness["ready"])
        self.assertEqual(readiness["effectiveness_eligible_project_count"], 0)
        self.assertEqual(readiness["blockers"][0]["required"], 20)

    def test_fixture_benchmark_completes_and_resume_reuses_without_new_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            report, code = run_benchmark(
                corpus_path=CORPUS, profile_id="fixture", case_ids=["fixture-safe-negative"],
                output_root=Path(tmp) / "runs", cache_root=Path(tmp) / "cache", truth_path=TRUTH,
                adjudication_path=ADJUDICATIONS, allow_network=False, comparison_dimensions=["engine"],
                engine_identity={"engine": "test", "prompt": "v1", "model": "disabled"},
            )
            self.assertEqual(code, 0)
            self.assertTrue(report["summary"]["complete"])
            self.assertEqual(report["cases"][0]["resources"]["scanned_files"], 1)
            self.assertGreater(report["cases"][0]["resources"]["elapsed_seconds"], 0)
            run_id = report["run_id"]
            source = Path(tmp) / "runs" / run_id / "cases" / "fixture-safe-negative" / "source"
            marker = source / "resume-marker.txt"
            marker.write_text("preserve", encoding="utf-8")
            resumed, resumed_code = run_benchmark(
                corpus_path=CORPUS, profile_id="fixture", case_ids=["fixture-safe-negative"],
                output_root=Path(tmp) / "runs", cache_root=Path(tmp) / "cache", truth_path=TRUTH,
                adjudication_path=ADJUDICATIONS, allow_network=False, resume_run_id=run_id,
                comparison_dimensions=["engine"], engine_identity={"engine": "test", "prompt": "v1", "model": "disabled"},
            )
            self.assertEqual(resumed_code, 0)
            self.assertTrue(marker.exists())
            self.assertEqual(resumed["cases"][0]["reuse_decision"], "reused-compatible-completed-result")

    def test_changed_engine_preserves_stale_result_and_forces_rerun(self):
        with tempfile.TemporaryDirectory() as tmp:
            kwargs = dict(
                corpus_path=CORPUS, profile_id="fixture", case_ids=["fixture-safe-negative"],
                output_root=Path(tmp) / "runs", cache_root=Path(tmp) / "cache", truth_path=TRUTH,
                adjudication_path=ADJUDICATIONS, allow_network=False, comparison_dimensions=["engine"],
            )
            first, _ = run_benchmark(**kwargs, engine_identity={"engine": "one", "prompt": "v1", "model": "disabled"})
            second, code = run_benchmark(
                **kwargs, resume_run_id=first["run_id"],
                engine_identity={"engine": "two", "prompt": "v1", "model": "disabled"},
            )
            case_dir = Path(tmp) / "runs" / first["run_id"] / "cases" / "fixture-safe-negative"
            self.assertEqual(code, 0)
            self.assertTrue((case_dir / "stale-result-1.json").is_file())
            self.assertTrue((case_dir / "source-attempt-2").is_dir())
            self.assertNotEqual(second["cases"][0].get("reuse_decision"), "reused-compatible-completed-result")

    def test_missing_artifact_and_interrupted_state_force_safe_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            kwargs = dict(
                corpus_path=CORPUS, profile_id="fixture", case_ids=["fixture-safe-negative"],
                output_root=Path(tmp) / "runs", cache_root=Path(tmp) / "cache", truth_path=TRUTH,
                adjudication_path=ADJUDICATIONS, allow_network=False, comparison_dimensions=["engine"],
                engine_identity={"engine": "same", "prompt": "v1", "model": "disabled"},
            )
            first, _ = run_benchmark(**kwargs)
            case_dir = Path(tmp) / "runs" / first["run_id"] / "cases" / "fixture-safe-negative"
            result = AtomicJsonStore.read(case_dir / "result.json")
            Path(result["artifact_refs"]["report"]).unlink()
            state = AtomicJsonStore.read(case_dir / "state.json")
            state["status"] = "running"
            AtomicJsonStore.write(case_dir / "state.json", state)
            restarted, code = run_benchmark(**kwargs, resume_run_id=first["run_id"])
            self.assertEqual(code, 0)
            self.assertEqual(restarted["cases"][0]["status"], "completed")
            self.assertTrue((case_dir / "stale-result-1.json").is_file())
            self.assertTrue((case_dir / "source-attempt-2").is_dir())


def _resource(case_id, commit, scanned_files):
    return RunResourceSummary(
        schema_version="run-resource-summary.v1", run_id="run", target_identity=case_id,
        target_commit=commit, terminal_status="succeeded", scanned_files=scanned_files, scanned_bytes=10,
        stage_durations_ms={}, final_status_counts={}, llm_requests=0, llm_tokens=0, tool_calls=1,
        docker_starts=0, docker_results=0, repair_attempts=0, timeouts=0, budget_consumption={},
        accounting_gaps=[], contributing_refs=[], elapsed_seconds=1.0,
    ).to_dict()


def _report(run_id, engine):
    return {
        "schema_version": "benchmark-report.v1", "run_id": run_id,
        "fingerprints": {"comparison_protocol_fingerprint": "same"},
        "comparison_dimensions": ["engine"], "provenance": {"engine": engine},
        "summary": {"complete": True, "baseline_eligible": True, "completed": 1},
        "cases": [{"case_id": "c", "project_id": "p", "variant": "safe-negative", "status": "completed", "baseline_eligible": True, "effectiveness_eligible": True, "support_level": "full-dataflow", "counts": {"confirmed": 0}, "resources": {"scanned_files": 1, "llm_tokens": 10, "accounting_gaps": []}, "cleanup": {"success": True}}],
        "metrics": [{"metric_id": "candidate-recall", "value": 1.0, "numerator": 1, "denominator": 1, "reason": None}],
        "matches": [],
    }


def subprocess_completed(argv, stdout):
    import subprocess
    return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")


def _pid_is_running(pid):
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
    import ctypes

    process = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
    if not process:
        return False
    try:
        exit_code = ctypes.c_ulong()
        return bool(ctypes.windll.kernel32.GetExitCodeProcess(process, ctypes.byref(exit_code))) and exit_code.value == 259
    finally:
        ctypes.windll.kernel32.CloseHandle(process)


if __name__ == "__main__":
    unittest.main()
