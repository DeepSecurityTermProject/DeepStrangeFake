from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from audit_agent.config import AuditConfig, RemoteAcquisitionConfig
from audit_agent.repository import analyze_target
from audit_agent.repository_acquisition import (
    AcquisitionCleanup,
    AcquisitionError,
    AcquisitionRequest,
    AcquisitionResult,
    GitCommandResult,
    RepositoryAcquisitionService,
    acquisition_cache_key,
    normalize_github_source,
    normalize_remote_source,
    normalize_revision,
    prepare_audit_target,
    remote_source_kind,
)
from audit_agent.cli import build_parser
from audit_agent.pipeline import run_audit
from audit_agent.validation import _sandbox_materialization_allowed
from audit_agent.server.app import create_app
from audit_agent.server.job_store import JobStore
from audit_agent.server.schemas import ScanRunRequest
from audit_agent.server.runner import ScanJobRunner
from audit_agent.server.artifacts import read_runtime_state


COMMIT = "a" * 40


class SourcePolicyTests(unittest.TestCase):
    def test_normal_remote_analysis_is_metadata_only_and_does_not_clone(self):
        with mock.patch("audit_agent.repository.checkout_remote_target") as checkout:
            metadata = analyze_target("https://github.com/example/project")
        self.assertIsNone(metadata.root_path)
        self.assertIsNone(metadata.commit)
        self.assertEqual([], metadata.file_tree)
        checkout.assert_not_called()

    def test_canonical_github_url_is_normalized(self):
        self.assertEqual(
            "https://github.com/Owner/repo",
            normalize_github_source("https://github.com/Owner/repo.git"),
        )

    def test_canonical_github_and_gitlab_urls_are_normalized_and_typed(self):
        cases = [
            (
                "https://github.com/Owner/repo.git",
                "https://github.com/Owner/repo",
                "github",
            ),
            (
                "https://gitlab.com/Group/Subgroup/repo.git",
                "https://gitlab.com/Group/Subgroup/repo",
                "gitlab",
            ),
        ]
        for source, expected, kind in cases:
            with self.subTest(source=source):
                self.assertEqual(expected, normalize_remote_source(source))
                self.assertEqual(kind, remote_source_kind(source))

    def test_unsafe_urls_are_denied_before_git(self):
        denied = [
            "ssh://git@github.com/owner/repo",
            "git@github.com:owner/repo.git",
            "file:///tmp/repo",
            "https://bitbucket.org/owner/repo",
            "https://user:secret@github.com/owner/repo",
            "https://github.com/owner/repo?ref=main",
            "https://github.com/owner/repo#main",
            "https://github.com/owner/repo/extra",
            "https://github.com/../repo",
            "https://gitlab.com/repository-only",
        ]
        for source in denied:
            with self.subTest(source=source), self.assertRaises(AcquisitionError):
                normalize_remote_source(source)

    def test_pipeline_rejects_remote_like_protocols_before_acquisition(self):
        config = AuditConfig.default()
        config.remote_acquisition.enabled = True
        service = mock.Mock()
        for source in (
            "git://github.com/owner/repo",
            "git@github.com:owner/repo.git",
            "//github.com/owner/repo",
        ):
            with self.subTest(source=source), self.assertRaisesRegex(
                AcquisitionError, "source-policy-denied"
            ):
                prepare_audit_target(
                    source,
                    audit_scope=config.audit_scope,
                    config=config.remote_acquisition,
                    service=service,
                )
        service.acquire.assert_not_called()

    def test_revision_accepts_only_head_or_complete_object(self):
        self.assertEqual("HEAD", normalize_revision(None))
        self.assertEqual(COMMIT, normalize_revision(COMMIT.upper()))
        for revision in ("main", "v1", "abc123", "--upload-pack=evil"):
            with self.subTest(revision=revision), self.assertRaises(AcquisitionError):
                normalize_revision(revision)

    def test_structured_source_is_strict_and_legacy_target_normalizes_local(self):
        legacy = ScanRunRequest(target="fixtures/integration_smoke")
        self.assertEqual("local", legacy.source.kind)
        self.assertEqual("fixtures/integration_smoke", legacy.display_target)
        remote = ScanRunRequest(
            source={"kind": "github", "url": "https://github.com/example/repo", "commit": COMMIT}
        )
        self.assertEqual(COMMIT, remote.requested_revision)
        gitlab = ScanRunRequest(
            source={
                "kind": "gitlab",
                "url": "https://gitlab.com/example/group/repo",
                "commit": COMMIT,
            }
        )
        self.assertEqual("gitlab", gitlab.source.kind)
        self.assertEqual(COMMIT, gitlab.requested_revision)
        with self.assertRaises(ValueError):
            ScanRunRequest(
                target="local",
                source={"kind": "github", "url": "https://github.com/example/repo"},
            )
        with self.assertRaises(ValueError):
            ScanRunRequest(source={"kind": "github", "url": "x", "allow_network": True})

    def test_remote_config_round_trip_and_legacy_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "remote_acquisition": {
                            "enabled": True,
                            "network_enabled": False,
                            "cache_root": "cache",
                            "work_root": "work",
                        }
                    }
                ),
                encoding="utf-8",
            )
            config = AuditConfig.from_json(path)
        self.assertTrue(config.remote_acquisition.enabled)
        self.assertFalse(config.remote_acquisition.network_enabled)
        self.assertEqual(["github.com", "gitlab.com"], config.remote_acquisition.allowed_hosts)
        self.assertIn("remote_acquisition", config.to_dict())
        self.assertFalse(AuditConfig.from_json(_legacy_config()).remote_acquisition.enabled)

    def test_cli_accepts_revision_and_keeps_commit_as_compatibility_alias(self):
        parser = build_parser()
        for flag in ("--revision", "--commit"):
            with self.subTest(flag=flag):
                args = parser.parse_args(
                    ["scan", "--target", "https://gitlab.com/example/repo", flag, COMMIT]
                )
                self.assertEqual(COMMIT, args.revision)


class AcquisitionCoreTests(unittest.TestCase):
    def test_timeout_wrong_origin_missing_object_clone_failure_lock_and_mirror_budget(self):
        source = "https://github.com/example/repo"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def timeout_runner(*_args):
                return GitCommandResult(-1, timed_out=True)

            timeout_config = RemoteAcquisitionConfig(
                enabled=True,
                network_enabled=True,
                cache_root=str(root / "timeout-cache"),
                work_root=str(root / "timeout-work"),
            )
            timed = RepositoryAcquisitionService(timeout_config, command_runner=timeout_runner).acquire(
                AcquisitionRequest(source, "timeout", "HEAD")
            )
            self.assertEqual("git-timeout", timed.failure_reason)

            cache = root / "cache"
            mirror = cache / f"{acquisition_cache_key(source)}.git"
            mirror.mkdir(parents=True)

            def wrong_origin(argv, *_args):
                if "config" in argv:
                    return GitCommandResult(0, "https://github.com/other/repo\n")
                return GitCommandResult(0)

            config = RemoteAcquisitionConfig(
                enabled=True, cache_root=str(cache), work_root=str(root / "work"), lock_timeout_seconds=1
            )
            wrong = RepositoryAcquisitionService(config, command_runner=wrong_origin).acquire(
                AcquisitionRequest(source, "wrong-origin", COMMIT)
            )
            self.assertEqual("cache-origin-mismatch", wrong.failure_reason)

            def missing_object(argv, *_args):
                if "config" in argv:
                    return GitCommandResult(0, source + "\n")
                if "cat-file" in argv:
                    return GitCommandResult(1, stderr="missing")
                return GitCommandResult(0)

            missing = RepositoryAcquisitionService(config, command_runner=missing_object).acquire(
                AcquisitionRequest(source, "missing", COMMIT)
            )
            self.assertEqual("commit-missing-network-disabled", missing.failure_reason)

            clone_config = RemoteAcquisitionConfig(
                enabled=True,
                network_enabled=True,
                cache_root=str(root / "clone-cache"),
                work_root=str(root / "clone-work"),
            )

            def clone_failure(argv, *_args):
                if "clone" in argv:
                    return GitCommandResult(1, stderr="synthetic clone failure")
                return GitCommandResult(0)

            clone = RepositoryAcquisitionService(clone_config, command_runner=clone_failure).acquire(
                AcquisitionRequest(source, "clone-failure", COMMIT)
            )
            self.assertEqual("git-command-failed", clone.failure_reason)
            self.assertFalse(any(path.name.startswith(".") for path in (root / "clone-cache").glob("*")))

            lock_path = cache / f"{acquisition_cache_key(source)}.lock"
            lock_path.write_text("occupied", encoding="ascii")
            lock_config = RemoteAcquisitionConfig(
                enabled=True,
                cache_root=str(cache),
                work_root=str(root / "lock-work"),
                lock_timeout_seconds=0,
            )
            locked = RepositoryAcquisitionService(lock_config, command_runner=missing_object).acquire(
                AcquisitionRequest(source, "locked", COMMIT)
            )
            self.assertEqual("lock-timeout", locked.failure_reason)
            lock_path.unlink()

            (mirror / "large-object").write_bytes(b"12")

            def valid_object(argv, *_args):
                if "config" in argv:
                    return GitCommandResult(0, source + "\n")
                return GitCommandResult(0)

            budget_config = RemoteAcquisitionConfig(
                enabled=True,
                cache_root=str(cache),
                work_root=str(root / "budget-work"),
                max_mirror_bytes=1,
            )
            budget = RepositoryAcquisitionService(budget_config, command_runner=valid_object).acquire(
                AcquisitionRequest(source, "budget", COMMIT)
            )
            self.assertEqual("mirror-byte-budget-exceeded", budget.failure_reason)

    def test_disabled_and_cache_miss_fail_closed_without_command(self):
        calls = []

        def runner(*args):
            calls.append(args)
            raise AssertionError("Git must not run")

        disabled = RepositoryAcquisitionService(RemoteAcquisitionConfig(), command_runner=runner)
        result = disabled.acquire(AcquisitionRequest("https://github.com/example/repo", "job", COMMIT))
        self.assertEqual("remote-acquisition-disabled", result.failure_reason)
        enabled = RepositoryAcquisitionService(
            RemoteAcquisitionConfig(enabled=True, network_enabled=False), command_runner=runner
        )
        result = enabled.acquire(AcquisitionRequest("https://github.com/example/repo", "job", COMMIT))
        self.assertEqual("cache-miss-network-disabled", result.failure_reason)
        self.assertEqual([], calls)

    def test_archive_traversal_link_collision_and_budget_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = RemoteAcquisitionConfig(
                enabled=True,
                cache_root=str(root / "cache"),
                work_root=str(root / "work"),
                max_archive_members=2,
                max_archive_bytes=4,
                max_bytes=4,
            )
            service = RepositoryAcquisitionService(config)
            destination = root / "out"
            destination.mkdir()
            cases = [
                ("escape.tar", [("../escape.py", b"x", "file")], "archive-path-invalid"),
                ("link.tar", [("link", b"", "symlink")], "archive-entry-type-forbidden"),
                ("large.tar", [("large.py", b"12345", "file")], "export-byte-budget-exceeded"),
            ]
            for name, members, reason in cases:
                archive = root / name
                _write_tar(archive, members)
                with self.subTest(name=name), self.assertRaisesRegex(AcquisitionError, reason):
                    service._extract_archive(archive, destination)

    @unittest.skipUnless(shutil.which("git"), "system Git is required")
    def test_offline_system_git_cache_hit_exports_exact_commit_and_cleans(self):
        safe_temp_root = Path.cwd() / ".test-tmp"
        safe_temp_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=safe_temp_root) as tmp:
            root = Path(tmp)
            work = root / "source"
            bare = root / "origin.git"
            cache = root / "cache"
            exports = root / "exports"
            work.mkdir()
            _git(["init"], work)
            _git(["config", "user.email", "fixture@example.invalid"], work)
            _git(["config", "user.name", "Fixture"], work)
            (work / "app.py").write_text("query = input()\ncursor.execute(query)\n", encoding="utf-8")
            _git(["add", "app.py"], work)
            _git(["commit", "-m", "fixture"], work)
            commit = _git(["rev-parse", "HEAD"], work).strip()
            shutil.copytree(work / ".git", bare)
            _git(["config", "core.bare", "true"], bare)
            source = "https://github.com/example/fixture"
            mirror = cache / f"{acquisition_cache_key(source)}.git"
            cache.mkdir()
            shutil.copytree(bare, mirror)
            _git(["remote", "add", "origin", source], mirror)

            config = RemoteAcquisitionConfig(
                enabled=True,
                network_enabled=False,
                cache_root=str(cache),
                work_root=str(exports),
                command_timeout_seconds=10,
                total_timeout_seconds=30,
                cleanup_retry_delay_ms=0,
            )
            service = RepositoryAcquisitionService(config)
            result = service.acquire(AcquisitionRequest(source, "offline-job", commit))
            self.assertEqual("ready", result.status, result.failure_reason)
            self.assertEqual(commit, result.resolved_commit)
            self.assertEqual("hit", result.cache_status)
            self.assertFalse(result.network_used)
            self.assertEqual(1, result.exported_files)
            self.assertTrue((Path(result.export_path) / "app.py").is_file())
            command_text = " ".join(" ".join(item.argv) for item in result.command_outcomes)
            self.assertNotIn("checkout", command_text)
            self.assertNotIn("submodule", command_text)
            cleanup = service.cleanup(result)
            self.assertEqual("complete", cleanup.status)
            self.assertFalse(Path(result.export_path).exists())

    @unittest.skipUnless(shutil.which("git"), "system Git is required")
    def test_offline_system_git_cache_hit_supports_gitlab_nested_namespace(self):
        safe_temp_root = Path.cwd() / ".test-tmp"
        safe_temp_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=safe_temp_root) as tmp:
            root = Path(tmp)
            work = root / "source"
            bare = root / "origin.git"
            cache = root / "cache"
            exports = root / "exports"
            work.mkdir()
            _git(["init"], work)
            _git(["config", "user.email", "fixture@example.invalid"], work)
            _git(["config", "user.name", "Fixture"], work)
            (work / "app.py").write_text(
                "value = request.args.get('name')\n"
                "query = f\"SELECT * FROM users WHERE name='{value}'\"\n"
                "cursor.execute(query)\n",
                encoding="utf-8",
            )
            _git(["add", "app.py"], work)
            _git(["commit", "-m", "fixture"], work)
            commit = _git(["rev-parse", "HEAD"], work).strip()
            shutil.copytree(work / ".git", bare)
            _git(["config", "core.bare", "true"], bare)
            original = "https://gitlab.com/example/security/fixture.git"
            normalized = "https://gitlab.com/example/security/fixture"
            mirror = cache / f"{acquisition_cache_key(normalized)}.git"
            cache.mkdir()
            shutil.copytree(bare, mirror)
            _git(["remote", "add", "origin", normalized], mirror)

            config = RemoteAcquisitionConfig(
                enabled=True,
                network_enabled=False,
                cache_root=str(cache),
                work_root=str(exports),
                cleanup_retry_delay_ms=0,
            )
            service = RepositoryAcquisitionService(config)
            result = service.acquire(AcquisitionRequest(original, "gitlab-job", commit))
            self.assertEqual("ready", result.status, result.failure_reason)
            self.assertEqual(original, result.source)
            self.assertEqual(normalized, result.normalized_source)
            self.assertEqual(commit, result.resolved_commit)
            self.assertTrue((Path(result.export_path) / "app.py").is_file())
            self.assertEqual("complete", service.cleanup(result).status)

            audit_config = AuditConfig.default()
            audit_config.graph.mode = "legacy"
            audit_config.remote_acquisition = config
            summary = run_audit(
                original,
                audit_config,
                root / "runs",
                requested_revision=commit,
                job_id="gitlab-pipeline",
            )
            report = json.loads(Path(summary["report_ref"]).read_text(encoding="utf-8"))
            self.assertEqual("completed", report["run_status"])
            self.assertEqual("gitlab", report["acquisition"]["source_kind"])
            self.assertEqual(original, report["acquisition"]["original_source"])
            self.assertEqual(commit, report["acquisition"]["resolved_commit"])
            self.assertEqual(["app.py"], report["acquisition"]["scanned_files"])
            self.assertGreater(report["executive_summary"]["verification_candidate_count"], 0)
            self.assertEqual("complete", report["acquisition"]["cleanup_status"])

    def test_credentials_are_not_retained_in_failure_or_commands(self):
        sentinel = "SENTINEL-DO-NOT-STORE"
        service = RepositoryAcquisitionService(RemoteAcquisitionConfig(enabled=True))
        result = service.acquire(
            AcquisitionRequest(f"https://user:{sentinel}@github.com/example/repo", "job", COMMIT)
        )
        self.assertNotIn(sentinel, json.dumps(result.to_dict()))


class WebRemoteContractTests(unittest.TestCase):
    def test_options_expose_safe_capability_and_disabled_remote_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = AuditConfig.default()
            config.remote_acquisition.enabled = False
            app = create_app(
                JobStore(Path(tmp) / "jobs.json"),
                runner=_NoopRunner(),
                output_dir=Path(tmp) / "runs",
                config=config,
            )
            client = TestClient(app)
            options = client.get("/api/options").json()["remote_acquisition"]
            self.assertFalse(options["enabled"])
            self.assertNotIn("cache_root", options)
            response = client.post(
                "/api/runs",
                json={"source": {"kind": "github", "url": "https://github.com/example/repo", "commit": COMMIT}},
            )
            self.assertEqual(422, response.status_code)
            self.assertEqual("remote-acquisition-disabled", response.json()["detail"]["error"])

    def test_enabled_remote_job_preserves_source_and_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = AuditConfig.default()
            config.remote_acquisition.enabled = True
            runner = _NoopRunner()
            store = JobStore(Path(tmp) / "jobs.json")
            client = TestClient(
                create_app(store, runner=runner, output_dir=Path(tmp) / "runs", config=config)
            )
            response = client.post(
                "/api/runs",
                json={"source": {"kind": "github", "url": "https://github.com/example/repo", "commit": COMMIT}},
            )
            self.assertEqual(202, response.status_code)
            job = store.get(response.json()["job_id"])
            self.assertEqual("github", job.source["kind"])
            self.assertEqual(COMMIT, job.requested_revision)
            self.assertEqual(1, len(runner.submissions))

    def test_enabled_gitlab_job_preserves_source_and_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = AuditConfig.default()
            config.remote_acquisition.enabled = True
            runner = _NoopRunner()
            store = JobStore(Path(tmp) / "jobs.json")
            client = TestClient(
                create_app(store, runner=runner, output_dir=Path(tmp) / "runs", config=config)
            )
            source = "https://gitlab.com/example/security/repo"
            response = client.post(
                "/api/runs",
                json={"source": {"kind": "gitlab", "url": source, "commit": COMMIT}},
            )
            self.assertEqual(202, response.status_code, response.text)
            job = store.get(response.json()["job_id"])
            self.assertEqual(source, job.target)
            self.assertEqual("gitlab", job.source["kind"])
            self.assertEqual(COMMIT, job.requested_revision)
            self.assertEqual(1, len(runner.submissions))

            mismatch = client.post(
                "/api/runs",
                json={"source": {"kind": "github", "url": source, "commit": COMMIT}},
            )
            self.assertEqual(422, mismatch.status_code)
            self.assertEqual("source-kind-mismatch", mismatch.json()["detail"]["error"])

    def test_web_runner_scans_remote_fixture_and_persists_terminal_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            export = root / "export"
            export.mkdir()
            (export / "app.py").write_text(
                "query = f\"SELECT * FROM users WHERE id={request.args.get('id')}\"\n",
                encoding="utf-8",
            )
            source = "https://github.com/example/web-fixture"
            acquisition = AcquisitionResult(
                source=source,
                normalized_source=source,
                requested_revision=COMMIT,
                resolved_commit=COMMIT,
                status="ready",
                method="fake-offline-export",
                cache_status="fixture",
                network_used=False,
                export_path=str(export),
                exported_files=1,
                exported_bytes=(export / "app.py").stat().st_size,
                job_id="web-job",
            )
            config = AuditConfig.default()
            config.graph.mode = "legacy"
            config.remote_acquisition.enabled = True
            config.integration.load_env_file = False
            store = JobStore(root / "jobs.json")
            request = ScanRunRequest(
                source={"kind": "github", "url": source, "commit": COMMIT},
                graph_mode="legacy",
                output=str(root / "runs"),
            )
            job = store.create_job(
                source,
                root / "runs",
                source=request.source.model_dump(),
                requested_revision=COMMIT,
            )
            runner = ScanJobRunner(
                store,
                config=config,
                acquisition_service=_FakeAcquisitionService(acquisition),
            )
            runner.run_job(job.job_id, request)
            terminal = store.get(job.job_id)
            self.assertEqual("succeeded", terminal.status, terminal.error)
            self.assertEqual("complete", terminal.phase)
            self.assertEqual(COMMIT, terminal.resolved_commit)
            self.assertEqual("complete", terminal.cleanup_status)
            self.assertTrue(terminal.run_dir)
            self.assertGreater(terminal.summary.get("candidate_count", 0), 0)
            self.assertTrue(list((Path(terminal.run_dir) / "evidence").glob("*.json")))
            self.assertTrue((Path(terminal.run_dir) / "reports" / "report.json").is_file())
            repository = json.loads(
                (Path(terminal.run_dir) / "metadata" / "repository.json").read_text(encoding="utf-8")
            )
            self.assertEqual(["app.py"], repository["file_tree"])
            self.assertEqual(source, repository["target"]["source"])
            report = json.loads(
                (Path(terminal.run_dir) / "reports" / "report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(source, report["acquisition"]["original_source"])
            self.assertEqual(COMMIT, report["acquisition"]["resolved_commit"])
            self.assertEqual(["app.py"], report["acquisition"]["scanned_files"])
            self.assertGreater(report["executive_summary"]["scanned_file_count"], 0)
            self.assertGreater(report["executive_summary"]["verification_candidate_count"], 0)
            self.assertEqual("complete", report["acquisition"]["cleanup_status"])

    def test_cleanup_failure_keeps_artifacts_but_fails_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            export = root / "export"
            export.mkdir()
            (export / "app.py").write_text("API_KEY = 'not-a-real-secret-value'\n", encoding="utf-8")
            source = "https://github.com/example/cleanup-fixture"
            acquisition = AcquisitionResult(
                source=source,
                normalized_source=source,
                requested_revision=COMMIT,
                resolved_commit=COMMIT,
                status="ready",
                export_path=str(export),
                exported_files=1,
                exported_bytes=32,
                job_id="cleanup-job",
            )
            config = AuditConfig.default()
            config.graph.mode = "legacy"
            config.remote_acquisition.enabled = True
            config.integration.load_env_file = False
            store = JobStore(root / "jobs.json")
            request = ScanRunRequest(
                source={"kind": "github", "url": source, "commit": COMMIT},
                graph_mode="legacy",
                output=str(root / "runs"),
            )
            job = store.create_job(source, root / "runs", source=request.source.model_dump())
            runner = ScanJobRunner(
                store,
                config=config,
                acquisition_service=_FakeAcquisitionService(acquisition, cleanup_fails=True),
            )
            runner.run_job(job.job_id, request)
            terminal = store.get(job.job_id)
            self.assertEqual("failed", terminal.status)
            self.assertIn("cleanup-failed", terminal.error)
            self.assertEqual("failed", terminal.cleanup_status)
            self.assertTrue(terminal.run_dir)
            state = read_runtime_state(terminal)
            self.assertEqual("failed", state["status"])
            report = json.loads(
                (Path(terminal.run_dir) / "reports" / "report.json").read_text(encoding="utf-8")
            )
            self.assertEqual("failed", report["run_status"])
            self.assertEqual("failed", report["acquisition"]["cleanup_status"])
            resources = json.loads(
                Path(terminal.summary["resource_summary_ref"]).read_text(encoding="utf-8")
            )
            self.assertEqual("failed", resources["terminal_status"])
            self.assertEqual("failed", resources["acquisition"]["cleanup_status"])

    def test_acquisition_failure_and_empty_scope_cannot_succeed_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = AuditConfig.default()
            config.remote_acquisition.enabled = True
            config.integration.load_env_file = False
            source = "https://github.com/example/fail-closed"

            failed_result = AcquisitionResult(
                source=source,
                normalized_source=source,
                requested_revision=COMMIT,
                status="failed",
                failure_reason="git-command-failed",
                cleanup=AcquisitionCleanup(status="not-required"),
                job_id="failed-acquisition",
            )
            empty_export = root / "empty-export"
            (empty_export / "tests").mkdir(parents=True)
            (empty_export / "tests" / "only_test.py").write_text("pass\n", encoding="utf-8")
            empty_result = AcquisitionResult(
                source=source,
                normalized_source=source,
                requested_revision=COMMIT,
                resolved_commit=COMMIT,
                status="ready",
                export_path=str(empty_export),
                exported_files=1,
                exported_bytes=5,
                job_id="empty-scope",
            )

            for label, acquisition, cleanup_status in (
                ("acquisition", failed_result, "not-required"),
                ("empty", empty_result, "complete"),
            ):
                with self.subTest(label=label):
                    store = JobStore(root / f"{label}-jobs.json")
                    request = ScanRunRequest(
                        source={"kind": "github", "url": source, "commit": COMMIT},
                        output=str(root / f"{label}-runs"),
                    )
                    job = store.create_job(
                        source,
                        request.output,
                        source=request.source.model_dump(),
                        requested_revision=COMMIT,
                    )
                    runner = ScanJobRunner(
                        store,
                        config=config,
                        acquisition_service=_FakeAcquisitionService(acquisition),
                    )
                    runner.run_job(job.job_id, request)
                    terminal = store.get(job.job_id)
                    self.assertEqual("failed", terminal.status)
                    self.assertEqual("failed", terminal.phase)
                    self.assertEqual(cleanup_status, terminal.cleanup_status)
                    self.assertNotIn("candidate_count", terminal.summary)


class RemoteRuntimeIntegrationTests(unittest.TestCase):
    def test_remote_snapshot_sandbox_policy_requires_docker_no_network_and_verified_materialization(self):
        for kind in ("github", "gitlab"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "app.py").write_text("pass", encoding="utf-8")
                metadata = analyze_target(str(root))
                metadata.target.kind = kind
                metadata.target.materialization = "verified-remote-snapshot"
                metadata.materialization = {"status": "verified"}
                config = AuditConfig.default()
                config.sandbox.enabled = True
                config.sandbox.runner = "docker"
                config.sandbox.network = "none"
                self.assertTrue(_sandbox_materialization_allowed(config, metadata))
                config.sandbox.runner = "local"
                self.assertFalse(_sandbox_materialization_allowed(config, metadata))
                config.sandbox.runner = "docker"
                config.sandbox.network = "bridge"
                self.assertFalse(_sandbox_materialization_allowed(config, metadata))
                config.sandbox.network = "none"
                config.sandbox.allow_live_targets = True
                self.assertFalse(_sandbox_materialization_allowed(config, metadata))

    def test_acquired_fixture_is_scanned_by_legacy_and_graph_with_provenance(self):
        for graph_mode in ("legacy", "deterministic-graph"):
            with self.subTest(graph_mode=graph_mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                export = root / "export"
                export.mkdir()
                (export / "app.py").write_text(
                    "def unsafe(cursor, value):\n    cursor.execute(value)\n",
                    encoding="utf-8",
                )
                source = "https://github.com/example/fixture"
                acquisition = AcquisitionResult(
                    source=source,
                    normalized_source=source,
                    requested_revision=COMMIT,
                    resolved_commit=COMMIT,
                    status="ready",
                    method="fake-offline-export",
                    cache_status="fixture",
                    network_used=False,
                    export_path=str(export),
                    exported_files=1,
                    exported_bytes=(export / "app.py").stat().st_size,
                    job_id=f"job-{graph_mode}",
                )
                service = _FakeAcquisitionService(acquisition)
                phases = []
                config = AuditConfig.default()
                config.graph.mode = graph_mode
                config.remote_acquisition.enabled = True
                config.remote_acquisition.network_enabled = False
                summary = run_audit(
                    source,
                    config,
                    root / "runs",
                    requested_revision=COMMIT,
                    job_id=f"job-{graph_mode}",
                    acquisition_service=service,
                    progress_callback=phases.append,
                )
                metadata = json.loads(
                    (Path(summary["run_dir"]) / "metadata" / "repository.json").read_text(encoding="utf-8")
                )
                evidence = json.loads(Path(summary["acquisition_ref"]).read_text(encoding="utf-8"))
                resources = json.loads(Path(summary["resource_summary_ref"]).read_text(encoding="utf-8"))
                self.assertEqual(["app.py"], metadata["file_tree"])
                self.assertEqual("github", metadata["target"]["kind"])
                self.assertEqual(source, metadata["target"]["source"])
                self.assertEqual(COMMIT, metadata["commit"])
                self.assertEqual("verified-remote-snapshot", metadata["target"]["materialization"])
                self.assertEqual("complete", evidence["cleanup"]["status"])
                self.assertEqual("complete", summary["cleanup_status"])
                self.assertEqual("complete", resources["acquisition"]["cleanup_status"])
                self.assertEqual(COMMIT, resources["acquisition"]["resolved_commit"])
                self.assertFalse(export.exists())
                self.assertEqual(
                    [
                        "validating-source", "acquiring", "resolving-commit", "exporting",
                        "analyzing", "scanning", "verifying", "reporting", "cleaning-up",
                    ],
                    phases,
                )

    def test_gitlab_snapshot_produces_final_report_with_real_scan_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            export = root / "export"
            export.mkdir()
            (export / "app.py").write_text(
                "value = request.args.get('name')\nquery = f\"SELECT * FROM users WHERE name='{value}'\"\ncursor.execute(query)\n",
                encoding="utf-8",
            )
            source = "https://gitlab.com/example/security/fixture.git"
            normalized = "https://gitlab.com/example/security/fixture"
            acquisition = AcquisitionResult(
                source=source,
                normalized_source=normalized,
                requested_revision=COMMIT,
                resolved_commit=COMMIT,
                status="ready",
                method="fake-offline-export",
                cache_status="fixture",
                network_used=False,
                export_path=str(export),
                exported_files=1,
                exported_bytes=(export / "app.py").stat().st_size,
                job_id="gitlab-runtime",
            )
            config = AuditConfig.default()
            config.graph.mode = "legacy"
            config.remote_acquisition.enabled = True
            summary = run_audit(
                source,
                config,
                root / "runs",
                requested_revision=COMMIT,
                acquisition_service=_FakeAcquisitionService(acquisition),
            )
            report = json.loads(
                (Path(summary["run_dir"]) / "reports" / "report.json").read_text(encoding="utf-8")
            )
            self.assertEqual("completed", report["run_status"])
            self.assertEqual("gitlab", report["target_metadata"]["target"]["kind"])
            self.assertEqual(source, report["acquisition"]["original_source"])
            self.assertEqual(normalized, report["acquisition"]["normalized_source"])
            self.assertEqual(COMMIT, report["acquisition"]["resolved_commit"])
            self.assertEqual(["app.py"], report["acquisition"]["scanned_files"])
            self.assertEqual("complete", report["acquisition"]["cleanup_status"])
            self.assertGreater(report["executive_summary"]["verification_candidate_count"], 0)
            self.assertTrue(report["verification_candidates"])
            self.assertFalse(export.exists())

    def test_empty_remote_scope_fails_and_is_cleaned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            export = root / "export"
            (export / "tests").mkdir(parents=True)
            (export / "tests" / "test_only.py").write_text("assert True", encoding="utf-8")
            source = "https://github.com/example/empty"
            acquisition = AcquisitionResult(
                source=source,
                normalized_source=source,
                requested_revision=COMMIT,
                resolved_commit=COMMIT,
                status="ready",
                export_path=str(export),
                exported_files=1,
                exported_bytes=11,
                job_id="empty-job",
            )
            service = _FakeAcquisitionService(acquisition)
            config = AuditConfig.default()
            config.remote_acquisition.enabled = True
            with self.assertRaisesRegex(AcquisitionError, "empty-remote-scope"):
                run_audit(
                    source,
                    config,
                    root / "runs",
                    requested_revision=COMMIT,
                    acquisition_service=service,
                )
            self.assertFalse(export.exists())


class _NoopRunner:
    def __init__(self):
        self.submissions = []

    def submit(self, job_id, request):
        self.submissions.append((job_id, request))


class _FakeAcquisitionService:
    def __init__(self, result: AcquisitionResult, cleanup_fails: bool = False):
        self.result = result
        self.cleanup_fails = cleanup_fails

    def acquire(self, _request, **_kwargs):
        callback = _kwargs.get("progress_callback")
        if callback:
            for phase in ("acquiring", "resolving-commit", "exporting"):
                callback(phase)
        return self.result

    def cleanup(self, result):
        if self.cleanup_fails:
            result.cleanup = AcquisitionCleanup(status="failed", attempts=1, reason="cleanup-failed")
            return result.cleanup
        if result.export_path:
            shutil.rmtree(result.export_path, ignore_errors=True)
        result.cleanup = AcquisitionCleanup(status="complete", attempts=1)
        return result.cleanup


def _legacy_config() -> Path:
    path = Path(tempfile.mkdtemp()) / "legacy.json"
    path.write_text("{}", encoding="utf-8")
    return path


def _git(args: list[str], cwd: Path) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
    )
    if completed.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {completed.stderr}")
    return completed.stdout


def _write_tar(path: Path, members: list[tuple[str, bytes, str]]) -> None:
    with tarfile.open(path, "w") as handle:
        for name, content, kind in members:
            info = tarfile.TarInfo(name)
            if kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "target"
                handle.addfile(info)
            else:
                info.size = len(content)
                handle.addfile(info, io.BytesIO(content))
