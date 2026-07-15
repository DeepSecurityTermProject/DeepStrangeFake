from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import anyio
import httpx

from audit_agent.config import AuditConfig
from audit_agent.repository_acquisition import (
    AcquisitionError,
    GitCommandResult,
    normalize_remote_source,
    resolve_remote_revision,
)
from audit_agent.server.app import create_app
from audit_agent.server.job_store import JobStore
from audit_agent.server.preflight import PreflightError, PreflightService, configured_local_roots
from audit_agent.server.runner import ScanJobRunner


COMMIT = "a" * 40
SECOND_COMMIT = "b" * 40


class ASGITestClient:
    def __init__(self, app):
        self.app = app

    def get(self, url: str):
        return anyio.run(self._request, "GET", url, None)

    def post(self, url: str, json: dict | None = None):
        return anyio.run(self._request, "POST", url, json)

    def patch(self, url: str, json: dict | None = None):
        return anyio.run(self._request, "PATCH", url, json)

    async def _request(self, method: str, url: str, payload: dict | None):
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.request(method, url, json=payload)


class RecordingRunner:
    def __init__(self):
        self.submitted: list[tuple[str, object]] = []
        self._lock = threading.Lock()

    def submit(self, job_id, request):
        with self._lock:
            self.submitted.append((job_id, request))


def remote_config(root: Path) -> AuditConfig:
    config = AuditConfig.default()
    config.remote_acquisition.enabled = True
    config.remote_acquisition.network_enabled = True
    config.remote_acquisition.cache_root = str(root / "cache")
    config.remote_acquisition.work_root = str(root / "work")
    config.integration.load_env_file = False
    return config


def fake_remote_resolver(source, *, revision, revision_type, config):
    normalized = normalize_remote_source(source, config.allowed_hosts)
    requested = revision or "HEAD"
    resolved = SECOND_COMMIT if revision_type == "tag" else COMMIT
    return normalized, requested, resolved


class WorkspaceStoreTests(unittest.TestCase):
    def test_sqlite_projects_are_unique_and_runs_are_transactionally_related(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "source"
            source_root.mkdir()
            store = JobStore(root / "jobs.json")
            source = {"kind": "local", "path": str(source_root)}

            first = store.create_job("source", root / "runs", source=source)
            second = store.create_job("source", root / "runs", source={"kind": "local", "path": str(source_root / ".")})

            self.assertEqual(first.project_id, second.project_id)
            self.assertEqual(len(store.list_projects(status="all")), 1)
            self.assertEqual(len(store.list_jobs(project_id=first.project_id)), 2)
            self.assertEqual(store.workspace.journal_mode(), "wal")
            self.assertTrue(store.db_path.is_file())
            self.assertFalse((root / "jobs.json").exists())

    def test_project_and_first_run_roll_back_together_on_insert_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_source = root / "first"
            second_source = root / "second"
            first_source.mkdir()
            second_source.mkdir()
            store = JobStore(root / "jobs.json")
            existing = store.create_job(
                "first",
                root / "runs",
                source={"kind": "local", "path": str(first_source)},
            )
            duplicate_record = existing.to_dict()
            duplicate_record["target"] = "second"
            duplicate_record["project_id"] = ""

            with self.assertRaises(sqlite3.IntegrityError):
                store.workspace.create_job_record(
                    duplicate_record,
                    source={"kind": "local", "path": str(second_source)},
                )

            self.assertIsNone(
                store.get_project_by_source({"kind": "local", "path": str(second_source)})
            )
            self.assertEqual(len(store.list_projects(status="all")), 1)

    def test_concurrent_run_creation_does_not_lose_updates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "source"
            source_root.mkdir()
            store = JobStore(root / "jobs.json")
            project, _ = store.create_or_get_project({"kind": "local", "path": str(source_root)})

            def create(index: int):
                return store.create_job(
                    f"source-{index}",
                    root / "runs",
                    source={"kind": "local", "path": str(source_root)},
                    project_id=project.project_id,
                ).job_id

            with ThreadPoolExecutor(max_workers=4) as executor:
                created = list(executor.map(create, range(12)))

            self.assertEqual(len(set(created)), 12)
            self.assertEqual(len(store.list_jobs(project_id=project.project_id)), 12)

    def test_project_lifecycle_blocks_active_runs_and_preserves_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "source"
            source_root.mkdir()
            store = JobStore(root / "jobs.json")
            job = store.create_job(
                "source",
                root / "runs",
                source={"kind": "local", "path": str(source_root)},
            )

            with self.assertRaisesRegex(ValueError, "project-has-active-runs"):
                store.archive_project(job.project_id)
            store.mark_cancelled(job.job_id)
            archived = store.archive_project(job.project_id)
            self.assertEqual(archived.status, "archived")
            self.assertEqual(len(store.list_jobs(project_id=job.project_id)), 1)
            restored = store.restore_project(job.project_id)
            self.assertEqual(restored.status, "active")

    def test_legacy_import_is_idempotent_and_source_json_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "jobs.json"
            payload = {
                "jobs": [
                    {
                        "job_id": "JOB-legacy",
                        "target": "legacy-target",
                        "status": "succeeded",
                        "output_dir": str(root / "runs"),
                        "created_at": "2026-01-01T00:00:00+00:00",
                        "summary": {"validated_count": 1},
                    }
                ]
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            before = hashlib.sha256(path.read_bytes()).hexdigest()

            first = JobStore(path)
            second = JobStore(path)

            self.assertEqual(len(first.list_jobs()), 1)
            self.assertEqual(len(second.list_jobs()), 1)
            self.assertEqual(second.get("JOB-legacy").summary["validated_count"], 1)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)
            self.assertEqual(second.migration_diagnostics(), [])

    def test_malformed_legacy_file_records_diagnostic_without_resetting_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "jobs.json"
            store = JobStore(path)
            source_root = root / "source"
            source_root.mkdir()
            created = store.create_job(
                "source",
                root / "runs",
                source={"kind": "local", "path": str(source_root)},
            )
            path.write_text("{not-json", encoding="utf-8")

            reloaded = JobStore(path)

            self.assertEqual(reloaded.get(created.job_id).job_id, created.job_id)
            self.assertEqual(len(reloaded.migration_diagnostics()), 1)
            self.assertEqual(path.read_text(encoding="utf-8"), "{not-json")


class SourcePreflightTests(unittest.TestCase):
    def test_local_preflight_detects_metadata_and_duplicate_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "app.py").write_text("print('ok')\n", encoding="utf-8")
            (source / "package.json").write_text("{}", encoding="utf-8")
            store = JobStore(root / "jobs.json")
            project, _ = store.create_or_get_project({"kind": "local", "path": str(source)})
            service = PreflightService(store, AuditConfig.default(), allowed_local_roots=[root])

            result = service.preflight({"kind": "local", "path": str(source)})

            self.assertEqual(result.existing_project_id, project.project_id)
            self.assertEqual(result.metadata["file_count"], 2)
            self.assertIn("package.json", result.metadata["dependency_files"])
            self.assertEqual(result.languages[0]["name"], "Python")
            self.assertEqual(result.policy_version, "source-preflight.v1")
            consumed = service.consume(result.token, expected_source=result.source, project_id=project.project_id)
            self.assertEqual(consumed.source_identity, project.source_identity)
            with self.assertRaisesRegex(PreflightError, "preflight-token-used"):
                service.consume(result.token, expected_source=result.source)

    def test_local_preflight_denies_outside_root_and_budget_overflow(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_root = Path(outside)
            store = JobStore(root / "jobs.json")
            service = PreflightService(store, AuditConfig.default(), allowed_local_roots=[root])
            with self.assertRaisesRegex(PreflightError, "outside-allowed-roots"):
                service.preflight({"kind": "local", "path": str(outside_root)})

            source = root / "source"
            source.mkdir()
            (source / "one.py").write_text("1", encoding="utf-8")
            (source / "two.py").write_text("2", encoding="utf-8")
            config = AuditConfig.default()
            config.audit_scope.max_files = 1
            limited = PreflightService(store, config, allowed_local_roots=[root])
            with self.assertRaisesRegex(PreflightError, "file-budget-exceeded"):
                limited.preflight({"kind": "local", "path": str(source)})

    def test_default_local_roots_cover_all_visible_filesystems_and_can_be_narrowed(self):
        roots = configured_local_roots({})

        self.assertTrue(roots)
        self.assertTrue(
            any(Path.cwd().resolve() == root or root in Path.cwd().resolve().parents for root in roots)
        )
        for root in roots:
            self.assertEqual(root, Path(root.anchor).resolve(strict=False))

        with tempfile.TemporaryDirectory() as tmp:
            narrowed = configured_local_roots({"AUDIT_LOCAL_ALLOWED_ROOTS": tmp})
            self.assertEqual(narrowed, [Path(tmp).resolve()])

    def test_preflight_token_binds_revision_and_expires(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = remote_config(root)
            store = JobStore(root / "jobs.json")
            service = PreflightService(
                store,
                config,
                remote_resolver=fake_remote_resolver,
            )
            result = service.preflight(
                {"kind": "github", "url": "https://github.com/acme/repo"},
                revision_type="branch",
                revision="main",
            )
            mismatched = dict(result.source)
            mismatched["commit"] = SECOND_COMMIT
            with self.assertRaisesRegex(PreflightError, "revision-mismatch"):
                service.consume(result.token, expected_source=mismatched)
            result.expires_at_epoch = time.time() - 1
            with self.assertRaisesRegex(PreflightError, "token-invalid|token-expired"):
                service.consume(result.token, expected_source=result.source)

    def test_public_revision_resolver_handles_branch_tag_commit_and_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = remote_config(Path(tmp))

            def runner(argv, cwd, env, timeout):
                ref = argv[-1]
                if ref == "refs/heads/main":
                    stdout = f"{COMMIT}\trefs/heads/main\n"
                elif ref.endswith("^{}"):
                    stdout = f"{'c' * 40}\trefs/tags/v1\n{SECOND_COMMIT}\trefs/tags/v1^{{}}\n"
                else:
                    stdout = f"{COMMIT}\tHEAD\n"
                return GitCommandResult(0, stdout=stdout)

            _source, requested, branch = resolve_remote_revision(
                "https://github.com/acme/repo",
                revision="main",
                revision_type="branch",
                config=config.remote_acquisition,
                command_runner=runner,
            )
            self.assertEqual((requested, branch), ("main", COMMIT))
            _source, requested, tag = resolve_remote_revision(
                "https://github.com/acme/repo",
                revision="v1",
                revision_type="tag",
                config=config.remote_acquisition,
                command_runner=runner,
            )
            self.assertEqual((requested, tag), ("v1", SECOND_COMMIT))
            _source, requested, commit = resolve_remote_revision(
                "https://github.com/acme/repo",
                revision=SECOND_COMMIT.upper(),
                revision_type="commit",
                config=config.remote_acquisition,
                command_runner=runner,
            )
            self.assertEqual((requested, commit), (SECOND_COMMIT, SECOND_COMMIT))
            with self.assertRaisesRegex(AcquisitionError, "revision-policy-denied"):
                resolve_remote_revision(
                    "https://github.com/acme/repo",
                    revision="../unsafe",
                    revision_type="branch",
                    config=config.remote_acquisition,
                    command_runner=runner,
                )
            with self.assertRaisesRegex(AcquisitionError, "source-policy-denied"):
                resolve_remote_revision(
                    "https://token@github.com/acme/repo",
                    revision="main",
                    revision_type="branch",
                    config=config.remote_acquisition,
                    command_runner=runner,
                )


class ProjectApiTests(unittest.TestCase):
    def test_all_source_shapes_use_real_runner_queue_and_project_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local_source = root / "local-source"
            local_source.mkdir()
            (local_source / "app.py").write_text("print('fixture')\n", encoding="utf-8")
            store = JobStore(root / "jobs.json")
            config = remote_config(root)
            calls: list[tuple[str, dict]] = []

            def fake_run_audit(target, _config, output_dir, **kwargs):
                calls.append((target, kwargs))
                return {
                    "status": "succeeded",
                    "run_dir": str(Path(output_dir) / f"run-{len(calls)}"),
                    "validated_count": 0,
                }

            runner = ScanJobRunner(store, run_audit_func=fake_run_audit, max_workers=1, config=config)
            service = PreflightService(
                store,
                config,
                allowed_local_roots=[root],
                remote_resolver=fake_remote_resolver,
            )
            client = ASGITestClient(
                create_app(
                    job_store=store,
                    runner=runner,
                    output_dir=root / "runs",
                    config=config,
                    preflight_service=service,
                )
            )
            try:
                sources = (
                    ({"kind": "local", "path": str(local_source)}, {}),
                    ({"kind": "github", "url": "https://github.com/acme/course"}, {"revision_type": "branch", "revision": "main"}),
                    ({"kind": "gitlab", "url": "https://gitlab.com/acme/course"}, {"revision_type": "tag", "revision": "v1"}),
                )
                job_ids = []
                for source, revision in sources:
                    preview_response = client.post(
                        "/api/sources/preflight",
                        json={"source": source, **revision},
                    )
                    self.assertEqual(preview_response.status_code, 200, preview_response.text)
                    preview = preview_response.json()
                    queued = client.post(
                        "/api/runs",
                        json={
                            "source": preview["source"],
                            "preflight_token": preview["preflight_token"],
                            "graph_mode": "agent-led",
                        },
                    )
                    self.assertEqual(queued.status_code, 202, queued.text)
                    self.assertTrue(queued.json()["project_id"].startswith("PRJ-"))
                    job_ids.append(queued.json()["job_id"])

                deadline = time.time() + 3
                while time.time() < deadline and any(store.get(job_id).status not in {"succeeded", "failed"} for job_id in job_ids):
                    time.sleep(0.01)

                self.assertEqual([store.get(job_id).status for job_id in job_ids], ["succeeded"] * 3)
                self.assertEqual(len(calls), 3)
                self.assertEqual(len(store.list_projects(status="all")), 3)
                self.assertTrue(all(store.get(job_id).project_id for job_id in job_ids))
                self.assertIn("acquisition_service", calls[1][1])
                self.assertIn("acquisition_service", calls[2][1])
            finally:
                runner.executor.shutdown(wait=True, cancel_futures=True)

    def test_project_catalog_preflight_scan_and_lifecycle_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "app.py").write_text("print('safe')\n", encoding="utf-8")
            store = JobStore(root / "jobs.json")
            runner = RecordingRunner()
            config = remote_config(root)
            preflight = PreflightService(
                store,
                config,
                allowed_local_roots=[root],
                remote_resolver=fake_remote_resolver,
            )
            client = ASGITestClient(
                create_app(
                    job_store=store,
                    runner=runner,
                    output_dir=root / "runs",
                    config=config,
                    preflight_service=preflight,
                )
            )

            preview = client.post(
                "/api/sources/preflight",
                json={"source": {"kind": "local", "path": str(source)}},
            )
            self.assertEqual(preview.status_code, 200)
            first = client.post(
                "/api/runs",
                json={
                    "source": preview.json()["source"],
                    "preflight_token": preview.json()["preflight_token"],
                    "graph_mode": "agent-led",
                },
            )
            self.assertEqual(first.status_code, 202)
            project_id = first.json()["project_id"]
            self.assertEqual(first.json()["run_url"], f"/projects/{project_id}/runs/{first.json()['job_id']}")
            self.assertEqual(len(runner.submitted), 1)

            catalog = client.get("/api/projects?status=active")
            self.assertEqual(catalog.status_code, 200)
            self.assertEqual(catalog.json()["total"], 1)
            self.assertEqual(catalog.json()["projects"][0]["latest_run"]["job_id"], first.json()["job_id"])
            renamed = client.patch(
                f"/api/projects/{project_id}", json={"display_name": "Course Audit"}
            )
            self.assertEqual(renamed.json()["display_name"], "Course Audit")

            duplicate = client.post(
                "/api/sources/preflight",
                json={"source": {"kind": "local", "path": str(source / ".")}},
            )
            self.assertEqual(duplicate.json()["existing_project_id"], project_id)
            second = client.post(
                f"/api/projects/{project_id}/runs",
                json={
                    "source": duplicate.json()["source"],
                    "preflight_token": duplicate.json()["preflight_token"],
                },
            )
            self.assertEqual(second.status_code, 202)
            self.assertEqual(second.json()["project_id"], project_id)
            self.assertEqual(len(client.get(f"/api/projects/{project_id}/runs").json()["jobs"]), 2)

            blocked = client.post(f"/api/projects/{project_id}/archive")
            self.assertEqual(blocked.status_code, 409)
            store.mark_cancelled(first.json()["job_id"])
            store.mark_cancelled(second.json()["job_id"])
            archived = client.post(f"/api/projects/{project_id}/archive")
            self.assertEqual(archived.json()["status"], "archived")
            self.assertEqual(client.get("/api/projects?status=active").json()["total"], 0)
            restored = client.post(f"/api/projects/{project_id}/restore")
            self.assertEqual(restored.json()["status"], "active")

    def test_public_github_and_gitlab_preflight_queue_real_project_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = JobStore(root / "jobs.json")
            runner = RecordingRunner()
            config = remote_config(root)
            service = PreflightService(store, config, remote_resolver=fake_remote_resolver)
            client = ASGITestClient(
                create_app(
                    job_store=store,
                    runner=runner,
                    output_dir=root / "runs",
                    config=config,
                    preflight_service=service,
                )
            )
            for kind, url in (
                ("github", "https://github.com/acme/repo"),
                ("gitlab", "https://gitlab.com/acme/group/repo"),
            ):
                with self.subTest(kind=kind):
                    preview = client.post(
                        "/api/sources/preflight",
                        json={
                            "source": {"kind": kind, "url": url},
                            "revision_type": "branch",
                            "revision": "main",
                        },
                    )
                    self.assertEqual(preview.status_code, 200)
                    created = client.post(
                        "/api/runs",
                        json={
                            "source": preview.json()["source"],
                            "preflight_token": preview.json()["preflight_token"],
                        },
                    )
                    self.assertEqual(created.status_code, 202)
                    self.assertTrue(created.json()["project_id"].startswith("PRJ-"))
            self.assertEqual(len(runner.submitted), 2)

    def test_project_route_requires_matching_one_time_preflight(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            store = JobStore(root / "jobs.json")
            project, _ = store.create_or_get_project({"kind": "local", "path": str(source)})
            service = PreflightService(store, AuditConfig.default(), allowed_local_roots=[root])
            client = ASGITestClient(
                create_app(
                    job_store=store,
                    runner=RecordingRunner(),
                    output_dir=root / "runs",
                    preflight_service=service,
                )
            )
            without = client.post(
                f"/api/projects/{project.project_id}/runs",
                json={"source": {"kind": "local", "path": str(source)}},
            )
            self.assertEqual(without.status_code, 422)
            preview = client.post(
                "/api/sources/preflight",
                json={"source": {"kind": "local", "path": str(source)}},
            ).json()
            payload = {"source": preview["source"], "preflight_token": preview["preflight_token"]}
            self.assertEqual(client.post(f"/api/projects/{project.project_id}/runs", json=payload).status_code, 202)
            reused = client.post(f"/api/projects/{project.project_id}/runs", json=payload)
            self.assertEqual(reused.status_code, 409)
            self.assertEqual(reused.json()["detail"]["error"], "preflight-token-used")


if __name__ == "__main__":
    unittest.main()
