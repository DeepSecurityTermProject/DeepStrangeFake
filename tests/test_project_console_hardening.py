from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import anyio
import httpx

from audit_agent.config import AuditConfig, RemoteAcquisitionConfig
from audit_agent.message_bus import MessageBus
from audit_agent.repository_acquisition import (
    AcquisitionError,
    normalize_remote_source,
    resolve_remote_revision,
)
from audit_agent.server.app import create_app
from audit_agent.server.audit_events import AUDIT_EVENT_MAX_BYTES
from audit_agent.server.job_store import JobStore
from audit_agent.server.preflight import PreflightError, PreflightService
from audit_agent.server.workspace_store import SCHEMA_VERSION, WorkspaceStore


class ASGIClient:
    def __init__(self, app):
        self.app = app

    def get(self, url: str, *, headers: dict[str, str] | None = None):
        return anyio.run(self._request, "GET", url, None, headers)

    def post(self, url: str, payload: dict | None = None):
        return anyio.run(self._request, "POST", url, payload, None)

    async def _request(
        self,
        method: str,
        url: str,
        payload: dict | None,
        headers: dict[str, str] | None,
    ):
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.request(method, url, json=payload, headers=headers)


class RecordingRunner:
    def __init__(self):
        self.submitted: list[str] = []

    def submit(self, job_id, request):
        self.submitted.append(job_id)


class LegacyWebContractTests(unittest.TestCase):
    def test_legacy_run_and_artifact_contract_survives_project_import(self):
        contract = json.loads(
            (Path(__file__).with_name("legacy_web_api_contract.v1.json")).read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository = root / "repository"
            repository.mkdir()
            run_dir = root / "runs" / "legacy-runtime"
            (run_dir / "runtime_state").mkdir(parents=True)
            (run_dir / "messages").mkdir()
            (run_dir / "reports").mkdir()
            (run_dir / "runtime_state" / "state.json").write_text(
                json.dumps({"status": "succeeded", "tasks": []}), encoding="utf-8"
            )
            bus = MessageBus("legacy-runtime", run_dir / "messages" / "messages.jsonl")
            bus.publish("runtime", "analysis", "runtime.task", {"status": "succeeded"})
            (run_dir / "reports" / "report.json").write_text(
                json.dumps({"executive_summary": {"validated_count": 1}}), encoding="utf-8"
            )
            (run_dir / "reports" / "report.md").write_text("# Legacy report\n", encoding="utf-8")
            legacy_record = {
                "job_id": "JOB-legacy-contract",
                "target": str(repository),
                "status": "succeeded",
                "created_at": "2026-07-01T00:00:00+00:00",
                "started_at": "2026-07-01T00:00:01+00:00",
                "finished_at": "2026-07-01T00:00:02+00:00",
                "output_dir": str(root / "runs"),
                "run_dir": str(run_dir),
                "summary": {"validated_count": 1},
                "error": "",
                "source": {"kind": "local", "path": str(repository)},
                "phase": "complete",
                "requested_revision": None,
                "resolved_commit": None,
                "acquisition_summary": {},
                "acquisition_ref": None,
                "cleanup_status": None,
            }
            jobs_path = root / "jobs.json"
            original_jobs = json.dumps({"jobs": [legacy_record]}, ensure_ascii=False, indent=2)
            jobs_path.write_text(original_jobs, encoding="utf-8")

            store = JobStore(jobs_path)
            client = ASGIClient(create_app(job_store=store, runner=RecordingRunner()))
            response = client.get("/api/runs/JOB-legacy-contract")
            payload = response.json()

            self.assertEqual(response.status_code, 200)
            for field in contract["job_status_fields"]:
                self.assertIn(field, payload)
                self.assertEqual(payload[field], legacy_record[field])
            self.assertTrue(payload["project_id"].startswith("PRJ-"))
            scoped_path = f"/projects/{payload['project_id']}/runs/{payload['job_id']}"
            self.assertEqual(scoped_path.count("/"), 4)
            self.assertEqual(jobs_path.read_text(encoding="utf-8"), original_jobs)
            self.assertEqual(client.get("/api/runs/JOB-legacy-contract/runtime-state").json()["status"], "succeeded")
            self.assertIn("runtime_lifecycle", client.get("/api/runs/JOB-legacy-contract/replay-summary").json())
            self.assertEqual(
                client.get("/api/runs/JOB-legacy-contract/reports/report.json").json()["executive_summary"]["validated_count"],
                1,
            )
            self.assertIn("# Legacy report", client.get("/api/runs/JOB-legacy-contract/reports/report.md").text)

            created = client.post("/api/runs", {"target": str(repository)}).json()
            for field in contract["create_run_fields"]:
                self.assertIn(field, created)
            for field in contract["additive_fields"]:
                self.assertIn(field, created)


class StartupRecoveryTests(unittest.TestCase):
    def test_partially_applied_schema_is_completed_idempotently(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "workspace.sqlite3"
            connection = sqlite3.connect(db_path)
            try:
                connection.execute(
                    "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, "2026-07-01T00:00:00+00:00"),
                )
                connection.commit()
            finally:
                connection.close()
            first = WorkspaceStore(db_path)
            second = WorkspaceStore(db_path)
            with second.connection() as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
                versions = connection.execute("SELECT version FROM schema_migrations").fetchall()
            self.assertEqual(first.journal_mode(), "wal")
            self.assertTrue(
                {"projects", "runs", "migration_receipts", "event_index_state", "posture_snapshots", "finding_identities"}.issubset(tables)
            )
            self.assertEqual([row[0] for row in versions], [SCHEMA_VERSION])

    def test_stale_sqlite_writer_lock_fails_bounded_then_recovers(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = WorkspaceStore(Path(tmp) / "workspace.sqlite3", busy_timeout_ms=50)
            lock_connection = store._connect()
            lock_connection.execute("BEGIN IMMEDIATE")
            errors: list[Exception] = []

            def blocked_write():
                try:
                    store.create_or_get_project({"kind": "local", "path": str(Path(tmp) / "one")})
                except Exception as exc:  # Captured for the assertion in the parent thread.
                    errors.append(exc)

            worker = threading.Thread(target=blocked_write)
            worker.start()
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], sqlite3.OperationalError)
            lock_connection.rollback()
            lock_connection.close()
            project, created = store.create_or_get_project(
                {"kind": "local", "path": str(Path(tmp) / "one")}
            )
            self.assertTrue(created)
            self.assertTrue(project.project_id.startswith("PRJ-"))

    def test_restart_repairs_corrupt_event_tail_and_missing_artifacts_stay_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jobs_path = root / "jobs.json"
            db_path = root / "workspace.sqlite3"
            event_root = root / "events"
            store = JobStore(jobs_path, db_path=db_path, event_journal_root=event_root)
            job = store.create_job(str(root / "repository"), root / "runs")
            store.events.append(
                job.job_id,
                category="system",
                phase="queued",
                actor="test",
                title="persisted",
            )
            journal = store.events.journal_path(job.job_id)
            with journal.open("a", encoding="utf-8") as handle:
                handle.write('{"event_id":2')

            restarted = JobStore(jobs_path, db_path=db_path, event_journal_root=event_root)
            self.assertEqual([event.event_id for event in restarted.events.history(job.job_id)], [1, 2])
            self.assertEqual(restarted.workspace.get_event_index(job.job_id)["last_event_id"], 2)
            self.assertTrue(any(item["reason"] == "journal-truncated-at-line-3" for item in restarted.events.diagnostics()))
            client = ASGIClient(create_app(job_store=restarted, runner=RecordingRunner()))
            for suffix in ("runtime-state", "replay-summary", "reports/report.json"):
                response = client.get(f"/api/runs/{job.job_id}/{suffix}")
                self.assertEqual(response.status_code, 404)
                self.assertEqual(response.json()["detail"]["error"], "artifact-not-found")

    def test_interrupted_posture_backfill_is_idempotently_resumable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = JobStore(root / "jobs.json")
            first = store.create_job(str(root / "repository"), root / "runs")
            second = store.create_job(str(root / "repository"), root / "runs", project_id=first.project_id)
            store.mark_failed(first.job_id, "fixture failure")
            store.mark_failed(second.job_id, "fixture failure")
            with store.workspace.transaction(immediate=True) as connection:
                connection.execute("DELETE FROM posture_snapshots WHERE project_id = ?", (first.project_id,))

            original = store.workspace.upsert_posture_snapshot
            calls = 0

            def interrupted(snapshot):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise RuntimeError("simulated backfill interruption")
                return original(snapshot)

            with patch.object(store.workspace, "upsert_posture_snapshot", side_effect=interrupted):
                with self.assertRaises(RuntimeError):
                    store.posture.backfill_project(first.project_id)
            self.assertEqual(len(store.workspace.list_posture_snapshots(first.project_id)), 1)
            recovered = store.posture.backfill_project(first.project_id)
            repeated = store.posture.backfill_project(first.project_id)
            self.assertEqual([item["run_id"] for item in recovered], [first.job_id, second.job_id])
            self.assertEqual([item["run_id"] for item in repeated], [first.job_id, second.job_id])


class ConsoleSecurityRegressionTests(unittest.TestCase):
    def test_path_credentials_and_revision_inputs_fail_closed_without_secret_echo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            allowed = root / "allowed"
            outside = root / "outside"
            allowed.mkdir()
            outside.mkdir()
            store = JobStore(root / "jobs.json")
            service = PreflightService(store, AuditConfig.default(), allowed_local_roots=[allowed])
            with self.assertRaises(PreflightError) as path_error:
                service.preflight({"kind": "local", "path": str(allowed / ".." / "outside")})
            self.assertEqual(path_error.exception.reason, "local-source-outside-allowed-roots")

            credential_url = "https://course-user:course-password@github.com/example/repository"
            with self.assertRaises(AcquisitionError) as credential_error:
                normalize_remote_source(credential_url)
            self.assertEqual(credential_error.exception.reason, "source-policy-denied")
            self.assertNotIn("course-password", str(credential_error.exception))

            called = False

            def forbidden_runner(*args, **kwargs):
                nonlocal called
                called = True
                raise AssertionError("unsafe revision reached Git")

            config = RemoteAcquisitionConfig(enabled=True, network_enabled=True)
            with self.assertRaises(AcquisitionError) as revision_error:
                resolve_remote_revision(
                    "https://github.com/example/repository",
                    revision="main;touch-owned",
                    revision_type="branch",
                    config=config,
                    command_runner=forbidden_runner,
                )
            self.assertEqual(revision_error.exception.reason, "revision-policy-denied")
            self.assertFalse(called)

    def test_artifact_escape_sse_injection_secret_and_oversize_payloads_are_contained(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = JobStore(root / "jobs.json")
            job = store.create_job(str(root / "repository"), root / "runs")
            run_dir = root / "runs" / "runtime"
            (run_dir / "reports").mkdir(parents=True)
            (run_dir / "prompts").mkdir()
            (run_dir / "reports" / "public.txt").write_text("public", encoding="utf-8")
            (run_dir / "prompts" / "private.txt").write_text("private", encoding="utf-8")
            injected = store.events.append(
                job.job_id,
                category="system",
                phase="running",
                actor="fixture",
                title="safe title\n\nid: 999\nevent: evil",
                summary={
                    "message": "safe\n\nid: 999\nevent: evil",
                    "api_key": "course-secret-value",
                    "prompt": "private prompt",
                    "raw_response": "private response",
                    "authorization": "Bearer course-secret-value",
                    "large": "x" * 100_000,
                },
            )
            self.assertIsNotNone(injected)
            store.mark_succeeded(job.job_id, {"run_dir": str(run_dir)})
            client = ASGIClient(create_app(job_store=store, runner=RecordingRunner(), event_heartbeat_seconds=0.01))

            self.assertEqual(
                client.get(f"/api/runs/{job.job_id}/artifacts/reports/public.txt").status_code,
                200,
            )
            escaped = client.get(
                f"/api/runs/{job.job_id}/artifacts/reports%5C..%5Cprompts%5Cprivate.txt"
            )
            self.assertEqual(escaped.status_code, 403)
            self.assertEqual(escaped.json()["detail"]["error"], "artifact-access-denied")

            stream = client.get(f"/api/runs/{job.job_id}/events")
            self.assertEqual(stream.status_code, 200)
            self.assertNotIn("course-secret-value", stream.text)
            self.assertFalse(any(line == "id: 999" for line in stream.text.splitlines()))
            self.assertFalse(any(line == "event: evil" for line in stream.text.splitlines()))
            journal_text = store.events.journal_path(job.job_id).read_text(encoding="utf-8")
            self.assertNotIn("private prompt", journal_text)
            self.assertNotIn("private response", journal_text)
            self.assertNotIn("course-secret-value", journal_text)
            for line in journal_text.splitlines():
                self.assertLessEqual(len(line.encode("utf-8")), AUDIT_EVENT_MAX_BYTES)


class OperationalLimitTests(unittest.TestCase):
    def test_cancel_completion_race_commits_one_immutable_terminal_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = JobStore(root / "jobs.json")
            for index in range(8):
                job = store.create_job(str(root / f"repository-{index}"), root / "runs")
                store.mark_running(job.job_id)
                barrier = threading.Barrier(3)

                def complete():
                    barrier.wait()
                    store.mark_succeeded(job.job_id, {"validated_count": 1})

                def cancel():
                    barrier.wait()
                    store.mark_cancelled(job.job_id)

                complete_thread = threading.Thread(target=complete)
                cancel_thread = threading.Thread(target=cancel)
                complete_thread.start()
                cancel_thread.start()
                barrier.wait()
                complete_thread.join(timeout=2)
                cancel_thread.join(timeout=2)
                self.assertFalse(complete_thread.is_alive())
                self.assertFalse(cancel_thread.is_alive())

                winner = store.get(job.job_id)
                self.assertIn(winner.status, {"succeeded", "cancelled"})
                winner_status = winner.status
                store.mark_failed(job.job_id, "late failure")
                store.mark_degraded(job.job_id, {"late": True})
                store.mark_succeeded(job.job_id, {"late": True})
                store.mark_cancelled(job.job_id)
                self.assertEqual(store.get(job.job_id).status, winner_status)
                terminal_events = [
                    event for event in store.events.history(job.job_id) if event.terminal
                ]
                self.assertEqual(len(terminal_events), 1)
                self.assertEqual(terminal_events[0].status, winner_status)

    def test_project_and_run_lists_are_paginated_with_hard_input_bounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = JobStore(root / "jobs.json")
            first = store.create_job(str(root / "repository-0"), root / "runs")
            for index in range(1, 5):
                store.create_job(
                    str(root / "repository-0"),
                    root / "runs",
                    project_id=first.project_id,
                )
            for index in range(1, 5):
                store.create_job(str(root / f"repository-{index}"), root / "runs")
            client = ASGIClient(create_app(job_store=store, runner=RecordingRunner()))

            projects = client.get("/api/projects?limit=2&offset=1")
            self.assertEqual(projects.status_code, 200)
            self.assertEqual(len(projects.json()["projects"]), 2)
            self.assertEqual(projects.json()["total"], 5)
            self.assertEqual(projects.json()["limit"], 2)
            self.assertEqual(projects.json()["offset"], 1)
            self.assertTrue(projects.json()["has_more"])

            project_runs = client.get(
                f"/api/projects/{first.project_id}/runs?limit=2&offset=2"
            )
            self.assertEqual(project_runs.status_code, 200)
            self.assertEqual(len(project_runs.json()["jobs"]), 2)
            self.assertEqual(project_runs.json()["total"], 5)
            self.assertTrue(project_runs.json()["has_more"])

            global_runs = client.get("/api/runs?limit=4&offset=8")
            self.assertEqual(global_runs.status_code, 200)
            self.assertEqual(len(global_runs.json()["jobs"]), 1)
            self.assertEqual(global_runs.json()["total"], 9)
            self.assertFalse(global_runs.json()["has_more"])

            self.assertEqual(client.get("/api/projects?limit=201").status_code, 422)
            self.assertEqual(client.get("/api/runs?offset=100001").status_code, 422)
            self.assertEqual(client.get(f"/api/projects?query={'x' * 201}").status_code, 422)
            limits = client.get("/api/options").json()["console_limits"]
            self.assertEqual(limits["pagination"]["max_limit"], 200)
            self.assertFalse(limits["retention"]["automatic_deletion"])

    def test_event_snapshot_replay_window_and_subscriber_counts_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = JobStore(root / "jobs.json")
            store.events.replay_limit = 3
            store.events.max_subscribers_per_run = 1
            store.events.max_subscribers_total = 1
            job = store.create_job(str(root / "repository"), root / "runs")
            for index in range(4):
                store.events.append(
                    job.job_id,
                    category="system",
                    phase="running",
                    actor="fixture",
                    title=f"event-{index}",
                )
            client = ASGIClient(create_app(job_store=store, runner=RecordingRunner()))

            snapshot = client.get(f"/api/runs/{job.job_id}/events/snapshot").json()
            self.assertEqual(snapshot["journal_event_count"], 5)
            self.assertEqual(snapshot["last_event_id"], 5)
            self.assertEqual([item["event_id"] for item in snapshot["events"]], [3, 4, 5])
            self.assertTrue(snapshot["history_truncated"])
            self.assertEqual(snapshot["history_status"], "truncated")
            self.assertEqual(snapshot["history_reason"], "replay-window-limit")

            stale = client.get(f"/api/runs/{job.job_id}/events?cursor=0")
            self.assertEqual(stale.status_code, 409)
            self.assertEqual(stale.json()["detail"]["error"], "event-replay-limit-exceeded")
            self.assertEqual(stale.json()["detail"]["reset_cursor"], 5)

            self.assertTrue(store.events.try_acquire_subscriber(job.job_id))
            limited = client.get(f"/api/runs/{job.job_id}/events?cursor=5")
            self.assertEqual(limited.status_code, 429)
            self.assertEqual(limited.headers["retry-after"], "5")
            store.events.release_subscriber(job.job_id)
            self.assertEqual(store.events.subscriber_usage()["total"], 0)


if __name__ == "__main__":
    unittest.main()
