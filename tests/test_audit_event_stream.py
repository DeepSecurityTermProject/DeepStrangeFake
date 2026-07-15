from __future__ import annotations

import json
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi.testclient import TestClient

from audit_agent.models import MessageEnvelope
from audit_agent.server.app import create_app
from audit_agent.server.audit_events import (
    AUDIT_EVENT_MAX_BYTES,
    AUDIT_EVENT_SCHEMA_VERSION,
)
from audit_agent.server.job_store import JobStore


class _Runner:
    def __init__(self, store: JobStore):
        self.store = store

    def submit(self, job_id, request):
        return None

    def cancel(self, job_id):
        return self.store.mark_cancelled(job_id)


class AuditEventJournalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory(dir=".")
        self.root = Path(self.temporary.name)
        self.store = JobStore(
            self.root / "jobs.json",
            db_path=self.root / "workspace.sqlite3",
            event_journal_root=self.root / "events",
        )
        self.job = self.store.create_job(str(self.root), self.root / "runs")

    def tearDown(self):
        self.temporary.cleanup()

    def test_schema_ordering_concurrency_and_terminal_consistency(self):
        self.store.mark_running(self.job.job_id)

        def append(index: int):
            return self.store.events.append(
                self.job.job_id,
                category="evidence",
                phase="analyzing",
                actor=f"agent-{index % 3}",
                title=f"Evidence {index}",
                summary={"index": index},
            )

        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(append, range(40)))
        terminal = self.store.mark_succeeded(self.job.job_id, {})
        ignored = self.store.events.append(
            self.job.job_id,
            category="tool",
            phase="complete",
            actor="late-tool",
            title="Late event",
        )
        repeated = self.store.events.project_lifecycle(terminal, "succeeded")
        events = self.store.events.history(self.job.job_id)
        self.assertEqual([item.event_id for item in events], list(range(1, len(events) + 1)))
        self.assertEqual(events[-1].status, "succeeded")
        self.assertIsNone(ignored)
        self.assertEqual(repeated.event_id, events[-1].event_id)
        self.assertTrue(all(item.schema_version == AUDIT_EVENT_SCHEMA_VERSION for item in events))

    def test_allowlist_redaction_bounding_and_authorized_artifacts(self):
        self.store.mark_running(self.job.job_id)
        runtime_root = Path(self.job.output_dir) / "runtime-1"
        report = runtime_root / "reports" / "report.json"
        prompt = runtime_root / "prompts" / "private.txt"
        report.parent.mkdir(parents=True, exist_ok=True)
        prompt.parent.mkdir(parents=True, exist_ok=True)
        report.write_text("{}", encoding="utf-8")
        prompt.write_text("private", encoding="utf-8")
        message = MessageEnvelope(
            run_id="runtime-1",
            sender="tool-broker",
            recipient="analysis",
            message_type="runtime.tool",
            payload={
                "role": "analysis",
                "tool": "pattern-scan",
                "status": "ok",
                "success": True,
                "message": "api_key='super-secret-value' " + ("x" * 100_000),
                "reasoning": "must never be projected",
            },
            artifact_refs=[str(report), str(prompt)],
        )
        projected = self.store.events.project_message(self.job.job_id, self.store.get(self.job.job_id), message)
        unsupported = self.store.events.project_message(
            self.job.job_id,
            self.store.get(self.job.job_id),
            MessageEnvelope("runtime-1", "llm", "internal", "llm.internal.raw", {"raw_response": "secret"}),
        )
        budget = self.store.events.project_message(
            self.job.job_id,
            self.store.get(self.job.job_id),
            MessageEnvelope(
                "runtime-1",
                "orchestrator",
                "runtime",
                "investigation.budget",
                {"role": "orchestrator", "remaining": {"tokens": 12_000, "tool_calls": 5}},
            ),
        )
        direct = self.store.events.append(
            self.job.job_id,
            category="rationale",
            phase="analyzing",
            actor="analysis",
            title="Public rationale summary",
            summary={"rationale_summary": "bounded", "chain_of_thought": "private", "items": ["z" * 5_000] * 40},
        )
        self.assertIsNotNone(projected)
        self.assertIsNone(unsupported)
        self.assertEqual(budget.summary["remaining"]["remaining_token_budget"], 12_000)
        serialized = json.dumps(projected.to_dict(), ensure_ascii=False).encode("utf-8")
        self.assertLessEqual(len(serialized), AUDIT_EVENT_MAX_BYTES)
        self.assertIn("[REDACTED]", projected.summary["message"])
        self.assertNotIn("super-secret-value", serialized.decode("utf-8"))
        self.assertEqual(projected.artifact_refs, [f"/api/runs/{self.job.job_id}/artifacts/reports/report.json"])
        self.assertNotIn("chain_of_thought", direct.summary)

    def test_persistence_failure_is_not_visible_and_records_safe_diagnostic(self):
        before = self.store.events.snapshot(self.job.job_id)
        with patch("audit_agent.server.audit_events.os.fsync", side_effect=OSError("disk api_key=secret")):
            with self.assertRaises(OSError):
                self.store.events.append(
                    self.job.job_id,
                    category="error",
                    phase="queued",
                    actor="audit-service",
                    title="Persistence test",
                )
        after = self.store.events.snapshot(self.job.job_id)
        self.assertEqual(after["last_event_id"], before["last_event_id"])
        diagnostic = self.store.events.diagnostics()[-1]
        self.assertEqual(diagnostic["reason"], "journal-persistence-failed")
        self.assertNotIn("secret", json.dumps(diagnostic).lower())

    def test_crash_reconciliation_truncates_partial_tail_and_rebuilds_index(self):
        journal = self.store.events.journal_path(self.job.job_id)
        with journal.open("a", encoding="utf-8") as handle:
            handle.write('{"schema_version":"audit-event.v1","run_id":')
        with self.store.workspace.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE event_index_state SET last_event_id = 99 WHERE run_id = ?",
                (self.job.job_id,),
            )
        restarted = JobStore(
            self.root / "jobs.json",
            db_path=self.root / "workspace.sqlite3",
            event_journal_root=self.root / "events",
        )
        self.assertEqual(restarted.workspace.get_event_index(self.job.job_id)["last_event_id"], 1)
        self.assertEqual([item.event_id for item in restarted.events.history(self.job.job_id)], [1])
        self.assertNotIn('"run_id":', journal.read_text(encoding="utf-8").splitlines()[-1][0:10])

    def test_slow_readers_resume_from_journal_without_per_client_queue(self):
        for index in range(100):
            self.store.events.append(
                self.job.job_id,
                category="evidence",
                phase="analyzing",
                actor="analysis",
                title=f"Evidence {index}",
                summary={"index": index},
            )
        late = self.store.events.history(self.job.job_id, after=90)
        self.assertEqual([item.event_id for item in late], list(range(91, 102)))


class AuditEventSseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory(dir=".")
        self.root = Path(self.temporary.name)
        self.store = JobStore(
            self.root / "jobs.json",
            db_path=self.root / "workspace.sqlite3",
            event_journal_root=self.root / "events",
        )
        self.job = self.store.create_job(str(self.root), self.root / "runs")
        self.runner = _Runner(self.store)
        self.client = TestClient(
            create_app(
                self.store,
                runner=self.runner,
                output_dir=self.root / "runs",
                allowed_local_roots=[self.root],
                event_heartbeat_seconds=0.02,
            )
        )

    def tearDown(self):
        self.client.close()
        self.temporary.cleanup()

    def _complete(self):
        self.store.mark_running(self.job.job_id)
        self.store.update_phase(self.job.job_id, "analyzing")
        self.store.mark_succeeded(self.job.job_id, {"effective_mode": "agent-led"})

    def test_history_reconnect_terminal_snapshot_and_project_scope(self):
        self._complete()
        response = self.client.get(f"/api/projects/{self.job.project_id}/runs/{self.job.job_id}/events")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers["content-type"].startswith("text/event-stream"))
        ids = [int(line.split(":", 1)[1]) for line in response.text.splitlines() if line.startswith("id:")]
        self.assertEqual(ids, [1, 2, 3, 4])
        self.assertIn("event: terminal-snapshot", response.text)

        resumed = self.client.get(
            f"/api/runs/{self.job.job_id}/events",
            headers={"Last-Event-ID": "2"},
        )
        resumed_ids = [int(line.split(":", 1)[1]) for line in resumed.text.splitlines() if line.startswith("id:")]
        self.assertEqual(resumed_ids, [3, 4])
        already_current = self.client.get(f"/api/runs/{self.job.job_id}/events?cursor=4")
        self.assertNotIn("event: audit-event", already_current.text)
        self.assertIn("event: terminal-snapshot", already_current.text)
        self.assertEqual(self.client.get(f"/api/runs/{self.job.job_id}/events?cursor=-1").status_code, 422)
        self.assertEqual(self.client.get(f"/api/runs/{self.job.job_id}/events?cursor=99").status_code, 409)
        self.assertEqual(self.client.get("/api/runs/UNKNOWN/events").status_code, 404)
        self.assertEqual(
            self.client.get(f"/api/projects/WRONG/runs/{self.job.job_id}/events").status_code,
            404,
        )

    def test_active_delivery_reconnect_and_replay_keep_identical_ids(self):
        stream_waiting = threading.Event()
        original_wait = self.store.events.wait_for_events

        def observed_wait(run_id, after, timeout):
            stream_waiting.set()
            return original_wait(run_id, after, timeout)

        self.store.events.wait_for_events = observed_wait

        def finish():
            stream_waiting.wait(timeout=2)
            time.sleep(0.05)
            self.store.mark_running(self.job.job_id)
            self.store.update_phase(self.job.job_id, "analyzing")
            self.store.mark_succeeded(self.job.job_id, {})

        worker = threading.Thread(target=finish, daemon=True)
        worker.start()
        live = self.client.get(f"/api/runs/{self.job.job_id}/events?cursor=1")
        worker.join(timeout=2)
        live_ids = [int(line.split(":", 1)[1]) for line in live.text.splitlines() if line.startswith("id:")]
        self.assertEqual(live_ids, [2, 3, 4])
        self.assertIn("event: heartbeat", live.text)
        replay = self.client.get(f"/api/runs/{self.job.job_id}/events?cursor=1")
        replay_ids = [int(line.split(":", 1)[1]) for line in replay.text.splitlines() if line.startswith("id:")]
        self.assertEqual(replay_ids, live_ids)
        snapshot = self.client.get(f"/api/runs/{self.job.job_id}/events/snapshot").json()
        self.assertEqual([item["event_id"] for item in snapshot["events"]][1:], live_ids)

    def test_snapshot_labels_legacy_history_unavailable(self):
        legacy = self.store.create_job(str(self.root / "legacy"), self.root / "runs")
        self.store.events.journal_path(legacy.job_id).unlink(missing_ok=True)
        with self.store.workspace.transaction(immediate=True) as connection:
            connection.execute("DELETE FROM event_index_state WHERE run_id = ?", (legacy.job_id,))
        snapshot = self.client.get(f"/api/runs/{legacy.job_id}/events/snapshot").json()
        self.assertEqual(snapshot["history_status"], "unavailable")
        self.assertEqual(snapshot["history_reason"], "legacy-run-without-public-journal")

    def test_rerun_configuration_is_secret_safe_and_artifact_routes_are_allowlisted(self):
        rerun = self.store.create_job(
            str(self.root / "rerun"),
            self.root / "runs",
            request_snapshot={
                "source": {"kind": "local", "path": str(self.root)},
                "graph_mode": "agent-led",
                "preflight_token": "must-not-return",
                "api_key": "must-redact",
            },
        )
        config = self.client.get(f"/api/runs/{rerun.job_id}/rerun-config").json()["configuration"]
        self.assertNotIn("preflight_token", config)
        self.assertEqual(config["api_key"], "[REDACTED]")

        run_dir = self.root / "runs" / "runtime-public"
        report = run_dir / "reports" / "report.json"
        prompt = run_dir / "prompts" / "private.txt"
        report.parent.mkdir(parents=True, exist_ok=True)
        prompt.parent.mkdir(parents=True, exist_ok=True)
        report.write_text('{"safe": true}', encoding="utf-8")
        prompt.write_text("private", encoding="utf-8")
        self.store.mark_running(rerun.job_id)
        self.store.mark_succeeded(rerun.job_id, {"run_dir": str(run_dir)})
        self.assertEqual(self.client.get(f"/api/runs/{rerun.job_id}/artifacts/reports/report.json").status_code, 200)
        self.assertEqual(self.client.get(f"/api/runs/{rerun.job_id}/artifacts/prompts/private.txt").status_code, 403)
        self.assertEqual(
            self.client.get(
                f"/api/runs/{rerun.job_id}/artifacts/reports%5C..%5Cprompts%5Cprivate.txt"
            ).status_code,
            403,
        )


if __name__ == "__main__":
    unittest.main()
