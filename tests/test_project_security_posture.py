from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

import anyio
import httpx

from audit_agent.server.app import create_app
from audit_agent.server.job_store import JobStore
from audit_agent.server.posture import (
    FINGERPRINT_VERSION,
    RISK_FORMULA_VERSION,
    build_fingerprint,
    calculate_risk,
    classify_trend,
    project_report_findings,
)


class RecordingRunner:
    def submit(self, job_id, request):
        return None


def finding(
    finding_id: str,
    *,
    vulnerability_class: str = "sql-injection",
    severity: str = "high",
    confidence=1.0,
    path: str = "src/app.py",
    symbol: str | None = "lookup",
    sink: str = "cursor.execute",
    status: str = "confirmed",
) -> dict:
    return {
        "id": finding_id,
        "title": f"Fixture {finding_id}",
        "description": "Description is intentionally not an identity input.",
        "vulnerability_class": vulnerability_class,
        "severity": severity,
        "confidence": confidence,
        "location": {"path": path, "start_line": 14, "end_line": 14, "symbol": symbol},
        "affected_function": symbol,
        "verification_status": status,
        "validation": {"status": status, "verification_status": status},
        "dataflow_summary": {"sink": {"symbol": sink}},
    }


def chain(finding_id: str, status: str = "confirmed") -> dict:
    return {
        "id": f"EC-{finding_id}",
        "finding_id": finding_id,
        "source_locations": [{"path": "src/app.py", "start_line": 14, "end_line": 14}],
        "validation": {"status": status, "verification_status": status},
        "artifact_refs": [f"evidence/{finding_id}.json"],
        "tool_refs": [{"id": f"TR-{finding_id}"}],
    }


def report(candidates: list[dict], *, scanned_files: int = 3, degraded: bool = False) -> dict:
    return {
        "executive_summary": {
            "scanned_file_count": scanned_files,
            "languages": {"Python": 120},
        },
        "target_metadata": {
            "dominant_language": "Python",
            "languages": {"Python": 120},
            "dependencies": [{"name": "flask"}],
        },
        "findings": [item for item in candidates if item.get("verification_status") != "rejected"],
        "verification_candidates": candidates,
        "evidence_chains": [chain(item["id"], item.get("verification_status", "confirmed")) for item in candidates],
        "runtime": {
            "investigation": {
                "requested_mode": "agent-led",
                "effective_mode": "agent-led",
                "degraded_reasons": ["fixture-degraded"] if degraded else [],
                "fallback_reason": "fixture-degraded" if degraded else "",
                "evidence_gate_counts": {"promoted": len(candidates)},
                "investigation_budget": {
                    "limits": {"requests": 10, "tokens": 1000},
                    "used": {"requests": 2, "tokens": 100},
                },
            }
        },
        "run_status": "degraded" if degraded else "completed",
    }


def resource(*, scanned_files: int = 3, terminal_status: str = "succeeded", accounting: str = "complete") -> dict:
    return {
        "schema_version": "run-resource-summary.v1",
        "terminal_status": terminal_status,
        "scanned_files": scanned_files,
        "scanned_bytes": 512,
        "language": "Python",
        "scope": {"include": ["**/*"], "exclude": []},
        "llm_reconciliation_status": accounting,
        "accounting_gaps": [] if accounting == "complete" else [{"field": "llm_tokens", "reason": "missing"}],
        "budget_consumption": {"llm_requests": 2, "llm_tokens": 100, "tool_calls": 4},
    }


def trend_snapshot(run_id: str, fingerprints: list[str], *, complete: bool = True, version: str = FINGERPRINT_VERSION) -> dict:
    return {
        "run_id": run_id,
        "versions": {"fingerprint": version},
        "completeness": {"complete": complete},
        "findings": {
            "validated": [
                {"finding_id": f"F-{fingerprint}", "fingerprint": fingerprint, "severity": "high"}
                for fingerprint in fingerprints
            ]
        },
    }


def write_run_artifacts(run_dir: Path, payload: dict, resources: dict) -> None:
    reports = run_dir / "reports"
    reports.mkdir(parents=True)
    (reports / "report.json").write_text(json.dumps(payload), encoding="utf-8")
    (reports / "run-resource-summary-final.v1.json").write_text(
        json.dumps(resources), encoding="utf-8"
    )
    evidence = run_dir / "evidence"
    evidence.mkdir()
    for candidate in payload.get("verification_candidates", []):
        (evidence / f"{candidate['id']}.json").write_text("{}", encoding="utf-8")


class TrustedPostureUnitTests(unittest.TestCase):
    def test_risk_formula_uses_every_weight_clamps_confidence_and_caps_score(self):
        findings = [
            {"finding_id": "critical", "severity": "critical", "confidence": 1},
            {"finding_id": "high", "severity": "high", "confidence": 1},
            {"finding_id": "medium", "severity": "medium", "confidence": 1},
            {"finding_id": "low", "severity": "low", "confidence": 1},
            {"finding_id": "info", "severity": "informational", "confidence": 1},
        ]
        score = calculate_risk(findings)
        self.assertEqual(score["score"], 49)
        self.assertEqual(score["formula_version"], RISK_FORMULA_VERSION)
        self.assertEqual([item["weight"] for item in score["components"]], [25, 15, 7, 2, 0])

        edge = calculate_risk(
            [
                {"finding_id": "missing", "severity": "critical", "confidence": None},
                {"finding_id": "invalid", "severity": "high", "confidence": "bad"},
                {"finding_id": "upper", "severity": "high", "confidence": 8},
                {"finding_id": "lower", "severity": "medium", "confidence": -3},
                *[
                    {"finding_id": f"cap-{index}", "severity": "critical", "confidence": 1}
                    for index in range(4)
                ],
            ]
        )
        self.assertEqual(edge["score"], 100)
        self.assertEqual(edge["fallback_count"], 2)
        self.assertEqual(edge["clamped_count"], 2)
        self.assertIn("=1.0", edge["confidence_fallback_rule"])

    def test_fingerprint_is_stable_across_narrative_confidence_and_line_changes(self):
        first = finding("one")
        second = deepcopy(first)
        second.update({"title": "A different model title", "description": "Changed", "confidence": 0.2})
        second["location"]["start_line"] = 999
        second["location"]["end_line"] = 1001
        self.assertEqual(build_fingerprint(first)["fingerprint"], build_fingerprint(second)["fingerprint"])

        changed_class = deepcopy(first)
        changed_class["vulnerability_class"] = "command-injection"
        changed_symbol = deepcopy(first)
        changed_symbol["affected_function"] = "admin_lookup"
        changed_sink = deepcopy(first)
        changed_sink["dataflow_summary"]["sink"]["symbol"] = "os.system"
        identities = {
            build_fingerprint(item)["fingerprint"]
            for item in (first, changed_class, changed_symbol, changed_sink)
        }
        self.assertEqual(len(identities), 4)

        no_symbol = finding("fallback", symbol=None)
        fingerprint = build_fingerprint(no_symbol)
        self.assertEqual(fingerprint["quality"]["symbol"], "fallback-module-anchor")
        self.assertEqual(fingerprint["quality"]["overall"], "fallback")

    def test_report_projection_keeps_only_evidence_gated_confirmed_findings_in_core(self):
        candidates = [
            finding("confirmed"),
            finding("likely", status="likely"),
            finding("pending", status="pending"),
            finding("manual", status="manual-required"),
            finding("rejected", status="rejected"),
            finding("inconclusive", status="inconclusive"),
            finding("forged-confirmed"),
        ]
        payload = report(candidates)
        payload["evidence_chains"] = [item for item in payload["evidence_chains"] if item["finding_id"] != "forged-confirmed"]
        projection = project_report_findings(payload, run_id="JOB-1")
        self.assertEqual([item["finding_id"] for item in projection["validated"]], ["confirmed"])
        self.assertEqual(
            projection["validation_counts"],
            {"validated": 1, "candidate": 1, "pending": 1, "manual": 1, "rejected": 1, "inconclusive": 2},
        )
        self.assertEqual(projection["evidence_gate_failures"], 1)

        legacy = project_report_findings({"findings": candidates}, run_id="legacy")
        self.assertFalse(legacy["contract_available"])
        self.assertEqual(legacy["unavailable"]["reason"], "legacy-verification-contract-unavailable")

    def test_trends_cover_new_persistent_resolved_reintroduced_and_unconfirmed(self):
        first = trend_snapshot("one", ["A"])
        baseline = classify_trend(first, [])
        self.assertEqual(baseline["counts"]["new"], 1)

        second = trend_snapshot("two", ["A", "B"])
        second_trend = classify_trend(second, [first])
        self.assertEqual(second_trend["counts"]["persistent"], 1)
        self.assertEqual(second_trend["counts"]["new"], 1)

        third = trend_snapshot("three", ["B"])
        third_trend = classify_trend(third, [first, second])
        self.assertEqual(third_trend["counts"]["resolved"], 1)

        fourth = trend_snapshot("four", ["A", "B"])
        fourth_trend = classify_trend(fourth, [first, second, third])
        self.assertEqual(fourth_trend["counts"]["reintroduced"], 1)
        self.assertEqual(fourth_trend["counts"]["persistent"], 1)

        incomplete = trend_snapshot("incomplete", ["B"], complete=False)
        incomplete_trend = classify_trend(incomplete, [second])
        self.assertEqual(incomplete_trend["counts"]["resolved"], 0)
        self.assertEqual(incomplete_trend["counts"]["unconfirmed"], 1)
        self.assertIn("cannot-resolve", incomplete_trend["limitations"][0])

        incompatible = trend_snapshot("version-two", ["A"], version="finding-fingerprint.v2")
        incompatible_trend = classify_trend(incompatible, [first])
        self.assertFalse(incompatible_trend["comparable"])
        self.assertEqual(incompatible_trend["comparison_status"], "incompatible-fingerprint-version")
        self.assertGreaterEqual(incompatible_trend["counts"]["unconfirmed"], 1)


class ProjectPostureIntegrationTests(unittest.TestCase):
    def test_multi_run_dashboard_preserves_latest_truth_and_stable_high_risk_drilldown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            store = JobStore(root / "jobs.json")
            project, _ = store.create_or_get_project(
                {"kind": "local", "path": str(source)},
                display_name="Posture fixture",
                languages=[{"name": "Python", "files": 3}],
                metadata={"file_count": 3, "dependency_count": 1},
            )

            first = self._complete_run(store, project.project_id, root, "one", [finding("sql")])
            moved = finding("sql-later")
            moved["title"] = "Renamed narrative"
            moved["location"]["start_line"] = 300
            moved["location"]["end_line"] = 300
            critical = finding(
                "cmd",
                vulnerability_class="command-injection",
                severity="critical",
                symbol="execute_job",
                sink="os.system",
            )
            second = self._complete_run(store, project.project_id, root, "two", [moved, critical])
            failed = store.create_job(
                "source",
                root / "runs",
                source={"kind": "local", "path": str(source)},
                project_id=project.project_id,
            )
            store.mark_running(failed.job_id)
            store.mark_failed(failed.job_id, "fixture failure")

            app = create_app(job_store=store, runner=RecordingRunner())
            response = anyio.run(self._get, app, f"/api/projects/{project.project_id}/dashboard")
            self.assertEqual(response.status_code, 200, response.text)
            dashboard = response.json()
            self.assertEqual(dashboard["latest_run"]["job_id"], failed.job_id)
            self.assertEqual(dashboard["latest_run"]["status"], "failed")
            self.assertEqual(dashboard["latest_complete_posture"]["run_id"], second.job_id)
            self.assertTrue(dashboard["posture_is_historical"])
            self.assertEqual(dashboard["state"], "stale-historical-posture")
            self.assertFalse(dashboard["latest_run_posture"]["quality"]["evidence_complete"])
            self.assertEqual(dashboard["posture"]["risk"]["score"], 40)
            self.assertEqual(dashboard["posture"]["trend"]["counts"]["persistent"], 1)
            self.assertEqual(dashboard["posture"]["trend"]["counts"]["new"], 1)
            self.assertEqual(len(dashboard["high_risk_findings"]), 2)
            self.assertIn(second.job_id, dashboard["high_risk_findings"][0]["run_url"])
            self.assertIn("finding=cmd", dashboard["high_risk_findings"][0]["run_url"])
            self.assertEqual(store.workspace.get_posture_snapshot(first.job_id)["risk"]["score"], 15)
            self.assertEqual(len(store.workspace.list_finding_identities(project.project_id)), 2)

            repeated = store.posture.backfill_project(project.project_id)
            self.assertEqual(len(repeated), 3)
            self.assertEqual(len(store.workspace.list_posture_snapshots(project.project_id)), 3)

    def test_incomplete_accounting_cannot_create_authoritative_score_or_resolution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            store = JobStore(root / "jobs.json")
            project, _ = store.create_or_get_project({"kind": "local", "path": str(source)})
            first = self._complete_run(store, project.project_id, root, "one", [finding("sql")])

            run = store.create_job(
                "source", root / "runs", source={"kind": "local", "path": str(source)}, project_id=project.project_id
            )
            store.mark_running(run.job_id)
            run_dir = root / "runs" / "incomplete"
            write_run_artifacts(run_dir, report([]), resource(accounting="incomplete"))
            store.mark_succeeded(run.job_id, {"run_dir": str(run_dir)})
            snapshot = store.workspace.get_posture_snapshot(run.job_id)
            self.assertFalse(snapshot["completeness"]["complete"])
            self.assertIsNone(snapshot["risk"]["score"])
            self.assertEqual(snapshot["trend"]["counts"]["resolved"], 0)
            self.assertEqual(snapshot["trend"]["counts"]["unconfirmed"], 1)
            self.assertEqual(snapshot["trend"]["basis_run_id"], first.job_id)

    def test_missing_legacy_contract_is_explicitly_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            store = JobStore(root / "jobs.json")
            run = store.create_job("source", root / "runs", source={"kind": "local", "path": str(source)})
            store.mark_running(run.job_id)
            run_dir = root / "runs" / "legacy"
            reports = run_dir / "reports"
            reports.mkdir(parents=True)
            (reports / "report.json").write_text(
                json.dumps({"executive_summary": {"validated_count": 3}, "findings": []}), encoding="utf-8"
            )
            store.mark_succeeded(run.job_id, {"run_dir": str(run_dir)})
            snapshot = store.workspace.get_posture_snapshot(run.job_id)
            self.assertEqual(snapshot["availability"]["status"], "partial")
            self.assertFalse(snapshot["findings"]["contract_available"])
            self.assertIn("validation-incomplete", snapshot["completeness"]["reasons"])
            self.assertIsNone(snapshot["risk"]["score"])

    @staticmethod
    def _complete_run(store: JobStore, project_id: str, root: Path, name: str, candidates: list[dict]):
        source = root / "source"
        run = store.create_job(
            "source",
            root / "runs",
            source={"kind": "local", "path": str(source)},
            project_id=project_id,
        )
        store.mark_running(run.job_id)
        run_dir = root / "runs" / name
        write_run_artifacts(run_dir, report(candidates), resource())
        return store.mark_succeeded(run.job_id, {"run_dir": str(run_dir)})

    @staticmethod
    async def _get(app, path: str):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.get(path)


if __name__ == "__main__":
    unittest.main()
