from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from audit_agent.agent_led_benchmark import (
    _stability_preflight,
    _verification_plans_are_typed,
    default_blindspot_manifest_path,
    default_stability_manifest_path,
    evaluate_blindspot_corpus,
    evaluate_stability_records,
    load_blindspot_manifest,
    load_stability_manifest,
    run_real_model_stability,
)
from audit_agent.config import AuditConfig
from audit_agent.cli import build_parser


class BlindspotCorpusTests(unittest.TestCase):
    def test_live_promotion_commands_default_to_reasoning_model_timeout(self):
        parser = build_parser()
        blindspot = parser.parse_args(["agent-led-benchmark", "--live"])
        stability = parser.parse_args(["agent-led-stability", "--live"])
        self.assertEqual(blindspot.llm_timeout, 120)
        self.assertEqual(stability.llm_timeout, 120)

    def test_manifest_has_reviewed_balanced_24_case_shape(self):
        manifest = load_blindspot_manifest(default_blindspot_manifest_path())
        self.assertEqual(len(manifest["cases"]), 24)
        distribution = {}
        for case in manifest["cases"]:
            key = (case["class"], case["expected"])
            distribution[key] = distribution.get(key, 0) + 1
        self.assertEqual(set(distribution.values()), {3})
        self.assertTrue(all(set(case) == {"id", "class", "family", "expected", "path"} for case in manifest["cases"]))

    def test_offline_invocation_is_deferred_instead_of_claiming_perfect_recall(self):
        report = evaluate_blindspot_corpus()
        self.assertEqual(report["status"], "deferred")
        self.assertFalse(report["passed"])
        self.assertEqual(report["cases"], [])

    def test_live_evaluator_runs_both_public_pipeline_modes_on_neutral_targets(self):
        calls = []

        def fake_audit(target, config, output_dir):
            target_path = Path(target)
            self.assertEqual(target_path.name[:5], "case-")
            self.assertEqual([item.name for item in target_path.iterdir()], ["app.py"])
            self.assertNotIn("safe", str(target_path).lower())
            self.assertNotIn("vulnerable", str(target_path).lower())
            calls.append(config.graph.mode)
            run_dir = Path(output_dir) / f"run-{len(calls):03d}"
            (run_dir / "reports").mkdir(parents=True)
            (run_dir / "findings").mkdir()
            report_path = run_dir / "reports" / "report.json"
            resource_path = run_dir / "reports" / "resource.json"
            report_path.write_text(json.dumps({"findings": []}), encoding="utf-8")
            resource_path.write_text(json.dumps({
                "ledger_present": True,
                "llm_reconciliation_status": "complete",
                "llm_gap_ids": [],
            }), encoding="utf-8")
            return {
                "status": "succeeded",
                "run_dir": str(run_dir),
                "effective_mode": config.graph.mode,
                "report_ref": str(report_path),
                "resource_summary_ref": str(resource_path),
                "investigation_budget": {"used": {"requests": 1 if config.graph.mode == "agent-led" else 0}},
            }

        config = AuditConfig.default()
        config.runtime_enabled = True
        config.graph.mode = "agent-led"
        config.llm_decisions.enabled = True
        config.llm_decisions.roles = ["analysis", "verification"]
        with tempfile.TemporaryDirectory() as output:
            report = evaluate_blindspot_corpus(
                config=config,
                output_root=output,
                execute_live=True,
                audit_callable=fake_audit,
            )
        self.assertEqual(len(calls), 48)
        self.assertEqual(calls[::2], ["deterministic-graph"] * 24)
        self.assertEqual(calls[1::2], ["agent-led"] * 24)
        self.assertFalse(report["passed"])


class StabilityGateTests(unittest.TestCase):
    def test_fixed_commit_manifest_is_three_by_three_and_source_only(self):
        manifest = load_stability_manifest(default_stability_manifest_path())
        self.assertEqual(manifest["repetitions"], 3)
        self.assertEqual(len(manifest["targets"]), 3)
        self.assertTrue(all(len(item["commit"]) == 40 for item in manifest["targets"]))
        self.assertFalse(manifest["safety"]["target_writes"])
        self.assertFalse(manifest["safety"]["target_network"])
        self.assertFalse(manifest["safety"]["model_code_authority"])

    def test_stability_aggregation_requires_identical_findings_and_all_safety_gates(self):
        targets = ["one", "two", "three"]
        records = []
        for target in targets:
            for repetition in range(1, 4):
                records.append(
                    {
                        "target_id": target,
                        "repetition": repetition,
                        "terminal_status": "succeeded",
                        "effective_mode": "agent-led",
                        "normalized_high_critical": [
                            {"class": "sql-injection", "severity": "high", "path": "app.py", "line": 7}
                        ],
                        "target_integrity_ok": True,
                        "safety_ok": True,
                        "plan_authority_ok": True,
                        "accounting_ok": True,
                    }
                )
        report = evaluate_stability_records(records, target_ids=targets, repetitions=3)
        self.assertTrue(report["passed"], report["gates"])
        records[-1]["normalized_high_critical"] = []
        unstable = evaluate_stability_records(records, target_ids=targets, repetitions=3)
        self.assertFalse(unstable["gates"]["normalized_high_critical_stable"])

    def test_default_mock_configuration_is_explicitly_deferred_not_silently_run(self):
        report = run_real_model_stability(AuditConfig.default(), execute_live=False)
        self.assertEqual(report["status"], "deferred")
        self.assertIn("real-model-provider-not-configured", report["reasons"])
        self.assertIn("live-execution-not-requested", report["reasons"])

    def test_stability_requires_bounded_docker_instead_of_forbidding_verification(self):
        config = AuditConfig.default()
        manifest_path = default_stability_manifest_path()
        manifest = load_stability_manifest(manifest_path)
        reasons = _stability_preflight(config, manifest, manifest_path)
        self.assertIn("bounded-docker-sandbox-not-configured", reasons)
        self.assertNotIn("stability-safety-profile-not-source-only", reasons)

    def test_empty_verification_plan_list_is_not_typed_authority(self):
        self.assertFalse(_verification_plans_are_typed([]))


if __name__ == "__main__":
    unittest.main()
