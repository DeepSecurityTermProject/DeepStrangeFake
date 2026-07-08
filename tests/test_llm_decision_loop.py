import json
import tempfile
import unittest
from pathlib import Path

from audit_agent.config import AuditConfig
from audit_agent.models import Finding, SourceLocation
from audit_agent.pipeline import run_audit
from audit_agent.repository import analyze_target

from tests.test_repository_analysis import create_vulnerable_fixture


class LlmDecisionLoopContractTests(unittest.TestCase):
    def test_role_schemas_accept_valid_payloads_and_reject_shape_errors(self):
        from audit_agent.decisions import DecisionValidationError, role_decision_schema, validate_decision_payload

        valid = {
            "role": "verification",
            "action": "verify",
            "confidence": 0.82,
            "rationale": "Local evidence cites app.py and tool output.",
            "evidence_refs": ["TR-local"],
            "selected_actions": [{"finding_id": "F-1", "decision": "accept", "validation_level": "static-only"}],
            "requested_tools": [],
        }

        self.assertEqual(role_decision_schema("verification")["required"][0], "role")
        normalized = validate_decision_payload("verification", valid)
        self.assertEqual(normalized["role"], "verification")

        with self.assertRaises(DecisionValidationError):
            validate_decision_payload("verification", {"role": "verification", "confidence": 0.8})
        with self.assertRaises(DecisionValidationError):
            validate_decision_payload("verification", {**valid, "confidence": "high"})
        with self.assertRaises(DecisionValidationError):
            validate_decision_payload("analysis", "not-json")

    def test_decision_artifacts_are_redacted_when_persisted(self):
        from audit_agent.decisions import build_llm_decision, persist_decision_bundle

        with tempfile.TemporaryDirectory() as tmp:
            decision = build_llm_decision(
                role="analysis",
                payload={
                    "role": "analysis",
                    "action": "candidate-generation",
                    "confidence": 0.86,
                    "rationale": "Uses local evidence.",
                    "evidence_refs": ["TR-local"],
                    "selected_actions": [],
                    "requested_tools": [],
                },
                prompt_ref="PR-1",
                llm_response_ref="LS-1",
                provider_metadata={"api_key": "secret-value", "base_url": "https://example.test"},
                raw_output='{"api_key":"secret-value"}',
            )

            path = persist_decision_bundle(Path(tmp), "analysis", decision)
            payload = json.loads(path.read_text(encoding="utf-8"))

            self.assertIn("LLD-", payload["llm_decision"]["id"])
            self.assertNotIn("secret-value", json.dumps(payload))
            self.assertEqual(payload["llm_decision"]["provider_metadata"]["api_key"], "[REDACTED]")

    def test_string_actions_and_tools_from_live_models_are_normalized(self):
        from audit_agent.decisions import build_llm_decision, evaluate_decision_policy

        config = AuditConfig.default()
        config.llm_decisions.enabled = True
        decision = build_llm_decision(
            role="orchestrator",
            payload={
                "role": "orchestrator",
                "action": "generate_investigation_plan",
                "confidence": 0.96,
                "rationale": "Live model returned compact string arrays.",
                "evidence_refs": ["attack_surfaces[1]: app.py:15"],
                "selected_actions": ["source_inspection", "pattern_scanning"],
                "requested_tools": ["file_read", "semantic_search"],
            },
        )

        gate = evaluate_decision_policy("orchestrator", decision, config)

        self.assertEqual(decision.selected_actions[0]["action"], "source_inspection")
        self.assertEqual(decision.requested_tools[0]["tool_name"], "file_read")
        self.assertEqual(gate.status, "denied")
        self.assertIn("not registered", " ".join(gate.reasons))


class LlmDecisionPolicyTests(unittest.TestCase):
    def test_policy_rejects_memory_or_intelligence_only_analysis_candidate(self):
        from audit_agent.decisions import build_llm_decision, evaluate_decision_policy

        config = AuditConfig.default()
        config.llm_decisions.enabled = True
        proposal = build_llm_decision(
            role="analysis",
            payload={
                "role": "analysis",
                "action": "candidate-generation",
                "confidence": 0.91,
                "rationale": "CVE and memory context suggest SQL injection.",
                "evidence_refs": ["MEM-1", "VI-1"],
                "selected_actions": [
                    {
                        "title": "Memory-only SQL injection",
                        "vulnerability_class": "sql-injection",
                        "path": "app.py",
                        "start_line": 1,
                        "evidence": [],
                        "memory_refs": ["MEM-1"],
                        "intelligence_refs": ["VI-1"],
                    }
                ],
                "requested_tools": [],
            },
        )

        gate = evaluate_decision_policy("analysis", proposal, config)

        self.assertEqual(gate.status, "denied")
        self.assertIn("local evidence", " ".join(gate.reasons))

    def test_policy_denies_unsafe_validation_and_over_budget_tool_request(self):
        from audit_agent.decisions import build_llm_decision, evaluate_decision_policy

        config = AuditConfig.default()
        config.llm_decisions.enabled = True
        config.llm_decisions.tool_budget_per_role = {"recon": 0}
        recon = build_llm_decision(
            role="recon",
            payload={
                "role": "recon",
                "action": "tool-plan",
                "confidence": 0.8,
                "rationale": "Need one tool.",
                "evidence_refs": ["repo"],
                "selected_actions": [],
                "requested_tools": [{"tool_name": "pattern-scan", "arguments": {}}],
            },
        )
        verification = build_llm_decision(
            role="verification",
            payload={
                "role": "verification",
                "action": "verify",
                "confidence": 0.88,
                "rationale": "Requests unsafe live validation.",
                "evidence_refs": ["TR-local"],
                "selected_actions": [
                    {"finding_id": "F-1", "decision": "accept", "validation_level": "sandbox"}
                ],
                "requested_tools": [],
            },
        )

        recon_gate = evaluate_decision_policy("recon", recon, config)
        verification_gate = evaluate_decision_policy("verification", verification, config)

        self.assertEqual(recon_gate.status, "denied")
        self.assertIn("budget", " ".join(recon_gate.reasons).lower())
        self.assertEqual(verification_gate.status, "denied")
        self.assertIn("validation", " ".join(verification_gate.reasons).lower())

    def test_merge_records_policy_conflicts_and_fallback_reason(self):
        from audit_agent.decisions import build_llm_decision, merge_decision

        proposal = build_llm_decision(
            role="analysis",
            payload={
                "role": "analysis",
                "action": "candidate-generation",
                "confidence": 0.4,
                "rationale": "Weak.",
                "evidence_refs": [],
                "selected_actions": [],
                "requested_tools": [],
            },
            fallback_reason="low-confidence",
        )

        merged = merge_decision(
            role="analysis",
            deterministic_output={"candidate_count": 2},
            proposal=proposal,
            gate_status="denied",
            gate_reasons=["confidence below threshold"],
        )

        self.assertEqual(merged.decision_source, "policy-denied")
        self.assertEqual(merged.fallback_reason, "low-confidence")
        self.assertEqual(merged.final_output["candidate_count"], 2)


class LlmDecisionPipelineTests(unittest.TestCase):
    def test_pipeline_decision_mode_writes_artifacts_messages_and_report_fields(self):
        from audit_agent.message_bus import replay_summary

        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            output = Path(tmp) / "runs"
            config = AuditConfig.default()
            config.runtime_enabled = True
            config.llm.provider = "mock"
            config.llm_decisions.enabled = True
            config.llm_decisions.roles = ["orchestrator", "recon", "analysis", "verification"]
            config.memory.enabled = True
            config.message_bus.enabled = True
            config.mcp.enabled = False

            result = run_audit(str(project), config=config, output_dir=output)
            run_dir = Path(result["run_dir"])

            self.assertTrue((run_dir / "decisions").exists())
            self.assertTrue(list((run_dir / "decisions").glob("*.json")))
            report = json.loads((run_dir / "reports" / "report.json").read_text(encoding="utf-8"))
            self.assertTrue(report["runtime"]["llm_decisions"]["enabled"])
            self.assertIn("decision_source", report["findings"][0])
            self.assertIn("policy_gate", report["findings"][0])
            markdown = (run_dir / "reports" / "report.md").read_text(encoding="utf-8")
            self.assertIn("LLM Influence", markdown)

            summary = replay_summary(run_dir / "messages" / "messages.jsonl")
            self.assertIn("decision_lifecycle", summary)
            self.assertIn("analysis", summary["decision_lifecycle"]["roles"])

    def test_verification_llm_cannot_accept_finding_without_local_evidence(self):
        from audit_agent.decisions import apply_verification_decision_proposal, build_llm_decision

        config = AuditConfig.default()
        finding = Finding(
            vulnerability_class="sql-injection",
            severity="high",
            confidence=0.93,
            location=SourceLocation(path="app.py", start_line=1, end_line=1),
            title="Unsupported SQL injection",
            evidence=[],
            tool_refs=[],
            metadata={"memory_refs": ["MEM-1"]},
        )
        proposal = build_llm_decision(
            role="verification",
            payload={
                "role": "verification",
                "action": "verify",
                "confidence": 0.95,
                "rationale": "Model wants to accept from memory only.",
                "evidence_refs": ["MEM-1"],
                "selected_actions": [
                    {"finding_id": finding.id, "decision": "accept", "validation_level": "static-only"}
                ],
                "requested_tools": [],
            },
        )

        decisions, gate, merged = apply_verification_decision_proposal(
            [finding],
            deterministic_decisions=[],
            proposal=proposal,
            config=config,
        )

        self.assertEqual(gate.status, "denied")
        self.assertEqual(merged.decision_source, "policy-denied")
        self.assertEqual(decisions[0].decision, "reject")
        self.assertIn("local evidence", decisions[0].reason)

    def test_cli_accepts_llm_decision_flags(self):
        from audit_agent.cli import build_parser

        args = build_parser().parse_args(
            [
                "scan",
                "--target",
                ".",
                "--runtime",
                "--llm-decisions",
                "--llm-decision-roles",
                "analysis,verification",
            ]
        )

        self.assertTrue(args.llm_decisions)
        self.assertEqual(args.llm_decision_roles, "analysis,verification")

    @unittest.skipUnless(False, "live LLM decision smoke is opt-in")
    def test_live_llm_decision_smoke_uses_configured_model_when_enabled(self):
        metadata = analyze_target("fixtures/integration_smoke")
        self.assertIsNotNone(metadata.target.source)


if __name__ == "__main__":
    unittest.main()
