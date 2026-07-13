import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from audit_agent.config import AuditConfig
from audit_agent.message_bus import MessageBus, replay_summary
from audit_agent.repository import analyze_target
from audit_agent.storage import RunStore

from tests.test_repository_analysis import create_vulnerable_fixture


class RuntimeKernelModelTests(unittest.TestCase):
    def test_run_and_task_state_record_transitions_refs_and_fallback(self):
        from audit_agent.runtime import RunState, TaskState

        run = RunState(run_id="run-1", target="fixture")
        run.mark_running()
        task = TaskState(run_id=run.run_id, role="analysis", kind="agent")
        task.mark_running(message_ref="MSG-start")
        task.record_artifact("reports/report.json")
        task.mark_fallback("schema-invalid", message_ref="MSG-fallback")
        task.mark_succeeded(output_refs=["F-1"], message_ref="MSG-done")
        run.add_task(task)
        run.record_artifact("runtime_state/state.json")
        run.mark_succeeded({"validated_count": 1})

        payload = run.to_dict()

        self.assertEqual(payload["status"], "succeeded")
        self.assertEqual(payload["tasks"][0]["status"], "succeeded")
        self.assertEqual(payload["tasks"][0]["fallback_reason"], "schema-invalid")
        self.assertIn("MSG-fallback", payload["tasks"][0]["message_refs"])
        self.assertIn("runtime_state/state.json", payload["artifact_refs"])

    def test_agent_invocation_and_output_contracts_are_serializable(self):
        from audit_agent.runtime import AgentInvocation, AgentOutput, RunState, TaskState

        run = RunState(run_id="run-1", target="fixture")
        task = TaskState(run_id=run.run_id, role="recon", kind="agent")
        invocation = AgentInvocation(
            role="recon",
            run_state=run,
            task_state=task,
            inputs={"metadata_ref": "metadata/repository.json"},
        )
        output = AgentOutput(
            role="recon",
            payload={"high_risk_areas": ["app.py:15"]},
            artifact_refs=["handoffs/recon-to-analysis.json"],
            message_refs=["MSG-1"],
            next_actions=["analysis"],
        )

        self.assertEqual(invocation.to_dict()["role"], "recon")
        self.assertEqual(output.to_dict()["payload"]["high_risk_areas"], ["app.py:15"])

    def test_graph_state_fields_are_additive_and_old_state_remains_readable(self):
        from audit_agent.runtime import RunState, TaskState

        task = TaskState(
            run_id="run-graph",
            role="analysis",
            kind="agent",
            graph_node_id="analysis-refinement-1",
            graph_revision=2,
            dependency_refs=["node:local-context-1"],
            attempt=1,
            lineage={"parent_node_id": "analysis", "iteration": 1},
            transition_refs=["graphs/transitions-2.json"],
            correlation_refs=["proposal-1"],
            causation_refs=["checkpoint:post-analysis"],
        )
        run = RunState(
            run_id="run-graph",
            target="fixture",
            graph_mode="adaptive-graph",
            initial_graph_ref="graphs/initial.json",
            active_graph_ref="graphs/revision-2.json",
            graph_revision_refs=["graphs/revision-0.json", "graphs/revision-2.json"],
            mutation_refs=["graphs/mutation-1.json"],
            checkpoint_counts={"post-analysis": 1},
            execution_path=["orchestrator-plan", "analysis-refinement-1"],
        )
        run.add_task(task)
        restored = RunState.from_dict(run.to_dict())

        self.assertEqual(restored.graph_mode, "adaptive-graph")
        self.assertEqual(restored.tasks[0].graph_node_id, "analysis-refinement-1")
        self.assertEqual(restored.tasks[0].lineage["iteration"], 1)

        legacy = RunState.from_dict({"run_id": "old", "target": "fixture", "status": "succeeded"})
        self.assertEqual(legacy.graph_mode, "legacy")
        self.assertEqual(legacy.graph_revision_refs, [])
        self.assertEqual(legacy.tasks, [])


class AgentRegistryTests(unittest.TestCase):
    def test_registry_registers_roles_rejects_duplicates_and_reports_missing(self):
        from audit_agent.runtime import AgentRegistry

        registry = AgentRegistry()
        registry.register("analysis", lambda invocation: invocation.inputs, description="Analysis agent")

        self.assertEqual(registry.get("analysis").role, "analysis")
        with self.assertRaises(ValueError):
            registry.register("analysis", lambda invocation: invocation.inputs)
        with self.assertRaises(KeyError):
            registry.get("verification")

        missing = registry.validate_required(["analysis", "verification"])
        self.assertEqual(missing, ["verification"])


class RuntimeServicesTests(unittest.TestCase):
    def test_artifact_store_writes_redacted_artifacts_and_publishes_events(self):
        from audit_agent.runtime import ArtifactStore, RunState, TaskState

        with tempfile.TemporaryDirectory() as tmp:
            run = RunStore(Path(tmp)).create_run("fixture")
            bus = MessageBus(run.run_id, run.path / "messages" / "messages.jsonl")
            state = RunState(run_id=run.run_id, target="fixture")
            task = TaskState(run_id=run.run_id, role="analysis", kind="artifact")
            store = ArtifactStore(run, bus=bus, run_state=state)

            first = store.write_json("runtime_state", "state.json", {"api_key": "secret-value"}, task_state=task)
            second = store.write_json("runtime_state", "state.json", {"ok": True}, task_state=task)
            payload = json.loads(Path(first).read_text(encoding="utf-8"))
            summary = replay_summary(run.path / "messages" / "messages.jsonl")

            self.assertNotEqual(first, second)
            self.assertEqual(payload["api_key"], "[REDACTED]")
            self.assertIn(first, task.artifact_refs)
            self.assertIn("runtime.artifact", summary["types"])

    def test_tool_broker_dispatches_permitted_tools_and_records_denials(self):
        from audit_agent.runtime import ArtifactStore, RunState, TaskState, ToolBroker

        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            metadata = analyze_target(str(project))
            run = RunStore(Path(tmp) / "runs").create_run("fixture")
            bus = MessageBus(run.run_id, run.path / "messages" / "messages.jsonl")
            state = RunState(run_id=run.run_id, target="fixture")
            store = ArtifactStore(run, bus=bus, run_state=state)
            task = TaskState(run_id=run.run_id, role="analysis", kind="tool")
            broker = ToolBroker(AuditConfig.default(), store, bus=bus)

            ok = broker.dispatch("analysis", "source-context", {"path": "app.py", "start_line": 10, "end_line": 15}, metadata=metadata, task_state=task)
            denied = broker.dispatch("analysis", "validation.sandbox", {"command": "python -c print(1)"}, metadata=metadata, task_state=task)
            summary = replay_summary(run.path / "messages" / "messages.jsonl")

            self.assertTrue(ok.success)
            self.assertFalse(denied.success)
            self.assertEqual(denied.status, "denied")
            self.assertIn("runtime.tool", summary["types"])
            self.assertIn("runtime.tool.denied", summary["types"])


class AgentRuntimeCompatibilityTests(unittest.TestCase):
    def test_deterministic_graph_matches_legacy_normalized_results_and_required_artifacts(self):
        from audit_agent.pipeline import run_audit

        def run_mode(project, root, mode):
            config = AuditConfig.default()
            config.runtime_enabled = False
            config.graph.mode = mode
            config.cve_mcp.enabled = False
            return run_audit(str(project), config=config, output_dir=root / mode)

        def normalize(value, run_dir):
            volatile_keys = {
                "id",
                "created_at",
                "generated_at",
                "timestamp",
                "started_at",
                "finished_at",
                "elapsed_ms",
                "elapsed_seconds",
                "duration_ms",
                "runtime",
                "artifact_refs",
                "runtime_task_refs",
                "message_refs",
                "transition_refs",
                "correlation_refs",
                "causation_refs",
                "attempt_refs",
                "poc_refs",
                "sandbox_result_refs",
            }
            if isinstance(value, dict):
                return {
                    key: normalize(item, run_dir)
                    for key, item in sorted(value.items())
                    if key not in volatile_keys and not key.endswith("_at")
                }
            if isinstance(value, list):
                return [normalize(item, run_dir) for item in value]
            if isinstance(value, str):
                normalized = value.replace(str(run_dir), "<RUN_DIR>")
                return re.sub(r"\b([A-Z]{1,8})-[0-9a-f]{12}\b", r"\1-<ID>", normalized)
            return value

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = create_vulnerable_fixture(root)
            legacy = run_mode(project, root, "legacy")
            deterministic = run_mode(project, root, "deterministic-graph")
            legacy_dir = Path(legacy["run_dir"])
            deterministic_dir = Path(deterministic["run_dir"])
            legacy_report = json.loads(
                (legacy_dir / "reports" / "report.json").read_text(encoding="utf-8")
            )
            deterministic_report = json.loads(
                (deterministic_dir / "reports" / "report.json").read_text(encoding="utf-8")
            )
            semantic_summary_fields = {
                "candidate_count",
                "rejected_count",
                "validated_count",
                "confirmed_count",
                "likely_count",
                "manual_required_count",
                "validation_rejected_count",
                "validation_level_distribution",
            }
            contract = json.loads(
                (Path(__file__).parent / "legacy_runtime_contract.v1.json").read_text(encoding="utf-8")
            )

            self.assertEqual(
                {key: legacy.get(key) for key in semantic_summary_fields},
                {key: deterministic.get(key) for key in semantic_summary_fields},
            )
            self.assertEqual(
                normalize(legacy_report, legacy_dir),
                normalize(deterministic_report, deterministic_dir),
            )
            for run_dir in (legacy_dir, deterministic_dir):
                categories = {item.name for item in run_dir.iterdir() if item.is_dir()}
                self.assertTrue(set(contract["artifact_categories"]) <= categories)
                for category in contract["artifact_categories"]:
                    self.assertTrue(any((run_dir / category).iterdir()), category)

    def test_deterministic_graph_mode_drives_scheduler_and_persists_execution_path(self):
        from audit_agent.pipeline import run_audit

        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            config = AuditConfig.default()
            config.runtime_enabled = False
            config.graph.mode = "deterministic-graph"
            config.cve_mcp.enabled = False

            result = run_audit(str(project), config=config, output_dir=Path(tmp) / "runs")
            run_dir = Path(result["run_dir"])
            state = json.loads((run_dir / "runtime_state" / "state.json").read_text(encoding="utf-8"))

            self.assertEqual(state["graph_mode"], "deterministic-graph")
            self.assertTrue(state["initial_graph_ref"])
            self.assertTrue(state["final_graph_ref"])
            self.assertEqual(state["execution_path"][0], "orchestrator-plan")
            self.assertEqual(state["execution_path"][-1], "report-finalization")
            self.assertTrue(all(task["graph_node_id"] for task in state["tasks"]))
            self.assertTrue((run_dir / "graphs").is_dir())
            report = json.loads((run_dir / "reports" / "report.json").read_text(encoding="utf-8"))
            markdown = (run_dir / "reports" / "report.md").read_text(encoding="utf-8")
            graph_report = report["runtime"]["graph"]
            self.assertEqual(graph_report["schema_version"], "agent-execution-graph.v1")
            self.assertEqual(graph_report["template_version"], "v1")
            self.assertEqual(graph_report["execution_path"][-1], "report-finalization")
            self.assertEqual(graph_report["mutation_counts"], {"committed": 0, "denied": 0})
            self.assertTrue(Path(graph_report["artifact_refs"]["final_graph_ref"]).exists())
            self.assertTrue(Path(graph_report["artifact_refs"]["replay_ref"]).exists())
            self.assertIn("## Execution Graph", markdown)
            contract = json.loads(
                (Path(__file__).parent / "legacy_runtime_contract.v1.json").read_text(encoding="utf-8")
            )
            self.assertTrue(set(contract["summary_fields"]) <= set(result))

    def test_adaptive_checkpoint_next_action_inserts_analysis_into_live_execution_path(self):
        from audit_agent.runtime import AgentRegistry, AgentRuntime, default_agent_registry

        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            config = AuditConfig.default()
            config.runtime_enabled = False
            config.graph.mode = "adaptive-graph"
            config.cve_mcp.enabled = False
            defaults = default_agent_registry(config)
            registry = AgentRegistry()
            analysis_calls = []
            verification_inputs = []
            for role in defaults.roles():
                handler = defaults.get(role).handler
                if role == "analysis":
                    def adaptive_analysis(invocation, base_handler=handler):
                        output = base_handler(invocation)
                        analysis_calls.append(invocation.task_state.graph_node_id)
                        if len(analysis_calls) == 2:
                            for finding in output.payload["result"].payload["candidates"]:
                                finding.metadata["refinement_marker"] = "second-pass"
                        output.next_actions = ["repeat-analysis"]
                        return output

                    handler = adaptive_analysis
                elif role == "verification":
                    def observe_verification(invocation, base_handler=handler):
                        verification_inputs.extend(invocation.inputs["candidates"])
                        return base_handler(invocation)

                    handler = observe_verification
                registry.register(role, handler)

            result = AgentRuntime(
                config,
                output_dir=Path(tmp) / "runs",
                registry=registry,
            ).run_audit(str(project))
            run_dir = Path(result["run_dir"])
            state = json.loads((run_dir / "runtime_state" / "state.json").read_text(encoding="utf-8"))
            refinement_nodes = [
                node_id for node_id in state["execution_path"] if node_id.startswith("repeat-analysis-")
            ]

            self.assertEqual(len(refinement_nodes), 1)
            self.assertLess(
                state["execution_path"].index("post-analysis-checkpoint"),
                state["execution_path"].index(refinement_nodes[0]),
            )
            self.assertLess(
                state["execution_path"].index(refinement_nodes[0]),
                state["execution_path"].index("verification"),
            )
            self.assertEqual(state["checkpoint_counts"], {"post-analysis": 1})
            self.assertTrue(state["mutation_refs"])
            self.assertEqual(len(analysis_calls), 2)
            self.assertTrue(verification_inputs)
            self.assertTrue(
                all(item.metadata.get("refinement_marker") == "second-pass" for item in verification_inputs)
            )

    def test_adaptive_graph_uses_strict_model_decisions_at_both_checkpoints(self):
        from audit_agent.llm import MockLLMClient
        from audit_agent.models import LLMResponse
        from audit_agent.pipeline import run_audit

        class CheckpointClient:
            def __init__(self):
                self.checkpoints = []

            def complete(self, request):
                if "bounded graph decision agent" not in request.prompt:
                    return MockLLMClient().complete(request)
                checkpoint = "post-recon" if "checkpoint post-recon" in request.prompt else "post-analysis"
                self.checkpoints.append(checkpoint)
                action = "refine-static-scan" if checkpoint == "post-recon" else "repeat-analysis"
                payload = {
                    "checkpoint_id": checkpoint,
                    "next_actions": [action],
                    "rationale": "bounded local fixture refinement",
                }
                return LLMResponse(
                    request_id=request.id or "",
                    provider="mock",
                    model=request.model,
                    text=json.dumps(payload),
                    parsed_json=payload,
                    usage={"total_tokens": 12},
                )

        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            client = CheckpointClient()
            config = AuditConfig.default()
            config.runtime_enabled = True
            config.graph.mode = "adaptive-graph"
            config.llm_decisions.enabled = True
            config.llm_decisions.roles = ["orchestrator"]
            config.cve_mcp.enabled = False
            config.mcp.enabled = False

            with patch("audit_agent.runtime.build_llm_client", return_value=client):
                result = run_audit(str(project), config=config, output_dir=Path(tmp) / "runs")

            run_dir = Path(result["run_dir"])
            state = json.loads((run_dir / "runtime_state" / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(client.checkpoints, ["post-recon", "post-analysis"])
            self.assertTrue(any(item.startswith("refine-static-scan-") for item in state["execution_path"]))
            self.assertTrue(any(item.startswith("repeat-analysis-") for item in state["execution_path"]))
            self.assertEqual(state["checkpoint_counts"], {"post-recon": 1, "post-analysis": 1})
            self.assertGreaterEqual(len(list((run_dir / "prompts").glob("*graph-decision*"))), 2)
            self.assertTrue(any(task["graph_node_id"].startswith("refine-static-scan-") for task in state["tasks"]))
            messages = (run_dir / "messages" / "messages.jsonl").read_text(encoding="utf-8")
            self.assertIn("graph.mutation.committed", messages)
            report = json.loads((run_dir / "reports" / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["runtime"]["graph"]["mutation_counts"]["committed"], 2)
            replay_path = Path(report["runtime"]["graph"]["artifact_refs"]["replay_ref"])
            replay = json.loads(replay_path.read_text(encoding="utf-8"))
            self.assertEqual(replay["execution_path"], state["execution_path"])
            self.assertEqual(replay["committed_mutation_count"], 2)

    def test_poc_repair_artifacts_stay_correlated_to_one_graph_validation_attempt(self):
        from audit_agent.models import ValidationResult
        from audit_agent.pipeline import run_audit

        class FakeVerificationEngine:
            integrity_artifact_refs = ["verification/integrity-final.json"]

            def __init__(self, *args, **kwargs):
                pass

            def begin_validation_phase(self, metadata):
                return None

            def verify(self, decision, metadata, level):
                return ValidationResult(
                    finding_id=decision.finding.id or "",
                    level=level,
                    status="passed",
                    verification_status="confirmed",
                    attempt_refs=["verification/attempt-0.json", "verification/attempt-1.json"],
                    poc_refs=["verification/poc-0.json", "verification/poc-1.json"],
                    sandbox_result_refs=["verification/sandbox-0.json", "verification/sandbox-1.json"],
                    artifacts=["verification/repair-1.json"],
                    repair_attempt_count=1,
                    final_status="confirmed",
                )

            def finalize_validation_phase(self, metadata, staged):
                return [result for _, result in staged]

        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            config = AuditConfig.default()
            config.runtime_enabled = False
            config.graph.mode = "deterministic-graph"
            config.cve_mcp.enabled = False
            with patch("audit_agent.runtime.VerificationEngine", FakeVerificationEngine):
                result = run_audit(str(project), config=config, output_dir=Path(tmp) / "runs")

            run_dir = Path(result["run_dir"])
            state = json.loads((run_dir / "runtime_state" / "state.json").read_text(encoding="utf-8"))
            validation_task = next(item for item in state["tasks"] if item["graph_node_id"] == "validation")
            report = json.loads((run_dir / "reports" / "report.json").read_text(encoding="utf-8"))
            transitions = [
                transition
                for path in (run_dir / "graphs").glob("transitions-*.json")
                for transition in json.loads(path.read_text(encoding="utf-8"))["transitions"]
                if transition["node_id"] == "validation"
            ]

            self.assertEqual(validation_task["attempt"], 1)
            self.assertEqual(sum(item["new_status"] == "running" for item in transitions), 1)
            self.assertFalse(any(item["new_status"] == "fallback" for item in transitions))
            self.assertIn("verification/repair-1.json", validation_task["artifact_refs"])
            self.assertIn("verification/attempt-1.json", validation_task["correlation_refs"])
            self.assertEqual(report["verification_candidates"][0]["repair_summary"]["attempt_count"], 1)

    def test_adaptive_failures_retain_last_committed_graph_without_partial_nodes(self):
        from audit_agent.models import LLMResponse
        from audit_agent.pipeline import run_audit

        class FailingClient:
            def __init__(self, malformed=False):
                self.malformed = malformed

            def complete(self, request):
                if "bounded graph decision agent" not in request.prompt:
                    from audit_agent.llm import MockLLMClient
                    return MockLLMClient().complete(request)
                if not self.malformed:
                    raise RuntimeError("synthetic provider unavailable")
                payload = {"operation": "repeat-analysis"}
                return LLMResponse(
                    request_id=request.id or "",
                    provider="mock",
                    model=request.model,
                    text=json.dumps(payload),
                    parsed_json=payload,
                    usage={"total_tokens": 1},
                )

        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            for label, client in (("unavailable", FailingClient()), ("malformed", FailingClient(True))):
                config = AuditConfig.default()
                config.runtime_enabled = True
                config.graph.mode = "adaptive-graph"
                config.llm_decisions.enabled = True
                config.llm_decisions.roles = ["orchestrator"]
                config.cve_mcp.enabled = False
                config.mcp.enabled = False
                with self.subTest(label=label), patch(
                    "audit_agent.runtime.build_llm_client", return_value=client
                ):
                    result = run_audit(
                        str(project),
                        config=config,
                        output_dir=Path(tmp) / label,
                    )
                    run_dir = Path(result["run_dir"])
                    state = json.loads(
                        (run_dir / "runtime_state" / "state.json").read_text(encoding="utf-8")
                    )
                    final_graph = json.loads(Path(state["final_graph_ref"]).read_text(encoding="utf-8"))
                    self.assertEqual(final_graph["revision"], 0)
                    self.assertEqual(final_graph["global_replan_count"], 0)
                    self.assertFalse(any(node["lineage"]["proposal_ref"] for node in final_graph["nodes"]))
                    self.assertTrue(state["graph_fallback_reason"].startswith("model-decision-"))
                    self.assertTrue(list((run_dir / "runtime_errors").glob("graph-decision-*.json")))

    def test_policy_and_mutation_persistence_failures_do_not_commit_candidate(self):
        from audit_agent.runtime import AgentRegistry, AgentRuntime, default_agent_registry

        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))

            def registry_with_repeat(config):
                defaults = default_agent_registry(config)
                registry = AgentRegistry()
                for role in defaults.roles():
                    handler = defaults.get(role).handler
                    if role == "analysis":
                        def repeat(invocation, base=handler):
                            output = base(invocation)
                            output.next_actions = ["repeat-analysis"]
                            return output
                        handler = repeat
                    registry.register(role, handler)
                return registry

            cases = [
                ("policy", patch("audit_agent.runtime.GraphMutationPolicy.evaluate", side_effect=RuntimeError("policy failed"))),
                ("persistence", patch("audit_agent.runtime.GraphArtifactRecorder.persist_mutation", side_effect=OSError("disk failed"))),
            ]
            for label, failure_patch in cases:
                config = AuditConfig.default()
                config.runtime_enabled = False
                config.graph.mode = "adaptive-graph"
                config.cve_mcp.enabled = False
                with self.subTest(label=label), failure_patch:
                    result = AgentRuntime(
                        config,
                        output_dir=Path(tmp) / label,
                        registry=registry_with_repeat(config),
                    ).run_audit(str(project))
                state = json.loads(
                    (Path(result["run_dir"]) / "runtime_state" / "state.json").read_text(encoding="utf-8")
                )
                final_graph = json.loads(Path(state["final_graph_ref"]).read_text(encoding="utf-8"))
                self.assertEqual(final_graph["revision"], 0)
                self.assertFalse(any(node["node_id"].startswith("repeat-analysis-") for node in final_graph["nodes"]))
                expected = "policy-exception" if label == "policy" else "mutation-persistence-failed"
                self.assertEqual(state["graph_fallback_reason"], expected)

    def test_two_accepted_offline_paths_invoke_distinct_nodes_and_replay_deterministically(self):
        from audit_agent.runtime import AgentRegistry, AgentRuntime, default_agent_registry

        def run_path(project, output, action_role, action):
            config = AuditConfig.default()
            config.runtime_enabled = False
            config.graph.mode = "adaptive-graph"
            config.cve_mcp.enabled = False
            defaults = default_agent_registry(config)
            registry = AgentRegistry()
            for role in defaults.roles():
                handler = defaults.get(role).handler
                if role == action_role:
                    def adaptive(invocation, base=handler, selected=action):
                        result = base(invocation)
                        result.next_actions = [selected]
                        return result
                    handler = adaptive
                registry.register(role, handler)
            summary = AgentRuntime(config, output_dir=output, registry=registry).run_audit(str(project))
            run_dir = Path(summary["run_dir"])
            state = json.loads((run_dir / "runtime_state" / "state.json").read_text(encoding="utf-8"))
            report = json.loads((run_dir / "reports" / "report.json").read_text(encoding="utf-8"))
            replay = json.loads(Path(report["runtime"]["graph"]["artifact_refs"]["replay_ref"]).read_text(encoding="utf-8"))
            return state, replay

        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            context_state, context_replay = run_path(
                project, Path(tmp) / "context", "recon", "gather-more-local-context"
            )
            analysis_state, analysis_replay = run_path(
                project, Path(tmp) / "analysis-a", "analysis", "repeat-analysis"
            )
            repeated_state, repeated_replay = run_path(
                project, Path(tmp) / "analysis-b", "analysis", "repeat-analysis"
            )

            context_nodes = set(context_state["execution_path"])
            analysis_nodes = set(analysis_state["execution_path"])
            self.assertNotEqual(context_nodes, analysis_nodes)
            self.assertTrue(any(item.startswith("gather-more-local-context-") for item in context_nodes))
            self.assertTrue(any(item.startswith("repeat-analysis-") for item in analysis_nodes))
            self.assertEqual(context_replay["execution_path"], context_state["execution_path"])
            self.assertEqual(analysis_replay["execution_path"], analysis_state["execution_path"])
            for key in (
                "revision_order",
                "execution_path",
                "skipped_nodes",
                "retry_counts",
                "fallback_nodes",
                "final_node_statuses",
                "committed_mutation_count",
                "denied_mutation_count",
                "missing_refs",
                "inconsistencies",
            ):
                self.assertEqual(analysis_replay[key], repeated_replay[key], key)

    def test_skip_optional_path_runs_verification_and_replays_mutation_status(self):
        from audit_agent.runtime import AgentRegistry, AgentRuntime, default_agent_registry

        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            config = AuditConfig.default()
            config.runtime_enabled = False
            config.graph.mode = "adaptive-graph"
            config.cve_mcp.enabled = False
            defaults = default_agent_registry(config)
            registry = AgentRegistry()
            for role in defaults.roles():
                handler = defaults.get(role).handler
                if role == "analysis":
                    def skip_routing(invocation, base=handler):
                        output = base(invocation)
                        output.next_actions = ["route-verification", "skip-optional"]
                        return output

                    handler = skip_routing
                registry.register(role, handler)

            summary = AgentRuntime(
                config,
                output_dir=Path(tmp) / "runs",
                registry=registry,
            ).run_audit(str(project))
            run_dir = Path(summary["run_dir"])
            state = json.loads(
                (run_dir / "runtime_state" / "state.json").read_text(encoding="utf-8")
            )
            final_graph = json.loads(Path(state["final_graph_ref"]).read_text(encoding="utf-8"))
            replay = json.loads(
                (run_dir / "graphs" / f"replay-{final_graph['graph_id']}.json").read_text(
                    encoding="utf-8"
                )
            )
            routing = next(
                node
                for node in final_graph["nodes"]
                if node["node_id"].startswith("route-verification-")
            )

            self.assertEqual(state["status"], "succeeded")
            self.assertEqual(routing["status"], "skipped")
            self.assertEqual(
                next(node for node in final_graph["nodes"] if node["node_id"] == "verification")["status"],
                "succeeded",
            )
            self.assertNotIn(routing["node_id"], state["execution_path"])
            self.assertFalse(
                any(
                    edge["source_node_id"] == routing["node_id"]
                    and edge["target_node_id"] == "verification"
                    for edge in final_graph["edges"]
                )
            )
            self.assertTrue(replay["complete"], replay["inconsistencies"])
            self.assertIn(routing["node_id"], replay["skipped_nodes"])
            self.assertEqual(replay["final_node_statuses"][routing["node_id"]], "skipped")

    def test_default_graph_run_needs_no_external_service_and_does_not_write_target(self):
        from audit_agent.pipeline import run_audit

        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            source = project / "app.py"
            before = source.read_bytes()
            config = AuditConfig.default()

            with (
                patch("audit_agent.runtime.build_llm_client", side_effect=AssertionError("LLM must stay offline")),
                patch("audit_agent.runtime.CveMcpClient", side_effect=AssertionError("MCP must stay offline")),
                patch("audit_agent.verification.DockerSandboxRunner", side_effect=AssertionError("Docker must stay offline")),
            ):
                result = run_audit(str(project), config=config, output_dir=Path(tmp) / "runs")

            self.assertEqual(config.graph.mode, "deterministic-graph")
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(result["graph_mode"], "deterministic-graph")

    def test_graph_required_report_failure_persists_failed_primary_state(self):
        from audit_agent.pipeline import run_audit

        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            output = Path(tmp) / "runs"
            config = AuditConfig.default()
            config.runtime_enabled = False
            config.graph.mode = "deterministic-graph"
            config.cve_mcp.enabled = False
            with patch("audit_agent.runtime.ReportGenerator.build", side_effect=RuntimeError("report-failed")):
                with self.assertRaisesRegex(RuntimeError, "report-finalization"):
                    run_audit(str(project), config=config, output_dir=output)

            run_dir = next(output.iterdir())
            state = json.loads((run_dir / "runtime_state" / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["status"], "failed")
            self.assertEqual(state["graph_mode"], "deterministic-graph")
            self.assertTrue(state["final_graph_ref"])

    def test_legacy_malformed_decision_and_denied_tool_remain_fail_closed(self):
        from audit_agent.decisions import build_decision_from_llm_response, evaluate_decision_policy

        config = AuditConfig.default()
        config.llm_decisions.enabled = True
        malformed = build_decision_from_llm_response("analysis", {"model_text": "not-the-contract"})
        gate = evaluate_decision_policy("analysis", malformed, config)

        self.assertEqual(malformed.schema_status, "invalid")
        self.assertEqual(malformed.fallback_reason, "schema-invalid")
        self.assertEqual(gate.status, "denied")

    def test_legacy_required_report_finalization_failure_marks_run_failed(self):
        from audit_agent.pipeline import run_audit

        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            output = Path(tmp) / "runs"
            config = AuditConfig.default()
            config.graph.mode = "legacy"
            config.cve_mcp.enabled = False
            with patch("audit_agent.runtime.ReportGenerator.build", side_effect=RuntimeError("report-failed")):
                with self.assertRaisesRegex(RuntimeError, "report-failed"):
                    run_audit(str(project), config=config, output_dir=output)

            run_dir = next(output.iterdir())
            state = json.loads((run_dir / "runtime_state" / "state.json").read_text(encoding="utf-8"))
            resources = json.loads(
                (run_dir / "reports" / "run-resource-summary.v1.json").read_text(encoding="utf-8")
            )
            self.assertEqual(state["status"], "failed")
            self.assertEqual(resources["terminal_status"], "failed")

    def test_legacy_runtime_characterization_preserves_stage_order_and_contract(self):
        from audit_agent.pipeline import run_audit

        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            config = AuditConfig.default()
            config.runtime_enabled = False
            config.graph.mode = "legacy"
            config.cve_mcp.enabled = False

            result = run_audit(str(project), config=config, output_dir=Path(tmp) / "runs")
            run_dir = Path(result["run_dir"])
            state = json.loads((run_dir / "runtime_state" / "state.json").read_text(encoding="utf-8"))
            report = json.loads((run_dir / "reports" / "report.json").read_text(encoding="utf-8"))
            task_order = [(task["role"], task["kind"]) for task in state["tasks"]]
            contract = json.loads(
                (Path(__file__).parent / "legacy_runtime_contract.v1.json").read_text(encoding="utf-8")
            )

            self.assertEqual(task_order, [tuple(item) for item in contract["task_order"]])
            self.assertTrue(set(contract["summary_fields"]) <= set(result))
            self.assertTrue(set(contract["artifact_categories"]) <= {item.name for item in run_dir.iterdir()})
            self.assertTrue(set(contract["report_fields"]) <= set(report))

    def test_run_audit_delegates_to_runtime_kernel_and_preserves_outputs(self):
        from audit_agent.pipeline import run_audit

        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            config = AuditConfig.default()
            config.runtime_enabled = True
            config.llm.provider = "mock"
            config.llm_decisions.enabled = True
            config.memory.enabled = True
            config.message_bus.enabled = True
            config.mcp.enabled = False

            result = run_audit(str(project), config=config, output_dir=Path(tmp) / "runs")
            run_dir = Path(result["run_dir"])
            report = json.loads((run_dir / "reports" / "report.json").read_text(encoding="utf-8"))
            state = json.loads((run_dir / "runtime_state" / "state.json").read_text(encoding="utf-8"))
            replay = replay_summary(run_dir / "messages" / "messages.jsonl")

            self.assertIn("candidate_count", result)
            self.assertTrue((run_dir / "decisions").exists())
            self.assertEqual(report["runtime"]["kernel"]["name"], "AgentRuntime")
            self.assertTrue(report["runtime"]["kernel"]["state_ref"].endswith("runtime_state\\state.json") or report["runtime"]["kernel"]["state_ref"].endswith("runtime_state/state.json"))
            self.assertEqual(state["status"], "succeeded")
            self.assertIn("analysis", {task["role"] for task in state["tasks"]})
            self.assertIn("runtime_lifecycle", replay)
            self.assertIn("analysis", replay["runtime_lifecycle"]["roles"])


if __name__ == "__main__":
    unittest.main()
