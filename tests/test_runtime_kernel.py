import json
import tempfile
import unittest
from pathlib import Path

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
