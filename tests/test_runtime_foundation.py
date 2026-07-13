import json
import tempfile
import unittest
from pathlib import Path

from audit_agent.config import AuditConfig
from audit_agent.models import (
    LLMRequest,
    LLMResponse,
    MCPCallRecord,
    MemoryRecord,
    MessageEnvelope,
    PromptRenderRecord,
    ToolCallRequest,
)
from audit_agent.storage import RunStore


class RuntimeFoundationTests(unittest.TestCase):
    def test_default_config_exposes_runtime_settings(self):
        config = AuditConfig.default()

        self.assertEqual(config.llm.provider, "mock")
        self.assertEqual(config.llm.api_key_env, "OPENAI_API_KEY")
        self.assertEqual(config.prompts.default_version, "v1")
        self.assertIn("analysis", config.tools.per_agent_budgets)
        self.assertEqual(config.mcp.transport, "stdio")
        self.assertEqual(config.memory.mode, "lexical")
        self.assertTrue(config.message_bus.enabled)
        self.assertEqual(config.graph.mode, "deterministic-graph")

    def test_graph_runtime_mode_validates_and_serializes(self):
        from audit_agent.config import GraphRuntimeConfig

        for mode in ("legacy", "deterministic-graph", "adaptive-graph"):
            config = AuditConfig.default()
            config.graph = GraphRuntimeConfig(mode=mode)
            self.assertEqual(config.to_dict()["graph"]["mode"], mode)

        with self.assertRaisesRegex(ValueError, "graph.mode"):
            GraphRuntimeConfig(mode="free-form-agents")

    def test_run_store_creates_runtime_artifact_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = RunStore(Path(tmp)).create_run("runtime-target")
            names = {path.name for path in run.path.iterdir()}

            self.assertTrue(
                {"prompts", "llm", "messages", "memory", "mcp", "runtime_errors"}.issubset(names)
            )

    def test_runtime_models_are_serializable_with_stable_ids(self):
        prompt = PromptRenderRecord(
            template_id="analysis.candidates",
            version="v1",
            role="analysis",
            variables={"target": "demo"},
            rendered="Analyze demo",
        )
        request = LLMRequest(role="analysis", prompt=prompt.rendered, model="mock-model")
        response = LLMResponse(
            request_id=request.id,
            provider="mock",
            model="mock-model",
            text='{"candidates": []}',
            parsed_json={"candidates": []},
            usage={"prompt_tokens": 3, "completion_tokens": 4},
        )
        tool_call = ToolCallRequest(
            agent="analysis",
            tool_name="source-context",
            arguments={"path": "app.py", "start_line": 1, "end_line": 3},
        )
        mcp = MCPCallRecord(
            session_id="session-1",
            tool_name="lookup_cve",
            arguments={"cve_id": "CVE-2099-0001"},
            success=True,
            response={"id": "CVE-2099-0001"},
        )
        memory = MemoryRecord(
            namespace="repository",
            target_id="demo",
            content="request args reach os.system",
            source_path="app.py",
            start_line=10,
            end_line=12,
        )
        message = MessageEnvelope(
            run_id="run-1",
            sender="analysis",
            recipient="tool-protocol",
            message_type="tool.request",
            payload=tool_call.to_dict(),
            artifact_refs=[prompt.id, response.id],
        )

        for item in [prompt, request, response, tool_call, mcp, memory, message]:
            payload = item.to_dict()
            self.assertTrue(payload["id"])
            json.dumps(payload)


if __name__ == "__main__":
    unittest.main()
