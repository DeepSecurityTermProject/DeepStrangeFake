import tempfile
import time
import unittest
from pathlib import Path

from audit_agent.config import AuditConfig
from audit_agent.repository import analyze_target
from audit_agent.tool_protocol import (
    ToolBudget,
    ToolPermissionError,
    ToolRegistry,
    ToolRuntime,
    build_default_tool_registry,
)

from tests.test_repository_analysis import create_vulnerable_fixture


class ToolProtocolRuntimeTests(unittest.TestCase):
    def test_default_registry_declares_existing_tools(self):
        registry = build_default_tool_registry(AuditConfig.default())
        declarations = registry.declarations()
        names = {decl.name for decl in declarations}

        self.assertIn("repository-search", names)
        self.assertIn("source-context", names)
        self.assertIn("pattern-scan", names)
        self.assertIn("memory.retrieve", names)
        self.assertIn("mcp.cve.lookup", names)

    def test_tool_runtime_executes_source_context_and_records_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            metadata = analyze_target(str(project))
            runtime = ToolRuntime(build_default_tool_registry(AuditConfig.default()), artifact_root=Path(tmp) / "tools")

            result = runtime.call(
                agent="analysis",
                tool_name="source-context",
                arguments={"metadata": metadata, "path": "app.py", "start_line": 8, "end_line": 8},
            )

            self.assertTrue(result.success)
            self.assertEqual(result.tool_name, "source-context")
            self.assertTrue(result.artifact_paths)
            self.assertIn("select * from users", result.observations[0].evidence)

    def test_forbidden_tool_is_denied_without_execution(self):
        runtime = ToolRuntime(build_default_tool_registry(AuditConfig.default()))

        result = runtime.call(
            agent="analysis",
            tool_name="validation.sandbox",
            arguments={"command": "python -c print(1)"},
        )

        self.assertFalse(result.success)
        self.assertEqual(result.status, "denied")
        self.assertIn("not permitted", result.message.lower())

    def test_budget_exhaustion_returns_structured_result(self):
        registry = ToolRegistry()
        registry.register(
            name="echo",
            description="Echo arguments",
            input_schema={"type": "object"},
            permission_group="repository-read",
            handler=lambda arguments: {"ok": arguments},
        )
        runtime = ToolRuntime(registry, budget=ToolBudget(per_agent={"analysis": 1}))

        first = runtime.call("analysis", "echo", {"value": 1})
        second = runtime.call("analysis", "echo", {"value": 2})

        self.assertTrue(first.success)
        self.assertFalse(second.success)
        self.assertEqual(second.status, "budget-exhausted")

    def test_registry_rejects_duplicate_tool_names(self):
        registry = ToolRegistry()
        registry.register("echo", "Echo", {"type": "object"}, "repository-read", lambda arguments: arguments)

        with self.assertRaises(ValueError):
            registry.register("echo", "Duplicate", {"type": "object"}, "repository-read", lambda arguments: arguments)

    def test_tool_timeout_returns_structured_result(self):
        registry = ToolRegistry()
        registry.register(
            name="slow",
            description="Slow tool",
            input_schema={"type": "object"},
            permission_group="repository-read",
            handler=lambda arguments: time.sleep(0.2),
            timeout_seconds=0.01,
        )
        runtime = ToolRuntime(registry)

        result = runtime.call("analysis", "slow", {})

        self.assertFalse(result.success)
        self.assertEqual(result.status, "timeout")


if __name__ == "__main__":
    unittest.main()
