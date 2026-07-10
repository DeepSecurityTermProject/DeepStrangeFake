import json
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from audit_agent.cli import _apply_runtime_args, build_parser, main
from audit_agent.config import AuditConfig
from audit_agent.message_bus import MessageBus


class RuntimeCliDocsTests(unittest.TestCase):
    def test_scan_cli_accepts_runtime_flags(self):
        parser = build_parser()

        args = parser.parse_args(
            [
                "scan",
                "--target",
                ".",
                "--runtime",
                "--llm-provider",
                "mock",
                "--model",
                "deterministic-local",
                "--prompt-version",
                "v1",
                "--memory-mode",
                "lexical",
                "--mcp-mode",
                "degraded",
                "--sandbox",
                "--sandbox-runner",
                "docker",
                "--sandbox-docker-image",
                "python:3.12-slim",
                "--sandbox-docker-context",
                "desktop-linux",
                "--sandbox-docker-host",
                "npipe:////./pipe/dockerDesktopLinuxEngine",
                "--include",
                "src/**",
                "--exclude",
                "legacy/**",
            ]
        )

        self.assertTrue(args.runtime)
        self.assertEqual(args.llm_provider, "mock")
        self.assertEqual(args.model, "deterministic-local")
        self.assertEqual(args.prompt_version, "v1")
        self.assertEqual(args.memory_mode, "lexical")
        self.assertEqual(args.mcp_mode, "degraded")
        self.assertTrue(args.sandbox)
        self.assertEqual(args.sandbox_runner, "docker")
        self.assertEqual(args.sandbox_docker_image, "python:3.12-slim")
        self.assertEqual(args.sandbox_docker_context, "desktop-linux")
        self.assertEqual(args.sandbox_docker_host, "npipe:////./pipe/dockerDesktopLinuxEngine")
        self.assertEqual(args.include, ["src/**"])
        self.assertEqual(args.exclude, ["legacy/**"])

        config = AuditConfig.default()
        _apply_runtime_args(config, args)

        self.assertTrue(config.sandbox.enabled)
        self.assertEqual(config.sandbox.runner, "docker")
        self.assertEqual(config.sandbox.docker_image, "python:3.12-slim")
        self.assertEqual(config.sandbox.docker_context, "desktop-linux")
        self.assertEqual(config.sandbox.docker_host, "npipe:////./pipe/dockerDesktopLinuxEngine")
        self.assertIn("src/**", config.audit_scope.include_patterns)
        self.assertIn("legacy/**", config.audit_scope.exclude_patterns)

    def test_replay_command_summarizes_message_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "messages.jsonl"
            bus = MessageBus("run-1", log_path)
            bus.publish("analysis", "tool", "tool.request", {"tool": "source-context"})

            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = main(["replay", "--messages", str(log_path)])

            self.assertEqual(exit_code, 0)
            self.assertIn("tool.request", output.getvalue())

    def test_runtime_docs_exist_with_required_topics(self):
        docs = (Path("docs") / "usage.md").read_text(encoding="utf-8")

        self.assertIn("API key", docs)
        self.assertIn("Prompt", docs)
        self.assertIn("tool-calling", docs)
        self.assertIn("MCP", docs)
        self.assertIn("RAG", docs)
        self.assertIn("message bus", docs.lower())


if __name__ == "__main__":
    unittest.main()
