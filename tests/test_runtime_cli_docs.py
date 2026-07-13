import json
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

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
                "--graph-mode",
                "adaptive-graph",
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
                "--validation-level",
                "sandbox",
                "--llm-poc-repair",
                "--max-repair-attempts",
                "2",
                "--include",
                "src/**",
                "--exclude",
                "legacy/**",
            ]
        )

        self.assertTrue(args.runtime)
        self.assertEqual(args.graph_mode, "adaptive-graph")
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
        self.assertTrue(args.llm_poc_repair)
        self.assertEqual(args.max_repair_attempts, 2)
        self.assertEqual(args.include, ["src/**"])
        self.assertEqual(args.exclude, ["legacy/**"])

        config = AuditConfig.default()
        _apply_runtime_args(config, args)

        self.assertEqual(config.graph.mode, "adaptive-graph")
        self.assertTrue(config.sandbox.enabled)
        self.assertEqual(config.sandbox.runner, "docker")
        self.assertEqual(config.sandbox.docker_image, "python:3.12-slim")
        self.assertEqual(config.sandbox.docker_context, "desktop-linux")
        self.assertEqual(config.sandbox.docker_host, "npipe:////./pipe/dockerDesktopLinuxEngine")
        self.assertTrue(config.poc_repair.enabled)
        self.assertEqual(config.poc_repair.max_repair_attempts, 2)
        self.assertEqual(config.poc_repair.effective_source, "explicit")
        config.validate_poc_repair_prerequisites()
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

    def test_graph_decision_smoke_is_explicitly_skipped_without_live_opt_in(self):
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = main(["graph-decision-smoke"])

        self.assertEqual(exit_code, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["status"], "skipped")
        self.assertFalse(payload["prerequisites"]["live_flag"])

    def test_graph_decision_smoke_uses_dotenv_key_in_the_provider_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "fixtures" / "integration_smoke"
            target.mkdir(parents=True)
            (root / ".env").write_text(
                "AUDIT_AGENT_LLM_PROVIDER=openai-compatible\n"
                "LLM_MODEL=synthetic-real-model\n"
                "LLM_API_KEY=synthetic-provider-key\n",
                encoding="utf-8",
            )
            run_dir = root / "fake-run"
            captured = {}

            def fake_run_audit(target_path, config, output_dir):
                captured["provider"] = config.llm.provider
                captured["model"] = config.llm.model
                captured["api_key_env"] = config.llm.api_key_env
                captured["api_key_visible"] = os.environ.get(config.llm.api_key_env)
                (run_dir / "runtime_state").mkdir(parents=True)
                (run_dir / "prompts").mkdir(parents=True)
                (run_dir / "runtime_state" / "state.json").write_text(
                    json.dumps({"status": "succeeded", "graph_mode": "adaptive-graph"}),
                    encoding="utf-8",
                )
                (run_dir / "prompts" / "graph-decision-synthetic.json").write_text(
                    "{}",
                    encoding="utf-8",
                )
                return {"run_dir": str(run_dir)}

            previous_cwd = Path.cwd()
            output = io.StringIO()
            try:
                os.chdir(root)
                with (
                    patch.dict(os.environ, {"AUDIT_AGENT_RUN_GRAPH_SMOKE": "1"}, clear=True),
                    patch("audit_agent.cli.run_audit", side_effect=fake_run_audit),
                    redirect_stdout(output),
                ):
                    exit_code = main(
                        [
                            "graph-decision-smoke",
                            "--live",
                            "--target",
                            str(target),
                            "--output",
                            str(root / "runs"),
                        ]
                    )
            finally:
                os.chdir(previous_cwd)

        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "passed")
        self.assertEqual(captured["provider"], "openai-compatible")
        self.assertEqual(captured["model"], "synthetic-real-model")
        self.assertEqual(captured["api_key_env"], "LLM_API_KEY")
        self.assertEqual(captured["api_key_visible"], "synthetic-provider-key")
        self.assertNotIn("synthetic-provider-key", output.getvalue())

    def test_runtime_docs_exist_with_required_topics(self):
        docs = (Path("docs") / "usage.md").read_text(encoding="utf-8")

        self.assertIn("API key", docs)
        self.assertIn("Prompt", docs)
        self.assertIn("tool-calling", docs)
        self.assertIn("MCP", docs)
        self.assertIn("RAG", docs)
        self.assertIn("message bus", docs.lower())
        self.assertIn("deterministic-graph", docs)
        self.assertIn("adaptive-graph", docs)
        self.assertIn("last committed graph", docs)


if __name__ == "__main__":
    unittest.main()
