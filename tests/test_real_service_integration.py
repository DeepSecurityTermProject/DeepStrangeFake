import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from audit_agent.cli import build_parser, main
from audit_agent.config import AuditConfig
from audit_agent.integration import (
    load_integration_environment,
    redact_secrets,
    run_integration_preflight,
    run_integration_smoke,
)
from audit_agent.mcp_client import MCPClient


FAKE_MCP_SERVER = r"""
import json
import sys

for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    if method == "initialize":
        result = {"serverInfo": {"name": "fake-cve-mcp", "version": "test"}, "capabilities": {"tools": {}}}
    elif method == "tools/list":
        result = {"tools": [
            {"name": "lookup_cve", "description": "Lookup CVE", "inputSchema": {"type": "object"}},
            {"name": "get_epss_score", "description": "EPSS", "inputSchema": {"type": "object"}}
        ]}
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "{\"cve_id\":\"CVE-2099-0001\",\"cvss\":9.1,\"cwe_ids\":[\"CWE-89\"]}"}]}
    else:
        result = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": request.get("id"), "result": result}) + "\n")
    sys.stdout.flush()
"""


class RealServiceIntegrationTests(unittest.TestCase):
    def test_dotenv_updates_llm_and_local_mcp_command_without_exposing_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cve_dir = root / "cve-mcp-server"
            python_path = cve_dir / "venv" / "Scripts" / "python.exe"
            env_file = root / ".env"
            env_file.write_text(
                "\n".join(
                    [
                        "OPENAI_API_KEY=super-secret-value",
                        "AUDIT_AGENT_LLM_BASE_URL=https://models.example/v1",
                        "AUDIT_AGENT_LLM_MODEL=live-model",
                        "AUDIT_AGENT_LLM_RESPONSE_FORMAT=json_object",
                        f"AUDIT_AGENT_CVE_MCP_DIR={cve_dir}",
                        f"AUDIT_AGENT_CVE_MCP_PYTHON={python_path}",
                    ]
                ),
                encoding="utf-8",
            )
            config = AuditConfig.default()
            config.integration.env_file = str(env_file)
            env = {}

            result = load_integration_environment(config, cwd=root, env=env)

            self.assertTrue(result.loaded)
            self.assertEqual(config.llm.base_url, "https://models.example/v1")
            self.assertEqual(config.llm.model, "live-model")
            self.assertEqual(config.llm.response_format, "json_object")
            self.assertEqual(config.mcp.command, [str(python_path), "-m", "cve_mcp.server"])
            self.assertEqual(config.mcp.working_dir, str(cve_dir))
            self.assertEqual(config.mcp.env["CACHE_DB_PATH"], str(cve_dir / ".cache" / "cache.db"))
            self.assertEqual(config.mcp.env["AUDIT_LOG_PATH"], str(cve_dir / ".cache" / "audit.log"))
            self.assertEqual(env["OPENAI_API_KEY"], "super-secret-value")
            self.assertNotIn("super-secret-value", json.dumps(result.to_dict()))

    def test_dotenv_accepts_llm_api_key_and_base_url_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env_file = root / ".env"
            env_file.write_text(
                "\n".join(
                    [
                        "LLM_API_KEY=alias-secret-value",
                        "LLM_API_BASE_URL=https://alias.example/v1",
                        "LLM_MODEL=alias-model",
                    ]
                ),
                encoding="utf-8",
            )
            config = AuditConfig.default()
            config.integration.env_file = str(env_file)
            env = {}

            result = load_integration_environment(config, cwd=root, env=env)

            self.assertTrue(result.loaded)
            self.assertEqual(config.llm.provider, "openai-compatible")
            self.assertEqual(config.llm.api_key_env, "LLM_API_KEY")
            self.assertEqual(config.llm.base_url, "https://alias.example/v1")
            self.assertEqual(config.llm.model, "alias-model")
            self.assertEqual(env["LLM_API_KEY"], "alias-secret-value")
            self.assertNotIn("alias-secret-value", json.dumps(result.to_dict()))

    def test_invalid_llm_response_format_override_is_rejected(self):
        config = AuditConfig.default()
        with self.assertRaisesRegex(ValueError, "response_format"):
            load_integration_environment(
                config,
                env={"AUDIT_AGENT_LLM_RESPONSE_FORMAT": "free-form"},
            )

    def test_redaction_removes_secret_keys_and_values_recursively(self):
        payload = {
            "Authorization": "Bearer secret-token",
            "nested": {
                "api_key": "secret-token",
                "message": "request failed with token=secret-token",
            },
        }

        redacted = redact_secrets(payload, secret_values=["secret-token"])

        serialized = json.dumps(redacted)
        self.assertNotIn("secret-token", serialized)
        self.assertEqual(redacted["Authorization"], "[REDACTED]")
        self.assertEqual(redacted["nested"]["api_key"], "[REDACTED]")

    def test_llm_preflight_reports_missing_api_key_without_secret_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = AuditConfig.default()
            config.llm.provider = "openai-compatible"
            config.llm.model = "unit-live-model"
            config.llm.api_key_env = "AUDIT_AGENT_MISSING_KEY"
            config.integration.load_env_file = False

            report = run_integration_preflight(
                config,
                output_dir=Path(tmp),
                include_llm=True,
                include_mcp=False,
                execute_live=False,
                env={},
            )

            self.assertEqual(report.overall_status, "fail")
            self.assertEqual(report.components["llm"].status, "fail")
            self.assertIn("AUDIT_AGENT_MISSING_KEY", report.components["llm"].message)
            self.assertTrue(Path(report.artifacts["json"]).exists())
            self.assertTrue(Path(report.artifacts["markdown"]).exists())
            self.assertNotIn("super-secret", json.dumps(report.to_dict()).lower())

    def test_mcp_preflight_discovers_available_and_missing_safe_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = Path(tmp) / "fake_mcp.py"
            server.write_text(FAKE_MCP_SERVER, encoding="utf-8")
            config = AuditConfig.default()
            config.mcp.command = [sys.executable, str(server)]
            config.integration.safe_cve_mcp_tools = ["lookup_cve", "get_epss_score", "check_kev_status"]

            report = run_integration_preflight(
                config,
                output_dir=Path(tmp) / "runs",
                include_llm=False,
                include_mcp=True,
                execute_live=False,
                env={},
            )

            self.assertEqual(report.components["mcp"].status, "pass")
            self.assertIn("lookup_cve", report.components["mcp"].details["available_tools"])
            self.assertIn("check_kev_status", report.components["mcp"].details["missing_safe_tools"])

    def test_mcp_allowlist_denies_disallowed_tool_without_calling_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = Path(tmp) / "fake_mcp.py"
            server.write_text(FAKE_MCP_SERVER, encoding="utf-8")
            client = MCPClient(
                command=[sys.executable, str(server)],
                timeout_seconds=5,
                allowed_tools=["lookup_cve"],
            )

            with client:
                result = client.call_tool("search_exploits", {"cve_id": "CVE-2099-0001"})

            self.assertFalse(result.success)
            self.assertTrue(result.call_record.degraded)
            self.assertIn("policy-denied", result.message)
            self.assertEqual(client.query_count, 0)

    def test_integration_cli_accepts_preflight_flags(self):
        parser = build_parser()

        args = parser.parse_args(["integration", "preflight", "--llm", "--mcp", "--live", "--output", "runs"])

        self.assertEqual(args.command, "integration")
        self.assertEqual(args.integration_command, "preflight")
        self.assertTrue(args.llm)
        self.assertTrue(args.mcp)
        self.assertTrue(args.live)

    def test_integration_preflight_cli_writes_json_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = main(["integration", "preflight", "--llm", "--output", str(Path(tmp) / "runs")])

            payload = json.loads(output.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertIn(payload["overall_status"], {"pass", "fail", "skip"})
            self.assertTrue(Path(payload["artifacts"]["json"]).exists())

    def test_integration_smoke_can_skip_mcp_for_llm_only_decision_smoke(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = AuditConfig.default()
            config.llm.provider = "mock"
            config.integration.load_env_file = False

            report = run_integration_smoke(
                config=config,
                target="fixtures/integration_smoke",
                output_dir=Path(tmp) / "runs",
                execute_live=False,
                include_llm=True,
                include_mcp=False,
                env={},
            )

            self.assertEqual(report.components["llm"].status, "skip")
            self.assertEqual(report.components["mcp"].status, "skip")

    @unittest.skipUnless(os.environ.get("AUDIT_AGENT_RUN_INTEGRATION") == "1", "live integration is opt-in")
    def test_live_cve_mcp_preflight_against_configured_command(self):
        config = AuditConfig.default()
        report = run_integration_preflight(
            config,
            output_dir=Path("runs") / "live-cve-mcp-preflight",
            include_llm=False,
            include_mcp=True,
            execute_live=True,
        )

        self.assertIn(report.overall_status, {"pass", "fail"})


if __name__ == "__main__":
    unittest.main()
