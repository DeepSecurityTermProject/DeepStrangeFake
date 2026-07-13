import os
import tempfile
import unittest
from pathlib import Path

from audit_agent.integration import load_integration_environment
from audit_agent.llm import build_llm_client
from audit_agent.verification import VerificationEngine, VerificationStatus
from tests.test_poc_repair_core import FakeDockerRunner, MissingImportGenerator, repair_config, synthetic_case


class LivePoCRepairProviderConfigTests(unittest.TestCase):
    def test_live_smoke_config_loads_llm_api_key_alias_from_dotenv(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text(
                "LLM_API_KEY=synthetic-provider-key\n"
                "LLM_API_BASE_URL=https://synthetic.invalid/v1\n"
                "LLM_MODEL=synthetic-model\n",
                encoding="utf-8",
            )
            config = repair_config()
            env: dict[str, str] = {}

            loaded = load_integration_environment(config, cwd=root, env=env)

            self.assertTrue(loaded.loaded)
            self.assertEqual("LLM_API_KEY", config.llm.api_key_env)
            self.assertEqual("synthetic-provider-key", env[config.llm.api_key_env])
            self.assertEqual("https://synthetic.invalid/v1", config.llm.base_url)
            self.assertEqual("synthetic-model", config.llm.model)
            self.assertEqual("openai-compatible", config.llm.provider)


class LivePoCRepairProviderSmokeTests(unittest.TestCase):
    def test_real_provider_respects_exact_contract_and_policy_invariants(self):
        repo_root = Path(__file__).resolve().parents[1]
        config = repair_config()
        load_integration_environment(config, cwd=repo_root)
        if os.environ.get("AUDIT_AGENT_RUN_REPAIR_PROVIDER_TESTS") != "1":
            self.skipTest(
                "Set AUDIT_AGENT_RUN_REPAIR_PROVIDER_TESTS=1 for the opt-in networked provider smoke."
            )
        if not os.environ.get(config.llm.api_key_env):
            self.skipTest(f"{config.llm.api_key_env} is required in .env or the shell.")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata, decision = synthetic_case(root)
            source_path = Path(metadata.root_path) / "app.py"
            source_before = source_path.read_bytes()
            config.llm.model = os.environ.get("AUDIT_AGENT_REPAIR_MODEL", config.llm.model)
            config.llm.base_url = os.environ.get("AUDIT_AGENT_REPAIR_BASE_URL", config.llm.base_url)
            client = build_llm_client(config.llm)
            runner = FakeDockerRunner()
            engine = VerificationEngine(config, root / "run", llm_client=client)
            engine.generator = MissingImportGenerator()
            engine.runner = runner

            result = engine.verify_and_finalize_single(decision, metadata, level="sandbox")

            self.assertEqual(1, result.repair_attempt_count)
            self.assertEqual(2, len(runner.starts))
            self.assertEqual(VerificationStatus.CONFIRMED, result.status)
            self.assertEqual(VerificationStatus.CONFIRMED, result.final_status)
            self.assertEqual(VerificationStatus.CONFIRMED, result.verification_status)
            self.assertFalse(result.final_stop_reason)
            self.assertTrue(result.integrity_summary.get("unchanged"))
            self.assertEqual(source_before, source_path.read_bytes())


if __name__ == "__main__":
    unittest.main()
