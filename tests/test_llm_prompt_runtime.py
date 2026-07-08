import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from audit_agent.config import AuditConfig, LlmConfig, PromptRuntimeConfig
from audit_agent.llm import (
    LLMConfigurationError,
    LLMProviderError,
    LLMValidationError,
    MockLLMClient,
    OpenAICompatibleClient,
    validate_json_schema,
)
from audit_agent.models import LLMRequest
from audit_agent.prompts import PromptRegistry, PromptTemplate, render_default_prompt


class LlmPromptRuntimeTests(unittest.TestCase):
    def test_mock_llm_returns_deterministic_json_and_usage(self):
        client = MockLLMClient(
            responses={"analysis": {"candidates": [{"title": "demo", "vulnerability_class": "sql-injection"}]}}
        )
        request = LLMRequest(role="analysis", prompt="Find candidates", model="deterministic-local")

        first = client.complete(request)
        second = client.complete(request)

        self.assertEqual(first.parsed_json, second.parsed_json)
        self.assertEqual(first.provider, "mock")
        self.assertGreater(first.usage["prompt_tokens"], 0)
        self.assertEqual(first.raw_response["mode"], "deterministic")

    def test_real_provider_requires_configured_api_key(self):
        env_name = "AUDIT_AGENT_TEST_KEY"
        os.environ.pop(env_name, None)
        config = LlmConfig(provider="openai-compatible", api_key_env=env_name)

        with self.assertRaises(LLMConfigurationError):
            OpenAICompatibleClient(config)

    def test_json_schema_validation_rejects_missing_required_field(self):
        schema = {"type": "object", "required": ["candidates"], "properties": {"candidates": {"type": "array"}}}

        with self.assertRaises(LLMValidationError):
            validate_json_schema({"findings": []}, schema)

    def test_prompt_registry_renders_versioned_template_and_validates_variables(self):
        registry = PromptRegistry()
        registry.register(
            PromptTemplate(
                template_id="analysis.candidates",
                version="v1",
                role="analysis",
                required_variables=["repository_summary", "tool_outputs"],
                output_schema={"type": "object", "required": ["candidates"]},
                safety_constraints=["CVE/RAG context alone cannot validate a finding."],
                body="Repo: {{repository_summary}}\nTools: {{tool_outputs}}\nSafety: {{safety_constraints}}",
            )
        )

        record = registry.render(
            "analysis.candidates",
            "v1",
            {"repository_summary": "Flask app", "tool_outputs": "pattern scan"},
        )

        self.assertIn("Flask app", record.rendered)
        self.assertIn("CVE/RAG context alone", record.rendered)
        self.assertEqual(record.role, "analysis")
        with self.assertRaises(ValueError):
            registry.render("analysis.candidates", "v1", {"repository_summary": "missing tools"})

    def test_default_prompt_templates_are_available_and_deterministic(self):
        config = PromptRuntimeConfig(default_version="v1")

        first = render_default_prompt(
            role="verification",
            template_id="verification.decision",
            variables={"candidate_json": "{}", "evidence_summary": "local code evidence"},
            config=config,
        )
        second = render_default_prompt(
            role="verification",
            template_id="verification.decision",
            variables={"candidate_json": "{}", "evidence_summary": "local code evidence"},
            config=config,
        )

        self.assertEqual(first.rendered, second.rendered)
        self.assertIn("intelligence-only", first.rendered.lower())
        json.dumps(first.to_dict())

    def test_llm_artifacts_are_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = MockLLMClient(responses={"recon": {"high_risk_areas": []}})
            request = LLMRequest(role="recon", prompt="Recon", model="deterministic-local")
            response = client.complete(request)
            path = client.persist(Path(tmp), request, response)

            self.assertTrue(path.exists())
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["response"]["provider"], "mock")

    def test_openai_compatible_provider_normalizes_response_after_retry(self):
        attempts = {"count": 0}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                body = {
                    "model": "unit-model",
                    "choices": [
                        {
                            "message": {"content": "{\"candidates\": []}"},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
                }
                return json.dumps(body).encode("utf-8")

        def fake_urlopen(request, timeout):
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise urllib.error.URLError("fail once")
            return FakeResponse()

        env_name = "AUDIT_AGENT_TEST_OPENAI_KEY"
        os.environ[env_name] = "test-key"
        try:
            config = LlmConfig(
                provider="openai-compatible",
                model="unit-model",
                base_url="http://example.test/v1",
                api_key_env=env_name,
                retry_count=1,
                timeout_seconds=5,
            )
            client = OpenAICompatibleClient(config)
            with patch("urllib.request.urlopen", side_effect=fake_urlopen):
                response = client.complete(LLMRequest(role="analysis", prompt="{}", model="unit-model"))
        finally:
            os.environ.pop(env_name, None)

        self.assertEqual(attempts["count"], 2)
        self.assertEqual(response.provider, "openai-compatible")
        self.assertEqual(response.parsed_json, {"candidates": []})
        self.assertEqual(response.usage["total_tokens"], 5)

    def test_openai_compatible_provider_classifies_authentication_failure(self):
        env_name = "AUDIT_AGENT_TEST_OPENAI_KEY"
        os.environ[env_name] = "secret-key"
        try:
            config = LlmConfig(
                provider="openai-compatible",
                model="unit-model",
                base_url="http://example.test/v1",
                api_key_env=env_name,
                retry_count=0,
                timeout_seconds=5,
            )
            client = OpenAICompatibleClient(config)
            error = urllib.error.HTTPError(
                url="http://example.test/v1/chat/completions",
                code=401,
                msg="Unauthorized secret-key",
                hdrs={},
                fp=None,
            )
            with patch("urllib.request.urlopen", side_effect=error):
                with self.assertRaises(LLMProviderError) as caught:
                    client.complete(LLMRequest(role="analysis", prompt="{}", model="unit-model"))
        finally:
            os.environ.pop(env_name, None)

        self.assertEqual(caught.exception.error_type, "authentication")
        self.assertEqual(caught.exception.status_code, 401)
        self.assertNotIn("secret-key", json.dumps(caught.exception.to_dict()))

    @unittest.skipUnless(os.environ.get("AUDIT_AGENT_RUN_INTEGRATION") == "1", "live integration is opt-in")
    def test_live_llm_smoke_uses_configured_provider_when_enabled(self):
        from audit_agent.integration import run_integration_preflight

        config = AuditConfig.default()
        config.llm.provider = os.environ.get("AUDIT_AGENT_LLM_PROVIDER", "openai-compatible")
        report = run_integration_preflight(
            config,
            output_dir=Path("runs") / "live-llm-preflight",
            include_llm=True,
            include_mcp=False,
            execute_live=True,
        )

        self.assertIn(report.overall_status, {"pass", "fail"})


if __name__ == "__main__":
    unittest.main()
