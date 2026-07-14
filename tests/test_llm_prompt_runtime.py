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
from audit_agent.prompts import (
    POC_REPAIR_RESPONSE_SCHEMA,
    PromptRegistry,
    PromptTemplate,
    default_prompt_registry,
    render_default_prompt,
)


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

    def test_analysis_schema_rejects_categorical_candidate_confidence(self):
        prompt = render_default_prompt(
            role="analysis",
            template_id="analysis.candidates",
            variables={
                "repository_summary": {},
                "tool_outputs": [],
                "memory_context": [],
                "intelligence_context": [],
            },
        )
        payload = {
            "role": "analysis",
            "action": "review",
            "confidence": 0.8,
            "rationale": "Review local evidence.",
            "evidence_refs": ["TR-local"],
            "selected_actions": [],
            "requested_tools": [],
            "candidates": [
                {
                    "vulnerability_class": "sql-injection",
                    "severity": "high",
                    "confidence": "high",
                    "path": "app.py",
                    "start_line": 15,
                    "end_line": 15,
                    "evidence": ["cursor.execute(query)"],
                }
            ],
        }

        with self.assertRaises(LLMValidationError):
            validate_json_schema(payload, prompt.output_schema)

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

    def test_poc_repair_prompt_exposes_nested_schema_and_minimal_valid_example(self):
        record = default_prompt_registry().render(
            "poc-repair.edits",
            "v1",
            {
                "prior_script": "print(Path.cwd())",
                "repair_manifest": {"editable_slots": [{"slot_id": "imports", "operations": ["add_import"]}]},
                "diagnostics": "NameError: Path is not defined",
                "dataflow_context": "synthetic",
                "source_sink_snippets": "synthetic",
                "missing_evidence": "marker absent",
                "attempt_index": 2,
                "remaining_budget": 0,
            },
        )

        edit_schema = record.output_schema["properties"]["edits"]
        self.assertEqual(3, len(edit_schema["items"]["oneOf"]))
        self.assertEqual(["add_import"], edit_schema["items"]["oneOf"][0]["properties"]["op"]["enum"])
        self.assertEqual("string", record.output_schema["properties"]["changes"]["items"]["type"])
        self.assertIn('"op":"add_import"', record.rendered)
        self.assertIn('"module":"pathlib"', record.rendered)
        self.assertIn('"changes":[', record.rendered)
        fixture = json.loads(
            (Path(__file__).resolve().parents[1] / "audit_agent" / "prompt_templates" / "poc-repair.edits.v1.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(POC_REPAIR_RESPONSE_SCHEMA, fixture["response"])
        self.assertEqual("add_import", fixture["minimal_valid_response"]["edits"][0]["op"])

    def test_graph_decision_prompt_has_closed_checkpoint_action_schema(self):
        record = default_prompt_registry().render(
            "orchestrator.graph-decision",
            "v1",
            {
                "checkpoint_id": "post-recon",
                "completed_stage": {"high_risk_areas": ["app.py"]},
                "available_actions": ["gather-more-local-context", "refine-static-scan"],
                "remaining_budgets": {"replans": 1, "checkpoints": 1},
            },
        )

        action_schema = record.output_schema["properties"]["next_actions"]["items"]
        self.assertEqual(action_schema["type"], "string")
        self.assertIn("repeat-analysis", action_schema["enum"])
        self.assertIn('"next_actions":["gather-more-local-context"]', record.rendered)

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

    def test_openai_compatible_provider_prefers_json_schema_then_falls_back_to_json_object(self):
        request_bodies = []

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
                            "message": {
                                "content": json.dumps(
                                    {
                                        "diagnosis": "Import Path.",
                                        "edits": [
                                            {
                                                "op": "add_import",
                                                "slot_id": "imports",
                                                "module": "pathlib",
                                                "name": "Path",
                                            }
                                        ],
                                        "changes": ["Add Path import."],
                                    }
                                )
                            },
                            "finish_reason": "stop",
                        }
                    ],
                }
                return json.dumps(body).encode("utf-8")

        def fake_urlopen(request, timeout):
            body = json.loads(request.data.decode("utf-8"))
            request_bodies.append(body)
            if len(request_bodies) == 1:
                raise urllib.error.HTTPError(
                    url=request.full_url,
                    code=400,
                    msg="json_schema unsupported",
                    hdrs={},
                    fp=None,
                )
            return FakeResponse()

        env_name = "AUDIT_AGENT_TEST_STRUCTURED_OUTPUT_KEY"
        os.environ[env_name] = "test-key"
        try:
            config = LlmConfig(
                provider="openai-compatible",
                model="unit-model",
                base_url="http://example.test/v1",
                api_key_env=env_name,
                retry_count=0,
            )
            client = OpenAICompatibleClient(config)
            request = LLMRequest(
                role="poc-repair",
                prompt="Return strict JSON.",
                model="unit-model",
                response_schema=POC_REPAIR_RESPONSE_SCHEMA,
                response_format="auto",
            )
            with patch("urllib.request.urlopen", side_effect=fake_urlopen):
                response = client.complete(request)
        finally:
            os.environ.pop(env_name, None)

        self.assertEqual(2, len(request_bodies))
        first_format = request_bodies[0]["response_format"]
        self.assertEqual("json_schema", first_format["type"])
        self.assertTrue(first_format["json_schema"]["strict"])
        self.assertEqual(POC_REPAIR_RESPONSE_SCHEMA, first_format["json_schema"]["schema"])
        self.assertEqual({"type": "json_object"}, request_bodies[1]["response_format"])
        self.assertEqual("add_import", response.parsed_json["edits"][0]["op"])

    def test_configured_json_object_bypasses_json_schema_probe(self):
        request_bodies = []

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return json.dumps(
                    {
                        "model": "unit-model",
                        "choices": [
                            {
                                "message": {"content": '{"result":"ok"}'},
                                "finish_reason": "stop",
                            }
                        ],
                        "usage": {"total_tokens": 5},
                    }
                ).encode("utf-8")

        def fake_urlopen(request, timeout):
            request_bodies.append(json.loads(request.data.decode("utf-8")))
            return FakeResponse()

        env_name = "AUDIT_AGENT_TEST_CONFIGURED_FORMAT_KEY"
        with patch.dict(os.environ, {env_name: "test-key"}):
            client = OpenAICompatibleClient(
                LlmConfig(
                    provider="openai-compatible",
                    model="unit-model",
                    base_url="https://provider.example/v1",
                    api_key_env=env_name,
                    retry_count=0,
                    response_format="json_object",
                )
            )
            request = LLMRequest(
                role="analysis",
                prompt="Return strict JSON.",
                model="unit-model",
                response_schema={"type": "object"},
                response_format="auto",
            )
            with patch("urllib.request.urlopen", side_effect=fake_urlopen):
                client.complete(request)

        self.assertEqual(1, len(request_bodies))
        self.assertEqual({"type": "json_object"}, request_bodies[0]["response_format"])

    def test_auto_format_rejection_is_cached_across_resumed_client(self):
        request_bodies = []

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return json.dumps(
                    {
                        "model": "unit-model",
                        "choices": [
                            {
                                "message": {"content": '{"result":"ok"}'},
                                "finish_reason": "stop",
                            }
                        ],
                        "usage": {"total_tokens": 5},
                    }
                ).encode("utf-8")

        def unsupported_schema(request, timeout):
            request_bodies.append(json.loads(request.data.decode("utf-8")))
            if len(request_bodies) == 1:
                raise urllib.error.HTTPError(
                    request.full_url,
                    400,
                    "json_schema unsupported",
                    {},
                    None,
                )
            return FakeResponse()

        env_name = "AUDIT_AGENT_TEST_CACHED_FORMAT_KEY"
        config = LlmConfig(
            provider="openai-compatible",
            model="unit-model",
            base_url="https://unknown-provider.example/v1",
            api_key_env=env_name,
            retry_count=0,
        )
        request = LLMRequest(
            role="analysis",
            prompt="Return strict JSON.",
            model="unit-model",
            response_schema={"type": "object"},
            response_format="auto",
        )
        with patch.dict(os.environ, {env_name: "test-key"}):
            runtime_state = {}
            first_client = OpenAICompatibleClient(config)
            first_client.set_runtime_state(runtime_state)
            with patch("urllib.request.urlopen", side_effect=unsupported_schema):
                first_client.complete(request)

            resumed_state = json.loads(json.dumps(runtime_state))
            resumed_client = OpenAICompatibleClient(config)
            resumed_client.set_runtime_state(resumed_state)
            resumed_request = LLMRequest(
                role="verification",
                prompt="Return strict JSON.",
                model="unit-model",
                response_schema={"type": "object"},
                response_format="auto",
            )
            with patch("urllib.request.urlopen", side_effect=unsupported_schema):
                resumed_client.complete(resumed_request)

        self.assertEqual(
            ["json_schema", "json_object", "json_object"],
            [body["response_format"]["type"] for body in request_bodies],
        )
        self.assertEqual(
            ["json_object"],
            list(resumed_state["response_format_capabilities"].values()),
        )

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
