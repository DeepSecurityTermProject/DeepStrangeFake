import json
import io
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from audit_agent.config import AuditConfig, LlmConfig
from audit_agent.llm import LLMBudgetExceeded, LLMProviderError, MockLLMClient, OpenAICompatibleClient
from audit_agent.llm_accounting import (
    AuditedLLMGateway,
    LifecycleEvent,
    LifecycleLedger,
    reconcile_llm_lifecycle,
)
from audit_agent.models import LLMRequest, LLMResponse, stable_id


SENTINEL = "sentinel-accounting-secret-value"


def request(role="analysis"):
    return LLMRequest(
        role=role,
        prompt=f"local synthetic fixture {SENTINEL}",
        model="fixture-model",
        provider="mock",
        id=f"request-{role}",
    )


def response(req, *, tokens=7, text='{"result":"ok"}'):
    return LLMResponse(
        request_id=req.id or "",
        provider="mock",
        model=req.model,
        text=text,
        parsed_json=json.loads(text),
        usage={"prompt_tokens": 3, "completion_tokens": tokens - 3, "total_tokens": tokens},
        raw_response={"authorization": f"Bearer {SENTINEL}"},
    )


def assert_secret_absent(test, root):
    for path in Path(root).rglob("*"):
        if path.is_file():
            test.assertNotIn(SENTINEL, path.read_text(encoding="utf-8", errors="replace"), str(path))


class StaticClient:
    def __init__(self, value=None, error=None):
        self.value = value
        self.error = error

    def complete(self, req):
        if self.error:
            raise self.error
        return self.value or response(req)


class RetryingObservedClient:
    def complete_with_attempt_observer(self, req, observer):
        first = observer.dispatch_started({"response_format": "json_schema"})
        observer.attempt_failed(first, {"error_type": "network", "diagnostic": SENTINEL})
        second = observer.dispatch_started({"response_format": "json_schema"})
        value = response(req, tokens=11)
        observer.attempt_response(second, value)
        return value


class LlmAuditAccountingTests(unittest.TestCase):
    def test_known_provider_cost_budget_denies_post_response_and_future_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            req = request()
            priced = response(req, tokens=7)
            priced.usage["cost_usd"] = 0.75
            state = {}
            gateway = AuditedLLMGateway(
                StaticClient(priced),
                LifecycleLedger(Path(tmp), "run-known-cost"),
                request_budget=3,
                token_budget=100,
                cost_budget_usd=0.5,
                accounting_state=state,
            )
            with self.assertRaisesRegex(LLMBudgetExceeded, "known cost"):
                gateway.invoke(req)
            self.assertEqual(gateway.requests_used, 1)
            self.assertEqual(gateway.tokens_used, 7)
            self.assertEqual(gateway.cost_used_usd, 0.75)
            self.assertEqual(state["cost_budget_usd"], 0.5)
            with self.assertRaisesRegex(LLMBudgetExceeded, "known cost") as denied:
                gateway.invoke(request("verification"))
            self.assertEqual(denied.exception.receipt.provider_attempt_ids, [])
            accounting = reconcile_llm_lifecycle(Path(tmp))
            self.assertEqual(accounting.pre_dispatch_denials, 1)
            self.assertEqual(accounting.terminal_status_counts, {"budget-denied": 2})

    def test_schema_invalid_response_is_persisted_and_counted_before_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            req = request()
            invalid = response(req, tokens=13, text='{"unexpected":true}')
            gateway = AuditedLLMGateway(
                StaticClient(invalid),
                LifecycleLedger(Path(tmp), "run-schema-invalid", secret_values=[SENTINEL]),
                request_budget=2,
                token_budget=100,
            )

            prompt_ref = Path(tmp) / "prompts" / "analysis.json"
            prompt_ref.parent.mkdir()
            prompt_ref.write_text("{}", encoding="utf-8")
            receipt = gateway.invoke(req, prompt_ref=str(prompt_ref))
            gateway.record_schema(receipt, valid=False, errors=[f"bad {SENTINEL}"])
            gateway.record_fallback(receipt, "schema-invalid")
            gateway.terminalize(receipt, "fallback")
            accounting = reconcile_llm_lifecycle(Path(tmp))

            self.assertTrue(Path(receipt.response_ref).is_file())
            self.assertEqual(accounting.llm_requests, 1)
            self.assertEqual(accounting.llm_tokens, 13)
            self.assertEqual(accounting.terminal_status_counts, {"fallback": 1})
            self.assertTrue(accounting.complete)
            prior_secret_derived_request_id = stable_id(
                "LR", req.role, req.model, req.prompt, req.created_at
            )
            self.assertFalse(
                any(
                    prior_secret_derived_request_id in path.read_text(encoding="utf-8", errors="replace")
                    for path in Path(tmp).rglob("*")
                    if path.is_file()
                )
            )
            assert_secret_absent(self, tmp)

    def test_provider_errors_messages_and_credential_urls_are_redacted(self):
        from audit_agent.message_bus import MessageBus, replay_summary

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider_error = LLMProviderError(
                "synthetic provider failure",
                "network",
                "mock",
                "fixture-model",
                1,
                diagnostic=f"https://fixture-user:{SENTINEL}@provider.invalid/v1",
            )
            gateway = AuditedLLMGateway(
                StaticClient(error=provider_error),
                LifecycleLedger(root, "run-error-redaction", secret_values=[SENTINEL]),
                request_budget=2,
                token_budget=100,
            )
            with self.assertRaises(LLMProviderError):
                gateway.invoke(request("provider-error-redaction"))

            bus = MessageBus(
                "run-error-redaction",
                root / "messages" / "messages.jsonl",
                secret_values=[SENTINEL],
            )
            bus.publish(
                "fixture",
                "runtime",
                "fixture.secret",
                {
                    "echo": SENTINEL,
                    "url": f"https://fixture-user:{SENTINEL}@provider.invalid/v1",
                },
            )
            replay = replay_summary(root / "messages" / "messages.jsonl")
            self.assertEqual(replay["message_count"], 1)
            assert_secret_absent(self, root)
            serialized = "\n".join(
                path.read_text(encoding="utf-8", errors="replace")
                for path in root.rglob("*")
                if path.is_file()
            )
            self.assertNotIn("fixture-user:", serialized)

    def test_request_group_attempt_and_token_semantics_are_table_driven(self):
        scenarios = {
            "accepted": {"client": StaticClient(), "requests": 1, "attempts": 1, "tokens": 7},
            "provider-error": {
                "client": StaticClient(error=LLMProviderError("failed", "network", "mock", "m", 1)),
                "requests": 1,
                "attempts": 1,
                "tokens": None,
            },
            "timeout": {
                "client": StaticClient(error=TimeoutError("synthetic timeout")),
                "requests": 1,
                "attempts": 1,
                "tokens": None,
            },
            "retry": {"client": RetryingObservedClient(), "requests": 1, "attempts": 2, "tokens": None},
            "pre-dispatch": {"client": StaticClient(), "requests": 0, "attempts": 0, "tokens": 0},
            "pre-token-plan": {"client": StaticClient(), "requests": 0, "attempts": 0, "tokens": 0},
        }
        for name, expected in scenarios.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                req = request(name)
                gateway = AuditedLLMGateway(
                    expected["client"],
                    LifecycleLedger(Path(tmp), f"run-{name}"),
                    request_budget=0 if name == "pre-dispatch" else 2,
                    token_budget=3 if name == "pre-token-plan" else 100,
                )
                try:
                    receipt = gateway.invoke(req)
                    gateway.record_schema(receipt, valid=True)
                    gateway.record_policy(receipt, accepted=True)
                    gateway.terminalize(receipt, "accepted")
                except (LLMProviderError, TimeoutError, LLMBudgetExceeded):
                    pass
                accounting = reconcile_llm_lifecycle(Path(tmp))
                self.assertEqual(accounting.llm_requests, expected["requests"])
                self.assertEqual(accounting.provider_attempts, expected["attempts"])
                self.assertEqual(accounting.llm_tokens, expected["tokens"])
                self.assertEqual(accounting.retries, max(0, expected["attempts"] - expected["requests"]))

    def test_remaining_token_budget_caps_requests_and_denies_before_dispatch(self):
        class SequencedClient:
            def __init__(self):
                self.requests = []

            def complete(self, req):
                self.requests.append(req)
                usage = (
                    {"prompt_tokens": 20, "completion_tokens": 50, "total_tokens": 70}
                    if len(self.requests) == 1
                    else {"prompt_tokens": 23, "completion_tokens": 7, "total_tokens": 30}
                )
                return LLMResponse(
                    request_id=req.id or "",
                    provider="mock",
                    model=req.model,
                    text='{"result":"ok"}',
                    parsed_json={"result": "ok"},
                    usage=usage,
                )

        with tempfile.TemporaryDirectory() as tmp:
            client = SequencedClient()
            state = {}
            gateway = AuditedLLMGateway(
                client,
                LifecycleLedger(Path(tmp), "run-hard-token-cap"),
                request_budget=5,
                token_budget=100,
                accounting_state=state,
            )
            first_request = LLMRequest(
                role="first",
                prompt="x",
                model="fixture-model",
                max_tokens=80,
                id="request-hard-cap-first",
            )
            first = gateway.invoke(first_request)
            first_started = json.loads(Path(first.event_refs[0]).read_text(encoding="utf-8"))
            self.assertEqual(
                {
                    "estimator": "utf8-byte-upper-bound.v1",
                    "token_budget": 100,
                    "tokens_used_before_request": 0,
                    "remaining_token_budget": 100,
                    "prompt_token_estimate": 24,
                    "configured_max_tokens": 80,
                    "effective_max_tokens": 76,
                    "dispatch_allowed": True,
                },
                first_started["details"]["token_budget_plan"],
            )
            gateway.record_schema(first, valid=True)
            gateway.record_policy(first, accepted=True)
            gateway.terminalize(first, "accepted")

            second_request = LLMRequest(
                role="next",
                prompt="y",
                model="fixture-model",
                max_tokens=50,
                id="request-hard-cap-second",
            )
            second = gateway.invoke(second_request)
            gateway.record_schema(second, valid=True)
            gateway.record_policy(second, accepted=True)
            gateway.terminalize(second, "accepted")

            with self.assertRaisesRegex(LLMBudgetExceeded, "token budget") as denied:
                gateway.invoke(
                    LLMRequest(
                        role="third",
                        prompt="z",
                        model="fixture-model",
                        max_tokens=50,
                        id="request-hard-cap-third",
                    )
                )
            accounting = reconcile_llm_lifecycle(
                Path(tmp),
                budget_counters=state,
            )

        self.assertEqual([76, 7], [item.max_tokens for item in client.requests])
        self.assertEqual(100, gateway.tokens_used)
        self.assertEqual(100, state["tokens_used"])
        self.assertEqual([], denied.exception.receipt.provider_attempt_ids)
        self.assertEqual(2, accounting.llm_requests)
        self.assertEqual(2, accounting.provider_attempts)
        self.assertEqual(1, accounting.pre_dispatch_denials)
        self.assertEqual(100, accounting.llm_tokens)
        self.assertTrue(accounting.complete, [item.to_dict() for item in accounting.gaps])

    def test_provider_ignoring_max_tokens_is_persisted_and_denied_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            req = LLMRequest(
                role="violation",
                prompt="x",
                model="fixture-model",
                max_tokens=1000,
                id="request-provider-token-violation",
            )
            oversized = LLMResponse(
                request_id=req.id or "",
                provider="mock",
                model=req.model,
                text='{"result":"oversized"}',
                parsed_json={"result": "oversized"},
                usage={"prompt_tokens": 20, "completion_tokens": 81, "total_tokens": 101},
            )
            gateway = AuditedLLMGateway(
                StaticClient(oversized),
                LifecycleLedger(Path(tmp), "run-provider-token-violation"),
                request_budget=2,
                token_budget=100,
            )
            with self.assertRaisesRegex(LLMBudgetExceeded, "exceeded token budget") as denied:
                gateway.invoke(req)
            receipt = denied.exception.receipt
            accounting = reconcile_llm_lifecycle(Path(tmp))
            self.assertTrue(Path(receipt.response_ref).is_file())
            self.assertLess(receipt.request.max_tokens, req.max_tokens)
            self.assertEqual(101, gateway.tokens_used)
            self.assertEqual(101, accounting.llm_tokens)
            self.assertEqual({"budget-denied": 1}, accounting.terminal_status_counts)
            self.assertTrue(accounting.complete, [item.to_dict() for item in accounting.gaps])

    def test_lifecycle_round_trip_collision_corruption_and_missing_terminal_are_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = LifecycleLedger(Path(tmp), "run-ledger")
            event = LifecycleEvent(
                event_id="event-fixed",
                request_group_id="group-fixed",
                sequence=1,
                kind="request-started",
                role="analysis",
            )
            ref = ledger.write_event(event)
            with self.assertRaises(FileExistsError):
                ledger.write_event(event)
            payload = json.loads(Path(ref).read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], "llm-lifecycle-event.v1")

            accounting = reconcile_llm_lifecycle(Path(tmp))
            self.assertFalse(accounting.complete)
            self.assertTrue(any("missing-terminal" in item.reason for item in accounting.gaps))

            Path(ref).write_text("{corrupt", encoding="utf-8")
            corrupt = reconcile_llm_lifecycle(Path(tmp))
            self.assertFalse(corrupt.complete)
            self.assertTrue(any("corrupt-event" in item.reason for item in corrupt.gaps))

    def test_illegal_lifecycle_order_and_repeated_same_second_invocations_are_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = LifecycleLedger(Path(tmp), "run-order")
            request_one = request("same-role")
            request_two = request("same-role")
            first = ledger.request_group_id(request_one, 1)
            second = ledger.request_group_id(request_two, 2)
            self.assertNotEqual(first, second)

            ledger.write_event(
                LifecycleEvent(
                    event_id="event-request",
                    request_group_id=first,
                    sequence=1,
                    kind="request-started",
                    role="analysis",
                )
            )
            ledger.write_event(
                LifecycleEvent(
                    event_id="event-schema-before-response",
                    request_group_id=first,
                    sequence=2,
                    kind="schema-valid",
                    role="analysis",
                )
            )
            ledger.write_event(
                LifecycleEvent(
                    event_id="event-terminal",
                    request_group_id=first,
                    sequence=3,
                    kind="request-terminal",
                    role="analysis",
                    terminal_status="accepted",
                )
            )
            ledger.write_event(
                LifecycleEvent(
                    event_id="event-after-terminal",
                    request_group_id=first,
                    sequence=4,
                    kind="fallback-used",
                    role="analysis",
                )
            )

            accounting = reconcile_llm_lifecycle(Path(tmp))
            illegal = [item.gap_id for item in accounting.gaps if item.reason == "illegal-transition"]
            self.assertEqual(len(illegal), 2)
            self.assertFalse(accounting.complete)
            self.assertEqual(
                illegal,
                [
                    item.gap_id
                    for item in reconcile_llm_lifecycle(Path(tmp)).gaps
                    if item.reason == "illegal-transition"
                ],
            )

    def test_strict_models_reject_unknown_event_and_terminal_values(self):
        with self.assertRaises(ValueError):
            LifecycleEvent(
                event_id="event-invalid",
                request_group_id="group",
                sequence=1,
                kind="arbitrary-code",
                role="analysis",
            )

    def test_openai_transport_retries_are_distinct_attempts_in_one_request_group(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return json.dumps(
                    {
                        "model": "fixture-model",
                        "choices": [{"message": {"content": '{"result":"ok"}'}, "finish_reason": "stop"}],
                        "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
                    }
                ).encode("utf-8")

        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"AUDIT_ACCOUNTING_KEY": "fixture-key"}
        ):
            client = OpenAICompatibleClient(
                LlmConfig(
                    provider="openai-compatible",
                    model="fixture-model",
                    api_key_env="AUDIT_ACCOUNTING_KEY",
                    retry_count=1,
                )
            )
            gateway = AuditedLLMGateway(
                client,
                LifecycleLedger(Path(tmp), "run-observed-retry"),
                request_budget=2,
                token_budget=100,
            )
            with patch(
                "urllib.request.urlopen",
                side_effect=[urllib.error.URLError("synthetic network"), Response()],
            ):
                receipt = gateway.invoke(request("observed-retry"))
            gateway.record_schema(receipt, valid=True)
            gateway.record_policy(receipt, accepted=True)
            gateway.terminalize(receipt, "accepted")

            accounting = reconcile_llm_lifecycle(Path(tmp))
            self.assertEqual(accounting.total_request_groups, 1)
            self.assertEqual(accounting.llm_requests, 1)
            self.assertEqual(accounting.provider_attempts, 2)
            self.assertEqual(accounting.retries, 1)
            self.assertIsNone(accounting.llm_tokens)
            self.assertTrue(any(item.provider_attempt_id == receipt.provider_attempt_ids[0] for item in accounting.gaps))

    def test_openai_attempt_observer_covers_format_fallback_and_failures(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return json.dumps(
                    {
                        "model": "fixture-model",
                        "choices": [{"message": {"content": '{"result":"ok"}'}, "finish_reason": "stop"}],
                        "usage": {"total_tokens": 5},
                    }
                ).encode("utf-8")

        def http_error(code):
            return urllib.error.HTTPError(
                "https://provider.invalid/v1/chat/completions",
                code,
                "synthetic",
                {},
                io.BytesIO(b"{}"),
            )

        with patch.dict(os.environ, {"AUDIT_ACCOUNTING_KEY": "fixture-key"}):
            with tempfile.TemporaryDirectory() as tmp:
                client = OpenAICompatibleClient(
                    LlmConfig(
                        provider="openai-compatible",
                        model="fixture-model",
                        base_url="https://provider.invalid/v1",
                        api_key_env="AUDIT_ACCOUNTING_KEY",
                        retry_count=0,
                    )
                )
                gateway = AuditedLLMGateway(
                    client,
                    LifecycleLedger(Path(tmp), "run-format-fallback"),
                    request_budget=2,
                    token_budget=1_000,
                )
                req = request("format-fallback")
                req.response_schema = {"type": "object"}
                req.response_format = "auto"
                with patch("urllib.request.urlopen", side_effect=[http_error(400), Response()]):
                    receipt = gateway.invoke(req)
                gateway.record_schema(receipt, valid=True)
                gateway.record_policy(receipt, accepted=True)
                gateway.terminalize(receipt, "accepted")
                accounting = reconcile_llm_lifecycle(Path(tmp))
                self.assertEqual(accounting.llm_requests, 1)
                self.assertEqual(accounting.provider_attempts, 2)
                self.assertEqual(accounting.retries, 1)
                self.assertIsNone(accounting.llm_tokens)

            failures = {
                "authentication": (http_error(401), "provider-error", 1),
                "rate-limit": (http_error(429), "provider-error", 1),
                "network": (urllib.error.URLError("synthetic network"), "provider-error", 1),
                "timeout": (TimeoutError("synthetic timeout"), "timeout", 1),
            }
            for name, (failure, terminal, attempts) in failures.items():
                with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                    client = OpenAICompatibleClient(
                        LlmConfig(
                            provider="openai-compatible",
                            model="fixture-model",
                            api_key_env="AUDIT_ACCOUNTING_KEY",
                            retry_count=0,
                        )
                    )
                    gateway = AuditedLLMGateway(
                        client,
                        LifecycleLedger(Path(tmp), f"run-{name}"),
                        request_budget=2,
                        token_budget=100,
                    )
                    with patch("urllib.request.urlopen", side_effect=failure):
                        with self.assertRaises(LLMProviderError):
                            gateway.invoke(request(name))
                    accounting = reconcile_llm_lifecycle(Path(tmp))
                    self.assertEqual(accounting.llm_requests, 1)
                    self.assertEqual(accounting.provider_attempts, attempts)
                    self.assertEqual(accounting.terminal_status_counts, {terminal: 1})
                    self.assertIsNone(accounting.llm_tokens)

            with tempfile.TemporaryDirectory() as tmp:
                client = OpenAICompatibleClient(
                    LlmConfig(
                        provider="openai-compatible",
                        model="fixture-model",
                        api_key_env="AUDIT_ACCOUNTING_KEY",
                        retry_count=1,
                    )
                )
                gateway = AuditedLLMGateway(
                    client,
                    LifecycleLedger(Path(tmp), "run-exhausted-retries"),
                    request_budget=2,
                    token_budget=100,
                )
                failures = [
                    urllib.error.URLError("synthetic network one"),
                    urllib.error.URLError("synthetic network two"),
                ]
                with patch("urllib.request.urlopen", side_effect=failures):
                    with self.assertRaises(LLMProviderError):
                        gateway.invoke(request("exhausted-retries"))
                accounting = reconcile_llm_lifecycle(Path(tmp))
                self.assertEqual(accounting.llm_requests, 1)
                self.assertEqual(accounting.provider_attempts, 2)
                self.assertEqual(accounting.retries, 1)
                self.assertEqual(accounting.terminal_status_counts, {"provider-error": 1})

    def test_deepseek_capability_uses_one_accounted_json_object_attempt(self):
        request_bodies = []

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return json.dumps(
                    {
                        "model": "deepseek-fixture",
                        "choices": [
                            {
                                "message": {"content": '{"result":"ok"}'},
                                "finish_reason": "stop",
                            }
                        ],
                        "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
                    }
                ).encode("utf-8")

        def fake_urlopen(http_request, timeout):
            request_bodies.append(json.loads(http_request.data.decode("utf-8")))
            return Response()

        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"AUDIT_ACCOUNTING_KEY": "fixture-key"}
        ):
            state = {}
            client = OpenAICompatibleClient(
                LlmConfig(
                    provider="openai-compatible",
                    model="deepseek-fixture",
                    base_url="https://api.deepseek.com",
                    api_key_env="AUDIT_ACCOUNTING_KEY",
                    retry_count=0,
                )
            )
            gateway = AuditedLLMGateway(
                client,
                LifecycleLedger(Path(tmp), "run-deepseek-format"),
                request_budget=2,
                token_budget=1_000,
                accounting_state=state,
            )
            req = request("deepseek-format")
            req.provider = "openai-compatible"
            req.model = "deepseek-fixture"
            req.response_schema = {"type": "object"}
            req.response_format = "auto"
            with patch("urllib.request.urlopen", side_effect=fake_urlopen):
                receipt = gateway.invoke(req)
            gateway.record_schema(receipt, valid=True)
            gateway.record_policy(receipt, accepted=True)
            gateway.terminalize(receipt, "accepted")

            accounting = reconcile_llm_lifecycle(Path(tmp))

        self.assertEqual(1, len(request_bodies))
        self.assertEqual({"type": "json_object"}, request_bodies[0]["response_format"])
        self.assertEqual(1, accounting.provider_attempts)
        self.assertEqual(0, accounting.retries)
        self.assertEqual(5, accounting.llm_tokens)
        self.assertTrue(accounting.complete, [item.to_dict() for item in accounting.gaps])
        self.assertEqual(["json_object"], list(state["response_format_capabilities"].values()))

    def test_offline_runtime_counts_schema_invalid_response_and_tamper_is_detected(self):
        from audit_agent.pipeline import run_audit

        class MixedClient:
            def complete(self, req):
                if req.role == "recon":
                    return LLMResponse(
                        request_id=req.id or "",
                        provider="mock",
                        model=req.model,
                        text=json.dumps({"unexpected": True, "echo": SENTINEL}),
                        parsed_json={"unexpected": True, "echo": SENTINEL},
                        usage={"total_tokens": 5},
                        raw_response={"authorization": f"Bearer {SENTINEL}"},
                    )
                value = MockLLMClient().complete(req)
                value.usage = {"total_tokens": 5}
                value.raw_response = {
                    "authorization": f"Bearer {SENTINEL}",
                    "echo": SENTINEL,
                }
                return value

        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "fixture"
            project.mkdir()
            (project / "app.py").write_text(
                "import os\n\ndef run(value):\n    return os.system(value)\n",
                encoding="utf-8",
            )
            config = AuditConfig.default()
            config.runtime_enabled = True
            config.graph.mode = "deterministic-graph"
            config.llm_decisions.enabled = True
            config.llm_decisions.roles = ["orchestrator", "recon", "analysis", "verification"]
            config.cve_mcp.enabled = False
            config.mcp.enabled = False
            with patch.dict(os.environ, {"OPENAI_API_KEY": SENTINEL}), patch(
                "audit_agent.runtime.build_llm_client", return_value=MixedClient()
            ):
                result = run_audit(str(project), config=config, output_dir=Path(tmp) / "runs")

            run_dir = Path(result["run_dir"])
            resources = json.loads(
                (run_dir / "reports" / "run-resource-summary.v1.json").read_text(encoding="utf-8")
            )
            self.assertEqual(resources["llm_total_request_groups"], 4)
            self.assertEqual(resources["llm_dispatched_request_groups"], 4)
            self.assertEqual(resources["llm_provider_attempts"], 4)
            self.assertEqual(resources["llm_tokens"], 20)
            self.assertEqual(resources["llm_reconciliation_status"], "complete")
            decision_files = sorted((run_dir / "decisions").glob("*.json"))
            self.assertTrue(decision_files)
            for decision_path in decision_files:
                decision = json.loads(decision_path.read_text(encoding="utf-8"))["llm_decision"]
                self.assertTrue(decision["request_group_id"])
                self.assertTrue(decision["provider_attempt_ids"])
                self.assertTrue(decision["schema_ref"])
                self.assertTrue(decision["policy_ref"])
                self.assertTrue(decision["terminal_ref"])
            from audit_agent.message_bus import replay_summary

            replay = replay_summary(run_dir / "messages" / config.message_bus.log_filename)
            self.assertEqual(len(replay["llm_request_lifecycle"]["request_groups"]), 4)
            self.assertEqual(replay["llm_request_lifecycle"]["provider_attempts"], 4)
            self.assertEqual(replay["llm_request_lifecycle"]["incomplete_groups"], [])
            invalid = [
                path
                for path in (run_dir / "llm").glob("*.json")
                if "unexpected" in path.read_text(encoding="utf-8")
            ]
            self.assertEqual(len(invalid), 1)
            assert_secret_absent(self, run_dir)

            invalid[0].unlink()
            tampered = reconcile_llm_lifecycle(run_dir, llm_enabled=True)
            self.assertFalse(tampered.complete)
            self.assertTrue(any(item.reason == "missing-response-ref" for item in tampered.gaps))

    def test_legacy_and_disabled_readers_do_not_fabricate_completeness(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            llm_root = root / "llm"
            llm_root.mkdir()
            (llm_root / "legacy.json").write_text(
                json.dumps({"response": {"usage": {"total_tokens": 9}}}),
                encoding="utf-8",
            )

            legacy = reconcile_llm_lifecycle(root, llm_enabled=True)
            self.assertFalse(legacy.ledger_present)
            self.assertEqual(legacy.accounting_source, "legacy-artifact-scan")
            self.assertFalse(legacy.complete)
            self.assertEqual(legacy.llm_tokens, 9)

        with tempfile.TemporaryDirectory() as tmp:
            disabled = reconcile_llm_lifecycle(Path(tmp), llm_enabled=False)
            self.assertTrue(disabled.complete)
            self.assertEqual(disabled.accounting_source, "disabled-zero")
            self.assertEqual(disabled.llm_requests, 0)
            self.assertEqual(disabled.llm_tokens, 0)

        with tempfile.TemporaryDirectory() as tmp:
            unknown = reconcile_llm_lifecycle(Path(tmp), llm_enabled=None)
            self.assertFalse(unknown.complete)
            self.assertEqual(unknown.accounting_source, "unknown")
            self.assertIsNone(unknown.llm_requests)
            self.assertIsNone(unknown.llm_tokens)

    def test_duplicate_usage_and_budget_counter_mismatch_are_not_repaired(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            response_ref = root / "llm" / "response.json"
            response_ref.parent.mkdir()
            response_ref.write_text("{}", encoding="utf-8")
            ledger = LifecycleLedger(root, "run-duplicate")
            group = "group-duplicate"
            attempt = "attempt-duplicate"
            events = [
                LifecycleEvent("event-1", group, 1, "request-started", "analysis"),
                LifecycleEvent("event-2", group, 2, "provider-dispatch-started", "analysis", provider_attempt_id=attempt),
                LifecycleEvent("event-3", group, 3, "provider-response-received", "analysis", provider_attempt_id=attempt, response_ref=str(response_ref), usage={"total_tokens": 7}),
                LifecycleEvent("event-4", group, 4, "provider-response-received", "analysis", provider_attempt_id=attempt, response_ref=str(response_ref), usage={"total_tokens": 7}),
                LifecycleEvent("event-5", group, 5, "request-terminal", "analysis", terminal_status="accepted"),
            ]
            for event in events:
                ledger.write_event(event)

            accounting = reconcile_llm_lifecycle(
                root,
                budget_counters={"requests_used": 2, "tokens_used": 14},
            )
            self.assertIsNone(accounting.llm_tokens)
            self.assertIn("duplicate-response", {item.reason for item in accounting.gaps})
            self.assertIn("budget-counter-mismatch", {item.reason for item in accounting.gaps})

    def test_response_artifact_content_is_authoritative_for_identity_and_usage(self):
        mutations = {
            "corrupt-response-artifact": lambda payload: "{corrupt",
            "response-request-id-mismatch": lambda payload: {
                **payload,
                "request": {**payload["request"], "id": "different-request"},
            },
            "response-id-mismatch": lambda payload: {
                **payload,
                "response": {**payload["response"], "id": "different-response"},
            },
            "response-usage-mismatch": lambda payload: {
                **payload,
                "response": {
                    **payload["response"],
                    "usage": {"total_tokens": 999},
                },
            },
        }
        for expected_reason, mutate in mutations.items():
            with self.subTest(expected_reason=expected_reason), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                req = request(f"artifact-{expected_reason}")
                gateway = AuditedLLMGateway(
                    StaticClient(response(req, tokens=25)),
                    LifecycleLedger(root, f"run-{expected_reason}"),
                    request_budget=2,
                    token_budget=1_000,
                )
                receipt = gateway.invoke(req)
                gateway.record_schema(receipt, valid=True)
                gateway.record_policy(receipt, accepted=True)
                gateway.terminalize(receipt, "accepted")
                response_path = Path(receipt.response_ref)
                payload = json.loads(response_path.read_text(encoding="utf-8"))
                changed = mutate(payload)
                response_path.write_text(
                    changed if isinstance(changed, str) else json.dumps(changed),
                    encoding="utf-8",
                )

                accounting = reconcile_llm_lifecycle(root)
                self.assertFalse(accounting.complete)
                self.assertIsNone(accounting.llm_tokens)
                self.assertIn(expected_reason, {item.reason for item in accounting.gaps})

    def test_authoritative_replay_exposes_deleted_lifecycle_event(self):
        from audit_agent.message_bus import MessageBus, replay_run_summary

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bus = MessageBus("run-replay-tamper", root / "messages" / "messages.jsonl")
            ledger = LifecycleLedger(root, "run-replay-tamper")
            req = request("replay-tamper")
            gateway = AuditedLLMGateway(
                StaticClient(response(req, tokens=5)),
                ledger,
                request_budget=2,
                token_budget=100,
            )
            receipt = gateway.invoke(req)
            gateway.record_schema(receipt, valid=True)
            gateway.record_policy(receipt, accepted=True)
            gateway.terminalize(receipt, "accepted")
            for ref in receipt.event_refs:
                event = json.loads(Path(ref).read_text(encoding="utf-8"))
                bus.publish(
                    "llm-gateway",
                    "runtime",
                    f"llm.lifecycle.{event['kind']}",
                    {
                        "request_group_id": event["request_group_id"],
                        "provider_attempt_id": event.get("provider_attempt_id"),
                        "event_id": event["event_id"],
                        "event_kind": event["kind"],
                        "terminal_status": event.get("terminal_status"),
                        "role": event["role"],
                    },
                    artifact_refs=[ref],
                )
            Path(receipt.event_refs[2]).unlink()

            replay = replay_run_summary(
                root / "messages" / "messages.jsonl",
                run_dir=root,
                llm_enabled=True,
            )
            ledger_result = reconcile_llm_lifecycle(root, llm_enabled=True)
            self.assertFalse(replay["llm_request_lifecycle"]["complete"])
            self.assertEqual(
                replay["llm_request_lifecycle"]["gap_ids"],
                ledger_result.gap_ids,
            )
            self.assertIn(
                receipt.request_group_id,
                replay["llm_request_lifecycle"]["incomplete_groups"],
            )

    def test_benchmark_readiness_reports_exact_llm_gap_id(self):
        from audit_agent.benchmark_evaluation import promotion_readiness

        report = {
            "summary": {"complete": True, "baseline_eligible": True},
            "cases": [
                {
                    "case_id": "fixture-case",
                    "project_id": "fixture-project",
                    "effectiveness_eligible": True,
                    "support_level": "full-dataflow",
                    "cleanup": {"success": True},
                    "resources": {
                        "accounting_gaps": [],
                        "llm_reconciliation_status": "incomplete",
                        "llm_gap_ids": ["LLMGAP-exact-fixture"],
                    },
                }
            ],
        }

        readiness = promotion_readiness(report, profile_kind="fixture")

        self.assertFalse(readiness["ready"])
        self.assertIn(
            {
                "field": "fixture-case.llm_accounting",
                "reason": "required-accounting-incomplete:LLMGAP-exact-fixture",
            },
            readiness["blockers"],
        )

        report["cases"][0]["resources"].update(
            {"llm_reconciliation_status": "complete", "llm_gap_ids": []}
        )
        self.assertTrue(promotion_readiness(report, profile_kind="fixture")["ready"])

    def test_benchmark_case_validation_accepts_reconciled_and_disabled_cases_only(self):
        from audit_agent.benchmark_models import RunResourceSummary
        from audit_agent.benchmark_runtime import validate_case_completion

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            refs = {}
            for name in ("report", "runtime_state", "resource_summary"):
                path = root / f"{name}.json"
                path.write_text("{}", encoding="utf-8")
                refs[name] = str(path)
            refs["run_dir"] = str(root)
            case = SimpleNamespace(
                case_id="fixture-case",
                commit="fixture-commit",
                budgets={
                    "llm_requests": 0,
                    "llm_tokens": 100,
                    "tool_calls": 1,
                    "docker_starts": 0,
                    "repair_attempts": 0,
                },
            )
            summary = RunResourceSummary(
                schema_version="run-resource-summary.v1",
                run_id="run",
                target_identity=case.case_id,
                target_commit=case.commit,
                terminal_status="succeeded",
                scanned_files=1,
                scanned_bytes=1,
                stage_durations_ms={},
                final_status_counts={},
                llm_requests=0,
                llm_tokens=0,
                tool_calls=1,
                docker_starts=0,
                docker_results=0,
                repair_attempts=0,
                timeouts=0,
                budget_consumption={},
                accounting_gaps=[],
                contributing_refs=[],
                ledger_present=False,
                accounting_source="disabled-zero",
                llm_reconciliation_status="complete",
                elapsed_seconds=1.0,
            ).to_dict()
            result = {
                "status": "pending-validation",
                "acquisition": {"status": "ready", "resolved_commit": case.commit},
                "runtime": {"status": "succeeded"},
                "resources": summary,
                "artifact_refs": refs,
                "cleanup": {"success": True},
            }
            self.assertEqual(validate_case_completion(case, result), (True, None))

    def test_benchmark_reconciles_live_ledger_instead_of_trusting_stale_summary(self):
        from audit_agent.benchmark_models import RunResourceSummary
        from audit_agent.benchmark_runtime import validate_case_completion

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "run"
            req = request("benchmark-tamper")
            state = {}
            gateway = AuditedLLMGateway(
                StaticClient(response(req, tokens=11)),
                LifecycleLedger(run_dir, "run-benchmark-tamper"),
                request_budget=2,
                token_budget=100,
                accounting_state=state,
            )
            receipt = gateway.invoke(req)
            gateway.record_schema(receipt, valid=True)
            gateway.record_policy(receipt, accepted=True)
            gateway.terminalize(receipt, "accepted")
            live = reconcile_llm_lifecycle(run_dir, llm_enabled=True, budget_counters=state)
            case = SimpleNamespace(
                case_id="fixture-tamper",
                commit="fixture-commit",
                budgets={
                    "llm_requests": 2,
                    "llm_tokens": 100,
                    "tool_calls": 1,
                    "docker_starts": 0,
                    "repair_attempts": 0,
                },
            )
            report_ref = run_dir / "reports" / "report.json"
            runtime_ref = run_dir / "runtime_state" / "state.json"
            resource_ref = run_dir / "reports" / "run-resource-summary.v1.json"
            report_ref.parent.mkdir(parents=True)
            runtime_ref.parent.mkdir(parents=True)
            report_ref.write_text("{}", encoding="utf-8")
            runtime_ref.write_text(
                json.dumps({"llm_accounting": state}),
                encoding="utf-8",
            )
            summary = RunResourceSummary(
                schema_version="run-resource-summary.v1",
                run_id="run-benchmark-tamper",
                target_identity=case.case_id,
                target_commit=case.commit,
                terminal_status="succeeded",
                scanned_files=1,
                scanned_bytes=1,
                stage_durations_ms={},
                final_status_counts={},
                llm_requests=live.llm_requests,
                llm_tokens=live.llm_tokens,
                tool_calls=1,
                docker_starts=0,
                docker_results=0,
                repair_attempts=0,
                timeouts=0,
                budget_consumption={},
                accounting_gaps=[],
                contributing_refs=list(live.contributing_refs),
                ledger_present=True,
                accounting_source=live.accounting_source,
                llm_total_request_groups=live.total_request_groups,
                llm_dispatched_request_groups=live.llm_requests,
                llm_provider_attempts=live.provider_attempts,
                llm_retries=live.retries,
                llm_pre_dispatch_denials=live.pre_dispatch_denials,
                llm_terminal_status_counts=live.terminal_status_counts,
                llm_reconciliation_status="complete",
                llm_gap_ids=[],
                llm_contributing_refs=list(live.contributing_refs),
                elapsed_seconds=1.0,
            )
            resource_ref.write_text(json.dumps(summary.to_dict()), encoding="utf-8")
            result = {
                "status": "pending-validation",
                "acquisition": {"status": "ready", "resolved_commit": case.commit},
                "runtime": {"status": "succeeded"},
                "resources": summary.to_dict(),
                "artifact_refs": {
                    "run_dir": str(run_dir),
                    "report": str(report_ref),
                    "runtime_state": str(runtime_ref),
                    "resource_summary": str(resource_ref),
                },
                "cleanup": {"success": True},
            }
            self.assertEqual(validate_case_completion(case, result), (True, None))
            Path(receipt.response_ref).unlink()
            valid, reason = validate_case_completion(case, result)
            self.assertFalse(valid)
            self.assertTrue(reason.startswith("llm-accounting-incomplete:LLMGAP-"), reason)
