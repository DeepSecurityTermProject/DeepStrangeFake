from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Protocol

from .config import LlmConfig
from .models import LLMRequest, LLMResponse, to_plain
from .redaction import redact_secrets
from .storage import immutable_path


class LLMConfigurationError(RuntimeError):
    pass


class LLMValidationError(RuntimeError):
    pass


class LLMProviderError(RuntimeError):
    def __init__(
        self,
        message: str,
        error_type: str,
        provider: str,
        model: str,
        attempts: int,
        status_code: int | None = None,
        diagnostic: str = "",
        secret_values: list[str] | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_type = error_type
        self.provider = provider
        self.model = model
        self.attempts = attempts
        self.status_code = status_code
        self.diagnostic = diagnostic
        self.secret_values = secret_values or []

    def to_dict(self) -> dict[str, Any]:
        return redact_secrets(
            {
                "message": self.message,
                "error_type": self.error_type,
                "provider": self.provider,
                "model": self.model,
                "attempts": self.attempts,
                "status_code": self.status_code,
                "diagnostic": self.diagnostic,
            },
            self.secret_values or _known_secret_values(),
        )


class LLMClient(Protocol):
    def complete(self, request: LLMRequest) -> LLMResponse:
        ...


class MockLLMClient:
    def __init__(self, responses: dict[str, Any] | None = None):
        self.responses = responses or {}

    def complete(self, request: LLMRequest) -> LLMResponse:
        started = time.monotonic()
        payload = self.responses.get(request.role)
        if payload is None:
            payload = _default_payload_for_role(request.role)
        text = json.dumps(payload, ensure_ascii=False)
        return LLMResponse(
            request_id=request.id or "",
            provider="mock",
            model=request.model,
            text=text,
            parsed_json=payload,
            usage={
                "prompt_tokens": max(1, len(request.prompt.split())),
                "completion_tokens": max(1, len(text.split())),
                "total_tokens": max(2, len(request.prompt.split()) + len(text.split())),
            },
            finish_reason="stop",
            latency_ms=int((time.monotonic() - started) * 1000),
            raw_response={"mode": "deterministic", "role": request.role, "payload": payload},
        )

    def persist(self, root: Path | str, request: LLMRequest, response: LLMResponse) -> Path:
        root = Path(root)
        root.mkdir(parents=True, exist_ok=True)
        path = immutable_path(root / f"{request.role}-{response.id}.json")
        payload = {"request": request.to_dict(), "response": response.to_dict()}
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        response.artifact_path = str(path)
        return path


class OpenAICompatibleClient:
    def __init__(self, config: LlmConfig):
        self.config = config
        self.api_key = os.environ.get(config.api_key_env)
        if not self.api_key:
            raise LLMConfigurationError(
                f"Missing API key environment variable for provider {config.provider}: {config.api_key_env}"
            )

    def complete(self, request: LLMRequest) -> LLMResponse:
        started = time.monotonic()
        url = self.config.base_url.rstrip("/") + "/chat/completions"
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"}
        last_error: Exception | None = None
        attempts_per_format = max(1, self.config.retry_count + 1)
        total_attempts = 0
        response_formats = _response_format_candidates(request)
        for format_index, response_format in enumerate(response_formats):
            data = json.dumps(_request_body(request, self.config, response_format)).encode("utf-8")
            for retry_index in range(1, attempts_per_format + 1):
                total_attempts += 1
                try:
                    http_request = urllib.request.Request(url, data=data, headers=headers, method="POST")
                    with urllib.request.urlopen(http_request, timeout=self.config.timeout_seconds) as response:
                        raw = json.loads(response.read().decode("utf-8"))
                    text = raw.get("choices", [{}])[0].get("message", {}).get("content", "")
                    parsed = _try_parse_json(text)
                    return LLMResponse(
                        request_id=request.id or "",
                        provider=self.config.provider,
                        model=raw.get("model") or request.model or self.config.model,
                        text=text,
                        parsed_json=parsed,
                        usage=raw.get("usage", {}),
                        finish_reason=raw.get("choices", [{}])[0].get("finish_reason"),
                        latency_ms=int((time.monotonic() - started) * 1000),
                        raw_response=raw,
                    )
                except urllib.error.HTTPError as exc:
                    last_error = exc
                    if exc.code in {401, 403}:
                        raise _provider_error("authentication", self.config, total_attempts, exc, exc.code)
                    if exc.code == 429:
                        raise _provider_error("rate_limit", self.config, total_attempts, exc, exc.code)
                    has_format_fallback = format_index + 1 < len(response_formats)
                    if exc.code == 400 and response_format == "json_schema" and has_format_fallback:
                        break
                    if exc.code == 400 or retry_index >= attempts_per_format:
                        raise _provider_error("invalid_request", self.config, total_attempts, exc, exc.code)
                except (TimeoutError, socket.timeout) as exc:
                    last_error = exc
                    if retry_index >= attempts_per_format:
                        raise _provider_error("timeout", self.config, total_attempts, exc)
                except json.JSONDecodeError as exc:
                    last_error = exc
                    if retry_index >= attempts_per_format:
                        raise _provider_error("invalid_json", self.config, total_attempts, exc)
                except urllib.error.URLError as exc:
                    last_error = exc
                    if retry_index >= attempts_per_format:
                        error_type = "timeout" if isinstance(exc.reason, (TimeoutError, socket.timeout)) else "network"
                        raise _provider_error(error_type, self.config, total_attempts, exc)
                except OSError as exc:
                    last_error = exc
                    if retry_index >= attempts_per_format:
                        raise _provider_error("network", self.config, total_attempts, exc)
        raise _provider_error(
            "provider",
            self.config,
            total_attempts,
            last_error or RuntimeError("unknown provider error"),
        )


def _response_format_candidates(request: LLMRequest) -> list[str | None]:
    mode = request.response_format
    if not mode or not request.response_schema:
        return [None]
    if mode == "auto":
        return ["json_schema", "json_object"]
    if mode in {"json_schema", "json_object"}:
        return [mode]
    raise LLMConfigurationError(f"Unsupported response format: {mode}")


def _request_body(
    request: LLMRequest,
    config: LlmConfig,
    response_format: str | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": request.model or config.model,
        "messages": [{"role": "user", "content": request.prompt}],
        "temperature": request.temperature,
    }
    if request.max_tokens or config.max_tokens:
        body["max_tokens"] = request.max_tokens or config.max_tokens
    if response_format == "json_schema":
        schema_name = "".join(character if character.isalnum() else "_" for character in request.role).strip("_")
        body["response_format"] = {
            "type": "json_schema",
            "json_schema": {
                "name": schema_name or "structured_response",
                "strict": True,
                "schema": request.response_schema,
            },
        }
    elif response_format == "json_object":
        body["response_format"] = {"type": "json_object"}
    return body


def build_llm_client(config: LlmConfig) -> LLMClient:
    if config.provider == "mock":
        return MockLLMClient()
    if config.provider in {"openai-compatible", "openai", "deepseek-compatible", "ollama-compatible"}:
        return OpenAICompatibleClient(config)
    raise LLMConfigurationError(f"Unsupported LLM provider: {config.provider}")


class LLMBudgetExceeded(RuntimeError):
    pass


class BudgetedLLMClient:
    def __init__(self, inner: LLMClient, *, request_budget: int, token_budget: int):
        self.inner = inner
        self.request_budget = max(0, int(request_budget))
        self.token_budget = max(0, int(token_budget))
        self.requests_used = 0
        self.tokens_used = 0

    def complete(self, request: LLMRequest) -> LLMResponse:
        if self.requests_used >= self.request_budget:
            raise LLMBudgetExceeded("LLM request budget exhausted")
        if self.tokens_used >= self.token_budget:
            raise LLMBudgetExceeded("LLM token budget exhausted")
        response = self.inner.complete(request)
        total = response.usage.get("total_tokens")
        if total is None:
            total = int(response.usage.get("prompt_tokens") or 0) + int(
                response.usage.get("completion_tokens") or 0
            )
        next_total = self.tokens_used + int(total or 0)
        self.requests_used += 1
        if next_total > self.token_budget:
            raise LLMBudgetExceeded("LLM response exceeded token budget")
        self.tokens_used = next_total
        return response


def validate_json_schema(value: Any, schema: dict[str, Any]) -> None:
    if not schema:
        return
    expected_type = schema.get("type")
    _validate_type("value", value, expected_type)
    if isinstance(value, dict):
        for field in schema.get("required", []):
            if field not in value:
                raise LLMValidationError(f"Missing required field: {field}")
        for name, prop_schema in schema.get("properties", {}).items():
            if name in value:
                _validate_type(name, value[name], prop_schema.get("type"))
                validate_json_schema(value[name], prop_schema)
    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        for item in value:
            validate_json_schema(item, schema["items"])
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise LLMValidationError(f"Field value must be at least {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            raise LLMValidationError(f"Field value must be at most {schema['maximum']}")


def persist_llm_artifact(root: Path | str, request: LLMRequest, response: LLMResponse) -> Path:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    path = immutable_path(root / f"{request.role}-{response.id}.json")
    path.write_text(
        json.dumps(
            redact_secrets({"request": request.to_dict(), "response": response.to_dict()}),
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    response.artifact_path = str(path)
    return path


def _validate_type(name: str, value: Any, expected: str | None) -> None:
    if expected == "array" and not isinstance(value, list):
        raise LLMValidationError(f"Field {name} must be an array")
    if expected == "object" and not isinstance(value, dict):
        raise LLMValidationError(f"Field {name} must be an object")
    if expected == "string" and not isinstance(value, str):
        raise LLMValidationError(f"Field {name} must be a string")
    if expected == "number" and (isinstance(value, bool) or not isinstance(value, (int, float))):
        raise LLMValidationError(f"Field {name} must be a number")
    if expected == "integer" and (isinstance(value, bool) or not isinstance(value, int)):
        raise LLMValidationError(f"Field {name} must be an integer")


def _try_parse_json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _default_payload_for_role(role: str) -> dict[str, Any]:
    if role == "poc-repair":
        return {
            "diagnosis": "The generated harness is missing pathlib.Path.",
            "edits": [
                {
                    "op": "add_import",
                    "slot_id": "imports",
                    "module": "pathlib",
                    "name": "Path",
                }
            ],
            "changes": ["Add the allowlisted Path import in the declared imports slot."],
        }
    if role == "orchestrator":
        return {
            "role": "orchestrator",
            "action": "plan",
            "confidence": 0.78,
            "rationale": "Prioritize local source sinks and keep the default safe agent order.",
            "evidence_refs": ["repository-metadata"],
            "selected_actions": [
                {
                    "agent_order": ["recon", "analysis", "verification"],
                    "focus_areas": ["command-injection", "sql-injection"],
                    "budgets": {"analysis": 100, "tools": 80},
                }
            ],
            "requested_tools": [],
            "plan": {"vulnerability_classes": [], "agent_order": ["recon", "analysis", "verification"]},
        }
    if role == "recon":
        return {
            "role": "recon",
            "action": "tool-plan",
            "confidence": 0.74,
            "rationale": "Use repository metadata and safe static tooling only.",
            "evidence_refs": ["repository-metadata"],
            "selected_actions": [{"context_slices": [], "memory_queries": ["request args os.system select"]}],
            "requested_tools": [],
            "high_risk_areas": [],
            "dependency_concerns": [],
        }
    if role == "analysis":
        return {
            "role": "analysis",
            "action": "candidate-generation",
            "confidence": 0.76,
            "rationale": "No additional LLM-only candidates are promoted without local evidence.",
            "evidence_refs": [],
            "selected_actions": [],
            "requested_tools": [],
            "candidates": [],
        }
    if role == "verification":
        return {
            "role": "verification",
            "action": "verify",
            "confidence": 0.8,
            "rationale": "Keep deterministic verification unless local evidence supports a change.",
            "evidence_refs": [],
            "selected_actions": [],
            "requested_tools": [],
            "decisions": [],
        }
    return {"result": "ok"}


def _provider_error(
    error_type: str,
    config: LlmConfig,
    attempts: int,
    exc: Exception,
    status_code: int | None = None,
) -> LLMProviderError:
    message = f"LLM provider {error_type} error for {config.provider}/{config.model}"
    return LLMProviderError(
        message=message,
        error_type=error_type,
        provider=config.provider,
        model=config.model,
        attempts=attempts,
        status_code=status_code,
        diagnostic=str(exc),
        secret_values=_known_secret_values(),
    )


def _known_secret_values() -> list[str]:
    secrets = []
    for key, value in os.environ.items():
        if value and any(fragment in key.lower() for fragment in ("key", "token", "secret", "password")):
            secrets.append(value)
    return secrets
