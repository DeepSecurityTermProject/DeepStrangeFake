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
        body = {
            "model": request.model or self.config.model,
            "messages": [{"role": "user", "content": request.prompt}],
            "temperature": request.temperature,
        }
        if request.max_tokens or self.config.max_tokens:
            body["max_tokens"] = request.max_tokens or self.config.max_tokens
        data = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"}
        last_error: Exception | None = None
        attempts = max(1, self.config.retry_count + 1)
        for attempt in range(1, attempts + 1):
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
                    raise _provider_error("authentication", self.config, attempt, exc, exc.code)
                if exc.code == 429:
                    raise _provider_error("rate_limit", self.config, attempt, exc, exc.code)
            except (TimeoutError, socket.timeout) as exc:
                last_error = exc
                if attempt >= attempts:
                    raise _provider_error("timeout", self.config, attempt, exc)
            except json.JSONDecodeError as exc:
                last_error = exc
                if attempt >= attempts:
                    raise _provider_error("invalid_json", self.config, attempt, exc)
            except urllib.error.URLError as exc:
                last_error = exc
                if attempt >= attempts:
                    error_type = "timeout" if isinstance(exc.reason, (TimeoutError, socket.timeout)) else "network"
                    raise _provider_error(error_type, self.config, attempt, exc)
            except OSError as exc:
                last_error = exc
                if attempt >= attempts:
                    raise _provider_error("network", self.config, attempt, exc)
        raise _provider_error("provider", self.config, attempts, last_error or RuntimeError("unknown provider error"))


def build_llm_client(config: LlmConfig) -> LLMClient:
    if config.provider == "mock":
        return MockLLMClient()
    if config.provider in {"openai-compatible", "openai", "deepseek-compatible", "ollama-compatible"}:
        return OpenAICompatibleClient(config)
    raise LLMConfigurationError(f"Unsupported LLM provider: {config.provider}")


def validate_json_schema(value: Any, schema: dict[str, Any]) -> None:
    if not schema:
        return
    expected_type = schema.get("type")
    if expected_type == "object" and not isinstance(value, dict):
        raise LLMValidationError("Expected JSON object")
    if expected_type == "array" and not isinstance(value, list):
        raise LLMValidationError("Expected JSON array")
    if isinstance(value, dict):
        for field in schema.get("required", []):
            if field not in value:
                raise LLMValidationError(f"Missing required field: {field}")
        for name, prop_schema in schema.get("properties", {}).items():
            if name in value:
                _validate_type(name, value[name], prop_schema.get("type"))


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


def _try_parse_json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _default_payload_for_role(role: str) -> dict[str, Any]:
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
