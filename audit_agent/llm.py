from __future__ import annotations

import json
import hashlib
import http.client
import io
import os
import socket
import threading
import time
import urllib.error
import urllib.request
import urllib.parse
from dataclasses import replace
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


class LLMCancelled(RuntimeError):
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


class ProviderAttemptObserver(Protocol):
    def dispatch_started(self, details: dict[str, Any] | None = None) -> str:
        ...

    def attempt_failed(self, attempt_id: str, details: dict[str, Any] | None = None) -> None:
        ...

    def attempt_response(self, attempt_id: str, response: LLMResponse) -> None:
        ...


class MockLLMClient:
    def __init__(self, responses: dict[str, Any] | None = None):
        self.responses = responses or {}

    def complete(self, request: LLMRequest) -> LLMResponse:
        started = time.monotonic()
        payload = self.responses.get(request.role)
        if payload is None:
            required = set((request.response_schema or {}).get("required", []))
            if "hypotheses" in required:
                payload = {
                    "hypotheses": [],
                    "updates": [],
                    "rationale": "Explicit test mock produced no repository-specific hypotheses.",
                }
            elif "primitives" in required:
                payload = {
                    "confidence": 0.0,
                    "rationale": "Explicit test mock deferred to the trusted default plan.",
                    "primitives": [],
                }
            else:
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
        self._cancellation_token = None
        self._connections: set[http.client.HTTPConnection] = set()
        self._connections_lock = threading.Lock()
        self._response_format_capabilities: dict[str, str] = {}
        self._response_format_state: dict[str, Any] | None = None
        self._response_format_lock = threading.Lock()

    def set_runtime_state(self, state: dict[str, Any]) -> None:
        """Attach the run-persisted capability cache without storing endpoint secrets."""
        stored = state.get("response_format_capabilities")
        if not isinstance(stored, dict):
            stored = {}
            state["response_format_capabilities"] = stored
        with self._response_format_lock:
            self._response_format_state = state
            self._response_format_capabilities.update(
                {
                    str(key): str(value)
                    for key, value in stored.items()
                    if value in {"json_schema", "json_object"}
                }
            )

    def set_cancellation_token(self, token) -> None:
        self._cancellation_token = token

    def cancel_active(self) -> None:
        with self._connections_lock:
            connections = list(self._connections)
        for connection in connections:
            try:
                connection.close()
            except OSError:
                continue

    def _check_cancelled(self) -> None:
        if self._cancellation_token is not None and self._cancellation_token.cancelled:
            raise LLMCancelled("LLM request cancelled")

    def _post_json(self, url: str, data: bytes, headers: dict[str, str]) -> dict[str, Any]:
        # Preserve the simple transport for standalone callers and its stable
        # test seam. Run-scoped gateways install a cancellation token and use
        # the closable HTTPConnection path below.
        if self._cancellation_token is None:
            request = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        self._check_cancelled()
        parsed = urllib.parse.urlsplit(url)
        connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        connection = connection_type(parsed.hostname, parsed.port, timeout=self.config.timeout_seconds)
        with self._connections_lock:
            self._connections.add(connection)
        unregister = (
            self._cancellation_token.register(self.cancel_active)
            if self._cancellation_token is not None and hasattr(self._cancellation_token, "register")
            else lambda: None
        )
        try:
            path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
            connection.request("POST", path, body=data, headers=headers)
            response = connection.getresponse()
            body = response.read()
            self._check_cancelled()
            if response.status >= 400:
                raise urllib.error.HTTPError(
                    url,
                    response.status,
                    response.reason,
                    response.headers,
                    io.BytesIO(body),
                )
            return json.loads(body.decode("utf-8"))
        except (OSError, http.client.HTTPException) as exc:
            if self._cancellation_token is not None and self._cancellation_token.cancelled:
                raise LLMCancelled("LLM request cancelled") from exc
            raise
        finally:
            unregister()
            with self._connections_lock:
                self._connections.discard(connection)
            connection.close()

    def complete(self, request: LLMRequest) -> LLMResponse:
        return self.complete_with_attempt_observer(request, None)

    def complete_with_attempt_observer(
        self,
        request: LLMRequest,
        observer: ProviderAttemptObserver | None,
    ) -> LLMResponse:
        started = time.monotonic()
        url = self.config.base_url.rstrip("/") + "/chat/completions"
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"}
        last_error: Exception | None = None
        attempts_per_format = max(1, self.config.retry_count + 1)
        total_attempts = 0
        preferred_format, preferred_source = self._preferred_response_format(request)
        response_formats = _response_format_candidates(request, preferred_format)
        for format_index, response_format in enumerate(response_formats):
            format_source = (
                preferred_source
                if preferred_format == response_format
                else "auto-probe" if format_index == 0 else "auto-fallback"
            )
            data = json.dumps(_request_body(request, self.config, response_format)).encode("utf-8")
            for retry_index in range(1, attempts_per_format + 1):
                total_attempts += 1
                attempt_id = (
                    observer.dispatch_started(
                        {
                            "attempt_index": total_attempts,
                            "response_format": response_format or "text",
                            "response_format_source": format_source,
                        }
                    )
                    if observer
                    else ""
                )
                try:
                    self._check_cancelled()
                    raw = self._post_json(url, data, headers)
                    text = raw.get("choices", [{}])[0].get("message", {}).get("content", "")
                    parsed = _try_parse_json(text)
                    result = LLMResponse(
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
                    if observer:
                        observer.attempt_response(attempt_id, result)
                    if request.response_format == "auto" and response_format in {
                        "json_schema",
                        "json_object",
                    }:
                        self._remember_response_format(request, response_format)
                    return result
                except urllib.error.HTTPError as exc:
                    last_error = exc
                    has_format_fallback = format_index + 1 < len(response_formats)
                    capability_rejected = (
                        exc.code == 400
                        and request.response_format == "auto"
                        and response_format == "json_schema"
                        and has_format_fallback
                    )
                    if observer:
                        observer.attempt_failed(
                            attempt_id,
                            {
                                "error_type": "http",
                                "status_code": exc.code,
                                "response_format": response_format or "text",
                                "response_format_source": format_source,
                                "capability_rejected": capability_rejected,
                            },
                        )
                    if exc.code in {401, 403}:
                        raise _provider_error("authentication", self.config, total_attempts, exc, exc.code)
                    if exc.code == 429:
                        raise _provider_error("rate_limit", self.config, total_attempts, exc, exc.code)
                    if capability_rejected:
                        break
                    if exc.code == 400 or retry_index >= attempts_per_format:
                        raise _provider_error("invalid_request", self.config, total_attempts, exc, exc.code)
                except (TimeoutError, socket.timeout) as exc:
                    last_error = exc
                    if observer:
                        observer.attempt_failed(attempt_id, {"error_type": "timeout"})
                    if retry_index >= attempts_per_format:
                        raise _provider_error("timeout", self.config, total_attempts, exc)
                except json.JSONDecodeError as exc:
                    last_error = exc
                    if observer:
                        observer.attempt_failed(attempt_id, {"error_type": "invalid_json"})
                    if retry_index >= attempts_per_format:
                        raise _provider_error("invalid_json", self.config, total_attempts, exc)
                except urllib.error.URLError as exc:
                    last_error = exc
                    error_type = "timeout" if isinstance(exc.reason, (TimeoutError, socket.timeout)) else "network"
                    if observer:
                        observer.attempt_failed(attempt_id, {"error_type": error_type})
                    if retry_index >= attempts_per_format:
                        raise _provider_error(error_type, self.config, total_attempts, exc)
                except OSError as exc:
                    last_error = exc
                    if observer:
                        observer.attempt_failed(attempt_id, {"error_type": "network"})
                    if retry_index >= attempts_per_format:
                        raise _provider_error("network", self.config, total_attempts, exc)
        raise _provider_error(
            "provider",
            self.config,
            total_attempts,
            last_error or RuntimeError("unknown provider error"),
        )

    def _preferred_response_format(self, request: LLMRequest) -> tuple[str | None, str]:
        if request.response_format != "auto" or not request.response_schema:
            return None, "request"
        configured = self.config.response_format
        if configured != "auto":
            return configured, "config"
        cached = self._cached_response_format(request)
        if cached:
            return cached, "run-cache"
        known = _known_provider_response_format(self.config)
        if known:
            return known, "provider-capability"
        return None, "auto-probe"

    def _cached_response_format(self, request: LLMRequest) -> str | None:
        key = _response_format_capability_key(self.config, request)
        with self._response_format_lock:
            value = self._response_format_capabilities.get(key)
        return value if value in {"json_schema", "json_object"} else None

    def _remember_response_format(self, request: LLMRequest, response_format: str) -> None:
        if response_format not in {"json_schema", "json_object"}:
            return
        key = _response_format_capability_key(self.config, request)
        with self._response_format_lock:
            self._response_format_capabilities[key] = response_format
            if self._response_format_state is not None:
                stored = self._response_format_state.setdefault(
                    "response_format_capabilities", {}
                )
                if isinstance(stored, dict):
                    stored[key] = response_format


def _response_format_candidates(
    request: LLMRequest,
    preferred_format: str | None = None,
) -> list[str | None]:
    mode = request.response_format
    if not mode or not request.response_schema:
        return [None]
    if mode == "auto":
        if preferred_format in {"json_schema", "json_object"}:
            return [preferred_format]
        return ["json_schema", "json_object"]
    if mode in {"json_schema", "json_object"}:
        return [mode]
    raise LLMConfigurationError(f"Unsupported response format: {mode}")


def _known_provider_response_format(config: LlmConfig) -> str | None:
    provider = str(config.provider or "").strip().lower()
    hostname = (urllib.parse.urlsplit(config.base_url).hostname or "").lower()
    if provider == "deepseek-compatible" or hostname == "deepseek.com" or hostname.endswith(
        ".deepseek.com"
    ):
        return "json_object"
    if provider == "openai" or hostname == "openai.com" or hostname.endswith(".openai.com"):
        return "json_schema"
    return None


def _response_format_capability_key(config: LlmConfig, request: LLMRequest) -> str:
    identity = "\n".join(
        [
            str(config.provider or "").strip().lower(),
            str(config.base_url or "").strip().rstrip("/").lower(),
            str(request.model or config.model or "").strip().lower(),
        ]
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


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
    def __init__(self, message: str, *, response: LLMResponse | None = None):
        super().__init__(message)
        self.response = response


PROMPT_TOKEN_ESTIMATOR = "utf8-byte-upper-bound.v1"
PROMPT_TOKEN_FRAMING_ALLOWANCE = 16


def estimate_request_prompt_tokens(request: LLMRequest) -> int:
    """Return a provider-neutral conservative upper bound for prompt tokens."""
    schema = json.dumps(
        request.response_schema or {},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return max(
        1,
        len(str(request.prompt).encode("utf-8"))
        + len(str(request.role).encode("utf-8"))
        + len(schema.encode("utf-8"))
        + PROMPT_TOKEN_FRAMING_ALLOWANCE,
    )


def plan_request_token_budget(
    request: LLMRequest,
    *,
    token_budget: int,
    tokens_used: int,
    default_max_tokens: int | None = None,
) -> tuple[LLMRequest, dict[str, Any]]:
    remaining = max(0, int(token_budget) - int(tokens_used))
    prompt_estimate = estimate_request_prompt_tokens(request)
    configured_limit = request.max_tokens
    if (
        isinstance(configured_limit, bool)
        or not isinstance(configured_limit, int)
        or configured_limit < 1
    ):
        configured_limit = default_max_tokens
    if (
        isinstance(configured_limit, bool)
        or not isinstance(configured_limit, int)
        or configured_limit < 1
    ):
        configured_limit = None
    completion_allowance = max(0, remaining - prompt_estimate)
    effective_max_tokens = (
        min(configured_limit, completion_allowance)
        if configured_limit is not None
        else completion_allowance
    )
    plan = {
        "estimator": PROMPT_TOKEN_ESTIMATOR,
        "token_budget": int(token_budget),
        "tokens_used_before_request": int(tokens_used),
        "remaining_token_budget": remaining,
        "prompt_token_estimate": prompt_estimate,
        "configured_max_tokens": configured_limit,
        "effective_max_tokens": effective_max_tokens,
        "dispatch_allowed": effective_max_tokens > 0,
    }
    if effective_max_tokens < 1:
        return request, plan
    return replace(request, max_tokens=effective_max_tokens), plan


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
        default_max_tokens = getattr(getattr(self.inner, "config", None), "max_tokens", None)
        effective_request, plan = plan_request_token_budget(
            request,
            token_budget=self.token_budget,
            tokens_used=self.tokens_used,
            default_max_tokens=default_max_tokens,
        )
        if not plan["dispatch_allowed"]:
            raise LLMBudgetExceeded("LLM token budget exhausted")
        self.requests_used += 1
        response = self.inner.complete(effective_request)
        total = response.usage.get("total_tokens")
        if total is None:
            prompt = response.usage.get("prompt_tokens")
            completion = response.usage.get("completion_tokens")
            if (
                isinstance(prompt, int)
                and not isinstance(prompt, bool)
                and isinstance(completion, int)
                and not isinstance(completion, bool)
            ):
                total = prompt + completion
        if isinstance(total, bool) or not isinstance(total, int) or total < 0:
            return response
        next_total = self.tokens_used + total
        if next_total > self.token_budget:
            raise LLMBudgetExceeded("LLM response exceeded token budget", response=response)
        self.tokens_used = next_total
        return response


def validate_json_schema(value: Any, schema: dict[str, Any]) -> None:
    if not schema:
        return
    if "oneOf" in schema:
        matches = 0
        errors: list[str] = []
        for candidate in schema["oneOf"]:
            try:
                validate_json_schema(value, candidate)
                matches += 1
            except LLMValidationError as exc:
                errors.append(str(exc))
        if matches != 1:
            raise LLMValidationError(
                f"Field value must match exactly one schema alternative (matched {matches})"
            )
    if "const" in schema and value != schema["const"]:
        raise LLMValidationError(f"Field value must equal {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise LLMValidationError(f"Field value must be one of {schema['enum']!r}")
    expected_type = schema.get("type")
    _validate_type("value", value, expected_type)
    if isinstance(value, dict):
        for field in schema.get("required", []):
            if field not in value:
                raise LLMValidationError(f"Missing required field: {field}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                raise LLMValidationError(f"Unknown fields are not allowed: {unknown}")
        for name, prop_schema in properties.items():
            if name in value:
                _validate_type(name, value[name], prop_schema.get("type"))
                validate_json_schema(value[name], prop_schema)
    if isinstance(value, list):
        if "minItems" in schema and len(value) < int(schema["minItems"]):
            raise LLMValidationError(f"Field value requires at least {schema['minItems']} items")
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            raise LLMValidationError(f"Field value permits at most {schema['maxItems']} items")
        if isinstance(schema.get("items"), dict):
            for item in value:
                validate_json_schema(item, schema["items"])
    if isinstance(value, str):
        if "minLength" in schema and len(value) < int(schema["minLength"]):
            raise LLMValidationError(f"Field value requires at least {schema['minLength']} characters")
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            raise LLMValidationError(f"Field value permits at most {schema['maxLength']} characters")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise LLMValidationError(f"Field value must be at least {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            raise LLMValidationError(f"Field value must be at most {schema['maximum']}")


def persist_llm_artifact(
    root: Path | str,
    request: LLMRequest,
    response: LLMResponse,
    secret_values: list[str] | tuple[str, ...] | None = None,
) -> Path:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    path = immutable_path(root / f"{request.role}-{response.id}.json")
    path.write_text(
        json.dumps(
            redact_secrets(
                {"request": request.to_dict(), "response": response.to_dict()},
                secret_values,
            ),
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
