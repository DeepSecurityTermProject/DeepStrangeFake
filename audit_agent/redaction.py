from __future__ import annotations

import re
from typing import Any


REDACTION_MARKER = "[REDACTED]"
SECRET_KEY_FRAGMENTS = (
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "password",
    "secret",
    "token",
)


def redact_secrets(value: Any, secret_values: list[str] | tuple[str, ...] | None = None) -> Any:
    secrets = [item for item in (secret_values or []) if item]
    return _redact(value, secrets)


def redact_text(value: str, secret_values: list[str] | tuple[str, ...] | None = None) -> str:
    """Redact configured values and credential-shaped literals in untrusted text."""
    text = str(value)
    for secret in [item for item in (secret_values or []) if item]:
        text = text.replace(secret, REDACTION_MARKER)
    text = re.sub(
        r"(?i)(['\"]?(?:api[_-]?key|access[_-]?token|auth[_-]?token|token|password|passwd|secret|authorization)['\"]?\s*[:=]\s*)(['\"])([^'\"\r\n]+)(\2)",
        lambda match: match.group(1) + match.group(2) + REDACTION_MARKER + match.group(4),
        text,
    )
    text = re.sub(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+", REDACTION_MARKER, text)
    text = re.sub(r"\bAKIA[0-9A-Z]{16}\b", REDACTION_MARKER, text)
    text = re.sub(r"\b(?:sk|ghp|github_pat)_[A-Za-z0-9_-]{12,}\b", REDACTION_MARKER, text)
    text = re.sub(r"\bsk-[A-Za-z0-9_-]{12,}\b", REDACTION_MARKER, text)
    return text


def _redact(value: Any, secrets: list[str]) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if _is_secret_key(key_text):
                redacted[key_text] = REDACTION_MARKER
            else:
                redacted[key_text] = _redact(item, secrets)
        return redacted
    if isinstance(value, list):
        return [_redact(item, secrets) for item in value]
    if isinstance(value, tuple):
        return [_redact(item, secrets) for item in value]
    if isinstance(value, str):
        text = redact_text(value, secrets)
        if _looks_like_authorization(text):
            return REDACTION_MARKER
        return text
    return value


def _is_secret_key(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    if lowered in {
        "llm_tokens",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "token_count",
        "token_usage",
        "max_tokens",
        "secret_env_names",
        "api_key_env_name",
    }:
        return False
    return any(fragment in lowered for fragment in SECRET_KEY_FRAGMENTS)


def _looks_like_authorization(text: str) -> bool:
    lowered = text.lower().strip()
    return lowered.startswith("bearer ") or lowered.startswith("basic ")
