from __future__ import annotations

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
        text = value
        if _looks_like_authorization(text):
            return REDACTION_MARKER
        for secret in secrets:
            text = text.replace(secret, REDACTION_MARKER)
        return text
    return value


def _is_secret_key(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    return any(fragment in lowered for fragment in SECRET_KEY_FRAGMENTS)


def _looks_like_authorization(text: str) -> bool:
    lowered = text.lower().strip()
    return lowered.startswith("bearer ") or lowered.startswith("basic ")
