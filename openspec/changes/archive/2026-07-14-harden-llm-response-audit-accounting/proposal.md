## Why

A bounded live adaptive-graph run showed that a provider response can consume requests and tokens, fail schema validation, and fall back before the response artifact is persisted. Because `run-resource-summary.v1` currently derives LLM usage from persisted success artifacts, benchmark cost and budget accounting can undercount real provider activity and incorrectly appear promotion-ready.

## What Changes

- Add an immutable, redacted LLM request-attempt ledger covering request start, provider response, schema result, policy outcome, fallback, and terminal status.
- Persist every received provider response before schema or policy rejection, including schema-invalid output, while keeping secrets and credential-bearing metadata redacted.
- Record provider errors, timeouts, retries, and pre-request budget denials without inventing response or token usage.
- Reconcile request and token totals from authoritative ledger/client usage with response artifacts, runtime errors, and configured budgets.
- Make missing, duplicate, inconsistent, or uncorrelated LLM accounting machine-readable and block benchmark baseline promotion when required accounting is incomplete.
- Preserve deterministic fallback and backward compatibility for older runs that do not contain the new ledger, reporting explicit accounting gaps instead of fabricated zero values.

## Capabilities

### New Capabilities
- `llm-request-audit-accounting`: Defines the immutable LLM request lifecycle ledger, response/error correlation, authoritative usage reconciliation, redaction, and benchmark accounting gates.

### Modified Capabilities
- `llm-agent-decision-contracts`: Requires schema-invalid and policy-rejected model output to retain a redacted response reference, validation status, and deterministic fallback correlation.
- `decision-auditability-and-replay`: Requires replayable LLM request lifecycle artifacts and complete resource-summary accounting across successful, invalid, denied, failed, and budget-limited paths.

## Impact

- Affects `audit_agent/llm.py`, `audit_agent/runtime.py`, LLM artifact persistence, message-bus events, `audit_agent/resource_summary.py`, benchmark validation/promotion, reports, and replay-facing run metadata.
- Adds schema-versioned ledger artifacts and additive resource-summary fields; existing report and Web consumers remain readable.
- Adds offline fake-provider tests for success, schema-invalid, provider-error, retry, timeout, budget-denied, duplicate, missing-artifact, and legacy-run cases, plus one opt-in bounded real-provider smoke.
- Does not add new providers, Agent roles, tools, target access, Docker behavior, or parallel execution.
