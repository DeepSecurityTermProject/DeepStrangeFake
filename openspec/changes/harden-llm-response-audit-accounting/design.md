## Context

The runtime currently persists an LLM artifact only after the provider call and role-specific schema validation have both succeeded far enough for the caller to reach `write_llm`. This leaves several real-cost paths unaudited: schema-invalid responses in non-decision roles, post-response token-budget rejection, provider retries hidden inside the OpenAI-compatible client, and provider failures that have no response artifact. `run-resource-summary.v1` then derives request and token totals by scanning `run/llm/*.json`, so omitted artifacts also disappear from accounting.

This change affects the provider boundary, budget enforcement, role-level validation and fallback, message-bus events, resource-summary generation, replay, and benchmark promotion. It must preserve deterministic fallback, offline tests, current provider compatibility, and the existing no-secret artifact policy. It must also coexist with legacy run directories and the active benchmark pipeline without fabricating historical usage.

The following terms are used consistently:

- A **request group** is one application-level invocation of an LLM role, including a repair invocation.
- A **provider attempt** is one physical dispatch to a provider. Retries and response-format fallbacks are separate provider attempts in the same request group.
- A **pre-dispatch denial** is a request group rejected by budget or policy before any provider attempt.
- A **received response** is provider output available to the process, whether or not later schema, policy, confidence, or budget checks accept it.

## Goals / Non-Goals

**Goals:**

- Persist a redacted, append-only lifecycle for every run-scoped LLM request group and provider attempt.
- Persist received responses before schema, policy, confidence, merge, or post-response budget checks.
- Count dispatched request groups, physical provider attempts, retries, and provider-reported token usage with explicit unknown states.
- Reconcile lifecycle records, response/error artifacts, client budget counters, and `run-resource-summary.v1` without silently accepting omissions or duplicates.
- Make incomplete accounting and integrity failures machine-readable, replayable, and blocking for benchmark promotion.
- Cover decision roles, adaptive-graph checkpoints, and LLM PoC repair through one run-scoped accounting boundary.

**Non-Goals:**

- Adding providers, changing prompts, improving model output quality, or changing role decision schemas.
- Treating provider-estimated or locally tokenized values as provider-reported billing truth.
- Reconstructing exact usage for historical runs that never persisted it.
- Adding parallel LLM execution or a distributed event store.
- Changing target access, Docker execution, PoC safety policy, MCP behavior, or repository write policy.
- Making the standalone integration preflight artifact part of a project audit's resource summary; it may reuse the recorder but remains a separate run identity.

## Decisions

### 1. Use immutable per-event lifecycle artifacts

Each audit run will store schema-versioned events beneath `llm_attempts/<request_group_id>/`. A request-group event is written before the first possible dispatch, and each provider attempt has a stable `provider_attempt_id`. Event filenames contain a monotonic sequence and event ID; an existing path is an integrity error, not a reason to silently create a suffixed duplicate.

Required event kinds are `request-started`, `provider-dispatch-started`, `provider-response-received`, `provider-attempt-failed`, `schema-valid`, `schema-invalid`, `policy-accepted`, `policy-denied`, `fallback-used`, `budget-denied`, and `request-terminal`. Events carry only the fields applicable to that transition. The terminal event records one of `accepted`, `fallback`, `provider-error`, `timeout`, `budget-denied`, or `incomplete` plus refs to prior events.

This is preferred over one mutable summary file because a crash between provider return and final role handling must leave recoverable evidence. It is preferred over one JSONL file because immutable files provide clearer corruption, duplicate, and partial-write detection on the current local Windows runtime. A derived request summary may be cached, but lifecycle events remain authoritative.

### 2. Put accounting at the run-scoped LLM invocation boundary

A run-scoped invocation gateway will own request-group creation, budget prechecks, provider dispatch observation, immediate response persistence, and terminalization. Decision roles, graph checkpoints, and PoC repair must use this gateway rather than calling a provider client directly. Callers retain role-specific schema and policy logic but report those outcomes through the gateway receipt.

The OpenAI-compatible transport will expose provider-attempt callbacks around every HTTP dispatch, including retries and response-format fallback. A compatibility adapter records one provider attempt for mock or injected clients that expose only `complete()`. This is preferred over adding persistence independently at each call site because call-site patches previously allowed malformed and exceptional paths to escape accounting.

### 3. Persist the response before downstream rejection

When a provider response is received, the gateway first writes the redacted normal LLM response artifact and `provider-response-received` event. Only then may token-budget enforcement, schema validation, policy checks, confidence checks, repair selection, or fallback occur. The caller receives a receipt containing request-group, provider-attempt, prompt, and response refs.

Schema-invalid and policy-denied output remains evidence, never final agent output. Validation errors and policy reasons are appended as lifecycle events and included in the separate decision or repair record. This ordering also covers a response that pushes the run beyond its token budget: usage and the response are recorded before deterministic fallback or termination.

### 4. Define exact request and token semantics

The existing `llm_requests` field remains the number of request groups that crossed the provider-dispatch boundary at least once. New additive fields record total request groups, provider attempts, retries, pre-dispatch denials, terminal-status counts, and accounting source. A retry increments provider attempts but not request groups.

`llm_tokens` is the sum of provider-reported usage from received responses, counted once per correlated provider attempt. If a dispatched attempt may have consumed tokens but the provider supplied no trustworthy usage, `llm_tokens` is null and an accounting gap identifies the attempt. The system must not substitute zero or a local estimate. A pre-dispatch denial contributes zero dispatched requests and zero tokens and does not create an unknown-usage gap.

Budget request consumption occurs at dispatch and therefore includes failed or timed-out dispatches. Token consumption is charged when trustworthy response usage is received. Provider retries remain bounded by provider retry configuration and are visible separately from the application request budget.

### 5. Reconcile independent evidence and fail closed on disagreement

Resource-summary generation will replay the lifecycle ledger and cross-check it against response/error artifacts, prompt and decision refs, provider attempt observations, and the run-scoped budget tracker. Reconciliation emits stable gap IDs for missing terminal events, missing or duplicate responses, duplicate attempt IDs, invalid transitions, uncorrelated refs, usage mismatch, budget-counter mismatch, and dispatched attempts with unknown usage.

An LLM request count may remain numeric when it is independently exact while token usage is null. A field is marked complete only when all evidence needed for that field agrees. File presence alone is never proof of completeness.

### 6. Make replay and benchmark gates consume the same reconciliation result

Replay will reconstruct request groups, provider attempts, validation and policy outcomes, fallback, and terminal state from lifecycle artifacts without invoking a model. `run-resource-summary.v1` will include the reconciliation status, ledger refs, additive counts, and accounting gaps. Benchmark validation and baseline promotion use this status rather than rescanning `run/llm` independently.

Any required run with missing, duplicate, corrupt, inconsistent, or unknown LLM accounting is ineligible for promotion and reports exact blocking IDs. Runs with no enabled LLM and no request groups remain complete with zero usage.

### 7. Apply redaction before persistence and correlation

Every request, response, error, event, and diagnostic passes through the existing secret redactor plus configured secret values before writing. Ledger records may include provider and model names, usage, status codes, hashes of non-secret artifact content, and safe refs. They must not include API keys, authorization headers, credential-bearing URLs, proxy credentials, raw environment mappings, or hashes derived directly from secrets.

Tests will seed sentinel secrets in prompts, provider errors, raw responses, environment-derived configuration, and URLs, then scan all new artifacts and message logs for leakage.

### 8. Treat legacy runs explicitly

If a run has no lifecycle ledger, resource-summary readers may use the existing response-artifact scan only as `legacy-artifact-scan`. Such a result must expose `ledger_present = false` and cannot claim that rejected, failed, or omitted requests are known. Existing summaries remain readable, but strict benchmark promotion requires the new ledger for LLM-enabled runs.

No migration will synthesize request events or token totals for historical runs. This is preferred over backfilling because the missing schema-invalid and failed responses cannot be inferred reliably.

## Risks / Trade-offs

- [More artifacts per LLM call] -> Keep events compact, schema-versioned, and referenced from a derived summary; bound real smoke request counts.
- [A crash can leave a started request without a terminal event] -> Preserve it as an `incomplete` reconciliation result instead of deleting or repairing history.
- [Provider retries may not expose usage for failed attempts] -> Count dispatches exactly, set affected token totals to unknown, and emit attempt-specific gaps.
- [Injected third-party test clients cannot expose internal retries] -> Record one observable provider attempt and identify the adapter source; exact retry claims require the attempt-observer contract.
- [Changing budget accounting can alter when retries stop] -> Preserve application request-group budgets, expose physical attempt counts separately, and add boundary tests before replacing the current wrapper.
- [Raw model output can contain sensitive target text] -> Reuse configured artifact redaction and keep current run-directory access assumptions; this change does not create a remote telemetry sink.
- [Two active OpenSpec changes touch resource summaries and promotion] -> Keep fields additive, use the existing `run-resource-summary.v1` contract, and add integration tests that exercise benchmark ingestion rather than duplicating benchmark logic.

## Migration Plan

1. Add lifecycle models, immutable persistence, redaction, and deterministic reconciliation behind the run-scoped gateway.
2. Instrument mock and OpenAI-compatible provider attempts and refactor budget tracking so response persistence precedes post-response denial.
3. Move decision roles, adaptive-graph checkpoints, and PoC repair onto the gateway; retain adapters for existing injected clients.
4. Extend resource-summary and replay models with additive ledger fields and legacy-reader behavior.
5. Make benchmark validation and promotion consume reconciliation status and blocking IDs.
6. Enable the new path by default after offline success, failure, corruption, and legacy tests pass; run one bounded opt-in real-provider smoke.

Rollback may restore the previous invocation path and summary reader because old consumers ignore additive fields. New lifecycle artifacts are retained as inert evidence and are not deleted. Runs produced after rollback are marked legacy/incomplete for strict promotion rather than being misrepresented as fully accounted.

## Open Questions

- Whether a future provider adapter can expose provider billing IDs for external invoice reconciliation; this is not required for this change.
- Whether lifecycle artifacts should later move to a compact database for large parallel runs; the current local sequential runtime does not require it.
