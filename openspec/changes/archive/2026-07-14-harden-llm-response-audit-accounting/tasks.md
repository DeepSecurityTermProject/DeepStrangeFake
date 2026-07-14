## 1. Lock Current Failures and Accounting Semantics

- [x] 1.1 Add a failing runtime characterization test where a provider returns schema-invalid output with nonzero usage, and assert that the current missing response ref and undercount are reproduced before implementation.
- [x] 1.2 Add table-driven expected-accounting fixtures for accepted, schema-invalid, policy-denied, provider-error, timeout, retry, pre-dispatch budget denial, and post-response token-budget denial paths.
- [x] 1.3 Define and test the invariant that `llm_requests` counts dispatched application request groups, provider-attempt totals count physical dispatches, retries do not create extra request groups, and unknown dispatched usage is never zero-filled.
- [x] 1.4 Add reusable sentinel-secret and artifact-tree assertion helpers that inspect LLM artifacts, lifecycle events, messages, reports, replay output, and resource summaries.

## 2. Add Lifecycle Models and Immutable Storage

- [x] 2.1 Add schema-versioned request-group, provider-attempt, lifecycle-event, terminal-status, accounting-source, and reconciliation-gap models with strict enum and required-field validation.
- [x] 2.2 Implement stable request-group/provider-attempt/event correlation IDs that distinguish repeated invocations and retries while remaining deterministic under replay.
- [x] 2.3 Implement the `llm_attempts/<request_group_id>/` immutable event writer with redaction before persistence and explicit collision detection instead of silent suffixing.
- [x] 2.4 Implement a lifecycle reader and transition validator that rejects duplicate IDs, illegal ordering, missing refs, malformed payloads, and contradictory terminal outcomes.
- [x] 2.5 Add unit tests proving valid lifecycle round trips and proving duplicate, corrupt, partially written, and missing-terminal lifecycles produce stable gap IDs without mutation or repair.

## 3. Introduce the Run-Scoped Audited LLM Boundary

- [x] 3.1 Implement a run-scoped LLM invocation gateway that persists `request-started`, applies pre-dispatch budgets, tracks one request group across provider attempts, and returns a receipt for downstream schema/policy reporting.
- [x] 3.2 Make the gateway persist the normal redacted LLM response artifact and response-received event before post-response token-budget enforcement or any caller validation.
- [x] 3.3 Add gateway APIs for schema-valid/schema-invalid, policy-accepted/policy-denied, fallback-used, and terminal outcomes, with idempotent terminalization and explicit incomplete detection.
- [x] 3.4 Replace or refactor `BudgetedLLMClient` so request usage is charged at dispatch, response tokens are charged only from trustworthy received usage, and over-budget responses remain persisted before denial.
- [x] 3.5 Add a compatibility adapter for mock and injected legacy clients that records one observable provider attempt and labels hidden-retry visibility as unavailable.
- [x] 3.6 Add focused tests for pre-dispatch denial, post-response denial, provider exception, timeout, terminalization after fallback, and crash-like interruption after each lifecycle transition.

## 4. Observe Physical Provider Attempts and Retries

- [x] 4.1 Add a secret-safe provider-attempt observer contract around every OpenAI-compatible HTTP dispatch without exposing headers, API keys, credential-bearing URLs, proxy credentials, or raw environment mappings.
- [x] 4.2 Instrument transport retries and response-format fallback so every physical dispatch receives a distinct provider-attempt ID and outcome inside the original request group.
- [x] 4.3 Preserve response usage and safe provider diagnostics for successful and failed attempts, and mark token use unknown when a dispatched attempt has no trustworthy usage.
- [x] 4.4 Add fake-transport tests for success after retry, exhausted retries, JSON-schema to JSON-object fallback, authentication failure, rate limit, network error, and timeout with exact request-group/provider-attempt assertions.

## 5. Migrate Every Audit-Run LLM Call Site

- [x] 5.1 Route standard Orchestrator, Recon, Analysis, and Verification LLM role calls through the gateway and persist schema-invalid responses before existing deterministic fallback behavior.
- [x] 5.2 Route adaptive-graph checkpoint decisions through the gateway and correlate graph fallback, proposal, policy, revision, and final node-path refs with the triggering request group and provider attempt.
- [x] 5.3 Route PoC repair LLM calls through the gateway while preserving typed-edit safety gates, separate repair request groups, normalized repair records, and the prohibition on target-project writes.
- [x] 5.4 Remove or isolate direct audit-run provider calls and update dependency construction so all runtime modes share one ledger and budget tracker; add a test that fails if a known audit call path bypasses the gateway.
- [x] 5.5 Keep standalone integration preflight under a separate run identity, document whether it reuses the recorder, and prove its usage cannot be mixed into a project audit's resource summary.

## 6. Correlate Decisions, Messages, and Replay

- [x] 6.1 Extend LLM decision and repair records with request-group, provider-attempt, response/error, schema, policy, fallback, and terminal refs while retaining backward-compatible readers.
- [x] 6.2 Publish redacted lifecycle message-bus events for request start, dispatch, response/error, schema, policy, fallback, budget denial, and terminalization with stable correlation fields.
- [x] 6.3 Extend side-effect-free replay to reconstruct request groups, physical attempts, retries, validation/policy outcomes, fallback, and terminal state from artifacts without invoking LLM, MCP, tools, Docker, or target operations.
- [x] 6.4 Add replay tests for accepted, schema-invalid fallback, retried success, provider timeout, pre-dispatch denial, missing event, and duplicate event paths, asserting exact normalized replay output and gap IDs.

## 7. Reconcile Resource Summaries and Legacy Runs

- [x] 7.1 Implement lifecycle-led LLM reconciliation that cross-checks events, response/error artifacts, decision/repair refs, and budget counters and returns independent completeness for request counts, provider-attempt counts, and token totals.
- [x] 7.2 Extend `run-resource-summary.v1` and runtime metadata additively with ledger presence, accounting source, total request groups, dispatched groups, provider attempts, retries, pre-dispatch denials, terminal-status counts, reconciliation status, gap IDs, and contributing refs.
- [x] 7.3 Replace response-file-count accounting for new runs, while retaining an explicit `legacy-artifact-scan` reader that never claims full lifecycle completeness or fabricates omitted usage.
- [x] 7.4 Add deterministic tests proving schema-invalid responses are counted, retries are not double-counted as request groups, duplicate usage is not summed twice, exact request counts survive unknown token use, and LLM-disabled runs report complete zeros.
- [x] 7.5 Add legacy-run tests for valid old response artifacts, missing artifacts, unknown historical LLM enablement, and strict-promotion rejection without modifying the legacy run directory.

## 8. Enforce Benchmark Accounting Gates

- [x] 8.1 Update benchmark case validation and baseline promotion to consume resource-summary reconciliation status and exact blocking IDs rather than independently counting `run/llm` files.
- [x] 8.2 Add end-to-end benchmark tests where deleting a response, deleting a lifecycle event, duplicating usage, corrupting an event, or changing a budget counter makes the exact case/field/attempt ineligible for promotion.
- [x] 8.3 Add positive benchmark tests showing a fully reconciled LLM-enabled case and a genuinely LLM-disabled zero-use case remain eligible when all other gates pass.
- [x] 8.4 Verify benchmark JSON and Markdown expose accounting source, reconciliation status, null unknowns, and blocking reasons consistently without presenting an incomplete run as a baseline.

## 9. Verify Redaction and Backward Compatibility

- [x] 9.1 Seed sentinel secrets into prompts, raw responses, provider errors, authorization metadata, environment-derived settings, and credential-bearing URLs and assert no artifact, event, message, report, or replay output leaks values or secret-derived hashes.
- [x] 9.2 Add schema/backward-compatibility tests proving existing report and Web consumers can read additive resource-summary fields and older decision/run artifacts remain viewable with explicit legacy limitations.
- [x] 9.3 Update operator and developer documentation with lifecycle terminology, artifact layout, request/token semantics, gap IDs, legacy behavior, and benchmark promotion consequences.

## 10. End-to-End Acceptance

- [x] 10.1 Run focused offline tests for lifecycle storage, audited invocation, provider retries, decision fallback, graph checkpoints, PoC repair, replay, resource summaries, benchmark gates, and redaction; retain the exact command and passing result.
- [x] 10.2 Run the full default test suite without model credentials and confirm live tests skip while no deterministic test reaches a network provider.
- [x] 10.3 Run an offline end-to-end fake-provider audit containing at least one accepted response and one schema-invalid fallback; assert exact request groups, provider attempts, tokens, response refs, replay path, and complete reconciliation.
- [x] 10.4 Run an offline tamper acceptance by deleting or duplicating one authoritative artifact from the prior run and prove resource reconciliation and benchmark promotion fail with the expected stable blocker.
- [x] 10.5 Run one opt-in bounded real-provider smoke using configured credentials, assert a received schema-invalid response is still persisted and counted when encountered, scan all artifacts for credential leakage, and record a skip reason rather than claiming success when the provider is unavailable.
- [x] 10.6 Run `openspec validate harden-llm-response-audit-accounting --type change --strict --no-interactive`, run repository diff/format checks, and record the final test evidence before marking the change complete.
