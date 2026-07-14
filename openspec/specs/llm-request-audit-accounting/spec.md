# llm-request-audit-accounting Specification

## Purpose
Define complete, immutable, secret-safe lifecycle accounting for every LLM request and make reconciliation authoritative for replay, reporting, and benchmark promotion.

## Requirements

### Requirement: Run-scoped LLM request lifecycles are immutable and complete
The system SHALL persist a schema-versioned, append-only lifecycle for every LLM request group executed within an audit run, including role, prompt ref, request-group ID, provider-attempt IDs, provider/model metadata, timestamps, dispatch state, validation and policy outcomes, fallback refs, and terminal status.

#### Scenario: Request is eligible for provider dispatch
- **WHEN** a run-scoped role initiates an LLM request that passes the pre-dispatch budget gate
- **THEN** the system SHALL persist a redacted `request-started` event before dispatch and SHALL correlate every later event with the same request-group ID.

#### Scenario: Run stops between request start and terminalization
- **WHEN** a persisted request group has no valid terminal event
- **THEN** reconciliation SHALL classify it as incomplete, identify its last valid event, and SHALL NOT invent a response, usage value, or terminal outcome.

#### Scenario: Lifecycle event identifier collides
- **WHEN** a writer attempts to reuse an existing event ID or provider-attempt ID with different content
- **THEN** the system SHALL preserve the existing artifact and SHALL record or report a duplicate-integrity gap instead of silently writing a suffixed replacement as a second valid event.

### Requirement: Every physical provider attempt is observable
The system SHALL record each physical provider dispatch, including transport retries and response-format fallbacks, as a distinct provider attempt within one application request group.

#### Scenario: Provider succeeds without retry
- **WHEN** one provider dispatch returns a response
- **THEN** the request group SHALL contain one provider-attempt ID and the provider-attempt total SHALL increase by one.

#### Scenario: Provider retries before success
- **WHEN** the provider performs one or more transport retries before returning a response
- **THEN** each dispatch SHALL have a distinct attempt ID and outcome, the retry count SHALL be derivable, and the application request-group count SHALL increase only once.

#### Scenario: Compatibility client hides internal retries
- **WHEN** an injected client implements only the legacy completion interface
- **THEN** the system SHALL record one observable provider attempt, identify the compatibility accounting source, and SHALL NOT claim visibility into hidden retries.

### Requirement: Received responses are persisted before downstream checks
The system SHALL persist a redacted response artifact and provider-response event immediately after output is received and before token-budget, schema, policy, confidence, merge, or fallback decisions are applied.

#### Scenario: Response fails schema validation
- **WHEN** a provider response contains usage but fails the role schema
- **THEN** the response and usage SHALL remain persisted, a schema-invalid event SHALL reference the validation errors, and final agent output SHALL use the configured repair or deterministic fallback path.

#### Scenario: Response is denied by policy
- **WHEN** a schema-valid response fails a policy or confidence gate
- **THEN** the system SHALL preserve the response ref, append the denial reason, and correlate the resulting fallback or terminal outcome.

#### Scenario: Response exceeds the remaining token budget
- **WHEN** provider-reported usage causes the token budget to be exceeded after a response is received
- **THEN** the system SHALL persist the response and usage before recording the budget denial and SHALL NOT promote the response into final agent output.

### Requirement: Errors, timeouts, and budget denials have honest terminal records
The system SHALL distinguish provider errors, timeouts, pre-dispatch denials, post-response budget denials, and fallback outcomes without fabricating response or usage artifacts.

#### Scenario: Provider fails after dispatch
- **WHEN** a physical provider attempt ends in an error without a response
- **THEN** the attempt SHALL record a redacted error type and dispatch evidence, SHALL omit a response ref, and SHALL mark token usage unknown when provider usage is unavailable.

#### Scenario: Provider times out
- **WHEN** a provider attempt times out after dispatch
- **THEN** the attempt SHALL terminate as timeout, the dispatched-attempt count SHALL include it, and token usage SHALL be null with an attempt-specific accounting gap unless trustworthy usage exists.

#### Scenario: Budget denies before dispatch
- **WHEN** the request or token budget is exhausted before any provider call
- **THEN** the request group SHALL terminate as budget-denied with zero provider dispatches and zero additional tokens and SHALL reference the deterministic fallback when one is used.

### Requirement: Resource accounting uses defined request and token semantics
The system SHALL derive LLM resource totals from reconciled lifecycle evidence, where `llm_requests` counts request groups that dispatched at least once, provider-attempt totals count physical dispatches, and `llm_tokens` sums trustworthy provider-reported usage exactly once per correlated response.

#### Scenario: Multiple outcomes occur in one run
- **WHEN** a run contains accepted, schema-invalid, provider-failed, retried, and pre-dispatch-denied request groups
- **THEN** the summary SHALL count all dispatched request groups and provider attempts, include all terminal-status counts, and exclude the pre-dispatch denial from dispatched request and token totals.

#### Scenario: Dispatched attempt has unknown token use
- **WHEN** an attempt may have consumed tokens but no trustworthy usage is available
- **THEN** `llm_tokens` SHALL be null, an accounting gap SHALL identify the attempt and reason, and the system SHALL NOT substitute zero or a local estimate.

#### Scenario: Request count is exact but token use is unknown
- **WHEN** dispatch events are complete but one or more token usages are unknown
- **THEN** the system SHALL retain the exact request and provider-attempt counts while marking only the affected token accounting incomplete.

### Requirement: Reconciliation detects missing, duplicate, and inconsistent evidence
The system SHALL reconcile lifecycle events, prompt and response artifacts, provider errors, decision or repair records, and budget counters, and SHALL emit stable machine-readable gap IDs for every missing, duplicate, corrupt, uncorrelated, or contradictory item.

#### Scenario: Response artifact is deleted
- **WHEN** a response-received event references a response artifact that is missing
- **THEN** reconciliation SHALL report the missing ref, mark the affected accounting incomplete, and SHALL NOT accept another uncorrelated artifact as a substitute.

#### Scenario: Usage is duplicated
- **WHEN** the same provider attempt or response usage appears more than once
- **THEN** reconciliation SHALL report a duplicate gap and SHALL NOT double-count the usage.

#### Scenario: Budget counter disagrees with the ledger
- **WHEN** the run-scoped budget tracker and lifecycle-derived dispatch or token totals differ
- **THEN** the summary SHALL expose the mismatch with both observed values and SHALL mark the affected field incomplete.

### Requirement: LLM accounting artifacts are secret-safe
The system SHALL redact configured secrets before persisting request, response, error, lifecycle, message-bus, reconciliation, and resource-summary data.

#### Scenario: Secret appears in multiple provider fields
- **WHEN** a sentinel credential appears in a prompt, raw response, error diagnostic, authorization metadata, environment-derived value, or credential-bearing URL
- **THEN** no persisted lifecycle artifact, response artifact, message, report, or resource summary SHALL contain the credential or a secret-derived hash.

### Requirement: Benchmark promotion requires complete LLM accounting
The system SHALL expose one reconciliation status and exact blocking gap IDs for benchmark validation, and LLM-enabled benchmark runs SHALL be promotion-ineligible unless required LLM accounting is complete.

#### Scenario: Required benchmark run has an accounting gap
- **WHEN** a benchmark case has missing, duplicate, corrupt, inconsistent, uncorrelated, or unknown required LLM evidence
- **THEN** validation and baseline promotion SHALL fail with the exact case, field, attempt when available, and gap ID.

#### Scenario: Benchmark run has LLM disabled
- **WHEN** a benchmark run has no enabled LLM and no LLM request groups
- **THEN** zero LLM request and token totals SHALL be complete and SHALL not create a promotion blocker.

### Requirement: Legacy runs remain readable without fabricated completeness
The system SHALL read runs without the new lifecycle ledger through an explicitly identified legacy artifact-scan mode and SHALL not infer omitted failed or rejected requests.

#### Scenario: Legacy run contains valid response artifacts
- **WHEN** a historical run has response artifacts but no lifecycle ledger
- **THEN** the reader MAY report artifact-derived totals with `ledger_present` false and accounting source `legacy-artifact-scan`, but SHALL not claim full lifecycle completeness.

#### Scenario: Legacy LLM-enabled run is offered for strict promotion
- **WHEN** a run without the lifecycle ledger is evaluated by a strict benchmark promotion gate
- **THEN** promotion SHALL fail with a legacy-accounting blocker rather than treating absent evidence as zero usage.
