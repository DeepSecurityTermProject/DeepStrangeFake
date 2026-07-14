## ADDED Requirements

### Requirement: Agent-led is the default compatible runtime mode
The system SHALL accept `agent-led`, `deterministic`, `adaptive`, and `legacy` modes and SHALL request `agent-led` when CLI, Web, or configuration input omits the mode.

#### Scenario: Mode is omitted
- **WHEN** a valid audit request contains no graph/runtime mode
- **THEN** requested mode SHALL be `agent-led` and the response/report SHALL expose requested and effective mode.

#### Scenario: Prior mode is explicit
- **WHEN** a caller explicitly selects deterministic, adaptive, or legacy mode
- **THEN** the runtime SHALL use that mode without requiring agent-led artifacts and SHALL preserve its established success semantics.

#### Scenario: Old persisted payload is read
- **WHEN** a stored request or result predates agent-led additive fields
- **THEN** serializers and Web APIs SHALL read it with compatible defaults rather than fail migration.

### Requirement: Agent-led budgets are hard and auditable
The runtime SHALL enforce configurable hard ceilings whose defaults are 32 hypotheses, 6 rounds per hypothesis, 8 tool calls per hypothesis, 50 promoted candidates, 200,000 model tokens, 40 model requests, USD 5 when cost is known, and 15 minutes absolute run time.

#### Scenario: Hypothesis action budget is exhausted
- **WHEN** a hypothesis reaches its round or tool-call ceiling
- **THEN** the runtime SHALL stop new actions for it, transition it to an appropriate bounded state, and persist the budget reason.

#### Scenario: Global model budget is exhausted
- **WHEN** the next request would exceed the request, token, known-cost, or absolute-time budget
- **THEN** the gateway SHALL deny dispatch, create auditable zero-dispatch accounting, stop new investigations, and finish trusted convergence from committed evidence.

#### Scenario: Remaining tokens permit only a bounded completion
- **WHEN** the conservative prompt-token estimate plus the configured completion limit would exceed the remaining token budget
- **THEN** the gateway SHALL transmit an effective `max_tokens` no greater than the remaining budget after the prompt estimate and SHALL persist the estimator, estimate, pre-request counters, configured limit, and effective limit.

#### Scenario: Provider ignores the transmitted completion limit
- **WHEN** provider-reported usage exceeds the budget despite the pre-dispatch prompt estimate and effective `max_tokens`
- **THEN** the gateway SHALL persist the response and actual usage, record a post-response provider-budget violation, fail closed, and SHALL NOT rewrite the overage to the configured ceiling.

#### Scenario: Cost is unknown
- **WHEN** the provider cannot supply a trustworthy cost
- **THEN** request, token, hypothesis, action, candidate, and time budgets SHALL still be enforced and cost SHALL be recorded as unknown rather than zero.

### Requirement: Real provider use is explicit and deterministic
Agent-led mode SHALL use the configured audited LLM gateway, a single configured model, and temperature zero; mock providers SHALL be permitted only by an explicit development or test setting.

#### Scenario: Real provider is available
- **WHEN** an ordinary agent-led audit has valid real-provider configuration
- **THEN** all Analysis and Verification calls SHALL pass through audited lifecycle, redaction, accounting, schema, policy, and budget controls.

#### Scenario: Provider capability is configured or known
- **WHEN** the configured provider or endpoint supports JSON Object but not JSON Schema structured output
- **THEN** the runtime SHALL send JSON Object directly without a knowingly unsupported JSON Schema attempt, while the local response schema remains authoritative.

#### Scenario: Unknown provider rejects JSON Schema negotiation
- **WHEN** an `auto` request to an unknown OpenAI-compatible endpoint rejects JSON Schema with HTTP 400 and JSON Object fallback succeeds
- **THEN** the runtime SHALL audit the rejected attempt, cache JSON Object capability for the same provider, endpoint, and model for the remainder of the run and checkpoint resume, and SHALL NOT infer zero usage for the rejected attempt.

#### Scenario: Mock is configured for an ordinary audit
- **WHEN** a non-development request resolves to a mock provider or no usable real provider
- **THEN** the runtime SHALL not claim agent-led execution and SHALL perform an explicit degraded deterministic fallback.

### Requirement: Failure behavior depends on committed progress
The agent-led runtime SHALL distinguish failures before any valid hypothesis from failures after committed evidence and SHALL preserve completed trusted work during convergence.

#### Scenario: Model fails before valid hypothesis
- **WHEN** the model is unavailable, malformed after repair, timed out, or denied before any valid hypothesis exists
- **THEN** the runtime SHALL execute full deterministic fallback, expose the fallback reason, and terminate `degraded` because requested and effective modes differ.

#### Scenario: Model fails after valid evidence
- **WHEN** provider failure occurs after valid hypothesis evidence is committed
- **THEN** the runtime SHALL stop new hypotheses and complete current gates, trusted verification, evidence, and reporting from committed work.

#### Scenario: Budget or time expires mid-run
- **WHEN** a hard global budget or absolute timeout is reached after progress
- **THEN** the runtime SHALL stop new investigations, finalize current trusted gates and validations where safe, preserve Judge-completed statuses, mark remaining promoted candidates `manual-required`, and terminate `degraded`.

### Requirement: Degraded is an explicit terminal state
Job lifecycle, API, report, and UI status contracts SHALL support terminal `degraded` for requested/effective mode divergence, budget exhaustion, or mid-run agent-led failure while preserving `succeeded`, `failed`, and cancellation semantics.

#### Scenario: Agent-led fallback completes
- **WHEN** deterministic fallback completes successfully for an agent-led request
- **THEN** the audit SHALL be terminal `degraded`, not `succeeded`, and SHALL expose requested mode, effective mode, and fallback reason.

#### Scenario: Explicit deterministic run completes
- **WHEN** an explicitly requested deterministic run completes without its own failure
- **THEN** it SHALL remain terminal `succeeded` and SHALL not be degraded merely because no model participated.

### Requirement: Cancellation propagates and finalizes safely
Cancellation SHALL propagate to outstanding model calls, registered tool processes, sandbox process trees, and remote acquisition cleanup, and SHALL write a final checkpoint and resource summary without launching new work.

#### Scenario: User cancels an active investigation
- **WHEN** CLI or Web cancellation is received
- **THEN** the coordinator SHALL stop dispatch, signal all active bounded operations, perform registered cleanup, persist cancellation/degradation context, and expose terminal cancellation according to the existing job contract.

### Requirement: Reports and Web expose bounded investigation observability
Run results, reports, and Web details SHALL add requested/effective mode, fallback reason, degradation reasons, hypothesis counts, evidence-gate counts, verification-plan refs, investigation-budget summary, and checkpoint summary while keeping detailed model reasoning and sensitive content out of summaries.

#### Scenario: Agent-led run is viewed
- **WHEN** a caller reads run detail or a report
- **THEN** the additive summaries SHALL be available and detailed redacted artifacts SHALL be referenced under immutable signal, investigation, evidence-gate, and verification-plan paths.

#### Scenario: Existing client reads the response
- **WHEN** a client ignores the additive fields
- **THEN** existing identifiers, findings, evidence, report, and status fields SHALL remain structurally compatible.

### Requirement: Promotion gates prove bounded scanner-independent value
The implementation SHALL include a reviewed 24-case paired blind-spot corpus and repeatable gates for discovery improvement, false confirmation, evidence completeness, safety, latency, budgets, cancellation, compatibility, and real-model stability.

#### Scenario: Paired corpus is evaluated
- **WHEN** agent-led and deterministic modes run on the 12 scanner-miss positives and 12 paired safe/fixed negatives across the four supported classes
- **THEN** agent-led candidate recall improvement SHALL be at least 0.30, negative false-confirmed count SHALL be zero, and at least one promoted hypothesis SHALL originate without a startup signal.

#### Scenario: Confirmed finding is audited
- **WHEN** a corpus finding is confirmed
- **THEN** it SHALL have exact local evidence, independent corroboration, a verification evidence package, a registered verification plan, trusted execution or static-semantic observations, and a Judge record.

#### Scenario: Latency and budgets are checked
- **WHEN** the paired corpus runs under acceptance configuration
- **THEN** each case SHALL complete within `max(60 seconds, three times its deterministic duration)` and recorded consumption SHALL stay within every configured hard ceiling.

#### Scenario: Real-model stability is checked
- **WHEN** three reviewed small public repositories at fixed commits are each run three times with the real model
- **THEN** at least one expected high/critical issue SHALL confirm, normalized high/critical confirmed findings SHALL be identical across repetitions, and evidence SHALL show no target writes, external exploit network, model-authored execution, or incomplete model/tool accounting.
