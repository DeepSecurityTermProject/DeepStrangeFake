# llm-agent-decision-contracts Specification

## Purpose
TBD - created by archiving change enable-llm-agent-decision-loop. Update Purpose after archive.
## Requirements
### Requirement: Role-specific LLM decision schemas
The system SHALL define schema-validated LLM decision contracts for Orchestrator, Recon, Analysis, and Verification.

#### Scenario: Orchestrator decision schema is enforced
- **WHEN** the Orchestrator receives LLM output
- **THEN** the system SHALL validate audit scope, agent order, budgets, focus areas, confidence, rationale, and cited inputs against the Orchestrator decision schema.

#### Scenario: Verification decision schema is enforced
- **WHEN** the Verification agent receives LLM output
- **THEN** the system SHALL validate accept/reject decisions, validation level, confidence, priority, rationale, and evidence references against the Verification decision schema.

### Requirement: LLM decision records are explicit
The system SHALL persist LLM proposals as decision records separate from final agent outputs and SHALL correlate each proposal with its request group, provider attempt, prompt, pre-validation response artifact, schema result, and policy result.

#### Scenario: Decision record captures provenance
- **WHEN** an agent uses an LLM proposal
- **THEN** the decision record SHALL include role, request-group ID, provider-attempt ID, prompt reference, LLM response reference, model/provider metadata, parsed JSON, confidence, rationale, requested tools, evidence refs, schema status, and policy status.

#### Scenario: Malformed output is recorded
- **WHEN** received LLM output fails schema validation
- **THEN** the redacted response SHALL already be persisted, the decision record SHALL capture its response ref and validation errors, usage SHALL remain accountable, and the proposal SHALL NOT be promoted directly into final agent output.

#### Scenario: Valid output is denied by policy
- **WHEN** schema-valid LLM output fails a policy or confidence gate
- **THEN** the decision record SHALL retain the response and policy refs, record the denial reason, and identify the final fallback or merged decision source.

### Requirement: Repair and fallback handling
The system SHALL handle malformed, unsafe, missing, failed, or over-budget LLM decisions through configured repair and deterministic fallback while preserving a separate auditable lifecycle for every provider-backed attempt.

#### Scenario: Repair attempt succeeds
- **WHEN** an LLM decision fails schema validation and repair is enabled
- **THEN** the system SHALL create a separately correlated repair request group, perform at most the configured repair calls, and use repaired output only if it passes schema and policy gates.

#### Scenario: Fallback is used
- **WHEN** LLM output is absent, malformed after repair, unsafe, provider-failed, timed out, or over budget
- **THEN** the system SHALL use deterministic fallback and record the fallback reason, triggering request group, last provider attempt when one exists, response or error ref, and final decision ref.

#### Scenario: Budget is denied before provider dispatch
- **WHEN** a decision request is rejected by the request or token budget before dispatch
- **THEN** the system SHALL create no response artifact, SHALL record a zero-dispatch budget-denied lifecycle, and SHALL correlate the deterministic fallback with that denial.

### Requirement: Decision confidence is bounded
The system SHALL require role-specific confidence and completeness thresholds before an LLM proposal can influence final decisions.

#### Scenario: Low-confidence proposal is downgraded
- **WHEN** a model proposal has confidence below the configured role threshold
- **THEN** the system SHALL record the proposal but SHALL use deterministic or merged fallback behavior for the final decision.
