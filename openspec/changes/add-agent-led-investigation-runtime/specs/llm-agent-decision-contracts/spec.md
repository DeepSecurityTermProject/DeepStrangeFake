## MODIFIED Requirements

### Requirement: Role-specific LLM decision schemas
The system SHALL define schema-validated LLM decision contracts for Orchestrator, Recon, Analysis, and Verification; in agent-led mode Analysis SHALL produce investigation hypotheses and registered investigation actions rather than candidate findings, and Verification SHALL produce registered verification plans from normative evidence packages rather than final verdicts.

#### Scenario: Orchestrator decision schema is enforced
- **WHEN** the Orchestrator receives LLM output
- **THEN** the system SHALL validate audit scope, agent order, budgets, focus areas, confidence, rationale, and cited inputs against the Orchestrator decision schema.

#### Scenario: Analysis hypothesis schema is enforced
- **WHEN** the Analysis agent receives LLM output in agent-led mode
- **THEN** the system SHALL validate hypothesis IDs, supported vulnerability classes, scoped target refs, state, confidence, rationale, cited signals/evidence, and one registered next action without accepting a candidate finding, executable code, command, or verdict.

#### Scenario: Verification decision schema is enforced
- **WHEN** the Verification agent receives LLM output in agent-led mode
- **THEN** the system SHALL validate registered primitive IDs, typed parameters, expected observations, validation level, confidence, rationale, and normative evidence refs without accepting model-authored code, shell, container settings, or final verdicts.

#### Scenario: Prior-mode Verification schema is enforced
- **WHEN** the Verification agent receives LLM output in an explicit compatible mode that uses the prior decision contract
- **THEN** the system SHALL validate accept/reject decisions, validation level, confidence, priority, rationale, and evidence references against the versioned prior-mode Verification decision schema.

### Requirement: Repair and fallback handling
The system SHALL handle malformed, unsafe, missing, failed, or over-budget LLM decisions through configured repair and deterministic fallback while preserving a separate auditable lifecycle for every provider-backed attempt; agent-led fallback SHALL be progress-aware and SHALL not discard committed trusted evidence or verdicts.

#### Scenario: Repair attempt succeeds
- **WHEN** an LLM decision fails schema validation and repair is enabled
- **THEN** the system SHALL create a separately correlated repair request group, perform at most the configured repair calls, and use repaired output only if it passes schema and policy gates.

#### Scenario: Fallback is used before agent-led progress
- **WHEN** agent-led LLM output is absent, malformed after repair, unsafe, provider-failed, timed out, or over budget before any valid hypothesis exists
- **THEN** the system SHALL use full deterministic fallback and record requested/effective mode, fallback reason, triggering request group, last provider attempt when one exists, response or error ref, and final decision ref.

#### Scenario: Fallback is used after agent-led progress
- **WHEN** agent-led LLM output fails after a valid hypothesis or evidence checkpoint exists
- **THEN** the system SHALL stop new model-led investigations, retain committed evidence, complete trusted gates and verification where safe, and record a degraded convergence decision rather than restarting or discarding progress.

#### Scenario: Budget is denied before provider dispatch
- **WHEN** a decision request is rejected by the request, token, known-cost, or time budget before dispatch
- **THEN** the system SHALL create no response artifact, SHALL record a zero-dispatch budget-denied lifecycle, and SHALL correlate the deterministic or partial-convergence fallback with that denial.

## ADDED Requirements

### Requirement: Model decisions cannot directly create security authority
In agent-led mode, LLM decisions SHALL NOT directly create candidate findings, confirm vulnerabilities, register or invoke arbitrary tools, execute code or shell, widen repository scope, select container authority, or bypass EvidenceGate, trusted compilation, sandbox, or Judge.

#### Scenario: Analysis emits a candidate finding
- **WHEN** Analysis output contains a candidate or confirmed finding instead of a hypothesis/action contract
- **THEN** schema validation SHALL fail and no candidate SHALL be created.

#### Scenario: Verification emits a verdict
- **WHEN** Verification output attempts to set confirmed, rejected, or manual-required status
- **THEN** policy SHALL ignore or reject the attempted verdict and trusted verification/Judge SHALL remain authoritative.
