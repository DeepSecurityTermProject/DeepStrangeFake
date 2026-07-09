## ADDED Requirements

### Requirement: Verification distinguishes triage from confirmation
The system SHALL keep Verification triage decisions separate from runtime verification status so static acceptance cannot be reported as confirmed proof.

#### Scenario: Verification accepts a candidate for validation
- **WHEN** Verification accepts a candidate because local evidence and policy gates are sufficient for further review
- **THEN** the decision SHALL record validation eligibility but SHALL NOT assign `confirmed` until PoC execution and Judge evidence support it.

#### Scenario: Verification uses static-only validation
- **WHEN** Verification selects or falls back to `static-only` validation
- **THEN** the final verification status SHALL be `likely` or `rejected`, not `confirmed`, and the decision SHALL record the reason no PoC execution evidence exists.

#### Scenario: LLM recommends confirmation
- **WHEN** Verification LLM output proposes that a candidate is confirmed but PoC execution evidence is absent
- **THEN** deterministic policy SHALL override the proposal, prevent `confirmed`, and record a policy-gate reason.

### Requirement: Verification prioritizes dataflow-backed PoC candidates
The system SHALL prioritize dataflow-backed candidates for supported PoC validation before pattern-only or intelligence-only candidates.

#### Scenario: Supported dataflow candidate exists
- **WHEN** a path traversal candidate includes source-to-sink dataflow evidence and local source refs
- **THEN** Verification SHALL route it to PoC generation and sandbox execution before assigning a final verification status.

#### Scenario: Candidate lacks executable evidence
- **WHEN** a candidate is pattern-only, intelligence-only, or lacks enough local context for a supported PoC
- **THEN** Verification SHALL assign `likely`, `rejected`, or `manual-required` with a machine-verifiable reason instead of pretending to execute validation.
