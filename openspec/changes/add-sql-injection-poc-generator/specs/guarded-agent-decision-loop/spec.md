## MODIFIED Requirements

### Requirement: Verification LLM proposals participate under deterministic override
The system SHALL allow Verification LLM proposals to influence accept/reject, priority, and validation level while deterministic policy gates retain final override authority. The system SHALL treat SQL injection as eligible for sandbox PoC validation only when deterministic gates confirm it is a Python dataflow-backed SQLi candidate with a safely generatable SQLi harness.

#### Scenario: Verification agrees with evidence
- **WHEN** Verification LLM output accepts a candidate that has local evidence and passes policy gates
- **THEN** the final merged decision MAY use the LLM rationale and validation-level recommendation.

#### Scenario: Verification conflicts with policy
- **WHEN** Verification LLM output accepts a candidate that lacks local evidence, exceeds validation permissions, or references unresolved citations
- **THEN** deterministic policy SHALL override the LLM proposal and reject or downgrade the decision.

#### Scenario: SQLi sandbox eligibility is deterministic
- **WHEN** Verification evaluates a SQL injection candidate for sandbox validation
- **THEN** deterministic policy SHALL allow SQLi PoC execution only for Python dataflow-backed candidates with an openable trace and supported safe SQL query shape, regardless of any LLM recommendation.

#### Scenario: Unsupported SQLi recommendation is downgraded
- **WHEN** Verification LLM output recommends sandbox confirmation for unsupported ORM, JS/TS, non-SELECT, forged-trace, or missing-trace SQLi
- **THEN** deterministic policy SHALL downgrade the candidate to `likely` or `manual-required` and record the unsupported-shape reason.
