## ADDED Requirements

### Requirement: PoC repair authority is policy-gated
The system SHALL apply deterministic policy gates before an LLM PoC repair request, after its structured response, and before sandbox execution.

#### Scenario: Repairable failure passes the pre-call gate
- **WHEN** failure classification is `harness-error` or eligible `missing-evidence`, Docker repair is explicitly enabled, the original PoC is trace-backed, a compatible generator repair slot exists, and budget remains
- **THEN** policy SHALL permit one bounded typed-edit repair request with the allowed context fields.

#### Scenario: Terminal failure reaches the pre-call gate
- **WHEN** classification is `policy-denied`, `environment-error`, or `semantic-rejected`
- **THEN** policy SHALL deny the repair call and preserve the terminal status and reason.

#### Scenario: Unsafe response reaches the execution gate
- **WHEN** a repair response fails exact contract, repair-manifest, immutable-envelope, semantic-integrity, duplicate-hash, or AST safety checks
- **THEN** policy SHALL deny sandbox execution, record the exact gate result, and SHALL NOT allow the LLM to revise the policy decision in the same attempt.

#### Scenario: Provider fails after an eligible classification
- **WHEN** the repair provider fails, times out, or exceeds budget after the prior PoC was classified as repairable
- **THEN** policy SHALL retain the prior PoC failure class, record a separate repair stop reason, return `manual-required`, and SHALL NOT classify the provider failure as a PoC environment error.

### Requirement: Repair cannot promote verification status directly
The system SHALL treat LLM repair as a candidate typed-edit decision and SHALL keep Judge-facing evidence emission, sandbox execution, and final verification status under trusted deterministic policy.

#### Scenario: Safe repair is produced
- **WHEN** a repair passes all gates
- **THEN** the decision source SHALL record LLM repair influence, but `confirmed` or `rejected` SHALL be assigned only after trusted assembly, semantic-integrity validation, sandbox execution, Judge evaluation, and final target-integrity validation.

#### Scenario: Repair explanation conflicts with evidence
- **WHEN** the LLM diagnosis or change description claims success while sandbox or structured semantic evidence does not satisfy the Judge
- **THEN** deterministic evidence SHALL override the explanation and the final result SHALL remain `manual-required` or `rejected`.

### Requirement: Repair state transitions are monotonic
The system MUST NOT retry terminal semantic, policy, infrastructure, integrity, or budget outcomes in an effort to obtain confirmation.

#### Scenario: Candidate is rejected
- **WHEN** any attempt receives a deterministic `rejected` Judge outcome
- **THEN** the repair state machine SHALL terminate and no later repair request or sandbox execution SHALL occur for that finding.

#### Scenario: Docker or integrity fails after a repair
- **WHEN** Docker fails, policy denies the script, or target integrity changes
- **THEN** the state machine SHALL terminate as `manual-required`, SHALL retain all prior attempts, and SHALL NOT retry toward confirmation.

#### Scenario: Target changes after provisional confirmation
- **WHEN** the Judge has produced a provisional confirmation and the run-level after-manifest differs from the before-manifest
- **THEN** policy SHALL downgrade that confirmation to `manual-required`, link the integrity diff, and SHALL NOT publish a final confirmed result.
