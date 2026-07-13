## ADDED Requirements

### Requirement: PoC failures are classified before repair
The system SHALL create a machine-readable failure classification before deciding whether a failed PoC attempt may invoke the LLM repair agent.

#### Scenario: Harness failure is repairable
- **WHEN** sandbox evidence shows a Python syntax, import, name, attempt-path, or fixture-construction error and no policy, infrastructure, or semantic rejection evidence exists
- **THEN** the classifier SHALL record `harness-error`, cite the supporting attempt artifacts, and mark the failure eligible for bounded repair.

#### Scenario: Missing Judge evidence is conditionally repairable
- **WHEN** the sandbox completed without an infrastructure failure, the Judge-required signal or structured artifact was not produced, and the generator repair manifest exposes a compatible editable setup slot
- **THEN** the classifier SHALL record `missing-evidence`, preserve the immutable protected evidence writer, and mark the failure repairable only within the configured budget.

#### Scenario: Missing evidence has no compatible slot
- **WHEN** Judge evidence is missing but repair would require changing protected marker, measurement, sink, or result-writer nodes
- **THEN** the classifier SHALL retain `missing-evidence` as non-repairable and validation SHALL become `manual-required` without an LLM call.

#### Scenario: Infrastructure failure is terminal
- **WHEN** Docker is unavailable, the image is missing, container startup fails, or execution times out
- **THEN** the classifier SHALL record `environment-error`, the validation SHALL become `manual-required`, and the repair agent SHALL NOT be invoked for that failure.

#### Scenario: Policy denial is terminal
- **WHEN** the PoC safety gate or sandbox runner denies execution
- **THEN** the classifier SHALL record `policy-denied`, the validation SHALL become `manual-required`, and no later attempt SHALL execute that denied script.

#### Scenario: Semantic rejection is terminal
- **WHEN** deterministic Judge evidence proves sanitizer, no-flow, path confinement, or parameter-binding behavior
- **THEN** the classifier SHALL record `semantic-rejected`, preserve `rejected`, and the system SHALL NOT ask the LLM to modify the PoC toward confirmation.

### Requirement: LLM repair is bounded and evidence-grounded
The system SHALL invoke `LLMPoCRepairAgent` only for eligible failures and SHALL limit its authority and retry count.

#### Scenario: Eligible failed PoC is repaired
- **WHEN** an initial deterministic PoC is classified as `harness-error` or eligible `missing-evidence`, LLM repair is enabled, Docker runner is selected, and repair budget remains
- **THEN** the system SHALL send the constrained repair request, validate typed edits exactly, apply them only to declared repair slots, semantic-integrity-check and safety-check the assembled script, and execute it through Docker.

#### Scenario: Repair succeeds on the second attempt
- **WHEN** the initial PoC fails because of a missing import and the LLM returns a valid allowlisted `add_import` edit
- **THEN** the second attempt SHALL run in Docker and MAY become `confirmed` or `rejected` only from the independent Judge's execution evidence.

#### Scenario: Repair budget is exhausted
- **WHEN** one repair attempt by default or the configured hard maximum of two repair attempts completes without a terminal Judge result
- **THEN** the system SHALL stop, return `manual-required`, and record the budget stop reason and all attempt refs.

#### Scenario: Repair is unavailable
- **WHEN** repair is disabled, no repair client is injected, the provider fails, or the response remains malformed
- **THEN** the system SHALL preserve the last PoC failure classification and machine evidence, return `manual-required`, and record a separate repair stop reason without assembling or executing model output.

### Requirement: LLM PoC repair is explicitly enabled and unambiguously bounded
The system SHALL keep LLM PoC repair disabled by default and SHALL define repair count separately from total PoC execution attempts.

#### Scenario: Default configuration is loaded
- **WHEN** no explicit `poc_repair` configuration is provided
- **THEN** `poc_repair.enabled` SHALL be false, no repair-provider call SHALL occur, and existing deterministic verification behavior SHALL remain unchanged.

#### Scenario: Repair count is configured
- **WHEN** `max_repair_attempts` is configured within `0..2`
- **THEN** the system SHALL allow one deterministic initial execution plus at most that many LLM repair executions.

#### Scenario: Legacy defaults are present
- **WHEN** the new `poc_repair` section is absent and legacy `llm_decisions.repair_enabled` is true while `llm_decisions.enabled` is false
- **THEN** the legacy default SHALL NOT enable LLM PoC repair.

#### Scenario: Repair count is invalid
- **WHEN** a CLI, API, or configuration value is negative, greater than two, or uses ambiguous total-attempt semantics
- **THEN** configuration validation SHALL reject it before the run begins with an actionable repair-count error.

### Requirement: Duplicate repairs stop the loop
The system SHALL hash every normalized edit list and every initial or assembled script and SHALL prevent repeated edits or script content from consuming or extending the repair loop.

#### Scenario: LLM repeats a previous script
- **WHEN** a validated repair response has the same normalized edit hash or produces the same assembled script hash as any prior attempt for the finding
- **THEN** the system SHALL NOT start the sandbox runner, SHALL stop repair as `manual-required`, and SHALL persist the duplicate hash and stop reason.

### Requirement: Judge authority remains independent
The system SHALL keep vulnerability confirmation and rejection under the deterministic `VerificationJudge`, SHALL keep Judge-facing evidence emission under generator-owned protected code, and SHALL treat LLM repair output only as candidate typed edits.

#### Scenario: Model claims confirmation
- **WHEN** model output text claims that a vulnerability is confirmed or includes verdict-like content
- **THEN** the claim SHALL have no effect on verification status and only sandbox artifacts interpreted by the Judge MAY produce `confirmed` or PoC-backed `rejected`.

#### Scenario: Model attempts self-fulfilling evidence
- **WHEN** model edits attempt to print an expected confirmation marker, write a Judge result artifact, or hard-code confirming semantic values
- **THEN** semantic-integrity policy SHALL deny the assembled script before Docker and the Judge SHALL receive no evidence from that attempt.

#### Scenario: Zero exit lacks SQLi evidence
- **WHEN** a repaired SQLi script exits with code 0 but does not produce a valid `sqli-result.json`
- **THEN** the Judge SHALL NOT return `confirmed`, and the status SHALL remain repairable `missing-evidence` only when a compatible non-protected setup slot remains or become `manual-required` when no safe repair path or budget remains.

#### Scenario: Parameterized SQL is rejected without further repair
- **WHEN** a repaired or initial SQLi attempt produces valid semantic evidence that parameter binding treated the payload as data
- **THEN** the Judge SHALL return `rejected` and the repair loop SHALL stop immediately.

#### Scenario: Judge returns confirmation before target integrity is checked
- **WHEN** the deterministic Judge produces a confirming outcome during the validation phase
- **THEN** the outcome SHALL remain provisional until the run-level after-manifest matches the before-manifest, after which it MAY be finalized as `confirmed`.

### Requirement: Unsupported first-generation shapes remain out of scope
The system SHALL use LLM repair only after a supported deterministic PoC generator has produced an initial executable artifact.

#### Scenario: Deterministic generator cannot create a PoC
- **WHEN** a finding uses an unsupported language, ORM, sink shape, or vulnerability class and no deterministic generator can create the initial PoC
- **THEN** the system SHALL retain `likely` or `manual-required` with the generator reason and SHALL NOT invoke the LLM to invent the first PoC.
