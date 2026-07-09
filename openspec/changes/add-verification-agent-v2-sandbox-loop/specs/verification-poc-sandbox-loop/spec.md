## ADDED Requirements

### Requirement: Verification statuses are evidence-bound
The system SHALL assign every verification candidate one final status from `confirmed`, `likely`, `rejected`, or `manual-required`, and each status MUST include machine-verifiable evidence references.

#### Scenario: Static-only evidence is reviewed
- **WHEN** a candidate is accepted only from static source evidence, LLM rationale, CVE intelligence, memory context, or policy triage
- **THEN** the system SHALL assign at most `likely`, SHALL NOT assign `confirmed`, and SHALL NOT increment `confirmed_count`.

#### Scenario: Candidate is confirmed
- **WHEN** the system assigns `confirmed`
- **THEN** the candidate SHALL reference a real `PoCArtifact`, `SandboxRunResult`, and `VerificationAttempt`, and SHALL include stdout/stderr summaries, exit code, and Judge reason derived from sandbox execution evidence.

#### Scenario: Candidate is likely
- **WHEN** static or dataflow evidence is strong but a supported PoC cannot be safely executed
- **THEN** the candidate SHALL be marked `likely` with local evidence refs, dataflow refs when available, and a reason explaining why runtime confirmation was not produced.

#### Scenario: Candidate is rejected
- **WHEN** sanitizer evidence, no-flow evidence, policy evidence, or PoC execution contradicts the vulnerability claim
- **THEN** the candidate SHALL be marked `rejected` with the specific rejection reason and supporting evidence refs.

#### Scenario: Candidate requires manual validation
- **WHEN** sandbox execution is blocked by missing dependencies, timeout, unsupported vulnerability class, unsupported target shape, sandbox policy denial, or unsafe live-target requirements
- **THEN** the candidate SHALL be marked `manual-required` with the blocking reason and supporting evidence refs.

### Requirement: PoC artifacts are executable and traceable
The system SHALL model proof-of-concept scripts as first-class `PoCArtifact` records that are executable, tied to a finding, and stored under the run directory.

#### Scenario: PoC artifact is generated
- **WHEN** Verification generates a PoC for a candidate
- **THEN** the artifact SHALL include finding ID, vulnerability class, generator ID, script path, command argv, expected signal, safety profile, source/dataflow refs, and creation timestamp.

#### Scenario: PoC file is referenced
- **WHEN** a report, evidence chain, or runtime state references a PoC artifact
- **THEN** the referenced script file and artifact metadata file SHALL exist under the run directory and SHALL be openable by path.

#### Scenario: PoC cannot be generated
- **WHEN** the system lacks enough local context to generate a safe executable PoC
- **THEN** it SHALL record a `manual-required` or `likely` status with a blocking reason instead of writing a placeholder PoC artifact.

### Requirement: Local sandbox runner executes PoC artifacts
The system SHALL replace configured-command sandbox validation with a `LocalSandboxRunner` that executes a supplied `PoCArtifact` using an isolated attempt directory and fixed argv execution.

#### Scenario: PoC is executed
- **WHEN** the runner executes a PoC artifact
- **THEN** it SHALL run the PoC command as argv with `shell=False`, use an independent attempt directory, enforce a timeout, capture stdout and stderr to files, record cwd, argv, timeout, environment summary, exit code, duration, and generated artifact refs.

#### Scenario: Command is denied
- **WHEN** the PoC command executable or argument shape is outside the configured allowlist
- **THEN** the runner SHALL deny execution, create a `SandboxRunResult` with policy-denied status, and the candidate SHALL become `manual-required` with the policy reason unless other evidence rejects it.

#### Scenario: Attempt writes artifacts
- **WHEN** PoC execution creates files
- **THEN** the runner SHALL record only artifacts inside the attempt directory and SHALL reject or ignore paths that escape the attempt directory boundary.

#### Scenario: Execution times out
- **WHEN** PoC execution exceeds the configured timeout
- **THEN** the runner SHALL terminate the process, record timeout status, preserve available stdout/stderr, and mark the attempt as `manual-required` or eligible for bounded repair.

### Requirement: Path traversal dataflow findings have an MVP closed loop
The system SHALL support one real executable MVP closed loop for path traversal findings backed by dataflow evidence.

#### Scenario: Path traversal finding is dataflow-backed
- **WHEN** a candidate has dataflow evidence showing user-controlled path input reaching a file path sink without a sanitizer
- **THEN** Verification SHALL prioritize it for PoC generation and local sandbox execution.

#### Scenario: Path traversal PoC confirms vulnerability
- **WHEN** the generated path traversal PoC executes and the Judge observes the expected traversal signal from sandbox artifacts or stdout/stderr
- **THEN** the candidate SHALL be marked `confirmed` with PoC, sandbox result, attempt, exit code, stdout/stderr summaries, and Judge reason.

#### Scenario: Path traversal PoC disproves vulnerability
- **WHEN** the generated path traversal PoC executes and the Judge observes that the traversal is blocked, sanitized, or constrained to the safe base path
- **THEN** the candidate SHALL be marked `rejected` with the PoC contradiction evidence and Judge reason.

#### Scenario: Unsupported vulnerability class is encountered
- **WHEN** a SQL injection, command injection, hardcoded secret, or other unsupported class reaches Verification v2 during the MVP
- **THEN** the system SHALL NOT attempt to fake a closed loop and SHALL assign `likely` or `manual-required` with an explicit unsupported-class reason.

### Requirement: Judge reads execution evidence
The system SHALL determine `confirmed` and PoC-based `rejected` statuses through a Judge that reads sandbox execution evidence instead of trusting return code alone.

#### Scenario: Return code is zero
- **WHEN** a PoC process exits with code 0
- **THEN** the Judge SHALL still inspect expected signal evidence from stdout/stderr or generated artifacts before assigning `confirmed`.

#### Scenario: Return code is nonzero
- **WHEN** a PoC process exits with a nonzero code
- **THEN** the Judge SHALL inspect stdout/stderr and artifact evidence to decide whether the result is `rejected`, `manual-required`, or repairable.

### Requirement: Verification retry is bounded and auditable
The system SHALL support a limited self-repair loop for generated PoC artifacts while preserving every attempt.

#### Scenario: PoC repair is attempted
- **WHEN** a PoC fails due to syntax error, local path error, missing fixture setup, or harness construction error
- **THEN** the system MAY repair only the generated PoC artifact, SHALL NOT modify target project code, and SHALL persist a new `VerificationAttempt`.

#### Scenario: Retry budget is exhausted
- **WHEN** all allowed repair attempts are exhausted without a confirming or rejecting Judge result
- **THEN** the candidate SHALL be marked `manual-required` with the final blocking reason and all attempt refs.
