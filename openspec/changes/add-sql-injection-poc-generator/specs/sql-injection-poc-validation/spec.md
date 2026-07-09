## ADDED Requirements

### Requirement: SQL injection dataflow findings support safe PoC validation
The system SHALL support safe sandbox PoC validation for Python SQL injection findings when they are backed by local dataflow evidence and a transformable SQL query expression.

#### Scenario: Raw SQLi fixture is confirmed
- **WHEN** a Python SQL injection finding has dataflow evidence showing user-controlled input reaching a raw SQL `execute` or `query` sink without parameter binding
- **THEN** the system SHALL generate an executable SQLi PoC artifact, execute it with the local sandbox runner, write a semantic `sqli-result.json` artifact, and mark the candidate `confirmed` only when the Judge observes SQL injection semantics from that artifact.

#### Scenario: SQLi PoC evidence is complete
- **WHEN** a SQL injection candidate is marked `confirmed`
- **THEN** the candidate SHALL reference a real `PoCArtifact`, `SandboxRunResult`, `VerificationAttempt`, stdout/stderr summaries, exit code, Judge reason, the source dataflow trace, and an openable `sqli-result.json` artifact under the run directory.

#### Scenario: SQLi PoC uses local sqlite harness
- **WHEN** the SQLi PoC executes
- **THEN** it SHALL use only an attempt-local or in-memory sqlite harness, SHALL NOT connect to the target project's real database, web server, or network services, and SHALL NOT execute destructive SQL statements.

### Requirement: Parameterized SQL is rejected by PoC contradiction evidence
The system SHALL produce PoC-backed `rejected` status for parameterized Python SQL findings when sandbox execution proves the payload is treated as bound data rather than executable SQL syntax.

#### Scenario: Parameterized SQL fixture is rejected
- **WHEN** a Python SQL injection trace shows user-controlled input reaching a parameterized SQL sink
- **THEN** sandbox validation SHALL generate and execute a SQLi PoC harness and mark the candidate `rejected` when `sqli-result.json` shows no semantic widening from the payload.

#### Scenario: Parameterized rejection includes evidence
- **WHEN** a parameterized SQL candidate is marked `rejected`
- **THEN** the candidate SHALL include the PoC artifact, sandbox result, verification attempt, stdout/stderr summaries, exit code, Judge reason, source dataflow refs, and the `sqli-result.json` contradiction evidence.

### Requirement: SQLi PoC generation rejects forged or stale traces
The system SHALL refuse to generate SQLi PoC artifacts from traces that cannot be tied back to the current target source code.

#### Scenario: Forged trace cannot generate PoC
- **WHEN** a finding is labeled as SQL injection `complete-flow` but the referenced dataflow trace sink or query expression does not appear in the target file
- **THEN** the system SHALL NOT write a SQLi PoC artifact, SHALL NOT execute sandbox validation for that forged trace, SHALL NOT mark the candidate `confirmed`, and SHALL record a `likely` or `manual-required` reason explaining the target expression mismatch.

#### Scenario: Missing trace artifact cannot generate PoC
- **WHEN** a SQL injection finding lacks an openable dataflow trace artifact
- **THEN** the system SHALL NOT write a placeholder PoC and SHALL mark the candidate `likely` or `manual-required` with a missing-trace reason.

### Requirement: Unsupported SQLi shapes degrade safely
The system SHALL degrade unsupported SQL injection shapes to `likely` or `manual-required` instead of attempting unsafe or misleading PoC execution.

#### Scenario: Unsupported ORM SQLi is not executed
- **WHEN** a SQL injection finding uses ORM/session/query-builder behavior that cannot be safely represented by the sqlite harness
- **THEN** the system SHALL NOT generate a SQLi PoC and SHALL mark the candidate `likely` or `manual-required` with an unsupported ORM or query-builder reason.

#### Scenario: JS or TS SQLi is not executed
- **WHEN** a SQL injection finding comes from a JS or TS dataflow trace
- **THEN** the system SHALL NOT generate a Python SQLi PoC and SHALL mark the candidate `likely` or `manual-required` with an unsupported language reason.

#### Scenario: Non-SELECT SQL is not executed
- **WHEN** a SQL injection finding's transformable SQL operation is not a safe `SELECT` statement
- **THEN** the system SHALL NOT execute the SQL statement and SHALL mark the candidate `manual-required` or `likely` with a non-SELECT reason.

### Requirement: SQLi Judge requires semantic result evidence
The system SHALL determine SQL injection `confirmed` and PoC-backed `rejected` statuses from semantic result artifacts rather than return code or stdout alone.

#### Scenario: Return code zero without SQLi result is not confirmed
- **WHEN** a SQLi PoC process exits with code 0 but does not produce an openable `sqli-result.json` semantic evidence artifact under the attempt directory
- **THEN** the Judge SHALL NOT mark the candidate `confirmed` and SHALL return `manual-required` or `rejected` with a reason that semantic SQLi evidence was missing.

#### Scenario: SQLi result confirms semantic widening
- **WHEN** `sqli-result.json` shows that the attack payload returns marker rows or broadens results beyond the baseline query
- **THEN** the Judge SHALL mark the candidate `confirmed` and cite the result artifact as evidence.

#### Scenario: SQLi result contradicts injection
- **WHEN** `sqli-result.json` shows that the attack payload remains bound data and does not broaden results beyond the baseline query
- **THEN** the Judge SHALL mark the candidate `rejected` and cite the result artifact as contradiction evidence.

### Requirement: Existing path traversal verification remains compatible
The system SHALL preserve existing path traversal PoC validation behavior while adding SQL injection PoC validation.

#### Scenario: Path traversal validation still works
- **WHEN** a dataflow-backed path traversal finding is validated in sandbox mode
- **THEN** the existing path traversal PoC generator, sandbox runner, Judge, artifact refs, and status behavior SHALL remain compatible with prior tests.
