## ADDED Requirements

### Requirement: Runtime state is readable through job scope
The system SHALL expose a read-only endpoint for the runtime state file associated with a known scan job.

#### Scenario: Read runtime state
- **WHEN** a client sends `GET /api/runs/{job_id}/runtime-state` for a succeeded or running job whose `runtime_state/state.json` exists
- **THEN** the backend SHALL return the parsed JSON runtime state.

#### Scenario: Runtime state unavailable
- **WHEN** a client requests runtime state before the file exists
- **THEN** the backend SHALL return `404 Not Found` or a structured unavailable response without failing the job.

### Requirement: Replay summary is generated from the message log
The system SHALL expose a replay summary endpoint that uses the existing message replay logic.

#### Scenario: Read replay summary
- **WHEN** a client sends `GET /api/runs/{job_id}/replay-summary` and the job has `messages/messages.jsonl`
- **THEN** the backend SHALL return the result of replaying that message log, including decision lifecycle and runtime lifecycle summaries.

#### Scenario: Replay log unavailable
- **WHEN** a client requests replay summary before `messages/messages.jsonl` exists
- **THEN** the backend SHALL return `404 Not Found` or a structured unavailable response without exposing filesystem paths outside the job record.

### Requirement: Report files are readable through fixed endpoints
The system SHALL expose read-only endpoints for the JSON and Markdown report files produced by a scan run.

#### Scenario: Read JSON report
- **WHEN** a client sends `GET /api/runs/{job_id}/reports/report.json`
- **THEN** the backend SHALL return the parsed report JSON from the job's `reports/report.json`.

#### Scenario: Read Markdown report
- **WHEN** a client sends `GET /api/runs/{job_id}/reports/report.md`
- **THEN** the backend SHALL return the Markdown report content from the job's `reports/report.md` with an appropriate text response.

#### Scenario: Report unavailable
- **WHEN** a client requests a report file before it exists
- **THEN** the backend SHALL return `404 Not Found` or a structured unavailable response.

### Requirement: Artifact access is path-safe
The system SHALL restrict artifact reads to whitelisted files under the run directory associated with the requested job.

#### Scenario: No arbitrary artifact path
- **WHEN** a client uses the runtime artifact API
- **THEN** the backend SHALL NOT accept arbitrary relative path input for file reads.

#### Scenario: Path traversal is denied
- **WHEN** a request attempts to access a file outside the job's run directory by encoded traversal, absolute path, or unsupported report name
- **THEN** the backend SHALL deny the request and SHALL NOT return file content.

#### Scenario: Secrets are not exposed through job metadata
- **WHEN** the backend returns job status, runtime state, replay summary, or report metadata
- **THEN** it SHALL rely on existing redacted artifacts and SHALL NOT include API key values from `.env` or process environment.
