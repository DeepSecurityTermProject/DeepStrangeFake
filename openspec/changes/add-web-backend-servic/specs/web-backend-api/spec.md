## ADDED Requirements

### Requirement: Web backend exposes scan job API
The system SHALL provide a FastAPI backend with HTTP endpoints for creating scan jobs, listing jobs, reading job status, reading runtime state, reading replay summary, and retrieving report files.

#### Scenario: Create scan job
- **WHEN** a client sends `POST /api/runs` with a valid target and supported runtime options
- **THEN** the backend SHALL create a job, enqueue scan execution, and return `202 Accepted` with `job_id`, `status`, and `status_url`.

#### Scenario: List scan jobs
- **WHEN** a client sends `GET /api/runs`
- **THEN** the backend SHALL return known jobs with job ID, target, status, timestamps, run directory when available, and summary when available.

#### Scenario: Read scan job status
- **WHEN** a client sends `GET /api/runs/{job_id}` for a known job
- **THEN** the backend SHALL return the current job status, target, timestamps, run directory, summary, and error details.

#### Scenario: Unknown scan job
- **WHEN** a client requests a job ID that is not known
- **THEN** the backend SHALL return `404 Not Found` with a structured error response.

### Requirement: Web backend validates scan requests
The system SHALL validate scan request fields before creating a job.

#### Scenario: Missing target
- **WHEN** a client sends `POST /api/runs` without a target
- **THEN** the backend SHALL reject the request with `422 Unprocessable Entity`.

#### Scenario: Unsupported runtime option
- **WHEN** a client sends a runtime option outside the supported enum values for memory mode, MCP mode, or validation level
- **THEN** the backend SHALL reject the request with `422 Unprocessable Entity` and SHALL NOT create a job.

#### Scenario: Request does not carry secrets
- **WHEN** a client creates a scan job
- **THEN** the request schema SHALL NOT include model API key, MCP secret, password, or token fields; credentials SHALL continue to come from existing environment configuration.

### Requirement: Web backend remains CLI compatible
The system SHALL provide the web backend without changing existing CLI scan, benchmark, replay, or integration commands.

#### Scenario: CLI scan remains available
- **WHEN** the backend modules are installed
- **THEN** existing CLI commands SHALL continue to call `run_audit()` and produce the same run artifacts as before.

#### Scenario: Service can start locally
- **WHEN** a developer starts the backend with the documented local command
- **THEN** the service SHALL bind to a local host and expose the scan job API without requiring a frontend UI.
