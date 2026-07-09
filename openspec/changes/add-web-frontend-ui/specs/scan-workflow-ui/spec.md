## ADDED Requirements

### Requirement: Scan creation page captures audit options
The frontend SHALL provide a scan creation page that maps user choices to the backend `POST /api/runs` request body.

#### Scenario: Create mock scan
- **WHEN** a user enters a target, enables runtime, selects mock provider, selects memory/MCP/validation options, and submits the form
- **THEN** the frontend SHALL call `POST /api/runs` with a valid request body and show the created job ID.

#### Scenario: Create real-provider scan without secrets
- **WHEN** a user selects real provider mode
- **THEN** the frontend SHALL allow provider/model selection but SHALL NOT ask for API keys, tokens, passwords, or secrets.

#### Scenario: Enable LLM decisions
- **WHEN** a user enables LLM decisions and selects decision roles
- **THEN** the frontend SHALL include `llm_decisions` and `llm_decision_roles` in the create scan request.

#### Scenario: Reject invalid target before submit
- **WHEN** the target field is empty
- **THEN** the frontend SHALL prevent submission and show a validation message.

### Requirement: Task list page shows scan job status
The frontend SHALL provide a task list page using `GET /api/runs`.

#### Scenario: Display known jobs
- **WHEN** jobs exist in the backend job store
- **THEN** the task list SHALL show job ID, target, status, run directory when available, validated count when available, and timestamps.

#### Scenario: Status badges show lifecycle
- **WHEN** jobs have statuses `queued`, `running`, `succeeded`, or `failed`
- **THEN** the task list SHALL display visually distinct status badges for each lifecycle state.

#### Scenario: Open job detail
- **WHEN** a user selects a job from the task list
- **THEN** the frontend SHALL navigate to the detail route for that job ID.

### Requirement: Task list refreshes current status
The frontend SHALL keep job status reasonably fresh for local validation.

#### Scenario: Refresh task list
- **WHEN** a user opens the task list page
- **THEN** the frontend SHALL fetch the latest job list and provide a way to refresh the list.

#### Scenario: Running jobs remain visible
- **WHEN** a job is queued or running
- **THEN** the task list SHALL not hide it while the audit is in progress.
