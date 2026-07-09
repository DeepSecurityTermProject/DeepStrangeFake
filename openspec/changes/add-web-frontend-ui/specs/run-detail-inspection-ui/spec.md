## ADDED Requirements

### Requirement: Run detail page polls job status
The frontend SHALL provide a run detail page that polls job status while a scan is not terminal.

#### Scenario: Poll active job
- **WHEN** a run detail page is opened for a job whose status is `queued` or `running`
- **THEN** the frontend SHALL poll `GET /api/runs/{job_id}` until the job reaches `succeeded` or `failed`.

#### Scenario: Stop polling terminal job
- **WHEN** a job reaches `succeeded` or `failed`
- **THEN** the frontend SHALL stop status polling and begin loading available runtime artifacts.

#### Scenario: Unknown job detail
- **WHEN** the backend returns `404` for a job detail request
- **THEN** the frontend SHALL show a clear not-found state.

### Requirement: Run detail summary tab shows final counts
The run detail page SHALL include a Summary tab driven by job status and report summary.

#### Scenario: Show summary fields
- **WHEN** job status or report summary is available
- **THEN** the Summary tab SHALL show status, target, run directory, candidate count, rejected count, validated count, validation distribution, and runtime state reference when available.

#### Scenario: Show failed job error
- **WHEN** a job status is `failed`
- **THEN** the Summary tab SHALL show the sanitized error message.

### Requirement: Findings tab shows report findings
The run detail page SHALL include a Findings tab driven by `reports/report.json`.

#### Scenario: Show findings list
- **WHEN** `report.json` contains findings
- **THEN** the Findings tab SHALL show each finding title, vulnerability class, severity, confidence, location, evidence, and remediation.

#### Scenario: Empty findings
- **WHEN** `report.json` contains no findings
- **THEN** the Findings tab SHALL show an empty state rather than a broken table.

### Requirement: Runtime Tasks tab shows task state
The run detail page SHALL include a Runtime Tasks tab driven by `runtime_state/state.json`.

#### Scenario: Show runtime tasks
- **WHEN** runtime state contains task records
- **THEN** the Runtime Tasks tab SHALL show role, kind, status, fallback reason, artifact ref count, and message ref count for each task.

#### Scenario: Runtime state unavailable
- **WHEN** runtime state is not yet available
- **THEN** the Runtime Tasks tab SHALL show an unavailable state without breaking other tabs.

### Requirement: Replay tab shows lifecycle summaries
The run detail page SHALL include a Replay tab driven by replay summary.

#### Scenario: Show replay lifecycle
- **WHEN** replay summary is available
- **THEN** the Replay tab SHALL show message counts, decision lifecycle, and runtime lifecycle summaries.

#### Scenario: Replay unavailable
- **WHEN** replay summary is unavailable
- **THEN** the Replay tab SHALL show an unavailable state without breaking other tabs.

### Requirement: Markdown Report tab shows report text
The run detail page SHALL include a Markdown Report tab driven by `reports/report.md`.

#### Scenario: Show Markdown report
- **WHEN** Markdown report content is available
- **THEN** the Markdown Report tab SHALL display the report content in a readable report view.

#### Scenario: Markdown report unavailable
- **WHEN** Markdown report content is unavailable
- **THEN** the Markdown Report tab SHALL show an unavailable state.
