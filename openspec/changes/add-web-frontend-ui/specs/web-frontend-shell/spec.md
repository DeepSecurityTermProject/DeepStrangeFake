## ADDED Requirements

### Requirement: Frontend app uses Vite React TypeScript
The system SHALL include a `frontend/` single-page app built with Vite, React, and TypeScript.

#### Scenario: Frontend project exists
- **WHEN** the frontend change is implemented
- **THEN** the repository SHALL contain a `frontend/` project with `package.json`, TypeScript configuration, Vite configuration, and React source files.

#### Scenario: Frontend starts locally
- **WHEN** a developer runs the documented frontend dev command
- **THEN** the app SHALL start locally and render the scan console without requiring a production build.

#### Scenario: Frontend builds successfully
- **WHEN** the frontend build command is executed
- **THEN** TypeScript and Vite SHALL produce a successful production build.

### Requirement: Frontend has routed app shell
The frontend SHALL provide a routed app shell for scan creation, task listing, and run detail inspection.

#### Scenario: Navigate to scan creation
- **WHEN** a user opens the root route or scan creation route
- **THEN** the app SHALL show the scan creation workflow.

#### Scenario: Navigate to task list
- **WHEN** a user opens the task list route
- **THEN** the app SHALL show known scan jobs from the backend.

#### Scenario: Navigate to task detail
- **WHEN** a user opens a run detail route with a job ID
- **THEN** the app SHALL show the run detail layout for that job.

### Requirement: Frontend centralizes API access
The frontend SHALL use a typed API client for backend calls instead of scattering raw fetch calls across page components.

#### Scenario: API client wraps scan endpoints
- **WHEN** a page needs to create scans, list runs, read run status, or read artifacts
- **THEN** it SHALL call functions from the shared API client.

#### Scenario: API errors are visible
- **WHEN** the backend is unavailable or returns an error
- **THEN** the frontend SHALL show a clear error state without crashing the application.

### Requirement: Frontend follows operational UI conventions
The frontend SHALL present the audit workflow as a usable operational console.

#### Scenario: First viewport is usable application
- **WHEN** a user opens the frontend
- **THEN** the first screen SHALL present the scan workflow or audit console, not a marketing landing page.

#### Scenario: Controls fit their purpose
- **WHEN** the UI renders form controls, status badges, tabs, and action buttons
- **THEN** it SHALL use appropriate controls such as toggles, segmented controls, selects, tabs, tables, and icon buttons where useful.
