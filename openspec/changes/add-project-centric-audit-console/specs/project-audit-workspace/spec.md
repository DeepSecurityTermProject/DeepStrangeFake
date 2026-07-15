## ADDED Requirements

### Requirement: Durable project and run relationship
The system SHALL persist a project as the durable owner of one normalized code source and SHALL associate every newly submitted Web scan run with exactly one project. A project SHALL have a generated identity independent of its editable display name, and each run SHALL retain an immutable source, revision, and configuration snapshot.

#### Scenario: Repeated scans belong to one project
- **WHEN** a user starts multiple scans for the same project with different revisions or scan configurations
- **THEN** the system records separate runs under the same `project_id` and preserves each run's submitted snapshot

#### Scenario: Display name changes without changing identity
- **WHEN** a user renames a project
- **THEN** the system updates its display name without changing its `project_id`, normalized source identity, or run history

### Requirement: Canonical source uniqueness
The system SHALL derive a trusted canonical identity for each supported source and SHALL prevent two active or archived projects from representing the same canonical source. Local paths SHALL be resolved and normalized for the host platform; remote identities SHALL use normalized credential-free HTTPS host and repository paths.

#### Scenario: Duplicate local path spelling
- **WHEN** a user preflights a local path that resolves to an existing project's canonical directory despite case or separator differences
- **THEN** the system identifies the existing project and offers a new run under it rather than creating a duplicate project

#### Scenario: Duplicate remote URL spelling
- **WHEN** a user supplies an existing public repository with an equivalent URL that differs only by normalized host casing, trailing slash, or `.git` suffix
- **THEN** the system resolves the URL to the existing project identity

#### Scenario: Branch does not create a separate project
- **WHEN** a user selects a different branch, tag, or commit for an existing remote project
- **THEN** the system records the selection on the new run and does not create another project

### Requirement: Policy-bound source preflight
The system SHALL preflight a local directory or public GitHub/GitLab HTTPS repository before project creation or project-scoped run submission. Preflight SHALL validate source accessibility and policy, SHALL execute no project-controlled code, and SHALL return a bounded metadata summary plus an expiring token bound to the normalized source and resolved revision.

#### Scenario: Valid local source preflight
- **WHEN** a user submits a readable local directory within the configured allowed roots
- **THEN** the system returns its normalized identity, suggested project name, detected languages, bounded file-size metadata, and a preflight token without executing repository code

#### Scenario: Local source outside policy
- **WHEN** a user submits a local directory outside the configured allowed roots or repository limits
- **THEN** the system rejects preflight with a stable policy error and does not create a project or run

#### Scenario: Valid public remote revision
- **WHEN** a user submits an allowed public GitHub or GitLab URL with a branch, tag, commit, or default revision
- **THEN** the system safely resolves the selection to an immutable full commit, returns repository metadata and a bound preflight token, and does not run repository-controlled hooks or setup

#### Scenario: Unsupported or private remote source
- **WHEN** a source requires credentials, uses SSH, embeds URL credentials, or targets an unapproved host
- **THEN** the system rejects it without collecting, persisting, or echoing credentials

#### Scenario: Source changes after preflight
- **WHEN** project creation or run submission does not match the source and immutable revision bound to the preflight token
- **THEN** the system rejects the request and requires a new preflight

### Requirement: Project management lifecycle
The project catalog SHALL support listing, search, security-status filtering, recent-scan ordering, rename, archive, and restore. Archiving SHALL be reversible and SHALL NOT delete source content, runs, reports, evidence, or event journals.

#### Scenario: Archive an idle project
- **WHEN** a user archives a project with no queued or running scan
- **THEN** the project is hidden from the default active catalog, remains available through the archived filter, and retains all history

#### Scenario: Archive a busy project
- **WHEN** a user attempts to archive a project with a queued or running scan
- **THEN** the system rejects the transition and leaves the project active

#### Scenario: Restore a project
- **WHEN** a user restores an archived project
- **THEN** it returns to the active catalog with the same identity, source, runs, and dashboard history

#### Scenario: Permanent deletion is unavailable
- **WHEN** a user views project or run actions in the first release
- **THEN** no permanent-delete action or API is exposed

### Requirement: Transactional management index
The system SHALL store project, run, migration, event-index, and posture-summary records in a versioned local SQLite database using transactions and foreign-key constraints. Detailed audit artifacts SHALL remain in the existing filesystem layout and SHALL be referenced only through contained, authorized paths.

#### Scenario: Atomic project and first run creation
- **WHEN** a new-source scan request creates a project and submits its first run
- **THEN** the project/run relationship is committed atomically or the request fails without leaving an orphan project or run

#### Scenario: Concurrent state updates
- **WHEN** multiple jobs update status while project catalog requests are served
- **THEN** committed project and run records remain readable and no full-store JSON rewrite loses another job's update

#### Scenario: Artifact remains authoritative
- **WHEN** a client requests detailed evidence, runtime state, replay data, or a report
- **THEN** the system reads the authorized run artifact rather than treating a database summary as the evidence body

### Requirement: Idempotent legacy job import
The system SHALL read existing `jobs.json` data through an idempotent migration, SHALL preserve original job identifiers and timestamps where valid, and SHALL NOT modify or delete the source JSON file. Malformed legacy records SHALL produce diagnostics without destroying already imported data.

#### Scenario: First legacy import
- **WHEN** the service starts with a valid legacy job that is not in SQLite
- **THEN** the system creates or reuses an appropriate project, imports the run once, and records an import receipt

#### Scenario: Repeated startup
- **WHEN** the service restarts with the same legacy file
- **THEN** previously imported jobs are not duplicated and existing SQLite state is not reset

#### Scenario: Unresolvable legacy target
- **WHEN** a legacy job's target cannot be canonicalized safely
- **THEN** the system preserves the job under an explicitly marked legacy project and reports that source identity is unresolved

#### Scenario: Malformed legacy file
- **WHEN** `jobs.json` or an individual row is malformed
- **THEN** the system leaves the original file untouched, records a sanitized migration diagnostic, and continues serving previously committed database content

### Requirement: Three-step real scan workflow
The frontend SHALL provide a three-step workflow that selects an existing project or new source, performs source preflight, and reviews scan configuration before starting a real backend run. A successful submission SHALL navigate directly to the project-scoped run workspace.

#### Scenario: Create a project from a new source
- **WHEN** a user completes preflight and confirms configuration for a source that has no project
- **THEN** the backend creates the project and its first real scan run and the frontend navigates to that run

#### Scenario: Scan an existing project
- **WHEN** a user starts a scan from an existing project dashboard
- **THEN** the wizard reuses the project identity, permits revision and scan configuration changes, and creates only a new run

#### Scenario: Preflight failure
- **WHEN** source preflight fails
- **THEN** the wizard displays the stable error, preserves safe user input, and prevents progression to submission

#### Scenario: Submission failure after preflight
- **WHEN** the final run request is rejected or cannot be queued
- **THEN** the wizard remains recoverable, reports whether a project was committed, and does not claim that scanning started

### Requirement: Project-first navigation and compatibility routes
The frontend SHALL make projects the primary navigation model while retaining a cross-project run list and compatible legacy run links. The backend SHALL retain existing `/api/runs` request and response behavior with only additive project fields.

#### Scenario: Project-first routes
- **WHEN** a user navigates through the application
- **THEN** project catalog, project dashboard, project scan creation, project history, project-scoped run detail, global runs, and settings are available at the agreed routes

#### Scenario: Legacy run URL
- **WHEN** a user opens `/runs/:runId` for a known imported or new run
- **THEN** the frontend resolves its owning project and redirects to the project-scoped run page

#### Scenario: Existing API client creates a run
- **WHEN** an existing client calls `POST /api/runs` with a currently valid request and no project identifier
- **THEN** the backend preserves the accepted contract, finds or creates the normalized project, and submits the run through the same runner

#### Scenario: Existing run artifact endpoints
- **WHEN** a client reads a known run's status, runtime state, replay summary, JSON report, or Markdown report through the existing endpoint
- **THEN** the response remains available with its existing fields and semantics

### Requirement: Single-user localhost security boundary
The first release SHALL operate without application accounts only when bound to the local trusted deployment boundary. The absence of login SHALL NOT bypass local path policy, remote acquisition policy, secret redaction, artifact containment, or request validation.

#### Scenario: Localhost operation
- **WHEN** the console is run with the supported first-release configuration
- **THEN** backend and development frontend bind to loopback addresses and require no user login

#### Scenario: Unsafe path despite no login
- **WHEN** the local user submits a path denied by backend policy
- **THEN** the backend rejects it regardless of the single-user deployment assumption

