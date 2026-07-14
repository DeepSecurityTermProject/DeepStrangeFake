## ADDED Requirements

### Requirement: Scan requests use explicit source variants with legacy compatibility
The Web API SHALL accept a discriminated local-path, GitHub, or GitLab source object and SHALL continue to accept the existing non-empty `target` string as a backward-compatible local source. It MUST reject ambiguous requests, declared-kind/host mismatch, incompatible fields, unsupported remote revisions, and client attempts to override operator network policy. The CLI SHALL accept remote revisions through `--revision` and MAY retain `--commit` as a compatibility alias.

#### Scenario: Structured GitHub scan is queued
- **WHEN** a client submits a valid GitHub source object and supported scan options while remote acquisition is enabled
- **THEN** the API creates one queued job retaining the original display target and normalized source intent

#### Scenario: Structured GitLab scan is queued
- **WHEN** a client submits a valid GitLab source object and supported scan options while remote acquisition is enabled
- **THEN** the API creates one queued job retaining the original URL, GitLab source kind, and requested exact revision

#### Scenario: CLI pins a remote revision
- **WHEN** the user runs `scan --target <GitHub-or-GitLab-URL> --revision <full-object-id>`
- **THEN** the pipeline exports and scans only that exact commit and reports it as the resolved commit

#### Scenario: Legacy local target remains compatible
- **WHEN** an existing client submits only a local `target` string
- **THEN** the backend runs the existing local-path workflow without invoking remote acquisition

### Requirement: Web jobs expose acquisition progress without changing terminal polling
The job model SHALL retain the existing `queued`, `running`, `succeeded`, and `failed` statuses and SHALL add a phase field covering source validation, acquisition, commit resolution, export, analysis, scanning, verification, reporting, and cleanup. Phase and acquisition summaries MUST survive job-store persistence and API reloads.

#### Scenario: Remote job advances through acquisition
- **WHEN** a queued GitHub or GitLab scan begins and acquisition progresses
- **THEN** status remains `running` while phase and safe acquisition details advance monotonically until scanning starts or the job fails

### Requirement: Runtime consumes one prepared target with preserved provenance
The pipeline SHALL prepare a remote target exactly once and SHALL pass the same verified metadata and local export root to legacy and graph runtimes. Repository metadata MUST preserve the original remote source, provider kind, local materialization path, resolved commit, and acquisition evidence so scanners read the exported snapshot without presenting it as an unrelated user-local directory.

#### Scenario: Remote snapshot reaches both runtime modes
- **WHEN** the same verified remote fixture is scanned in legacy and deterministic/adaptive graph modes
- **THEN** each mode scans files from its prepared exact-commit export and reports the same source identity and resolved commit

### Requirement: Empty or unverified remote scopes cannot succeed
The system MUST NOT invoke normal audit completion for a remote target whose acquisition is not ready, whose resolved commit is absent or mismatched, whose export is missing, or whose effective file scope is empty. Failed acquisition MUST NOT fall back to metadata-only URL parsing or fabricate zero findings, zero resources, or a successful report.

#### Scenario: Remote URL produces no auditable files
- **WHEN** acquisition fails or repository analysis selects zero in-scope files from the exported snapshot
- **THEN** the job terminates as failed with an explicit acquisition or empty-scope reason and no success claim

### Requirement: Remote snapshot verification remains isolated
A verified remote snapshot SHALL be eligible for static analysis and, when explicitly configured, network-disabled Docker verification using read-only target access. Local-process sandbox execution, target-source writes, live-target traffic, project dependency installation, and project setup/build commands MUST remain prohibited for remotely acquired sources; LLM PoC repair remains limited to typed edits inside attempt directories.

#### Scenario: User requests Docker verification for a verified snapshot
- **WHEN** the source was safely materialized, Docker validation is explicitly enabled, the target mount is read-only, and sandbox network is disabled
- **THEN** the existing VerificationEngine may run generated bounded harnesses without executing project-controlled setup or modifying the target snapshot

#### Scenario: User requests local-process execution for a remote source
- **WHEN** a remote-acquired scan selects the local sandbox runner or any live/network target behavior
- **THEN** policy blocks execution and records a manual-required or failed verification reason without weakening the scan boundary

### Requirement: Acquisition evidence is visible in API and run artifacts
The backend SHALL expose safe source kind, acquisition phase/status, requested revision, resolved commit, cache outcome, network-use indicator, cleanup result, and acquisition artifact reference in job details and terminal run metadata. Replay and report readers MUST remain side-effect-free and MUST NOT perform clone, fetch, export, cleanup, or target operations.

#### Scenario: Operator inspects a completed remote scan
- **WHEN** a remote job reaches a terminal state
- **THEN** API and run artifacts identify exactly which commit was scanned and whether acquisition and cleanup were complete without exposing credentials or unsafe cache paths

### Requirement: Scan console supports bounded GitHub and GitLab workflows
The scan console SHALL provide a Local/GitHub/GitLab segmented source selector, validate the selected source before submission, show an exact commit input for remote modes, and send the structured source contract. The commit MAY be omitted only when backend options advertise HEAD resolution. Each provider mode MUST reflect backend host capability state, and run list/detail views SHALL display acquisition phase, resolved commit, cache status, and sanitized failures without disturbing existing local-scan controls.

#### Scenario: User pastes a GitHub URL and starts a scan
- **WHEN** GitHub acquisition is enabled and the user submits a valid public URL with otherwise valid scan options
- **THEN** the UI creates a remote scan job, navigates to its detail view, and polls acquisition and scan progress through the existing job API

#### Scenario: User pastes a GitLab URL and starts a scan
- **WHEN** GitLab acquisition is enabled and the user submits a canonical public GitLab URL with a required exact commit in cache-only mode
- **THEN** the UI creates a GitLab source request and follows the same acquisition and scan lifecycle

#### Scenario: Backend disables remote acquisition
- **WHEN** API options report that remote acquisition is disabled
- **THEN** the UI prevents remote submission while local-path scanning remains available

### Requirement: Remote workflow is testable without default network access
Default backend, frontend, and repository test suites SHALL use injected or fake acquisition services and local synthetic source exports and MUST NOT clone or fetch remote repositories. A bounded live public-provider smoke MAY run only behind an explicit opt-in environment gate and MUST record a skip reason when Git, network, or the reviewed fixture is unavailable.

#### Scenario: Default test suite executes
- **WHEN** developers run the normal test commands without the opt-in live gate
- **THEN** remote acquisition behavior is covered deterministically and no test reaches GitHub or another network destination
