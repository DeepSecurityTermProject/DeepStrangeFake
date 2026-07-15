## Context

The current FastAPI service exposes run-oriented endpoints under `/api/runs`, persists `ScanJob` objects in `runs/web/jobs.json`, and serves runtime state, replay summaries, and reports from existing run directories. The React application mirrors that model with `/create`, `/runs`, and `/runs/:jobId`, and refreshes active jobs every two seconds. Structured local/GitHub/GitLab sources and safe public remote acquisition already exist, but the service has no durable project identity, source preflight workflow, cross-run posture model, or streaming API.

The runtime already writes redacted `messages/messages.jsonl`, runtime state, evidence, reports, and immutable LLM accounting artifacts. These records remain the authority for audit evidence. The new console must project them into a live, human-readable view without exposing raw prompts, full model responses, hidden chain-of-thought, credentials, unrestricted source content, or arbitrary artifact paths.

The application remains a single-user localhost course-project deployment. Backend and frontend will be delivered as vertical slices, while preserving direct CLI usage, `run_audit()` behavior, current run artifacts, and existing Web API clients.

## Goals / Non-Goals

**Goals:**

- Make a project, identified by one normalized code source, the durable parent of repeated audit runs.
- Support real local-directory and public GitHub/GitLab project creation through a preflighted three-step scan wizard.
- Provide transaction-safe project/run indexing without moving large evidence and report artifacts into a database.
- Stream a persisted, ordered, redacted view of job and Agent activity with reconnect and replay semantics.
- Present deterministic project posture and cross-run finding trends without allowing an LLM to assign risk scores or finding identity.
- Preserve compatibility with legacy jobs, run URLs, CLI entrypoints, and artifact readers.
- Make failure, cancellation, degradation, incomplete coverage, disconnection, and empty states explicit in the UI.

**Non-Goals:**

- Authentication, teams, role-based access control, multi-tenancy, or non-localhost deployment.
- Private repository credentials, SSH repository URLs, arbitrary Git hosts, or a browser form for API keys.
- Permanent deletion of projects, runs, evidence, or reports.
- Pausing a run, resuming through an interactive control, or injecting human instructions into a running Agent.
- Exposing hidden chain-of-thought, raw provider payloads, complete prompts, or unbounded tool output.
- Replacing the audit runtime, report schema, evidence gates, sandbox policy, or remote-acquisition safety boundary.
- Treating candidates from static scanning as confirmed project vulnerabilities.

## Decisions

### 1. Use Project as the aggregate root and Run as immutable history

`Project` is a first-class persistent entity with a generated `project_id`, editable display name, normalized source identity, source descriptor, active/archived state, and timestamps. A `Run` retains its existing `job_id`, belongs to one project, and captures a source/revision/configuration snapshot so historical results do not change when project defaults change.

The normalized source identity has a uniqueness constraint. Local sources use a resolved absolute path with Windows path case-folding and separator normalization. Remote sources use the existing HTTPS host/repository normalization, remove URL credentials and a trailing `.git`, and normalize the supported host and repository path. Branches, tags, and commits are run revisions rather than separate projects.

Alternative considered: infer projects dynamically by grouping jobs on the displayed target. This was rejected because aliases, path case, URL spelling, directory moves, and changed revisions would split or merge history unpredictably.

### 2. Use SQLite for the management index and keep filesystem artifacts authoritative

A local SQLite database under the Web management directory stores schema version, projects, runs, event index state, dashboard snapshots, finding identities, and migration receipts. Foreign keys, transactions, uniqueness constraints, WAL mode, and a bounded busy timeout provide safer concurrent updates than rewriting one JSON file.

Reports, source snapshots, evidence, runtime state, replay messages, LLM accounting, and large tool outputs remain in the existing run directory. Database rows store identifiers, summaries, state, and whitelisted artifact references, not duplicate artifact bodies.

`JobStore` remains the compatibility-facing interface used by the runner. Its implementation delegates to the new workspace store, or a compatibility adapter supplies its existing methods and `ScanJob` payload shape. This prevents the Web change from altering runtime orchestration.

Alternative considered: add `projects.json` and continue rewriting `jobs.json`. This was rejected because project creation, duplicate detection, job submission, state transitions, and event offsets need multi-record atomicity.

### 3. Import legacy jobs idempotently and fail without destructive migration

On startup, a migration service reads but never rewrites or deletes `jobs.json`. Each source record receives a stable import receipt keyed by the source path, file fingerprint, and job ID. Import creates or reuses a normalized project when possible, then inserts the legacy run with the original `job_id` and timestamps. Unresolvable legacy targets are placed in an explicitly marked legacy project rather than discarded.

Repeating startup is a no-op for imported records. A malformed file or row is reported as a migration diagnostic and does not prevent the database from serving already committed data. The original JSON file remains available for rollback.

### 4. Add project and preflight APIs without breaking `/api/runs`

The primary API surface is:

- `POST /api/sources/preflight` validates and describes a local or public remote source and requested revision without executing project code.
- `GET/POST /api/projects` lists or creates projects.
- `GET/PATCH /api/projects/{projectId}` reads or renames a project.
- `POST /api/projects/{projectId}/archive` and `/restore` change lifecycle state.
- `GET/POST /api/projects/{projectId}/runs` lists history or submits a real scan.
- `GET /api/projects/{projectId}/dashboard` returns posture and trend projections.
- `GET /api/runs/{runId}/events` provides SSE delivery.

Preflight returns a short-lived opaque token bound to the normalized source, resolved revision information, detected metadata, policy result, and expiry. Project creation or run submission consumes matching preflight data so a client cannot present one source and submit another. Local preflight applies server-side allowed-root and repository-analysis limits. Remote preflight reuses the existing acquisition host allowlist and non-interactive Git controls; branch and tag names are resolved to an immutable full commit before analysis.

The existing `POST /api/runs` remains valid. If no `project_id` is supplied, the service finds or creates the project for the normalized structured source before submitting through the same path. Existing list, status, cancel, artifact, and report endpoints keep their response fields; new project fields are additive. `/runs/:runId` remains a frontend compatibility route and redirects after resolving the owning project.

### 5. Persist a console-specific event projection before streaming it

Each run owns an append-only console event journal. An `AuditEvent` contains at least `event_id`, `run_id`, `project_id`, timestamp, category, phase, severity, actor, title, structured summary, status, correlation/causation references, and whitelisted artifact references. Event IDs are monotonically increasing within a run.

The projection layer consumes job lifecycle transitions and selected existing message-bus records. It maps internal records to stable public categories such as system log, Agent hypothesis/rationale summary, action, tool call, evidence, validation, budget, state transition, and error. It does not copy hidden reasoning or assume that every internal message is safe for display.

The writer holds a per-run lock, appends and flushes the redacted event, then updates the SQLite index. Only a successfully persisted event is published to live subscribers. On startup, the index can be rebuilt from the journal if a crash occurred between append and index update. Long tool output is stored as an existing bounded artifact; the event contains only a summary and authorized reference.

Alternative considered: stream the in-memory message bus directly. This was rejected because refresh, reconnect, process restart, and post-run replay would then show a different history from the live session.

### 6. Use SSE for delivery and HTTP for commands

The event endpoint uses `text/event-stream`, emits each persisted event with an SSE `id`, accepts the standard `Last-Event-ID` header and an equivalent query parameter for clients that need it, sends periodic heartbeats, and terminates cleanly after the terminal event has been delivered. Reconnection replays strictly newer journal entries before switching to live delivery, without duplicate event IDs.

Cancellation and rerun remain ordinary HTTP commands. The frontend first loads the job/event snapshot, then opens SSE. It updates the TanStack Query cache from events and periodically reconciles job status. Repeated stream failure switches the page to the existing polling/artifact APIs, visibly marks the connection as degraded, and retries SSE with bounded backoff.

Alternative considered: WebSocket. It was rejected because the required live path is predominantly server-to-client, while commands already have auditable HTTP endpoints.

### 7. Treat the investigation view as an auditable rationale summary, not chain-of-thought

The public projection allows structured hypotheses, their current assessment, evidence references, next action, tool name, bounded input/output summaries, policy decisions, validation outcomes, budget counters, fallback reasons, and task status. It excludes raw prompts, raw provider response bodies, hidden chain-of-thought, environment-variable dumps, authorization headers, and unbounded code or tool output.

Redaction runs when producing the console event even if the source message was already redacted. Suspected credentials and configured secrets are replaced before persistence. Code excerpts are bounded and tied to evidence locations. Artifact access continues through existing path containment and filename allowlists.

### 8. Compute posture and finding identity in trusted code

Core severity counts and risk scores use validated findings only. Candidate, rejected, manual, or incomplete findings are shown separately. The fixed initial score is `min(100, round(sum(severity_weight * confidence)))`, with weights critical=25, high=15, medium=7, low=2, informational=0 and confidence clamped to `[0, 1]`. The response includes the formula version so later changes do not silently rewrite history.

A stable fingerprint is produced from trusted normalized fields: vulnerability class, normalized repository-relative file path, enclosing symbol when available, and sink/dangerous-operation identity. A deterministic fallback anchor is used when symbol metadata is unavailable. LLM-generated titles or descriptions are never identity inputs.

Across comparable complete runs, fingerprints are classified as new, persistent, resolved, or reintroduced. A run may resolve prior findings only when it succeeds without degradation, its report and coverage evidence are present, and it meets the configured completeness gate. Failed, cancelled, degraded, or coverage-incomplete runs leave prior findings unconfirmed.

The dashboard distinguishes the latest run from the latest complete posture run. It never labels stale results as the latest scan result; instead it reports why the newest run cannot produce a complete posture.

### 9. Keep the React stack and adopt project-first information architecture

The implementation keeps React, TypeScript, React Router, TanStack Query, Vitest, and the existing API client. Routes are `/projects`, `/projects/:projectId`, `/projects/:projectId/scans/new`, `/scans/new`, `/projects/:projectId/runs`, `/projects/:projectId/runs/:runId`, `/runs`, and `/settings`, with redirects from legacy routes.

The UI uses a restrained dark security-console theme, CSS design tokens, semantic severity colors, keyboard-visible focus, text equivalents for charts, and explicit loading/empty/error/degraded/disconnected states. It is desktop-first, remains usable on tablet, and provides basic narrow-screen viewing. No large component framework is required for this change.

### 10. Deliver four independently testable vertical slices

1. Project and scan creation: schema, migration, project/preflight APIs, project catalog, and real scan wizard.
2. Live run and replay: event projection, journal, SSE, fallback, and investigation workspace.
3. Dashboard and trends: aggregation, deterministic scoring/fingerprints, charts, and high-risk drill-down.
4. Integration hardening: legacy compatibility, migration fixtures, reconnection/cancellation/degradation tests, accessibility states, and documentation.

Each slice requires backend tests, frontend tests, and at least one API/UI integration path. Mock data can support isolated tests but does not satisfy slice completion.

## Risks / Trade-offs

- [SQLite and JSON artifact state can diverge after a crash] → Keep artifacts authoritative, make imports and projections idempotent, reconcile on startup, and expose diagnostics instead of silently inventing state.
- [Local path input could expose arbitrary server files] → Resolve paths server-side, enforce configured allowed roots and repository limits, never echo unnecessary absolute paths, and reject paths outside policy.
- [Remote branch or tag resolution can move between preflight and submission] → Bind the preflight token to an immutable resolved commit and scan that commit, not the mutable name.
- [SSE clients may reconnect slowly or receive duplicates around network failure] → Use monotonically increasing persisted IDs, `Last-Event-ID`, idempotent client reducers, heartbeats, and status reconciliation.
- [Internal messages may contain sensitive or overly verbose data] → Use an allowlist projection, second-pass redaction, bounded summaries, and existing artifact access controls.
- [A deterministic fingerprint may split or merge findings after refactors] → Version the fingerprint algorithm, preserve component fields, expose correlation status, and reserve an API for later manual correction without adding the UI now.
- [Risk scores can imply more certainty than the evidence supports] → Publish formula/version, separate candidates, show completeness and degradation prominently, and compute resolved status only from comparable complete runs.
- [Replacing `JobStore` internals can regress the runner] → Preserve its public methods and payloads, add adapter contract tests, and migrate in a vertical slice before changing consumers.
- [A project-first UI can hide cross-project failures] → Retain a global `/runs` view with status filters and a global running/failed indicator.

## Migration Plan

1. Add the SQLite schema, workspace store, and compatibility tests while the existing JSON store remains readable.
2. On startup, create or migrate the database transactionally, then run the read-only idempotent `jobs.json` importer and record diagnostics.
3. Switch the Web runner's `JobStore` dependency to the compatibility adapter and run existing backend/API tests unchanged.
4. Add project/preflight APIs and the project-first frontend behind the existing localhost service; keep legacy routes and payload fields.
5. Add the event projection/journal and SSE endpoint while retaining status polling as fallback.
6. Backfill dashboard snapshots and fingerprints from accessible completed reports; mark missing or non-comparable history explicitly rather than guessing.
7. Remove no legacy files or endpoints in this change. Rollback consists of running the previous application against the untouched `jobs.json` and run directories; the new SQLite database and event journals can be ignored.

## Open Questions

No product-level questions remain after the `/grill-me` session. Formula weights, event schema, fingerprint schema, database schema, and preflight-token formats MUST be explicitly versioned so future adjustments can be proposed without silently changing existing history.
