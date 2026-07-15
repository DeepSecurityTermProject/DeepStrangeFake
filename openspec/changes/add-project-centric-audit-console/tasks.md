## 1. Phase One - SQLite Project Foundation

- [x] 1.1 Define versioned SQLite tables and migrations for projects, runs, migration receipts, event index state, posture snapshots, and finding identities, including foreign keys, source-identity uniqueness, WAL mode, and bounded busy timeout.
- [x] 1.2 Implement project and run domain models plus a transactional workspace store for create, read, list, rename, archive, restore, and project-scoped run operations.
- [x] 1.3 Preserve the current `JobStore` method and `ScanJob` payload contracts through a SQLite-backed implementation or compatibility adapter used by `ScanJobRunner`.
- [x] 1.4 Implement canonical local and remote source identities, including Windows path normalization, credential-free HTTPS URL normalization, and duplicate-project lookup.
- [x] 1.5 Implement the read-only idempotent `jobs.json` importer with stable receipts, original job ID preservation, legacy-unresolved projects, sanitized row diagnostics, and no source-file mutation.
- [x] 1.6 Add storage and migration tests covering atomic project/first-run creation, concurrent job updates, duplicate sources, repeated startup, malformed legacy data, and rollback compatibility.

## 2. Phase One - Source Preflight and Project APIs

- [x] 2.1 Define strict request/response schemas for source preflight, projects, lifecycle actions, project-scoped run lists, and additive project fields on existing run responses.
- [x] 2.2 Implement local-source preflight with resolved-path identity, configured allowed-root enforcement, bounded repository metadata, language detection, and no project-code execution.
- [x] 2.3 Extend safe public remote preflight to resolve default revision, branch, tag, or commit to an immutable full commit while reusing host allowlists, non-interactive Git controls, resource limits, and credential rejection.
- [x] 2.4 Implement signed or server-stored expiring preflight tokens bound to canonical source, immutable revision, detected metadata, policy version, and expiry, with mismatch and replay handling.
- [x] 2.5 Add project list/create/get/rename/archive/restore endpoints with search, security-state filters, recent-run ordering, archive guards, and stable error payloads.
- [x] 2.6 Add project-scoped run list and create endpoints that consume matching preflight data and submit through the existing real `ScanJobRunner` path.
- [x] 2.7 Keep `POST /api/runs` backward compatible by finding or creating a canonical project when older clients omit `project_id`, and preserve all existing run/artifact endpoints.
- [x] 2.8 Add backend API tests for local/public-remote success, duplicate detection, mutable-revision binding, unsupported/private/credential-bearing URLs, denied local paths, archive guards, and legacy client compatibility.

## 3. Phase One - Project-First Frontend and Scan Wizard

- [x] 3.1 Extend TypeScript API contracts and the API client for project, preflight, project-run, lifecycle, pagination/filter, and additive legacy response fields.
- [x] 3.2 Replace the run-first shell with project-first routes and navigation while preserving redirects for `/create` and `/runs/:runId` and retaining the global `/runs` view.
- [x] 3.3 Establish accessible dark-theme design tokens, semantic severity/status styles, desktop-first layout, keyboard focus, and shared loading, empty, error, degraded, and unavailable states.
- [x] 3.4 Build the multi-project catalog with safe source display, language, latest run, posture status, search, filters, ordering, archive/restore, rename, and new-scan actions.
- [x] 3.5 Build wizard step one for selecting an existing project or entering a local directory or public GitHub/GitLab URL without credential fields.
- [x] 3.6 Build wizard step two for preflight progress, detected repository metadata, duplicate-project resolution, revision selection, and recoverable policy errors.
- [x] 3.7 Build wizard step three for scan configuration review, immutable resolved revision display, real submission, failure recovery, and navigation to the project-scoped run workspace.
- [x] 3.8 Add a basic project detail/history view that supports new scans and distinguishes projects with no runs, active runs, and terminal runs before the full posture dashboard is added.
- [x] 3.9 Add component and API-client tests for catalog actions, every wizard step, duplicate handling, source validation, submission errors, redirects, and responsive/accessibility states.
- [x] 3.10 Run a backend/frontend integration test that creates or reuses a real project from each supported source shape and queues a real project-scoped scan without using page-level mock data.
- [x] 3.11 Record Phase One API, UI, migration, test, and known-limit evidence; report it to the user and pause for confirmation before Phase Two.

## 4. Phase Two - Persisted Public Event Projection

- [x] 4.1 Define and version the `AuditEvent` schema, public categories, severity/status values, event size limits, and run-scoped monotonic ID rules.
- [x] 4.2 Implement the per-run append-only event journal with locking, flush-before-publish behavior, terminal-event handling, and whitelisted artifact references.
- [x] 4.3 Implement allowlist projection from job lifecycle transitions and existing message-bus records into system, Agent rationale, hypothesis, action, tool, evidence, validation, budget, state, and error events.
- [x] 4.4 Apply second-pass secret redaction, bounded code/tool summaries, hidden-chain-of-thought exclusion, and safe fallback diagnostics before journal persistence.
- [x] 4.5 Wire job submission, phase changes, cancellation, terminal states, runtime messages, and fallback/degraded reasons into the event projector without changing audit orchestration.
- [x] 4.6 Implement startup journal reconciliation and SQLite event-index rebuilding for append/index interruption without duplicate event IDs.
- [x] 4.7 Add event-journal tests for ordering, concurrency, persistence failure, crash reconciliation, unsupported internal messages, oversized output, redaction, and terminal consistency.

## 5. Phase Two - SSE Delivery and Recovery

- [x] 5.1 Add the project-aware run event endpoint using `text/event-stream`, SSE IDs, bounded heartbeats, disconnect cleanup, and safe unknown-run/cursor errors.
- [x] 5.2 Implement persisted-history replay followed by live delivery with no handoff gap and no duplicate IDs.
- [x] 5.3 Support standard `Last-Event-ID` reconnection and an equivalent validated cursor query for explicit browser recovery.
- [x] 5.4 Close terminal streams only after persisted terminal history is delivered and provide a consistent terminal snapshot when the client is already current.
- [x] 5.5 Add SSE integration tests for initial history, concurrent live events, reconnect, invalid cursor, terminal reconnect, slow/disconnected clients, and persistence-before-delivery.

## 6. Phase Two - Live Run Workspace and Replay UI

- [x] 6.1 Add an idempotent frontend event reducer and stream hook that loads a snapshot, resumes by event ID, tracks heartbeat/connection state, and bounds reconnect backoff.
- [x] 6.2 Reconcile SSE events with TanStack Query job/runtime/report caches and fall back visibly to the existing polling and artifact endpoints after bounded stream failures.
- [x] 6.3 Build the project-scoped run header with phase, effective mode, progress, elapsed time, budget summary, stream health, terminal state, and explicit degradation/fallback reasons.
- [x] 6.4 Build the unified timeline with Agent/category/phase/severity filters and accessible event status, correlation, and chronological grouping.
- [x] 6.5 Build bounded expandable details for rationale summaries, hypotheses, actions, tool calls, evidence, validation, budgets, errors, and authorized artifact links.
- [x] 6.6 Build the side panel for current investigation tasks, active Agents, candidates, collected evidence, and connection diagnostics without exposing hidden reasoning.
- [x] 6.7 Implement confirmation-based cancellation and terminal rerun review while ensuring navigation, refresh, and tab closure never cancel a job implicitly.
- [x] 6.8 Render terminal, degraded, failed, cancelled, empty, imported-without-journal, reconstructed, disconnected, and polling-fallback states explicitly.
- [x] 6.9 Add frontend tests for ordered rendering, filtering, duplicate suppression, refresh recovery, stream fallback/recovery, cancellation, rerun, effective-mode labeling, and redaction-safe presentation.
- [x] 6.10 Run an end-to-end active-job test that observes persisted events live, reconnects from a saved event ID, and later replays the identical event IDs and order.
- [x] 6.11 Record Phase Two journal, SSE, UI, recovery, test, and known-limit evidence; report it to the user and pause for confirmation before Phase Three.

## 7. Phase Three - Trusted Posture and Trend Services

- [x] 7.1 Define versioned posture completeness, risk formula, fingerprint, trend-comparison, and unavailable-data schemas.
- [x] 7.2 Implement report projection that separates validated findings from candidate, pending, manual, rejected, and inconclusive findings and preserves evidence references.
- [x] 7.3 Implement the trusted risk score with published severity weights, confidence clamping/fallback metadata, score cap, formula version, and explainable components.
- [x] 7.4 Implement versioned stable fingerprints from normalized class, repository-relative path, enclosing symbol, sink identity, and documented fallback-anchor quality.
- [x] 7.5 Implement completeness gating using terminal status, degradation, report presence, coverage evidence, validation state, and required accounting/evidence indicators.
- [x] 7.6 Implement new, persistent, resolved, reintroduced, and unconfirmed classification across comparable complete runs, including incompatible fingerprint-version handling.
- [x] 7.7 Implement idempotent posture snapshot/backfill jobs that read authoritative artifacts, retain formula/fingerprint versions, and never guess missing legacy data.
- [x] 7.8 Add the project dashboard API with metadata, latest-run truth, latest complete posture, severity/validation counts, risk, quality indicators, trend series, and high-risk finding references.
- [x] 7.9 Add backend tests for all score weights, invalid/missing confidence, fingerprint stability and separation, every trend transition, incomplete-run non-resolution, version mismatch, and legacy unavailable data.

## 8. Phase Three - Project Security Dashboard UI

- [x] 8.1 Build dashboard project/source metadata, latest audit, scan size/coverage, timing, active-run status, and explicit latest-complete-posture attribution.
- [x] 8.2 Build confirmed severity and separate validation-state summaries without presenting static candidates as confirmed vulnerabilities.
- [x] 8.3 Build the deterministic risk card with formula/version explanation, component drill-down, completeness status, and no-posture state.
- [x] 8.4 Build accessible recent-run risk and finding trend views with numeric/text equivalents and new/persistent/resolved/reintroduced/unconfirmed counts.
- [x] 8.5 Build investigation-quality cards for evidence completeness, validation completion, effective mode, fallback/degraded reasons, and budget usage distinct from risk.
- [x] 8.6 Build the high-risk finding list with severity, location, verification/evidence state, trend status, and links to the owning run and finding context.
- [x] 8.7 Add dashboard states for no runs, running-only, latest incomplete, stale historical posture, incompatible trend versions, missing legacy metadata, and API failure.
- [x] 8.8 Add frontend tests for score explanation, candidate separation, stale/incomplete labeling, chart text equivalents, drill-down navigation, and responsive/accessibility behavior.
- [x] 8.9 Run an integration fixture across multiple project runs and verify deterministic score, stable trend classification, latest-run truth, and high-risk drill-down end to end.
- [x] 8.10 Record Phase Three posture, trend, dashboard, accessibility, test, and known-limit evidence; report it to the user and pause for confirmation before Phase Four.

## 9. Phase Four - Compatibility and Operational Hardening

- [x] 9.1 Re-run all existing server, runner, remote-acquisition, frontend, replay, accounting, and agent-led runtime tests to prove the change did not alter audit semantics.
- [x] 9.2 Add contract tests that compare legacy `/api/runs` payloads and artifact endpoints before and after the project migration, including imported run redirects.
- [x] 9.3 Add startup and recovery tests for partially applied migrations, stale SQLite locks, missing artifact directories, corrupt event tails, and interrupted posture backfill.
- [x] 9.4 Add security regression tests for local path traversal, URL credentials, unsafe Git revisions, artifact escape, SSE payload injection, secret leakage, oversized events, and raw prompt/response exposure.
- [x] 9.5 Add bounded pagination, query limits, journal replay limits, stream subscriber limits, and documented retention behavior for project, run, event, and dashboard APIs.
- [x] 9.6 Verify cancellation races, terminal idempotency, concurrent project scans, browser refresh, backend restart, stream-to-poll fallback, and poll-to-stream recovery.
- [x] 9.7 Update local startup, storage/migration, project workflow, SSE troubleshooting, dashboard semantics, security boundary, rollback, and first-release limitation documentation.
- [x] 9.8 Run frontend typecheck, unit tests, production build, backend unit/integration tests, API smoke tests, and a local browser smoke walkthrough using only safe fixtures.
- [x] 9.9 Validate this OpenSpec change strictly and reconcile every completed checkbox with concrete code, test, or documentation evidence.
- [x] 9.10 Record final compatibility, security, performance-bound, test, migration/rollback, and remaining-limit evidence; report it to the user for final acceptance.
