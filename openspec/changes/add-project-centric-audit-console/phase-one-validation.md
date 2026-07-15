# Phase One Validation Evidence

Date: 2026-07-14

## Delivered scope

- SQLite workspace schema v1 with project, run, migration receipt, future event index, posture snapshot, and finding identity tables.
- Project-aware `JobStore` compatibility facade, canonical local/remote source identities, transaction-safe first-run creation, archive guards, and read-only legacy `jobs.json` import.
- Local and public remote source preflight with allowed-root and Git policy enforcement, bounded metadata inspection, immutable remote revisions, and one-time 10-minute `source-preflight.v1` tokens.
- Project catalog, lifecycle APIs, project-scoped run APIs, and backward-compatible `/api/runs` plus artifact endpoints.
- Project-first frontend navigation, catalog, basic detail/history, compatibility redirects, and three-step scan wizard.
- Kinetic Typography dark visual system with square borders, acid-yellow action color, visible focus, reduced-motion fallback, mobile breakpoints, and stable technical surfaces.

## Automated evidence

- Backend: `python -m unittest tests.test_project_audit_workspace tests.test_web_backend_service tests.test_repository_acquisition -v`
  - 56 tests passed.
  - Covers WAL/foreign keys, duplicate identities, rollback, concurrency, migration idempotence and diagnostics, local policy limits, branch/tag/commit resolution, one-time token binding, lifecycle guards, legacy clients, all three source shapes, and a real `ScanJobRunner` queue/terminal lifecycle.
- Frontend: `npm run typecheck`
  - Passed.
- Frontend: `npm test`
  - 26 tests passed; one environment-gated local API smoke test skipped when `VITE_E2E_API_URL` was unset.
  - Covers project filters/actions, rename/archive behavior, wizard steps, duplicate ownership, GitHub revision selection, recoverable errors, project-scoped navigation, API contracts, and legacy run redirects.
- Frontend: `npm run build`
  - Production build passed: 1,774 modules transformed; generated HTML, CSS, and JS bundles.

## Browser evidence

- Local backend and Vite frontend were started against the real project database and APIs.
- Project catalog loaded migrated project history with safe source display and status.
- Local fixture preflight detected 2 files, 496 bytes, Python, and existing-project ownership.
- Wizard advanced from source to preflight to review without mock page data; final launch submission is covered by component and backend integration tests.
- At a 390x844 viewport, document width remained within the viewport, navigation targets were 48px high, filters stacked, and project actions stayed reachable.
- Visual review found and fixed two issues before acceptance: an odd-card empty grid column and unsafe default preflight of the whole working directory.

## Known Phase One limits

- Remote preflight integration uses deterministic Git command/resolver fixtures in automated tests; it does not require external network access during acceptance.
- The all-source queue test uses the real `ScanJobRunner` and job lifecycle with a bounded audit-function test double, so it proves orchestration without launching a costly audit corpus.
- Live Agent events, SSE reconnect/replay, and polling fallback are Phase Two work.
- Security posture scoring, confirmed-finding trends, and the full project dashboard are Phase Three work; current catalog filtering reflects latest run state only.
- Preflight tokens are intentionally in-memory for this release and are invalidated by backend restart.
