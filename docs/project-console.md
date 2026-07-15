# Project-Centric Audit Console Operations

This document describes the first-release project console implemented by the
`add-project-centric-audit-console` change. It is a single-user localhost tool,
not an authenticated multi-user service.

## Start the backend and frontend

From the repository root, start FastAPI on loopback:

```powershell
.\.venv\Scripts\python.exe -m uvicorn audit_agent.server.app:app --host 127.0.0.1 --port 8000
```

In a second terminal, start the frontend:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:5173/`. The supported first release must remain bound to
`127.0.0.1`; it has no login, authorization, CSRF protection for an exposed
deployment, or tenant isolation.

Local source preflight permits every local or mapped filesystem root visible to
the backend process by default. This is intentionally broad for the local
single-user course environment. To restore a least-privilege boundary, set one
or more explicit roots before starting the backend; Windows uses semicolons:

```powershell
$env:AUDIT_LOCAL_ALLOWED_ROOTS = "D:\course-repositories;D:\fixtures"
```

The path policy does not remove the independent 25,000-file and 128 MiB local
preflight budgets. Keep the service bound to `127.0.0.1`: allowing all roots
means the backend can read any path accessible to its operating-system account.

Public GitHub/GitLab preflight remains controlled by the remote-acquisition
settings documented in `docs/usage.md`. The browser never collects repository
credentials or model API keys.

## Storage and migration

The default Web storage layout is:

```text
.audit-cache/web/workspace.sqlite3   project/run/index/posture management data
.audit-cache/web/events/*.jsonl      append-only public event journals
runs/web/jobs.json                   legacy import source, when present
runs/<runtime-run>/                  authoritative reports, evidence and runtime artifacts
```

SQLite uses foreign keys, WAL mode, transactional writes, and a bounded busy
timeout. The database is an index and projection store; report, evidence,
runtime, replay, accounting, and tool artifacts under the run directory remain
authoritative.

At startup the service creates any missing schema objects idempotently, reads
legacy `jobs.json`, and records import receipts. It never rewrites or deletes
the legacy JSON file. A malformed file or row produces a sanitized migration
diagnostic without resetting already committed SQLite data. Repeated startup
does not duplicate imported job IDs.

Before changing versions, stop the backend and copy both `.audit-cache/web` and
the relevant `runs` directory to a separate backup location. Do not copy an
actively written SQLite database without using an SQLite-aware backup method or
stopping the process first.

## Project and scan workflow

1. Open **Projects** and choose **New scan**.
2. Select an existing project, or enter a local directory or canonical public
   GitHub/GitLab HTTPS URL.
3. Preflight checks the allowed-root/remote policy, inspects bounded metadata,
   detects duplicate source identity, and resolves a remote selector to an
   immutable commit. It does not execute repository code.
4. Review the source, immutable revision and scan configuration.
5. Submit the real scan. The resulting run belongs to exactly one project and
   opens at `/projects/<project_id>/runs/<run_id>`.

Projects may be renamed, archived while idle, and restored. Archive is
reversible and retains all runs and artifacts. There is deliberately no
permanent-delete endpoint. The global `/runs` view remains available, and a
legacy `/runs/<run_id>` frontend URL resolves the owning project before it
redirects.

Management list endpoints use bounded pagination:

- default page size: 50;
- maximum page size: 200;
- maximum offset: 100,000;
- responses include `total`, `limit`, `offset`, and `has_more`.

The active values and retention declarations are available from
`GET /api/options` under `console_limits`.

## Live events, replay and troubleshooting

The run page first reads the persisted event snapshot and then opens the
project-scoped SSE endpoint with the latest event ID. The public JSONL journal,
not an in-memory queue, defines ordering and later replay. Events are flushed
before delivery, use monotonically increasing IDs, and receive a second secret
redaction pass.

Default operational bounds are:

- 500 events in the snapshot/reconnect replay window;
- 8 concurrent SSE subscribers per run;
- 32 concurrent SSE subscribers for the process;
- 10-second server heartbeat under the default application configuration;
- 100 retained in-memory sanitized event diagnostics.

If a snapshot contains more than the replay window, it returns the most recent
window with `history_status=truncated`, `history_reason=replay-window-limit`,
and explicit count/start metadata. A reconnect cursor older than that window
returns HTTP 409 `event-replay-limit-exceeded` with a safe reset cursor. A
subscriber limit returns HTTP 429 and `Retry-After: 5`.

The frontend retries short failures with bounded backoff. After three failures
it visibly enters polling fallback, continues status/artifact reconciliation,
and attempts background SSE recovery every 15 seconds. Refreshing, closing or
navigating away from a page closes only the browser stream; it never cancels
the backend job. Cancellation requires the separate confirmation action.

Troubleshooting order:

1. Check `/api/health`, then the run status endpoint.
2. Read `/events/snapshot` and inspect `history_status`, `history_reason`, and
   `last_event_id`.
3. For HTTP 409, reload the snapshot and reconnect from its latest ID.
4. For HTTP 429, close duplicate tabs or wait for disconnected streams to be
   released.
5. If the UI reports polling fallback, keep the page open; artifacts and job
   status remain available while background SSE recovery continues.
6. After an unclean backend stop, restart normally. Startup reconciliation
   truncates an invalid JSONL tail and rebuilds the derived event index without
   reusing an event ID.

## Dashboard semantics

The project dashboard separates the newest run from the newest complete
posture. A failed, cancelled, degraded, coverage-incomplete, evidence-incomplete
or accounting-incomplete latest run is shown as such; an older complete posture
is explicitly labelled historical.

Confirmed counts and the core risk score use only evidence-gated validated
findings. Candidate, pending, manual, rejected and inconclusive results remain
separate. The trusted formula is versioned and calculated in Python:

```text
min(100, round_half_up(sum(severity_weight * clamped_confidence)))
critical=25, high=15, medium=7, low=2, informational=0
```

Missing or non-finite confidence uses the published conservative fallback and
is disclosed in score metadata. Only complete comparable runs may resolve a
previous finding. Failed or incomplete runs leave prior findings unconfirmed.
Fingerprint algorithm versions must match before the dashboard claims new,
persistent, resolved or reintroduced continuity.

Dashboard responses retain at most 12 recent run/trend points and 20 high-risk
drill-down items. This display bound does not delete stored runs, snapshots or
finding identities.

## Security boundary

- Bind backend and frontend to loopback only.
- Local paths are resolved server-side and must remain under an allowed root.
- Remote sources permit only credential-free HTTPS GitHub/GitLab URLs and safe
  revision selectors; Git runs non-interactively with hardened arguments.
- Preflight tokens are short-lived, one-time, and bound to canonical source,
  project and immutable revision.
- Public event projection excludes prompts, raw provider responses, hidden
  reasoning, environment dumps, authorization headers, unbounded stdout/stderr
  and unrestricted code.
- Public artifact access is limited to approved categories and contained paths.
- Static candidates are never relabelled as confirmed vulnerabilities by the
  dashboard.

## Retention, recovery and rollback

The first release performs no automatic deletion. Projects, runs, run
artifacts, event journals and posture snapshots are retained until an operator
removes storage outside the application. Event diagnostics are the exception:
only the latest 100 sanitized in-memory diagnostics are kept, and they reset on
process restart. Expired unused preflight tokens are removed from memory.

If SQLite is temporarily locked, requests fail after the bounded busy timeout;
release the other writer and retry. Do not delete the database to clear a lock.
Missing run artifacts return explicit 404 responses and are not reconstructed
from SQLite summaries. Posture projection is idempotent and can be rerun from
authoritative artifacts after interruption.

Rollback to the previous run-oriented application:

1. Stop backend and frontend processes.
2. Preserve `.audit-cache/web`, `runs/web/jobs.json`, and all run directories.
3. Start the previous application version. It reads the untouched legacy JSON
   and existing run directories and may ignore the new SQLite/event files.
4. Do not write a synthesized `jobs.json` from SQLite. New runs that exist only
   in SQLite will not appear in the old UI; retain their run directories and
   return to the project-console version to access them.

## First-release limitations

- No accounts, roles, multi-tenancy or safe non-localhost deployment.
- No private repository credentials, SSH repositories or arbitrary Git hosts.
- No permanent deletion, pause/resume control or live human instruction to an
  Agent.
- Legacy reports without modern verification, coverage and accounting metadata
  cannot produce a trusted posture and are labelled unavailable.
- Cross-version fingerprint history is non-comparable without a future trusted
  migration.
- Snapshot replay is intentionally bounded; the append-only journal remains on
  disk, but the UI initially displays only the configured recent window.

## Verification commands

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -q
cd frontend
npm test
npm run typecheck
npm run build
```

OpenSpec verification from the repository root:

```powershell
openspec validate add-project-centric-audit-console --strict
```
