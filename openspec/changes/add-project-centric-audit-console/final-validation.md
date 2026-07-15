# Final Validation Evidence

## Outcome

The `add-project-centric-audit-console` change is implemented through Phase Four.
The project-first console, durable public event stream, trusted posture dashboard,
legacy compatibility layer, recovery behavior, operational bounds, documentation,
and safe local browser path are covered by code and current acceptance evidence.

## Requirement-to-evidence reconciliation

The task checklist was reconciled by implementation slice before final completion:

| Tasks | Authoritative implementation evidence | Verification evidence |
| --- | --- | --- |
| 1.1-1.6 | `audit_agent/server/workspace_store.py`, `audit_agent/server/job_store.py` | `tests/test_project_audit_workspace.py`, Phase One evidence |
| 2.1-2.8 | `audit_agent/server/schemas.py`, `preflight.py`, `app.py`, `repository_acquisition.py` | project-workspace, repository-acquisition and Web backend suites |
| 3.1-3.11 | project-first routes/pages, API client/types, scan wizard and shared CSS | frontend component/client tests and `phase-one-validation.md` |
| 4.1-4.7 | `audit_agent/server/audit_events.py` journal and projection | `tests/test_audit_event_stream.py` |
| 5.1-5.5 | project/global SSE routes and cursor handling in `app.py` | SSE history/live/reconnect/terminal tests |
| 6.1-6.11 | `frontend/src/events`, run workspace and detail tabs | event reducer/hook/UI tests and `phase-two-validation.md` |
| 7.1-7.9 | `audit_agent/server/posture.py` and workspace snapshot/finding storage | `tests/test_project_security_posture.py` |
| 8.1-8.10 | `ProjectSecurityDashboard.tsx`, project detail and finding deep links | dashboard/detail tests, browser fixture and `phase-three-validation.md` |
| 9.1 | unchanged audit/runtime compatibility | complete Python and frontend suites |
| 9.2 | versioned legacy Web contract fixture | imported job/API/artifact contract test and legacy redirect test |
| 9.3 | idempotent schema/event/posture recovery paths | partial schema, lock, missing artifact, corrupt tail and interrupted backfill tests |
| 9.4 | existing policy/containment plus event projection boundaries | consolidated negative security regression tests |
| 9.5 | `audit_agent/server/limits.py`, paginated stores/routes and bounded event service | pagination, input-bound, replay-window and subscriber-limit tests |
| 9.6 | immutable first-terminal-state handling and reconnect behavior | thread race, concurrent run, restart, refresh and stream recovery tests |
| 9.7 | `docs/project-console.md` and updated `docs/usage.md` | manual documentation review plus commands below |
| 9.8 | current backend/frontend and disposable real localhost fixture | full tests, typecheck, build, API and browser smoke evidence below |
| 9.9 | all checked tasks mapped above | strict OpenSpec validation and `git diff --check` |
| 9.10 | this document | final progress and validation rerun after checklist update |

Earlier slice detail remains in:

- `phase-one-validation.md`
- `phase-two-validation.md`
- `phase-three-validation.md`

## Compatibility evidence

- The final offline Python suite ran **383 tests**, all passing, with **7 explicit
  environment/opt-in skips**. It covers server, runner, remote acquisition,
  replay, LLM accounting, Agent-led runtime, deterministic/graph runtime,
  reporting, validation and the project console.
- The final frontend suite ran **40 tests**: **39 passed** and the existing live
  API-environment smoke was skipped.
- `tests/legacy_web_api_contract.v1.json` freezes the pre-project
  `POST /api/runs`, run-status and artifact fields. The hardening suite imports a
  legacy `jobs.json`, proves every legacy field/value and artifact endpoint is
  preserved, verifies additive project fields, and confirms the source JSON is
  byte-for-byte unchanged.
- `frontend/src/pages/LegacyRunRedirect.test.tsx` proves a legacy run resolves
  its owning project before redirecting to the project-scoped run route.
- CLI/runtime entrypoints remained covered by the full suite; no project-console
  path replaces `run_audit()` or the existing artifact authority.

## Recovery and concurrency evidence

`tests/test_project_console_hardening.py` proves:

- startup completes missing tables even when the current schema receipt already
  exists, and repeated initialization remains idempotent;
- an external SQLite writer lock fails after the bounded busy timeout, then the
  same write succeeds after the lock is released;
- restart truncates only an invalid JSONL tail and rebuilds the event index from
  the valid journal prefix;
- missing runtime/replay/report directories return stable `artifact-not-found`
  responses instead of fabricated data;
- a posture backfill interrupted after its first snapshot resumes and produces
  the same ordered two-snapshot result on repeated execution;
- real concurrent cancellation/completion races commit exactly one terminal
  state and one matching terminal event. Later succeeded, degraded, failed or
  cancelled updates cannot overwrite that winner;
- concurrent project run creation, browser refresh, backend restart,
  SSE-to-poll fallback and poll-to-SSE recovery remain covered by focused suites.

## Security regression evidence

The final negative tests verify that:

- a normalized `allowed/../outside` local path is rejected outside configured
  roots;
- credential-bearing URLs are rejected before Git and do not echo the password;
- unsafe branch syntax is rejected before the command runner is invoked;
- encoded/backslash artifact traversal cannot escape the public category;
- newline/`id:`/`event:` content remains inside JSON data and cannot inject an
  SSE frame;
- configured or credential-like secrets are redacted before journal/SSE output;
- prompt, raw response and authorization fields are absent from the public
  event journal;
- a 100,000-character input is deterministically bounded below the 16 KiB
  public event limit.

Existing remote-acquisition and event suites additionally cover host policy,
archive/link containment, wrong origins, resource budgets, persistence-before-
delivery, unsupported internal messages and authorized artifact references.

## Published operational bounds

The versioned non-secret values are centralized in
`audit_agent/server/limits.py` and returned by `/api/options`:

| Boundary | Value |
| --- | ---: |
| Default management page | 50 records |
| Maximum page | 200 records |
| Maximum offset | 100,000 |
| Event snapshot/reconnect window | 500 events |
| SSE subscribers per run | 8 |
| SSE subscribers per process | 32 |
| In-memory sanitized diagnostics | 100 |
| Dashboard recent run/trend points | 12 |
| Dashboard high-risk drill-down items | 20 |

Over-limit pagination inputs return 422; an old replay cursor returns 409 with
reset metadata; a saturated subscriber pool returns 429 with `Retry-After: 5`.
The first release has no automatic project, run, artifact, event-journal or
posture deletion. Snapshot/display bounds do not delete authoritative history.

## Final automated verification

Backend:

```text
.venv\Scripts\python.exe -m unittest discover -s tests -q
Ran 383 tests ... OK (skipped=7)
```

Frontend:

```text
npm test
Test Files 12 passed, 1 skipped
Tests 39 passed, 1 skipped

npm run typecheck
passed
```

The normal `npm run build` completed TypeScript checking but could not create
`frontend/dist/assets` because that default directory was occupied by another
session. The same production Vite build was then run without overwriting that
directory:

```text
npx vite build --configLoader runner --outDir dist-codex-project-console-final
1777 modules transformed
CSS 29.98 kB; JavaScript 338.10 kB
built successfully
```

The isolated output directory was removed after verification.

Source/spec hygiene:

```text
openspec validate add-project-centric-audit-console --strict
valid

git diff --check
passed (only existing Git config/line-ending warnings)
```

## API and browser smoke

A disposable localhost fixture used a dedicated SQLite database, event root and
run-artifact directory. It contained two complete comparable runs followed by a
failed run.

API smoke observed:

- health `ok`;
- paginated project count 1 with correct metadata;
- dashboard state `stale-historical-posture`;
- actual latest status `failed`;
- latest complete trusted risk **40** and confirmed count **2**.

The in-app browser verified the real FastAPI/Vite path:

- project catalog showed the failed latest state and opened the correct project;
- dashboard separated latest-run truth from historical complete posture;
- numeric trend rows were 15/1, 40/2 and incomplete/unconfirmed;
- the critical command-injection deep link opened the owning run, selected the
  Findings tab, and marked `command-current` active;
- at 390x844 the loaded dashboard had 375 CSS-pixel content width, no horizontal
  overflow and no checked visible interactive control below 44x44 pixels;
- browser console errors: none.

The disposable tab, servers, fixture module, environment override, database,
artifacts and isolated build directory were removed after validation. Existing
ports/processes belonging to other sessions were not stopped.

## Migration, rollback and retained limitations

Migration/rollback instructions are documented in `docs/project-console.md`.
The authoritative rollback facts are:

- legacy `runs/web/jobs.json` is read-only and retained;
- detailed run directories remain unchanged and authoritative;
- the previous run-oriented application may ignore the new SQLite and event
  files;
- runs created only in SQLite will not appear in the old UI, so storage must be
  preserved when rolling back and returning forward.

Remaining intentional first-release limits:

- localhost single-user deployment only; no authentication, RBAC or tenants;
- public credential-free GitHub/GitLab only; no private/SSH repositories;
- no permanent deletion, pause/resume or live human Agent instruction;
- legacy reports lacking verification/coverage/accounting metadata remain
  explicitly unavailable for trusted posture;
- incompatible fingerprint versions are non-comparable without a future trusted
  migration;
- event journals are retained, but initial UI replay is bounded to the published
  window;
- live provider, live network acquisition and live Docker tests remain explicit
  opt-in environment checks rather than default acceptance dependencies.

The two benchmark-selection nested repositories were already dirty and were not
modified by this change.
