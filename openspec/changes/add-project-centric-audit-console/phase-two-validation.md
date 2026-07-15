# Phase Two Validation Evidence

Date: 2026-07-15

## Delivered scope

- Added the versioned `audit-event.v1` public event contract with explicit category, severity, status, size, depth, string, list, and monotonic run-scoped ID limits.
- Added per-web-run append-only JSONL journals under the management event directory. Appends are run-locked, flushed and `fsync`-ed before live notification; failed writes are rolled back and never become replay-visible.
- Added journal-authoritative startup reconciliation that truncates an invalid crash tail and rebuilds the derived SQLite event index without inventing or duplicating IDs.
- Added a second-pass public projection that only maps allowlisted lifecycle and message-bus fields. It excludes full prompts, raw provider bodies, hidden reasoning, environment dumps, stdout/stderr, unbounded code/tool content, and non-public artifact categories.
- Wired queued/running/phase/terminal task transitions, selected runtime tasks and tools, structured Agent decisions, Agent-led hypotheses/actions/evidence gates/budgets, validation activity, and fallback/degraded reasons into the public projection without changing audit decisions or tool execution.
- Added project-scoped and compatibility SSE endpoints with persisted replay, `Last-Event-ID` and query cursor recovery, live handoff, heartbeats, terminal snapshots, deterministic cursor errors, and cursor-driven slow-client behavior without per-client unbounded queues.
- Added a safe event snapshot endpoint, safe rerun configuration endpoint, and allowlisted run-artifact endpoint.
- Replaced the run detail page with a project-scoped live investigation workspace: header truth, effective mode, progress, elapsed time, budget, connection state, unified filterable timeline, bounded details, authorized artifact links, Agent/task/evidence side panel, confirmed cancellation, terminal rerun review, explicit failure/degraded/cancelled/unavailable/reconstructed/fallback states, and preserved terminal report/replay tabs.
- Added idempotent frontend event merging, snapshot reconciliation, explicit cursor resume, bounded reconnect backoff, visible polling fallback, and background recovery.

## Automated validation

- Backend affected regression suite: **127 passed**.
  - Includes event ordering/concurrency, unsupported messages, redaction, output bounding, persistence failure, crash reconciliation, terminal consistency, slow readers, initial replay, concurrent live delivery, `Last-Event-ID`, cursor errors, terminal reconnect, persistence-before-delivery, active-job reconnect, and identical terminal replay IDs/order.
  - Includes existing project workspace, repository acquisition, runtime kernel, message bus, graph artifacts, runtime CLI, and Agent-led investigation regressions.
- Frontend suite: **33 passed, 1 environment-gated API smoke skipped**.
  - Includes reducer ordering/duplicate suppression, refresh recovery, stream fallback, timeline filters, effective-mode labels, secret-safe presentation, confirmation cancellation, rerun review, and unavailable legacy history.
- Frontend production build: **passed** (`1776` modules transformed; production assets emitted).
- `openspec validate add-project-centric-audit-console --strict`: **passed**.
- `git diff --check`: **passed** (line-ending notices only).

## Browser validation

- Started the real FastAPI and Vite applications and exercised a persisted active-job journal through the real frontend/API path.
- Desktop active state showed **9 ordered public events**, Live connection health, Agent/category/phase/severity filters, hypothesis/rationale summary, action, evidence-gate, and budget details.
- Terminal reload showed **10 identical ordered events**, Succeeded status, `agent-led` effective mode, terminal report/replay section, and the project-scoped rerun review link.
- The normalized budget exposed `remaining_token_budget` as accounting data rather than misclassifying it as a credential.
- At a **390 x 844** viewport, the header and workspace collapsed to one column, all four filters remained visible, all events rendered, and `body.scrollWidth <= viewport width` (no horizontal overflow).
- Browser console error log was empty.

## Known limits and compatibility behavior

- Legacy/imported jobs without an `audit-event.v1` journal are explicitly labeled `unavailable`; this phase does not synthesize a lifecycle that never existed.
- Journal locking is process-local and matches the current single-process web service. A future multi-process deployment must add a cross-process lock or single journal writer.
- The public event stream intentionally provides bounded rationale summaries, not hidden chain-of-thought, full prompts, raw model responses, or unrestricted tool output.
- Generic artifact access is restricted to the public category allowlist and contained under the terminal run directory. Prompt, model-response, message-log, environment, and arbitrary filesystem paths remain inaccessible.
- A local browser smoke audit attempted to write into the pre-existing `runs/` directory but that directory's host ACL denied the worker. Browser acceptance therefore used an isolated synthetic course event fixture against the real journal/SSE/UI path; automated runner regressions use writable temporary run roots.

## Phase gate

Phase Two tasks 4.1 through 6.11 are complete. Phase Three posture/risk/trend work has not started and requires explicit user confirmation.
