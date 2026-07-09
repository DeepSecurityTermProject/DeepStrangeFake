## Context

The project now has a reusable `AgentRuntime` behind the stable `run_audit(target, config, output_dir)` entry point. Each scan creates a run directory with `runtime_state/state.json`, `messages/messages.jsonl`, `reports/report.json`, and `reports/report.md`. This is a good foundation for a web backend because the service can orchestrate scan jobs and expose existing artifacts without reimplementing the four-agent audit logic.

The current package has no web dependencies and is designed for local Python 3.12 execution. The first backend should therefore be a local service suitable for a development UI, experiment demos, and course acceptance checks, not a multi-tenant production platform.

## Goals / Non-Goals

**Goals:**

- Provide a FastAPI backend for creating scan jobs and reading job/run artifacts.
- Keep the service thin: request validation, job tracking, background execution, and artifact reads.
- Reuse `run_audit()` and existing runtime config objects.
- Make job status visible before, during, and after execution.
- Restrict artifact access to whitelisted files under the run directory associated with a known job.
- Add offline tests that can run with mock LLM mode and local fixtures.

**Non-Goals:**

- Do not build a frontend UI in this change.
- Do not introduce Redis, Celery, database migrations, user accounts, authentication, or remote multi-user deployment.
- Do not change `AgentRuntime`, scanner behavior, LLM decision policy, MCP behavior, or report schema unless required by the API wrapper.
- Do not expose arbitrary filesystem browsing or arbitrary file downloads.
- Do not accept API keys or secrets in HTTP request bodies.

## Decisions

### Decision 1: Add a Thin FastAPI Service Layer

Create `audit_agent.server` with `app.py`, request/response schemas, a job store, a scan runner, and artifact helpers. The API layer should convert HTTP requests into `AuditConfig` options and call the existing `run_audit()` path.

Alternative considered: expose `AgentRuntime` directly as a long-lived service object. That would couple the backend to runtime internals and make later runtime refactors harder. The public compatibility boundary is already `run_audit()`, so the backend should start there.

### Decision 2: Use Local JobStore for the First Implementation

Use an in-process job registry with optional JSON persistence under a backend state directory such as `runs/web/jobs.json`. Each job stores `job_id`, `target`, `status`, `created_at`, `started_at`, `finished_at`, `run_dir`, `summary`, and `error`.

Alternative considered: Redis/Celery or a SQL database. Those are better for multi-process production deployments, but they add setup cost and are unnecessary for the current local prototype.

### Decision 3: Run Scans in a Bounded Background Executor

When `POST /api/runs` is accepted, the API creates a job and submits scan execution to a bounded `ThreadPoolExecutor`. The executor should default to one worker so LLM/MCP scans do not exhaust local resources. The response returns immediately with `202 Accepted`.

Alternative considered: run scans synchronously in the request handler. That is simpler, but long LLM/MCP scans would block the HTTP request and make status polling impossible.

### Decision 4: Keep Artifact Access Whitelisted

Artifact endpoints should resolve only from the run directory associated with a known job. They should serve:

- `runtime_state/state.json`
- replay summary derived from `messages/messages.jsonl`
- `reports/report.json`
- `reports/report.md`

No endpoint should accept an arbitrary path parameter in the first version.

Alternative considered: generic artifact browsing by relative path. That is convenient but creates path traversal and accidental secret exposure risk.

### Decision 5: Support Mock-First Configuration

The request schema should expose safe knobs already present in the CLI: `runtime`, `llm_provider`, `model`, `llm_decisions`, `llm_decision_roles`, `memory_mode`, `mcp_mode`, `validation_level`, and `output`. Defaults should allow a local mock scan without API keys.

Alternative considered: expose the full nested `AuditConfig`. That would be flexible, but it leaks too many low-level fields into the web API and makes validation harder.

## Risks / Trade-offs

- [Risk] In-process jobs are lost when the server restarts. -> Persist job metadata to JSON and recover completed job metadata from run paths where possible; document that this is not a distributed queue.
- [Risk] Concurrent scans can consume too much CPU, disk, or model budget. -> Default executor concurrency to one and make it configurable later.
- [Risk] Artifact endpoints could expose unintended files. -> Do not implement generic path reads; use explicit report/runtime endpoints only.
- [Risk] Live LLM/MCP calls can be slow. -> Use async job submission and status polling; keep API tests mock/offline.
- [Risk] Typos in the change ID persist. -> Keep the user-requested OpenSpec ID `add-web-backend-servic`, but name the service and capability text "web backend service" consistently.

## Migration Plan

1. Add FastAPI and uvicorn dependencies to project metadata.
2. Add `audit_agent/server` modules and tests with mock scans.
3. Add a local service startup command or documented uvicorn command.
4. Update usage docs with API examples and artifact inspection flow.
5. Validate through unit tests, a local mock API scan, report retrieval, replay retrieval, and OpenSpec strict validation.

Rollback is simple: remove the server package and dependencies. The CLI-first runtime remains unchanged because the backend calls `run_audit()` through the existing compatibility boundary.

## Open Questions

- Should the first implementation include a `serve` CLI subcommand, or is `python -m uvicorn audit_agent.server.app:app` enough for the course demo?
- Should completed jobs be discoverable only from the current server process, or should the API scan `runs/` on startup to reconstruct old jobs?
- Should the first API return Markdown reports as text/plain, JSON reports as application/json, or always return JSON envelopes with file content?
