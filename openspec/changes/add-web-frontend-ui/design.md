## Context

The project currently has a CLI-first audit runtime and a local FastAPI backend. The backend already exposes job creation, job listing/status, runtime state, replay summary, and report files. There is no frontend directory or Node/Vite project yet.

The frontend should be a validation UI rather than a public product site. It should feel like an operational audit console: dense, direct, and built for repeated scanning and evidence inspection. It should not be a landing page or marketing page.

## Goals / Non-Goals

**Goals:**

- Create `frontend/` as a Vite + React + TypeScript single-page app.
- Provide three primary routes: create scan, run list, and run detail.
- Cover all requested scan fields: target, runtime, mock/real provider, LLM decisions, memory, MCP, and validation.
- Poll `/api/runs/{job_id}` while a job is queued or running.
- Load runtime state, replay summary, report JSON, and Markdown report after a job reaches `succeeded` or `failed`.
- Add backend helper endpoints for frontend health checks and option discovery.
- Keep the UI local-first and safe: no API key input fields.

**Non-Goals:**

- Do not add authentication, multi-user accounts, or remote deployment packaging.
- Do not add job cancellation, benchmark management, or live log streaming in this first UI.
- Do not change the audit runtime or report schema.
- Do not build a landing page.
- Do not expose arbitrary artifact browsing.

## Decisions

### Decision 1: Use `frontend/` with Vite React TypeScript

Create a standalone `frontend/` app with Vite, React, TypeScript, and React Router. This keeps the Python backend and Node frontend concerns separate and makes the UI easy to run, test, and eventually package.

Alternative considered: server-render templates from FastAPI. That would avoid Node dependencies, but it would make tabs, polling, and client-side state more awkward and less representative of a modern UI.

### Decision 2: Use TanStack Query for API State and Polling

Use TanStack Query for job list fetching, job detail polling, and artifact loading. Polling should run only for non-terminal jobs and stop once a job is `succeeded` or `failed`.

Alternative considered: custom `setInterval` state. That is lighter initially but more error-prone around cleanup, retries, stale data, and dependent artifact fetches.

### Decision 3: Add Minimal Backend Helper Endpoints

Add:

- `GET /api/health`: returns backend readiness and service name.
- `GET /api/options`: returns enum values used by the scan creation form, including provider modes, memory modes, MCP modes, validation levels, and LLM decision roles.

The frontend should still be able to fall back to hardcoded defaults if `/api/options` is unavailable.

Alternative considered: hardcode all options only in the frontend. That works for the first demo but creates drift if backend enums change.

### Decision 4: Keep Form Model Close to `ScanRunRequest`

The create scan form should produce a request body matching the backend schema:

- `target`
- `runtime`
- `llm_provider`
- `model`
- `llm_decisions`
- `llm_decision_roles`
- `memory_mode`
- `mcp_mode`
- `validation_level`

Real provider mode should set provider/model fields but must not ask for API keys. Secrets remain in `.env` or process environment.

### Decision 5: Detail Page Loads Artifacts Lazily

The run detail route should first fetch status from `/api/runs/{job_id}`. Once status is terminal, it should fetch:

- `/api/runs/{job_id}/runtime-state`
- `/api/runs/{job_id}/replay-summary`
- `/api/runs/{job_id}/reports/report.json`
- `/api/runs/{job_id}/reports/report.md`

If an artifact endpoint returns 404, the tab should show an unavailable state instead of breaking the page.

### Decision 6: Operational UI Style

Use a restrained dashboard layout: left navigation, compact top status area, table/list views, tabs, and structured detail panels. Use icon buttons where useful and keep card radius at 8px or below. The first screen should be the usable scan console, not a hero page.

## Risks / Trade-offs

- [Risk] Frontend and backend schemas may drift. -> Centralize API types in `frontend/src/api/types.ts` and add API contract tests against representative payloads.
- [Risk] Polling can keep running after completion. -> Use terminal status checks in TanStack Query polling configuration.
- [Risk] Markdown rendering can create unsafe HTML concerns. -> First implementation can render Markdown as plain/preformatted text or use a safe Markdown renderer with raw HTML disabled.
- [Risk] Node dependency installation can be slow in restricted environments. -> Keep dependencies minimal and document manual install commands.
- [Risk] Vite dev server and FastAPI CORS can conflict. -> Use Vite proxy for `/api` in development; add backend CORS only if direct cross-origin access is needed.

## Migration Plan

1. Add backend health/options endpoints and tests.
2. Scaffold `frontend/` with Vite React TypeScript.
3. Add API client/types and app routing.
4. Build scan creation page and task list page.
5. Build run detail tabs and polling/artifact loading.
6. Add frontend unit/component tests and an end-to-end mock smoke path.
7. Update docs with backend/frontend startup commands and demo flow.

Rollback is straightforward: remove `frontend/` and backend helper endpoints. Existing backend scan/job APIs remain unchanged.

## Open Questions

- Should the app route root `/` open the scan creation page or the task list page? Recommended: scan creation page with a task list panel nearby.
- Should Markdown be rendered as formatted Markdown in the first implementation, or shown as plain text first for safety and speed?
- Should provider mode be only `mock` and `openai-compatible`, or should the UI display model presets loaded from `/api/options`?
