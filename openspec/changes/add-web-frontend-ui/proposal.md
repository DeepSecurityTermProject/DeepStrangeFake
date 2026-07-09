## Why

The backend can now create scan jobs and expose runtime artifacts, but users still need to exercise the system through raw HTTP calls or CLI commands. A small React frontend will make the audit workflow demonstrable: create a scan, watch job status, inspect findings, review runtime tasks, replay lifecycle, and read the Markdown report in one local UI.

## What Changes

- Add a `frontend/` Vite + React + TypeScript single-page app for local validation of the audit workflow.
- Add a scan creation page covering target, runtime, mock/real provider mode, LLM decisions, memory, MCP, and validation options.
- Add a task list page showing queued/running/succeeded/failed jobs, run directory, and validated finding count.
- Add a task detail page with tabs for Summary, Findings, Runtime Tasks, Replay, and Markdown Report.
- Add polling against `GET /api/runs/{job_id}` and lazy-load runtime/report/replay artifacts once a job reaches a terminal state.
- Add small backend helper endpoints for frontend health and option discovery.
- Add frontend tests and API contract tests so the UI can be validated without live LLM or MCP services.

## Capabilities

### New Capabilities

- `frontend-backend-support`: Defines the backend helper endpoints and compatibility behavior needed by the frontend.
- `web-frontend-shell`: Defines the Vite React TypeScript app shell, routing, API client, and local development integration.
- `scan-workflow-ui`: Defines the scan creation and task list user workflows.
- `run-detail-inspection-ui`: Defines the run detail tabs for summary, findings, runtime tasks, replay, and Markdown report.

### Modified Capabilities

- None. Existing scan job, runtime state, replay summary, and report APIs are reused as the frontend's primary data source.

## Impact

- Affected code: new `frontend/` app, backend helper routes under `audit_agent/server`, docs, and tests.
- New frontend dependencies: Vite, React, TypeScript, React Router, TanStack Query, and a lightweight icon package such as lucide-react.
- Backend behavior: add non-secret health/options endpoints; existing `/api/runs` behavior remains compatible.
- Development workflow: run FastAPI on `127.0.0.1:8000` and Vite frontend on `127.0.0.1:5173` with `/api` proxied to the backend.
- Security: frontend must not collect API keys or secrets; real provider mode only selects provider/model fields while secrets remain in backend environment configuration.
