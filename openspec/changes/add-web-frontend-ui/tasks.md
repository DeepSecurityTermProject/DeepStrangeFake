## 1. Backend Support and Contract Tests

- [x] 1.1 Add backend tests for `GET /api/health` returning non-secret service readiness metadata.
- [x] 1.2 Add backend tests for `GET /api/options` returning provider modes, memory modes, MCP modes, validation levels, and LLM decision roles.
- [x] 1.3 Implement `GET /api/health` and `GET /api/options` in the FastAPI backend.
- [x] 1.4 Verify existing `/api/runs` endpoints remain compatible after helper endpoints are added.

## 2. Frontend Project Setup

- [x] 2.1 Create `frontend/` Vite + React + TypeScript project structure.
- [x] 2.2 Add frontend dependencies for React Router, TanStack Query, and lucide-react icons.
- [x] 2.3 Configure Vite dev proxy from `/api` to `http://127.0.0.1:8000`.
- [x] 2.4 Add TypeScript, test, build, and preview npm scripts.
- [x] 2.5 Add base app shell with navigation and operational dashboard styling.

## 3. API Client and State Management

- [x] 3.1 Add TypeScript types for scan request, job status, job list, runtime state, replay summary, and report JSON.
- [x] 3.2 Add a centralized API client for health, options, create run, list runs, run status, runtime state, replay summary, report JSON, and Markdown report.
- [x] 3.3 Add TanStack Query setup and polling logic that stops on `succeeded` or `failed`.
- [x] 3.4 Add reusable loading, error, empty-state, status badge, and tab components.

## 4. Scan Workflow UI

- [x] 4.1 Implement scan creation page with target, runtime, provider, model, LLM decision, memory, MCP, and validation controls.
- [x] 4.2 Prevent empty target submissions and show form validation state.
- [x] 4.3 Submit scan creation requests and navigate to the created job detail route.
- [x] 4.4 Implement task list page with status, target, run directory, validated count, timestamps, refresh, and detail navigation.

## 5. Run Detail Inspection UI

- [x] 5.1 Implement run detail route that polls `/api/runs/{job_id}` until terminal status.
- [x] 5.2 Load runtime state, replay summary, report JSON, and Markdown report after terminal status.
- [x] 5.3 Implement Summary tab with run status, counts, run directory, runtime state ref, and failure error.
- [x] 5.4 Implement Findings tab from `report.json.findings`.
- [x] 5.5 Implement Runtime Tasks tab from `runtime_state.tasks`.
- [x] 5.6 Implement Replay tab for decision lifecycle and runtime lifecycle summaries.
- [x] 5.7 Implement Markdown Report tab with readable report content.
- [x] 5.8 Show unavailable states for artifact endpoints that return `404`.

## 6. Verification and Documentation

- [x] 6.1 Add frontend unit/component tests for form validation, API client behavior, polling termination, and run detail tabs.
- [x] 6.2 Run frontend typecheck, tests, and production build.
- [x] 6.3 Run backend tests and full Python offline suite.
- [x] 6.4 Run an end-to-end local smoke: create mock scan from UI, poll to success, and inspect all detail tabs.
- [x] 6.5 Update docs with backend and frontend startup commands plus demo flow.
- [x] 6.6 Run `openspec validate "add-web-frontend-ui" --strict`.
