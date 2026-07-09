## Why

The audit system is currently CLI-first: `run_audit()` can create rich runtime artifacts, but external users cannot start scans or inspect run state through a stable service API. A thin FastAPI backend is needed so a future web UI or integration client can create scan jobs, track progress, and read runtime evidence without reimplementing the CLI flow.

## What Changes

- Add a FastAPI web backend that exposes local HTTP endpoints for creating scan jobs and reading audit results.
- Add a local scan job lifecycle layer that maps request-level `job_id`s to `run_dir`, current status, summary, and errors.
- Reuse the existing `run_audit()` / `AgentRuntime` execution path instead of duplicating scanner or agent orchestration logic.
- Add read-only endpoints for `runtime_state/state.json`, replay summaries from `messages/messages.jsonl`, and report files under `reports/`.
- Add a small service entry point and development startup documentation.
- Add tests for API request validation, job status transitions, artifact access, report access, and path traversal denial.

## Capabilities

### New Capabilities

- `web-backend-api`: Defines the FastAPI HTTP surface for creating scan jobs, listing jobs, reading job status, and serving report/runtime endpoints.
- `scan-job-lifecycle`: Defines queued/running/succeeded/failed job state management and how web requests delegate to the existing audit runtime.
- `runtime-artifact-access`: Defines safe read-only access to runtime state, replay summaries, and report files produced by a scan run.

### Modified Capabilities

- None. Existing runtime, decision, replay, and reporting behavior is reused as-is behind the web backend.

## Impact

- Affected code: new `audit_agent/server/` modules, optional CLI `serve` entry point, tests, and docs.
- Public API: new local HTTP API under `/api/runs`.
- Dependencies: add `fastapi` and `uvicorn` for the backend service; tests may use FastAPI's test client.
- Security: artifact reads must be scoped to known job run directories and whitelisted filenames only; API requests must never accept raw API keys.
- Compatibility: existing CLI commands and `run_audit()` behavior remain unchanged.
