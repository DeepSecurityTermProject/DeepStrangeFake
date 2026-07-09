## 1. Test Scaffolding and Dependencies

- [x] 1.1 Add FastAPI backend dependencies to project metadata.
- [x] 1.2 Add API test scaffolding using FastAPI test client and local vulnerable fixture scans.
- [x] 1.3 Add request/response schema tests for create-run payload validation and unsupported enum rejection.
- [x] 1.4 Add compatibility tests proving existing CLI `scan` and `replay` commands still work after backend modules are added.

## 2. Job Lifecycle Layer

- [x] 2.1 Implement web job models for `queued`, `running`, `succeeded`, and `failed` states.
- [x] 2.2 Implement a local `JobStore` with stable job IDs, timestamps, target, run directory, summary, and sanitized error fields.
- [x] 2.3 Add tests for job creation, status transitions, failure recording, and job listing.
- [x] 2.4 Implement a bounded background scan runner that submits jobs and calls `run_audit(target, config, output_dir)`.
- [x] 2.5 Map web request options to `AuditConfig` fields for runtime, LLM provider/model, LLM decisions, memory mode, MCP mode, and validation level.

## 3. FastAPI Routes

- [x] 3.1 Implement `POST /api/runs` returning `202 Accepted` with `job_id`, status, and status URL.
- [x] 3.2 Implement `GET /api/runs` for listing known jobs.
- [x] 3.3 Implement `GET /api/runs/{job_id}` for current job status and final summary.
- [x] 3.4 Add structured `404` responses for unknown jobs.
- [x] 3.5 Add local service startup path, either documented uvicorn command or optional CLI `serve` command.

## 4. Runtime Artifact Access

- [x] 4.1 Implement artifact helpers that resolve files only inside the known job run directory.
- [x] 4.2 Implement `GET /api/runs/{job_id}/runtime-state` reading `runtime_state/state.json`.
- [x] 4.3 Implement `GET /api/runs/{job_id}/replay-summary` using existing `replay_summary()`.
- [x] 4.4 Implement `GET /api/runs/{job_id}/reports/report.json` returning parsed report JSON.
- [x] 4.5 Implement `GET /api/runs/{job_id}/reports/report.md` returning Markdown text.
- [x] 4.6 Add path traversal and unsupported artifact tests to prove arbitrary file reads are denied.

## 5. Documentation and Verification

- [x] 5.1 Update usage docs with backend startup, create scan request, polling, runtime state, replay summary, and report retrieval examples.
- [x] 5.2 Run focused backend API tests.
- [x] 5.3 Run full offline unit test suite.
- [x] 5.4 Run a mock API scan against `fixtures/integration_smoke` and verify status, runtime state, replay summary, and reports through HTTP endpoints.
- [x] 5.5 Run `openspec validate "add-web-backend-servic" --strict`.
