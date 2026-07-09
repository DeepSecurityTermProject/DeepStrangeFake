# Agentic Security Audit Usage

This implementation is a CLI-first research prototype for the OpenSpec change
`build-agentic-security-audit-system`. It follows the four-agent architecture:
Orchestrator, Recon, Analysis, and Verification. CVE intelligence from
`mukul975/cve-mcp-server` is modeled as a bounded read-only tool layer, not as a
fifth agent.

## Environment

Create and use a Python 3.12 virtual environment:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe --version
```

Run tests:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests
```

Install the package dependencies, including the optional local web backend:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
```

## Single-Target Audit

```powershell
.\.venv\Scripts\python.exe -m audit_agent scan --target D:\path\to\project --output runs
```

The run directory contains metadata, tool outputs, intelligence artifacts,
agent traces, handoffs, findings, evidence chains, proof-of-concept artifacts,
JSON/Markdown reports, message logs, and `runtime_state/state.json`.

## Local Web Backend

Start the FastAPI backend for local demos and the web UI:

```powershell
.\.venv\Scripts\python.exe -m uvicorn audit_agent.server.app:app --host 127.0.0.1 --port 8000
```

For Real provider scans started through the web API, the backend loads `.env`
from the server working directory. Supported model settings include
`LLM_API_KEY`, `LLM_API_BASE_URL`, and `LLM_MODEL`. API keys still stay out of
HTTP requests; omit `model` in the UI/API request to use `LLM_MODEL`.

Create a mock scan job:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/runs -ContentType "application/json" -Body '{
  "target": "fixtures/integration_smoke",
  "runtime": true,
  "llm_provider": "mock",
  "llm_decisions": true,
  "memory_mode": "lexical",
  "mcp_mode": "off",
  "validation_level": "static-only"
}'
```

Poll job status, then read runtime artifacts:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/runs/<job_id>
Invoke-RestMethod http://127.0.0.1:8000/api/runs/<job_id>/runtime-state
Invoke-RestMethod http://127.0.0.1:8000/api/runs/<job_id>/replay-summary
Invoke-RestMethod http://127.0.0.1:8000/api/runs/<job_id>/reports/report.json
Invoke-RestMethod http://127.0.0.1:8000/api/runs/<job_id>/reports/report.md
```

The backend is intentionally local-first. It does not accept API keys in HTTP
requests, and report/runtime endpoints only read fixed files under the run
directory associated with a known job.

## Local Web Frontend

Install and run the Vite + React + TypeScript frontend:

```powershell
cd frontend
npm install
npm run dev
```

Open the frontend at:

```text
http://127.0.0.1:5173/
```

If local policy blocks port `8000`, start the backend on another high port and
point the Vite proxy to it:

```powershell
.\.venv\Scripts\python.exe -m uvicorn audit_agent.server.app:app --host 127.0.0.1 --port 18000
cd frontend
$env:VITE_API_PROXY_TARGET = "http://127.0.0.1:18000"
npm run dev -- --port 18173
```

The UI supports:

- creating scan runs with target, runtime, provider, LLM decisions, memory, MCP,
  and validation controls;
- browsing queued, running, succeeded, and failed jobs;
- opening run details with Summary, Findings, Runtime Tasks, Replay, and
  Markdown Report tabs;
- polling run status until `succeeded` or `failed`, then loading runtime,
  replay, and report artifacts.

Run frontend verification:

```powershell
cd frontend
npm test
npm run typecheck
npm run build
```

Run a real local UI smoke against a live backend:

```powershell
cd frontend
$env:VITE_E2E_API_URL = "http://127.0.0.1:18000"
npm run test:smoke
```

The smoke renders the full React app, creates a mock scan through the UI,
polls the backend run to completion, and opens the Runtime Tasks, Replay, and
Markdown Report tabs.

## LLM Runtime Mode

The default remains mock mode, so no API key is required:

```powershell
.\.venv\Scripts\python.exe -m audit_agent scan --target D:\path\to\project --runtime --llm-provider mock
```

For a real OpenAI-compatible provider, set the configured API key environment
variable and choose the provider/model:

```powershell
$env:OPENAI_API_KEY = "..."
.\.venv\Scripts\python.exe -m audit_agent scan --target D:\path\to\project --runtime --llm-provider openai-compatible --model gpt-4.1-mini
```

The runtime writes rendered Prompt artifacts under `prompts/`, normalized LLM
request/response artifacts under `llm/`, and token/cost metadata into the JSON
report. Missing API keys fail before model calls are made.

## Guarded LLM Decision Mode

By default, LLM output is recorded as runtime evidence but does not control final
agent decisions. Enable guarded decision participation explicitly:

```powershell
.\.venv\Scripts\python.exe -m audit_agent scan --target D:\path\to\project --runtime --llm-provider mock --llm-decisions
```

Limit participation to selected roles when needed:

```powershell
.\.venv\Scripts\python.exe -m audit_agent scan --target D:\path\to\project --runtime --llm-decisions --llm-decision-roles analysis,verification
```

Each role writes LLM proposals, schema status, policy gates, merge records, and
fallback reasons under `decisions/`. Final findings include `decision_source`,
`llm_confidence`, `policy_gate`, local evidence refs, and contextual
intelligence refs in `reports/report.json` and the Markdown LLM influence
section. Memory and CVE context remain contextual unless local evidence also
supports the finding.

## Prompt Templates

Prompt templates are versioned by role and template ID. The built-in templates
cover Orchestrator, Recon, Analysis, and Verification, and each template declares
required variables, a JSON output schema, safety constraints, and a version.
Students can edit or add templates as long as required variables and output
schemas remain valid.

## Agent Tool-Calling Protocol

LLM agents use a structured tool-calling protocol rather than arbitrary Python
function calls. Tool declarations include name, JSON input schema, permission
group, timeout, and safety classification. The runtime enforces permissions,
budgets, denied-call behavior, timeouts, and normalized tool result artifacts.

## RAG Memory

RAG memory starts with deterministic lexical retrieval, so it works offline and
without embedding APIs:

```powershell
.\.venv\Scripts\python.exe -m audit_agent scan --target D:\path\to\project --runtime --memory-mode lexical
```

The memory layer indexes repository chunks with source path, line range, content
hash, namespace, and citations. Retrieval records are linked into agent traces,
evidence chains, and reports. Optional embedding providers can be added behind
the same interface, with lexical fallback when embeddings are unavailable.

## Benchmark

The default benchmark list is stored in `benchmarks/projects.json` and contains
20 open-source projects, including OpenVPN and MacCMS v10.

```powershell
.\.venv\Scripts\python.exe -m audit_agent benchmark --output runs
```

Remote repositories are not downloaded by the default batch runner. This keeps
the baseline safe and reproducible in restricted environments. Use repository
checkout explicitly when network and storage constraints are acceptable.

## CVE MCP Integration

Configure the CVE MCP command in `config/default.json` or `.env`:

```json
{
  "cve_mcp": {
    "enabled": true,
    "command": ["cve-mcp-server"],
    "query_budget": 50,
    "degraded_mode": true
  }
}
```

If the MCP server is unavailable, the adapter records degraded observations and
the audit continues. CVE data is treated as contextual intelligence for
prioritization and reporting. It cannot validate a finding without local code or
dependency evidence.

Runtime MCP mode uses a real stdio MCP client when enabled:

```powershell
.\.venv\Scripts\python.exe -m audit_agent scan --target D:\path\to\project --runtime --mcp-mode degraded
```

`degraded` mode records missing server, missing tool, timeout, or query-budget
failures as contextual runtime artifacts and keeps the audit safe.

For live model API and local checkout/venv `cve-mcp-server` integration, see
`docs/integration.md`. The short preflight command is:

```powershell
.\.venv\Scripts\python.exe -m audit_agent integration preflight --llm --mcp --output runs
```

## Agent Message Bus

Runtime mode writes an append-only message bus log under
`messages/messages.jsonl`. The log contains agent lifecycle events, prompt
renders, LLM calls, tool calls, RAG retrievals, MCP calls, validation events, and
report generation events. Decision mode adds `llm.decision`, `decision.schema`,
`decision.policy`, `decision.merge`, and `decision.fallback` events. Replay a log
with:

```powershell
.\.venv\Scripts\python.exe -m audit_agent replay --messages runs\<run>\messages\messages.jsonl
```

The replay output includes `runtime_lifecycle`, which summarizes task statuses,
tool calls, tool denials, service failures, artifacts, and fallback reasons by
role. For the full persisted runtime graph, open:

```powershell
Get-Content runs\<run>\runtime_state\state.json
```

## AST Dataflow Evidence

The built-in static scanner now includes a `dataflow-scan` tool. It records
source-to-sink traces for Python and JS/TS web inputs reaching SQL execution,
command execution, or file/path read sinks.

Python parsing uses the standard library `ast` module. JS/TS scanning uses
Tree-sitter through `tree-sitter-language-pack` when the optional parser
packages are installed, and falls back to bounded local scanning when they are
not installed:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[js-ast]"
```

Run a scan as usual:

```powershell
.\.venv\Scripts\python.exe -m audit_agent scan --target fixtures/integration_smoke --runtime --llm-provider mock
```

Each accepted dataflow-backed finding keeps only a compact summary in
`call_path` and report fields. The complete trace is stored as an immutable JSON
artifact under:

```text
runs\<run>\dataflow\traces\<trace-id>.json
```

Reports include a Dataflow Evidence section with source, sink, sanitizer status,
and trace refs. Evidence chains also reference the full trace artifacts so a
reviewer can reproduce the path without relying on LLM text.

The JS/TS trace artifact includes `metadata.parse_backend` so reviewers can see
whether a trace came from `tree-sitter` or the offline fallback. Current
propagation is MVP-bounded and mostly language-frontend local. Python supports
simple same-file helper return propagation, while deeper interprocedural and
cross-file dataflow remain follow-up engine work.
