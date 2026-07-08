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

Start the FastAPI backend for local demos or a future UI:

```powershell
.\.venv\Scripts\python.exe -m uvicorn audit_agent.server.app:app --host 127.0.0.1 --port 8000
```

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
