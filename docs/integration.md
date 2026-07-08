# Real LLM and CVE MCP Integration

This workflow keeps normal tests offline and makes live model/MCP calls explicit.
Use it after the Python 3.12 project virtualenv is available.

## Local CVE MCP Server

The official `mukul975/cve-mcp-server` quick start uses a local checkout,
virtualenv, editable install, and stdio startup:

```powershell
git clone https://github.com/mukul975/cve-mcp-server.git external\cve-mcp-server
.\.venv\Scripts\python.exe -m venv external\cve-mcp-server\venv
external\cve-mcp-server\venv\Scripts\python.exe -m pip install -e external\cve-mcp-server
external\cve-mcp-server\venv\Scripts\python.exe -m cve_mcp.server
```

For this project, the MCP command is loaded from `.env`:

```powershell
AUDIT_AGENT_CVE_MCP_DIR=D:\DeepStrangeFake\external\cve-mcp-server
AUDIT_AGENT_CVE_MCP_PYTHON=D:\DeepStrangeFake\external\cve-mcp-server\venv\Scripts\python.exe
```

The runtime builds this stdio command:

```powershell
D:\DeepStrangeFake\external\cve-mcp-server\venv\Scripts\python.exe -m cve_mcp.server
```

Alternatively, set `AUDIT_AGENT_CVE_MCP_COMMAND` to the exact command.

For Windows/sandboxed runs, the audit wrapper sets cve-mcp cache and audit log
paths under the local checkout:

```powershell
D:\DeepStrangeFake\external\cve-mcp-server\.cache\cache.db
D:\DeepStrangeFake\external\cve-mcp-server\.cache\audit.log
```

The default safe tool allowlist follows the real cve-mcp 0.2.0 tool names:
`lookup_cve`, `get_epss_score`, `check_kev`, `parse_cvss`,
`scan_dependencies`, `check_package_vulns`, `calculate_risk_score`, and
`triage_cve`.

## Model API

The runtime loads `.env` before live preflight or smoke runs. Supported names:

```powershell
LLM_API_KEY=...
LLM_API_BASE_URL=https://your-openai-compatible-endpoint/v1
LLM_MODEL=your-model
```

The OpenAI-style names are also supported:

```powershell
OPENAI_API_KEY=...
OPENAI_BASE_URL=https://your-openai-compatible-endpoint/v1
AUDIT_AGENT_LLM_MODEL=your-model
```

Do not commit `.env`. Reports record the variable names and redacted status, not
the API key value.

## Acceptance Commands

Offline tests:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests
```

Config-only preflight:

```powershell
.\.venv\Scripts\python.exe -m audit_agent integration preflight --llm --mcp --output runs
```

Live LLM and MCP preflight:

```powershell
$env:AUDIT_AGENT_RUN_INTEGRATION = "1"
.\.venv\Scripts\python.exe -m audit_agent integration preflight --llm --mcp --live --output runs
```

Controlled end-to-end smoke audit:

```powershell
$env:AUDIT_AGENT_RUN_INTEGRATION = "1"
.\.venv\Scripts\python.exe -m audit_agent integration smoke --live --target fixtures\integration_smoke --output runs
```

Controlled live LLM decision smoke using the configured `.env` `LLM_MODEL`:

```powershell
$env:AUDIT_AGENT_RUN_INTEGRATION = "1"
.\.venv\Scripts\python.exe -m audit_agent integration smoke --live --llm-decisions --target fixtures\integration_smoke --output runs
```

The decision smoke writes normal `prompts/` and `llm/` artifacts plus
`decisions/` artifacts for role proposals, policy gates, merge results, and
fallbacks. It remains bounded to the small local fixture and does not run the
20-project benchmark.

Replay the generated message log:

```powershell
.\.venv\Scripts\python.exe -m audit_agent replay --messages runs\<run>\messages\messages.jsonl
```
