from __future__ import annotations

import json
import os
import platform
import shlex
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .config import AuditConfig
from .llm import LLMProviderError, build_llm_client, persist_llm_artifact
from .mcp_client import MCPClient
from .models import LLMRequest, to_plain, utc_now
from .pipeline import run_audit
from .redaction import redact_secrets
from .storage import immutable_path


@dataclass
class EnvLoadResult:
    env_file: str
    loaded: bool
    values_loaded: list[str] = field(default_factory=list)
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return redact_secrets(to_plain(self))


@dataclass
class PreflightComponent:
    name: str
    status: str
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    artifacts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return redact_secrets(to_plain(self), _known_secret_values())


@dataclass
class IntegrationReport:
    overall_status: str
    command: str
    timestamp: str
    python_version: str
    env: EnvLoadResult
    components: dict[str, PreflightComponent] = field(default_factory=dict)
    artifacts: dict[str, str] = field(default_factory=dict)
    redaction_summary: str = "Secrets are redacted from integration reports."

    def to_dict(self) -> dict[str, Any]:
        return redact_secrets(to_plain(self), _known_secret_values())


def load_dotenv_values(path: str | Path) -> dict[str, str]:
    env_path = Path(path)
    if not env_path.exists():
        return {}
    values: dict[str, str] = {}
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def load_integration_environment(
    config: AuditConfig,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> EnvLoadResult:
    env_map = env if env is not None else os.environ
    root = Path(cwd or Path.cwd())
    configured = Path(config.integration.env_file)
    env_path = configured if configured.is_absolute() else root / configured
    loaded_values: dict[str, str] = {}
    if config.integration.load_env_file:
        loaded_values = load_dotenv_values(env_path)
        for key, value in loaded_values.items():
            env_map.setdefault(key, value)
    _apply_env_overrides(config, env_map)
    return EnvLoadResult(
        env_file=str(env_path),
        loaded=bool(loaded_values),
        values_loaded=sorted(loaded_values),
        message="loaded" if loaded_values else "not found or empty",
    )


def run_integration_preflight(
    config: AuditConfig | None = None,
    output_dir: str | Path = "runs",
    include_llm: bool = True,
    include_mcp: bool = True,
    execute_live: bool = False,
    env: dict[str, str] | None = None,
    cwd: str | Path | None = None,
    command: str = "integration preflight",
    llm_client_factory: Callable[[Any], Any] | None = None,
) -> IntegrationReport:
    config = config or AuditConfig.default()
    env_result = load_integration_environment(config, cwd=cwd, env=env)
    components: dict[str, PreflightComponent] = {
        "env": PreflightComponent(
            name="env",
            status="pass" if env_result.loaded else "skip",
            message=env_result.message,
            details=env_result.to_dict(),
        )
    }
    root = Path(output_dir) / config.integration.artifact_dir
    root.mkdir(parents=True, exist_ok=True)

    if include_llm:
        components["llm"] = _preflight_llm(config, root / "llm", execute_live, env or os.environ, llm_client_factory)
    else:
        components["llm"] = PreflightComponent("llm", "skip", "LLM preflight not requested.")

    if include_mcp:
        components["mcp"] = _preflight_mcp(config, root / "mcp", execute_live)
    else:
        components["mcp"] = PreflightComponent("mcp", "skip", "MCP preflight not requested.")

    components["artifacts"] = PreflightComponent(
        name="artifacts",
        status="pass",
        message="Integration artifact directory is writable.",
        details={"artifact_dir": str(root)},
    )
    report = IntegrationReport(
        overall_status=_overall_status(components),
        command=command,
        timestamp=utc_now(),
        python_version=platform.python_version(),
        env=env_result,
        components=components,
    )
    _persist_report(root, report)
    return report


def run_integration_smoke(
    config: AuditConfig | None = None,
    target: str | Path | None = None,
    output_dir: str | Path = "runs",
    execute_live: bool = False,
    include_llm: bool = True,
    include_mcp: bool = True,
    env: dict[str, str] | None = None,
    cwd: str | Path | None = None,
) -> IntegrationReport:
    config = config or AuditConfig.default()
    preflight = run_integration_preflight(
        config=config,
        output_dir=output_dir,
        include_llm=include_llm,
        include_mcp=include_mcp,
        execute_live=execute_live,
        env=env,
        cwd=cwd,
        command="integration smoke",
    )
    smoke_target = str(target or config.integration.smoke_target)
    if preflight.overall_status == "fail":
        preflight.components["smoke"] = PreflightComponent(
            name="smoke",
            status="skip",
            message="Smoke run skipped because preflight failed.",
            details={"target": smoke_target},
        )
    elif not execute_live:
        preflight.components["smoke"] = PreflightComponent(
            name="smoke",
            status="skip",
            message="Live smoke run requires explicit --live.",
            details={"target": smoke_target},
        )
    else:
        started = time.monotonic()
        config.runtime_enabled = True
        config.mcp.enabled = True
        config.memory.enabled = True
        result = run_audit(smoke_target, config=config, output_dir=output_dir)
        preflight.components["smoke"] = PreflightComponent(
            name="smoke",
            status="pass",
            message="Controlled audit smoke run completed.",
            details={
                "target": smoke_target,
                "duration_ms": int((time.monotonic() - started) * 1000),
                "run_dir": result["run_dir"],
                "message_log": str(Path(result["run_dir"]) / "messages" / config.message_bus.log_filename),
                "replay_command": f"{sys.executable} -m audit_agent replay --messages {Path(result['run_dir']) / 'messages' / config.message_bus.log_filename}",
            },
        )
        preflight.overall_status = _overall_status(preflight.components)
    root = Path(output_dir) / config.integration.artifact_dir
    _persist_report(root, preflight)
    return preflight


def _apply_env_overrides(config: AuditConfig, env: dict[str, str]) -> None:
    truthy = {"1", "true", "yes", "on"}
    if "AUDIT_REMOTE_ACQUISITION_ENABLED" in env:
        config.remote_acquisition.enabled = env["AUDIT_REMOTE_ACQUISITION_ENABLED"].lower() in truthy
    if "AUDIT_REMOTE_ACQUISITION_NETWORK" in env:
        config.remote_acquisition.network_enabled = env["AUDIT_REMOTE_ACQUISITION_NETWORK"].lower() in truthy
    if "AUDIT_REMOTE_ALLOWED_HOSTS" in env:
        config.remote_acquisition.allowed_hosts = [
            item.strip() for item in env["AUDIT_REMOTE_ALLOWED_HOSTS"].split(",") if item.strip()
        ]
    if "AUDIT_REMOTE_CACHE_ROOT" in env:
        config.remote_acquisition.cache_root = env["AUDIT_REMOTE_CACHE_ROOT"]
    if "AUDIT_REMOTE_WORK_ROOT" in env:
        config.remote_acquisition.work_root = env["AUDIT_REMOTE_WORK_ROOT"]
    if "AUDIT_REMOTE_COMMAND_TIMEOUT" in env:
        config.remote_acquisition.command_timeout_seconds = int(env["AUDIT_REMOTE_COMMAND_TIMEOUT"])
    if "AUDIT_REMOTE_TOTAL_TIMEOUT" in env:
        config.remote_acquisition.total_timeout_seconds = int(env["AUDIT_REMOTE_TOTAL_TIMEOUT"])
    if "AUDIT_REMOTE_LOCK_TIMEOUT" in env:
        config.remote_acquisition.lock_timeout_seconds = int(env["AUDIT_REMOTE_LOCK_TIMEOUT"])
    config.remote_acquisition.__post_init__()
    config.llm.provider = env.get("AUDIT_AGENT_LLM_PROVIDER", config.llm.provider)
    config.llm.model = env.get("AUDIT_AGENT_LLM_MODEL", env.get("LLM_MODEL", config.llm.model))
    config.llm.base_url = env.get(
        "AUDIT_AGENT_LLM_BASE_URL",
        env.get("OPENAI_BASE_URL", env.get("LLM_API_BASE_URL", config.llm.base_url)),
    )
    if "AUDIT_AGENT_LLM_API_KEY_ENV" in env:
        config.llm.api_key_env = env["AUDIT_AGENT_LLM_API_KEY_ENV"]
    elif "OPENAI_API_KEY" in env:
        config.llm.api_key_env = "OPENAI_API_KEY"
    elif "LLM_API_KEY" in env:
        config.llm.api_key_env = "LLM_API_KEY"
    if config.llm.provider == "mock" and config.llm.api_key_env in env:
        config.llm.provider = "openai-compatible"
    if "AUDIT_AGENT_LLM_TIMEOUT_SECONDS" in env:
        config.llm.timeout_seconds = int(env["AUDIT_AGENT_LLM_TIMEOUT_SECONDS"])
    if "AUDIT_AGENT_LLM_RETRY_COUNT" in env:
        config.llm.retry_count = int(env["AUDIT_AGENT_LLM_RETRY_COUNT"])
    if "AUDIT_AGENT_LLM_RESPONSE_FORMAT" in env:
        config.llm.response_format = env["AUDIT_AGENT_LLM_RESPONSE_FORMAT"].strip().lower()
        config.llm.__post_init__()
    if "AUDIT_AGENT_LLM_MAX_TOKENS" in env:
        config.llm.max_tokens = int(env["AUDIT_AGENT_LLM_MAX_TOKENS"])
    if "AUDIT_AGENT_LLM_TOKEN_BUDGET" in env:
        config.llm.token_budget = int(env["AUDIT_AGENT_LLM_TOKEN_BUDGET"])
    if "AUDIT_AGENT_INVESTIGATION_TOKEN_BUDGET" in env:
        investigation_token_budget = int(env["AUDIT_AGENT_INVESTIGATION_TOKEN_BUDGET"])
        config.investigation.token_budget = investigation_token_budget
        config.investigation.__post_init__()
        if "AUDIT_AGENT_LLM_TOKEN_BUDGET" not in env:
            config.llm.token_budget = investigation_token_budget
    if "AUDIT_AGENT_CVE_MCP_COMMAND" in env:
        config.mcp.command = _split_command(env["AUDIT_AGENT_CVE_MCP_COMMAND"])
    else:
        mcp_dir = env.get("AUDIT_AGENT_CVE_MCP_DIR")
        mcp_python = env.get("AUDIT_AGENT_CVE_MCP_PYTHON")
        if mcp_dir or mcp_python:
            root = Path(mcp_dir) if mcp_dir else None
            if not mcp_python and root:
                mcp_python = str(root / "venv" / "Scripts" / "python.exe")
            module = env.get("AUDIT_AGENT_CVE_MCP_MODULE", "cve_mcp.server")
            config.mcp.command = [str(mcp_python), "-m", module]
            config.mcp.working_dir = str(root) if root else config.mcp.working_dir
            if root:
                cache_dir = root / ".cache"
                config.mcp.env.setdefault("CACHE_DB_PATH", str(cache_dir / "cache.db"))
                config.mcp.env.setdefault("AUDIT_LOG_PATH", str(cache_dir / "audit.log"))
    if "AUDIT_AGENT_CVE_MCP_CACHE_DB_PATH" in env:
        config.mcp.env["CACHE_DB_PATH"] = env["AUDIT_AGENT_CVE_MCP_CACHE_DB_PATH"]
    if "AUDIT_AGENT_CVE_MCP_AUDIT_LOG_PATH" in env:
        config.mcp.env["AUDIT_LOG_PATH"] = env["AUDIT_AGENT_CVE_MCP_AUDIT_LOG_PATH"]
    if "AUDIT_AGENT_CVE_MCP_TIMEOUT_SECONDS" in env:
        config.mcp.timeout_seconds = int(env["AUDIT_AGENT_CVE_MCP_TIMEOUT_SECONDS"])
    if "AUDIT_AGENT_CVE_MCP_QUERY_BUDGET" in env:
        config.mcp.query_budget = int(env["AUDIT_AGENT_CVE_MCP_QUERY_BUDGET"])
    if "AUDIT_DEPENDENCY_INTELLIGENCE_ENABLED" in env:
        config.dependency_intelligence.enabled = env[
            "AUDIT_DEPENDENCY_INTELLIGENCE_ENABLED"
        ].strip().lower() in {"1", "true", "yes", "on"}
    if "AUDIT_DEPENDENCY_BATCH_SIZE" in env:
        config.dependency_intelligence.batch_size = int(env["AUDIT_DEPENDENCY_BATCH_SIZE"])
    if "AUDIT_DEPENDENCY_QUERY_BUDGET" in env:
        config.dependency_intelligence.query_budget = int(env["AUDIT_DEPENDENCY_QUERY_BUDGET"])
    if "AUDIT_DEPENDENCY_CACHE_POLICY" in env:
        config.dependency_intelligence.cache_policy = env["AUDIT_DEPENDENCY_CACHE_POLICY"]
    if "AUDIT_DEPENDENCY_CACHE_PATH" in env:
        config.dependency_intelligence.cache_path = env["AUDIT_DEPENDENCY_CACHE_PATH"]
    if "AUDIT_DEPENDENCY_CACHE_TTL_SECONDS" in env:
        config.dependency_intelligence.cache_ttl_seconds = int(
            env["AUDIT_DEPENDENCY_CACHE_TTL_SECONDS"]
        )
    config.dependency_intelligence.__post_init__()
    if "AUDIT_AGENT_CVE_MCP_ALLOWED_TOOLS" in env:
        config.mcp.allowed_tools = [item.strip() for item in env["AUDIT_AGENT_CVE_MCP_ALLOWED_TOOLS"].split(",") if item.strip()]
    if not config.mcp.allowed_tools:
        config.mcp.allowed_tools = list(config.integration.safe_cve_mcp_tools)


def _preflight_llm(
    config: AuditConfig,
    artifact_dir: Path,
    execute_live: bool,
    env: dict[str, str],
    llm_client_factory: Callable[[Any], Any] | None = None,
) -> PreflightComponent:
    if config.llm.provider == "mock":
        return PreflightComponent(
            name="llm",
            status="skip",
            message="Mock provider selected; no live model API required.",
            details=_llm_summary(config, key_present=False),
        )
    key_value = env.get(config.llm.api_key_env)
    if not key_value:
        return PreflightComponent(
            name="llm",
            status="fail",
            message=f"Missing model API key environment variable: {config.llm.api_key_env}",
            remediation=f"Set {config.llm.api_key_env} in .env or the shell.",
            details=_llm_summary(config, key_present=False),
        )
    summary = _llm_summary(config, key_present=True)
    if not execute_live:
        return PreflightComponent("llm", "pass", "Model API configuration is present.", summary)
    try:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        client = (llm_client_factory or build_llm_client)(config.llm)
        request = LLMRequest(
            role="integration-smoke",
            provider=config.llm.provider,
            model=config.llm.model,
            prompt='Return compact JSON: {"status":"ok"}',
            temperature=0.0,
            max_tokens=min(config.integration.llm_smoke_max_tokens, config.llm.max_tokens),
            response_schema={"type": "object"},
            response_format="auto",
        )
        response = client.complete(request)
        path = persist_llm_artifact(artifact_dir, request, response)
        details = {
            **summary,
            "latency_ms": response.latency_ms,
            "usage": response.usage,
            "finish_reason": response.finish_reason,
            "parsed_json": response.parsed_json is not None,
            "artifact_path": str(path),
        }
        return PreflightComponent("llm", "pass", "Live model smoke call completed.", details, artifacts=[str(path)])
    except LLMProviderError as exc:
        return PreflightComponent("llm", "fail", exc.message, {**summary, "error": exc.to_dict()})
    except Exception as exc:
        return PreflightComponent("llm", "fail", f"Live model smoke call failed: {exc}", summary)


def _preflight_mcp(config: AuditConfig, artifact_dir: Path, execute_live: bool) -> PreflightComponent:
    command = config.mcp.command
    if not command:
        return PreflightComponent("mcp", "skip", "No MCP command configured.", remediation="Configure AUDIT_AGENT_CVE_MCP_COMMAND.")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    allowed = config.mcp.allowed_tools or config.integration.safe_cve_mcp_tools
    details: dict[str, Any] = {
        "command": command,
        "working_dir": config.mcp.working_dir,
        "process_env": config.mcp.env,
        "required_safe_tools": allowed,
    }
    try:
        with MCPClient(
            command=command,
            timeout_seconds=config.mcp.timeout_seconds,
            query_budget=config.mcp.query_budget,
            allowed_tools=allowed,
            cwd=config.mcp.working_dir,
            env=config.mcp.env,
        ) as client:
            tools = client.list_tools()
            available = sorted({tool.name for tool in tools})
            missing = [name for name in allowed if name not in available]
            details.update(
                {
                    "initialized": client.session.initialized,
                    "server_info": client.session.server_info,
                    "capabilities": client.session.capabilities,
                    "stderr": client.stderr_output,
                    "available_tools": available,
                    "missing_safe_tools": missing,
                    "tool_schemas": {
                        tool.name: {"description": tool.description, "input_schema": tool.input_schema or {}}
                        for tool in tools
                        if tool.name in allowed
                    },
                }
            )
            if not client.session.initialized:
                details["stderr"] = client.stderr_output
                return PreflightComponent("mcp", "fail", client.session.message or "MCP initialization failed.", details)
            if execute_live and "lookup_cve" in available:
                result = client.call_tool("lookup_cve", {"cve_id": config.integration.smoke_cve_id})
                details["smoke_call"] = result.call_record.to_dict()
                status = "pass" if result.success else "fail"
                message = "MCP initialized and live lookup completed." if result.success else result.message
            else:
                status = "pass"
                message = "MCP initialized and tools discovered."
    except FileNotFoundError as exc:
        return PreflightComponent("mcp", "fail", f"MCP command unavailable: {exc}", details)
    except Exception as exc:
        return PreflightComponent("mcp", "fail", f"MCP preflight failed: {exc}", details)
    path = immutable_path(artifact_dir / "tool-inventory.json")
    path.write_text(json.dumps(redact_secrets(details), ensure_ascii=False, indent=2), encoding="utf-8")
    return PreflightComponent("mcp", status, message, details, artifacts=[str(path)])


def _persist_report(root: Path, report: IntegrationReport) -> None:
    root.mkdir(parents=True, exist_ok=True)
    json_path = immutable_path(root / "preflight.json")
    md_path = immutable_path(root / "preflight.md")
    json_path.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(_report_markdown(report), encoding="utf-8")
    report.artifacts["json"] = str(json_path)
    report.artifacts["markdown"] = str(md_path)
    json_path.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(_report_markdown(report), encoding="utf-8")


def _report_markdown(report: IntegrationReport) -> str:
    lines = [
        "# Integration Preflight Report",
        "",
        f"- Overall status: `{report.overall_status}`",
        f"- Command: `{report.command}`",
        f"- Timestamp: `{report.timestamp}`",
        f"- Python: `{report.python_version}`",
        f"- Env file: `{report.env.env_file}` ({'loaded' if report.env.loaded else 'not loaded'})",
        "",
        "## Components",
    ]
    for component in report.components.values():
        lines.extend(
            [
                "",
                f"### {component.name}",
                f"- Status: `{component.status}`",
                f"- Message: {component.message}",
            ]
        )
    lines.extend(["", "## Redaction", report.redaction_summary, ""])
    return "\n".join(lines)


def _llm_summary(config: AuditConfig, key_present: bool) -> dict[str, Any]:
    return {
        "provider": config.llm.provider,
        "model": config.llm.model,
        "base_url": config.llm.base_url,
        "api_key_env": config.llm.api_key_env,
        "api_key_present": key_present,
        "timeout_seconds": config.llm.timeout_seconds,
        "retry_count": config.llm.retry_count,
        "response_format": config.llm.response_format,
        "max_tokens": config.llm.max_tokens,
        "token_budget": config.llm.token_budget,
        "cost_budget_usd": config.llm.cost_budget_usd,
    }


def _overall_status(components: dict[str, PreflightComponent]) -> str:
    statuses = [item.status for item in components.values()]
    if any(status == "fail" for status in statuses):
        return "fail"
    if any(status == "pass" for status in statuses):
        return "pass"
    return "skip"


def _split_command(value: str) -> list[str]:
    if os.name == "nt":
        return shlex.split(value, posix=False)
    return shlex.split(value)


def _known_secret_values() -> list[str]:
    secrets = []
    for key, value in os.environ.items():
        if value and any(fragment in key.lower() for fragment in ("key", "token", "secret", "password")):
            secrets.append(value)
    return secrets
