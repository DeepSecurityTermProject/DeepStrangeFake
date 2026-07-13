from __future__ import annotations

import json
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from .models import to_plain

DEFAULT_AUDIT_EXCLUDE_PATTERNS = [
    "tests/**",
    "test/**",
    "fixtures/**",
    "external/**",
    "openspec/**",
    ".codex/**",
]


@dataclass
class LlmConfig:
    provider: str = "mock"
    model: str = "deterministic-local"
    temperature: float = 0.0
    local_model_endpoint: str | None = None
    base_url: str = "https://api.openai.com/v1"
    api_key_env: str = "OPENAI_API_KEY"
    timeout_seconds: int = 30
    retry_count: int = 2
    max_tokens: int = 4096
    token_budget: int = 200000
    cost_budget_usd: float | None = None


@dataclass
class PromptRuntimeConfig:
    default_version: str = "v1"
    template_dir: str = "audit_agent/prompt_templates"


@dataclass
class CveMcpConfig:
    name: str = "mukul975/cve-mcp-server"
    enabled: bool = True
    command: list[str] = field(default_factory=lambda: ["cve-mcp-server"])
    working_dir: str | None = None
    endpoint: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 15
    cache_policy: str = "per-run"
    query_budget: int = 50
    degraded_mode: bool = True
    outbound_network: str = "configurable"
    allowed_tools: list[str] = field(default_factory=list)


@dataclass
class McpRuntimeConfig:
    enabled: bool = True
    transport: str = "stdio"
    command: list[str] = field(default_factory=lambda: ["cve-mcp-server"])
    working_dir: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 15
    query_budget: int = 50
    degraded_mode: bool = True
    outbound_network: str = "configurable"
    allowed_tools: list[str] = field(default_factory=list)


@dataclass
class IntegrationConfig:
    enabled: bool = False
    env_file: str = ".env"
    load_env_file: bool = True
    live_flag_env: str = "AUDIT_AGENT_RUN_INTEGRATION"
    artifact_dir: str = "integration"
    smoke_target: str = "fixtures/integration_smoke"
    smoke_cve_id: str = "CVE-2021-44228"
    llm_smoke_max_tokens: int = 128
    safe_cve_mcp_tools: list[str] = field(
        default_factory=lambda: [
            "lookup_cve",
            "get_epss_score",
            "check_kev",
            "parse_cvss",
            "scan_dependencies",
            "check_package_vulns",
            "calculate_risk_score",
            "triage_cve",
        ]
    )


@dataclass
class ToolRuntimeConfig:
    default_timeout_seconds: int = 30
    per_agent_budgets: dict[str, int] = field(
        default_factory=lambda: {
            "orchestrator": 20,
            "recon": 60,
            "analysis": 100,
            "verification": 80,
            "reporting": 20,
            "validation": 20,
        }
    )


@dataclass
class MemoryRuntimeConfig:
    enabled: bool = True
    mode: str = "lexical"
    index_dir: str = "memory"
    embedding_provider: str = "none"
    exclude_patterns: list[str] = field(
        default_factory=lambda: [".git/", "node_modules/", ".venv/", "runs/", "*.pem", "*.key"]
    )
    redaction_patterns: list[str] = field(default_factory=lambda: ["secret", "password", "api_key", "token"])


@dataclass
class MessageBusConfig:
    enabled: bool = True
    log_filename: str = "messages.jsonl"


@dataclass
class LlmDecisionRuntimeConfig:
    enabled: bool = False
    roles: list[str] = field(
        default_factory=lambda: ["orchestrator", "recon", "analysis", "verification"]
    )
    confidence_thresholds: dict[str, float] = field(
        default_factory=lambda: {
            "orchestrator": 0.55,
            "recon": 0.6,
            "analysis": 0.7,
            "verification": 0.75,
        }
    )
    repair_enabled: bool = True
    max_repair_attempts: int = 1
    tool_budget_per_role: dict[str, int] = field(default_factory=dict)
    allow_live_target_actions: bool = False
    decision_artifact_dir: str = "decisions"


@dataclass
class PoCRepairConfig:
    enabled: bool = False
    max_repair_attempts: int = 1
    effective_source: str = "default"

    def __post_init__(self) -> None:
        if isinstance(self.max_repair_attempts, bool) or not isinstance(self.max_repair_attempts, int):
            raise ValueError("poc_repair.max_repair_attempts must be an integer in 0..2")
        if not 0 <= self.max_repair_attempts <= 2:
            raise ValueError("poc_repair.max_repair_attempts must be in 0..2")

    @property
    def total_execution_attempts(self) -> int:
        return 1 + self.max_repair_attempts


@dataclass
class AuditScope:
    vulnerability_classes: list[str] = field(
        default_factory=lambda: [
            "sql-injection",
            "command-injection",
            "path-traversal",
            "hardcoded-secret",
        ]
    )
    include_patterns: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_AUDIT_EXCLUDE_PATTERNS))
    analysis_budget: int = 100
    tool_budget: int = 80
    cve_query_budget: int = 50


@dataclass
class SandboxConfig:
    enabled: bool = False
    runner: str = "local"
    allow_live_targets: bool = False
    safe_commands: list[str] = field(default_factory=list)
    command_allowlist: list[str] = field(default_factory=list)
    timeout_seconds: int = 10
    workspace_prefix: str = "audit-agent-sandbox"
    docker_binary: str = "docker"
    docker_image: str = "python:3.12-slim"
    docker_context: str | None = None
    docker_host: str | None = None
    network: str = "none"
    memory_limit: str = "256m"
    cpu_limit: str = "1"
    pids_limit: int = 128


@dataclass
class ToolPermissions:
    repository_read: bool = True
    static_scan: bool = True
    vulnerability_intelligence: bool = True
    validation: bool = True
    live_network_validation: bool = False


@dataclass
class OutputConfig:
    runs_dir: str = "runs"
    report_formats: list[str] = field(default_factory=lambda: ["json", "markdown"])


@dataclass
class AuditConfig:
    llm: LlmConfig = field(default_factory=LlmConfig)
    prompts: PromptRuntimeConfig = field(default_factory=PromptRuntimeConfig)
    cve_mcp: CveMcpConfig = field(default_factory=CveMcpConfig)
    mcp: McpRuntimeConfig = field(default_factory=McpRuntimeConfig)
    integration: IntegrationConfig = field(default_factory=IntegrationConfig)
    tools: ToolRuntimeConfig = field(default_factory=ToolRuntimeConfig)
    memory: MemoryRuntimeConfig = field(default_factory=MemoryRuntimeConfig)
    message_bus: MessageBusConfig = field(default_factory=MessageBusConfig)
    llm_decisions: LlmDecisionRuntimeConfig = field(default_factory=LlmDecisionRuntimeConfig)
    poc_repair: PoCRepairConfig = field(default_factory=PoCRepairConfig)
    audit_scope: AuditScope = field(default_factory=AuditScope)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    tool_permissions: ToolPermissions = field(default_factory=ToolPermissions)
    output: OutputConfig = field(default_factory=OutputConfig)
    validation_levels: list[str] = field(
        default_factory=lambda: ["static-only", "poc-generate", "sandbox", "manual"]
    )
    default_validation_level: str = "static-only"
    runtime_enabled: bool = False

    @classmethod
    def default(cls) -> "AuditConfig":
        return cls()

    @classmethod
    def from_json(cls, path: str | Path) -> "AuditConfig":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        llm_decisions = LlmDecisionRuntimeConfig(
            **_known_kwargs(LlmDecisionRuntimeConfig, data.get("llm_decisions", {}))
        )
        if "poc_repair" in data:
            repair_values = _known_kwargs(PoCRepairConfig, data.get("poc_repair", {}))
            repair_values["effective_source"] = "explicit"
            poc_repair = PoCRepairConfig(**repair_values)
        elif llm_decisions.enabled and llm_decisions.repair_enabled:
            poc_repair = PoCRepairConfig(
                enabled=True,
                max_repair_attempts=llm_decisions.max_repair_attempts,
                effective_source="legacy",
            )
        else:
            poc_repair = PoCRepairConfig(effective_source="default")
        return cls(
            llm=LlmConfig(**_known_kwargs(LlmConfig, data.get("llm", {}))),
            prompts=PromptRuntimeConfig(**_known_kwargs(PromptRuntimeConfig, data.get("prompts", {}))),
            cve_mcp=CveMcpConfig(**_known_kwargs(CveMcpConfig, data.get("cve_mcp", {}))),
            mcp=McpRuntimeConfig(**_known_kwargs(McpRuntimeConfig, data.get("mcp", data.get("cve_mcp", {})))),
            integration=IntegrationConfig(**_known_kwargs(IntegrationConfig, data.get("integration", {}))),
            tools=ToolRuntimeConfig(**_known_kwargs(ToolRuntimeConfig, data.get("tools", {}))),
            memory=MemoryRuntimeConfig(**_known_kwargs(MemoryRuntimeConfig, data.get("memory", {}))),
            message_bus=MessageBusConfig(**_known_kwargs(MessageBusConfig, data.get("message_bus", {}))),
            llm_decisions=llm_decisions,
            poc_repair=poc_repair,
            audit_scope=AuditScope(**_known_kwargs(AuditScope, data.get("audit_scope", {}))),
            sandbox=SandboxConfig(**_known_kwargs(SandboxConfig, data.get("sandbox", {}))),
            tool_permissions=ToolPermissions(**_known_kwargs(ToolPermissions, data.get("tool_permissions", {}))),
            output=OutputConfig(**_known_kwargs(OutputConfig, data.get("output", {}))),
            validation_levels=data.get(
                "validation_levels", ["static-only", "poc-generate", "sandbox", "manual"]
            ),
            default_validation_level=data.get("default_validation_level", "static-only"),
            runtime_enabled=data.get("runtime_enabled", False),
        )

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)

    def validate_poc_repair_prerequisites(self) -> None:
        self.poc_repair.__post_init__()
        if not self.poc_repair.enabled:
            return
        if not self.sandbox.enabled:
            raise ValueError("LLM PoC repair requires sandbox execution to be enabled")
        if self.default_validation_level != "sandbox":
            raise ValueError("LLM PoC repair requires sandbox validation level")
        if str(self.sandbox.runner).lower() != "docker":
            raise ValueError("LLM PoC repair requires the Docker sandbox runner")
        if not self.runtime_enabled:
            raise ValueError("LLM PoC repair requires runtime LLM client configuration")
        if self.llm.provider not in {
            "mock",
            "openai-compatible",
            "openai",
            "deepseek-compatible",
            "ollama-compatible",
        }:
            raise ValueError("LLM PoC repair requires a configured mock or real provider")


def _known_kwargs(cls, values: dict[str, Any]) -> dict[str, Any]:
    allowed = {item.name for item in fields(cls)}
    return {key: value for key, value in values.items() if key in allowed}
