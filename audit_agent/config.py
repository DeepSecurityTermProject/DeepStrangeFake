from __future__ import annotations

import json
import os
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
    request_budget: int | None = None
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
class DependencyIntelligenceConfig:
    enabled: bool = True
    batch_size: int = 20
    query_budget: int = 50
    cache_policy: str = "persistent"
    cache_path: str = ".audit-cache/dependency-intelligence.v1.json"
    cache_ttl_seconds: int = 86_400

    def __post_init__(self) -> None:
        if self.batch_size <= 0:
            raise ValueError("dependency_intelligence.batch_size must be positive")
        if self.batch_size > 1000:
            raise ValueError("dependency_intelligence.batch_size must be at most 1000")
        if self.query_budget < 0:
            raise ValueError("dependency_intelligence.query_budget must not be negative")
        if self.cache_policy not in {"disabled", "per-run", "persistent"}:
            raise ValueError(
                "dependency_intelligence.cache_policy must be disabled, per-run, or persistent"
            )
        if self.cache_ttl_seconds < 0:
            raise ValueError("dependency_intelligence.cache_ttl_seconds must not be negative")

    @classmethod
    def from_environment(
        cls,
        env: dict[str, str] | None = None,
    ) -> "DependencyIntelligenceConfig":
        values = env or os.environ
        enabled_value = values.get("AUDIT_DEPENDENCY_INTELLIGENCE_ENABLED")
        enabled = True if enabled_value is None else enabled_value.strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        return cls(
            enabled=enabled,
            batch_size=int(values.get("AUDIT_DEPENDENCY_BATCH_SIZE", cls.batch_size)),
            query_budget=int(values.get("AUDIT_DEPENDENCY_QUERY_BUDGET", cls.query_budget)),
            cache_policy=values.get("AUDIT_DEPENDENCY_CACHE_POLICY", cls.cache_policy),
            cache_path=values.get("AUDIT_DEPENDENCY_CACHE_PATH", cls.cache_path),
            cache_ttl_seconds=int(
                values.get("AUDIT_DEPENDENCY_CACHE_TTL_SECONDS", cls.cache_ttl_seconds)
            ),
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
class GraphRuntimeConfig:
    mode: str = "deterministic-graph"
    max_nodes: int = 64
    max_scheduler_iterations: int = 256
    max_node_attempts: int = 2
    max_replans: int = 2
    max_checkpoints: int = 2

    def __post_init__(self) -> None:
        if self.mode not in {"legacy", "deterministic-graph", "adaptive-graph"}:
            raise ValueError(
                "graph.mode must be one of: legacy, deterministic-graph, adaptive-graph"
            )
        for name in (
            "max_nodes",
            "max_scheduler_iterations",
            "max_node_attempts",
            "max_replans",
            "max_checkpoints",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"graph.{name} must be a non-negative integer")


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
            "dependency-vulnerability",
        ]
    )
    include_patterns: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_AUDIT_EXCLUDE_PATTERNS))
    analysis_budget: int = 100
    tool_budget: int = 80
    cve_query_budget: int = 50
    max_files: int | None = None
    max_bytes: int | None = None


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
    max_starts: int | None = None


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
class RemoteAcquisitionConfig:
    enabled: bool = False
    network_enabled: bool = False
    allowed_hosts: list[str] = field(default_factory=lambda: ["github.com", "gitlab.com"])
    cache_root: str = ".audit-cache/repositories"
    work_root: str = ".audit-work/repositories"
    command_timeout_seconds: int = 60
    total_timeout_seconds: int = 180
    lock_timeout_seconds: int = 30
    max_mirror_bytes: int = 512 * 1024 * 1024
    max_archive_members: int = 50_000
    max_archive_bytes: int = 256 * 1024 * 1024
    max_files: int = 25_000
    max_bytes: int = 128 * 1024 * 1024
    cleanup_retries: int = 3
    cleanup_retry_delay_ms: int = 100

    def __post_init__(self) -> None:
        self.allowed_hosts = sorted({str(item).strip().lower() for item in self.allowed_hosts if str(item).strip()})
        supported_hosts = {"github.com", "gitlab.com"}
        if not self.allowed_hosts or not set(self.allowed_hosts).issubset(supported_hosts):
            raise ValueError("remote acquisition permits only github.com and gitlab.com")
        for name in (
            "command_timeout_seconds", "total_timeout_seconds", "lock_timeout_seconds",
            "max_mirror_bytes", "max_archive_members", "max_archive_bytes", "max_files",
            "max_bytes", "cleanup_retries", "cleanup_retry_delay_ms",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"remote_acquisition.{name} must be a non-negative integer")
        if self.command_timeout_seconds == 0 or self.total_timeout_seconds == 0:
            raise ValueError("remote acquisition timeouts must be positive")

    @classmethod
    def from_environment(cls, env: dict[str, str] | None = None) -> "RemoteAcquisitionConfig":
        values = env or os.environ
        truthy = {"1", "true", "yes", "on"}
        allowed_hosts = [
            item.strip()
            for item in values.get("AUDIT_REMOTE_ALLOWED_HOSTS", "github.com,gitlab.com").split(",")
            if item.strip()
        ]
        return cls(
            enabled=str(values.get("AUDIT_REMOTE_ACQUISITION_ENABLED", "")).lower() in truthy,
            network_enabled=str(values.get("AUDIT_REMOTE_ACQUISITION_NETWORK", "")).lower() in truthy,
            allowed_hosts=allowed_hosts,
            cache_root=values.get("AUDIT_REMOTE_CACHE_ROOT", cls.cache_root),
            work_root=values.get("AUDIT_REMOTE_WORK_ROOT", cls.work_root),
            command_timeout_seconds=int(values.get("AUDIT_REMOTE_COMMAND_TIMEOUT", cls.command_timeout_seconds)),
            total_timeout_seconds=int(values.get("AUDIT_REMOTE_TOTAL_TIMEOUT", cls.total_timeout_seconds)),
            lock_timeout_seconds=int(values.get("AUDIT_REMOTE_LOCK_TIMEOUT", cls.lock_timeout_seconds)),
        )


@dataclass
class AuditConfig:
    llm: LlmConfig = field(default_factory=LlmConfig)
    prompts: PromptRuntimeConfig = field(default_factory=PromptRuntimeConfig)
    cve_mcp: CveMcpConfig = field(default_factory=CveMcpConfig)
    mcp: McpRuntimeConfig = field(default_factory=McpRuntimeConfig)
    integration: IntegrationConfig = field(default_factory=IntegrationConfig)
    tools: ToolRuntimeConfig = field(default_factory=ToolRuntimeConfig)
    dependency_intelligence: DependencyIntelligenceConfig = field(
        default_factory=DependencyIntelligenceConfig
    )
    memory: MemoryRuntimeConfig = field(default_factory=MemoryRuntimeConfig)
    message_bus: MessageBusConfig = field(default_factory=MessageBusConfig)
    llm_decisions: LlmDecisionRuntimeConfig = field(default_factory=LlmDecisionRuntimeConfig)
    graph: GraphRuntimeConfig = field(default_factory=GraphRuntimeConfig)
    poc_repair: PoCRepairConfig = field(default_factory=PoCRepairConfig)
    audit_scope: AuditScope = field(default_factory=AuditScope)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    tool_permissions: ToolPermissions = field(default_factory=ToolPermissions)
    output: OutputConfig = field(default_factory=OutputConfig)
    remote_acquisition: RemoteAcquisitionConfig = field(default_factory=RemoteAcquisitionConfig)
    validation_levels: list[str] = field(
        default_factory=lambda: ["static-only", "poc-generate", "sandbox", "manual"]
    )
    default_validation_level: str = "static-only"
    runtime_enabled: bool = False

    @classmethod
    def default(cls) -> "AuditConfig":
        return cls(
            remote_acquisition=RemoteAcquisitionConfig.from_environment(),
            dependency_intelligence=DependencyIntelligenceConfig.from_environment(),
        )

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
            dependency_intelligence=DependencyIntelligenceConfig(
                **_known_kwargs(
                    DependencyIntelligenceConfig,
                    data.get("dependency_intelligence", {}),
                )
            ),
            memory=MemoryRuntimeConfig(**_known_kwargs(MemoryRuntimeConfig, data.get("memory", {}))),
            message_bus=MessageBusConfig(**_known_kwargs(MessageBusConfig, data.get("message_bus", {}))),
            llm_decisions=llm_decisions,
            graph=GraphRuntimeConfig(**_known_kwargs(GraphRuntimeConfig, data.get("graph", {}))),
            poc_repair=poc_repair,
            audit_scope=AuditScope(**_known_kwargs(AuditScope, data.get("audit_scope", {}))),
            sandbox=SandboxConfig(**_known_kwargs(SandboxConfig, data.get("sandbox", {}))),
            tool_permissions=ToolPermissions(**_known_kwargs(ToolPermissions, data.get("tool_permissions", {}))),
            output=OutputConfig(**_known_kwargs(OutputConfig, data.get("output", {}))),
            remote_acquisition=RemoteAcquisitionConfig(
                **_known_kwargs(RemoteAcquisitionConfig, data.get("remote_acquisition", {}))
            ),
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
