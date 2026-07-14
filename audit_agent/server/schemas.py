from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator


MemoryMode = Literal["lexical", "embedding", "off"]
McpMode = Literal["on", "off", "degraded"]
ValidationLevel = Literal["static-only", "poc-generate", "sandbox", "manual"]
SandboxRunner = Literal["local", "docker"]
GraphMode = Literal["legacy", "deterministic-graph", "adaptive-graph"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LocalSource(StrictModel):
    kind: Literal["local"]
    path: str = Field(min_length=1)


class GitHubSource(StrictModel):
    kind: Literal["github"]
    url: str = Field(min_length=1)
    commit: str | None = None


class GitLabSource(StrictModel):
    kind: Literal["gitlab"]
    url: str = Field(min_length=1)
    commit: str | None = None


RemoteSource = Union[GitHubSource, GitLabSource]
SourceSpec = Annotated[Union[LocalSource, GitHubSource, GitLabSource], Field(discriminator="kind")]


class ScanRunRequest(StrictModel):
    target: str | None = Field(default=None, min_length=1)
    source: SourceSpec | None = None
    runtime: bool = False
    graph_mode: GraphMode | None = None
    llm_provider: str | None = None
    model: str | None = None
    llm_decisions: bool = False
    llm_decision_roles: list[str] | None = None
    memory_mode: MemoryMode | None = None
    mcp_mode: McpMode | None = None
    validation_level: ValidationLevel | None = None
    sandbox_enabled: bool = False
    sandbox_runner: SandboxRunner | None = None
    sandbox_docker_image: str | None = None
    sandbox_docker_context: str | None = None
    sandbox_docker_host: str | None = None
    llm_poc_repair: bool = False
    max_repair_attempts: int = Field(default=1, ge=0, le=2)
    include_patterns: list[str] | None = None
    exclude_patterns: list[str] | None = None
    output: str | None = None

    @model_validator(mode="after")
    def normalize_source(self):
        if self.target and self.source:
            raise ValueError("provide either legacy target or structured source, not both")
        if not self.target and self.source is None:
            raise ValueError("target or source is required")
        if self.source is None:
            self.source = LocalSource(kind="local", path=str(self.target))
        return self

    @property
    def display_target(self) -> str:
        if isinstance(self.source, (GitHubSource, GitLabSource)):
            return self.source.url
        if isinstance(self.source, LocalSource):
            return self.source.path
        return str(self.target or "")

    @property
    def requested_revision(self) -> str | None:
        return self.source.commit if isinstance(self.source, (GitHubSource, GitLabSource)) else None

    @model_validator(mode="after")
    def validate_poc_repair(self):
        if not self.llm_poc_repair:
            return self
        if not self.runtime:
            raise ValueError("LLM PoC repair requires runtime LLM client configuration")
        if self.validation_level != "sandbox":
            raise ValueError("LLM PoC repair requires validation_level='sandbox'")
        if not self.sandbox_enabled:
            raise ValueError("LLM PoC repair requires sandbox_enabled=true")
        if self.sandbox_runner != "docker":
            raise ValueError("LLM PoC repair requires sandbox_runner='docker'")
        if self.llm_provider not in {None, "mock", "openai-compatible"}:
            raise ValueError("LLM PoC repair requires a configured mock or real provider")
        return self


class CreateRunResponse(StrictModel):
    job_id: str
    status: str
    status_url: str


class JobStatusResponse(StrictModel):
    job_id: str
    target: str
    status: str
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    output_dir: str
    run_dir: str | None = None
    summary: dict = Field(default_factory=dict)
    error: str = ""
    source: dict | None = None
    phase: str = "queued"
    requested_revision: str | None = None
    resolved_commit: str | None = None
    acquisition_summary: dict = Field(default_factory=dict)
    acquisition_ref: str | None = None
    cleanup_status: str | None = None


class JobListResponse(StrictModel):
    jobs: list[JobStatusResponse]
