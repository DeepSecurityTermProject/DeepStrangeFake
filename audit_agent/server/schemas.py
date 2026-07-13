from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


MemoryMode = Literal["lexical", "embedding", "off"]
McpMode = Literal["on", "off", "degraded"]
ValidationLevel = Literal["static-only", "poc-generate", "sandbox", "manual"]
SandboxRunner = Literal["local", "docker"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScanRunRequest(StrictModel):
    target: str = Field(min_length=1)
    runtime: bool = False
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


class JobListResponse(StrictModel):
    jobs: list[JobStatusResponse]
