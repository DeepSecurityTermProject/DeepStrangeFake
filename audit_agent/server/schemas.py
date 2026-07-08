from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


MemoryMode = Literal["lexical", "embedding", "off"]
McpMode = Literal["on", "off", "degraded"]
ValidationLevel = Literal["static-only", "poc-generate", "sandbox", "manual"]


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
    output: str | None = None


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
