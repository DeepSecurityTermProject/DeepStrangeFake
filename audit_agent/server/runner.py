from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from ..config import AuditConfig
from ..integration import load_integration_environment
from ..pipeline import run_audit
from .job_store import JobStore
from .schemas import ScanRunRequest


RunAuditFunc = Callable[[str, AuditConfig, str | Path], dict]


def build_audit_config(request: ScanRunRequest, cwd: str | Path | None = None) -> AuditConfig:
    config = AuditConfig.default()
    load_integration_environment(config, cwd=cwd)
    if request.validation_level:
        config.default_validation_level = request.validation_level
    if request.runtime:
        config.runtime_enabled = True
    if request.llm_provider:
        config.llm.provider = request.llm_provider
    if request.model:
        config.llm.model = request.model
    if request.llm_decisions:
        config.runtime_enabled = True
        config.llm_decisions.enabled = True
    if request.llm_decision_roles:
        config.llm_decisions.roles = list(request.llm_decision_roles)
    if request.memory_mode:
        config.memory.enabled = request.memory_mode != "off"
        config.memory.mode = "lexical" if request.memory_mode == "off" else request.memory_mode
    if request.mcp_mode:
        config.mcp.enabled = request.mcp_mode != "off"
        config.mcp.degraded_mode = request.mcp_mode in {"degraded", "on"}
    return config


class ScanJobRunner:
    def __init__(
        self,
        job_store: JobStore,
        run_audit_func: RunAuditFunc = run_audit,
        max_workers: int = 1,
    ):
        self.job_store = job_store
        self.run_audit_func = run_audit_func
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="audit-web")

    def submit(self, job_id: str, request: ScanRunRequest) -> None:
        self.executor.submit(self.run_job, job_id, request)

    def run_job(self, job_id: str, request: ScanRunRequest) -> None:
        job = self.job_store.mark_running(job_id)
        config = build_audit_config(request)
        output_dir = Path(request.output or job.output_dir)
        try:
            summary = self.run_audit_func(request.target, config, output_dir)
            self.job_store.mark_succeeded(job_id, summary)
        except Exception as exc:
            self.job_store.mark_failed(job_id, str(exc))
