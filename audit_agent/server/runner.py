from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
import inspect
from pathlib import Path
from typing import Callable

from ..config import AuditConfig
from ..integration import load_integration_environment
from ..pipeline import run_audit
from ..runtime import CancellationToken
from ..repository_acquisition import RepositoryAcquisitionService
from .job_store import JobStore
from .schemas import ScanRunRequest


RunAuditFunc = Callable[[str, AuditConfig, str | Path], dict]


def build_audit_config(
    request: ScanRunRequest,
    cwd: str | Path | None = None,
    base_config: AuditConfig | None = None,
) -> AuditConfig:
    config = copy.deepcopy(base_config) if base_config is not None else AuditConfig.default()
    load_integration_environment(config, cwd=cwd)
    if request.graph_mode:
        config.graph.mode = request.graph_mode
    if request.validation_level:
        config.default_validation_level = request.validation_level
    config.sandbox.enabled = request.sandbox_enabled
    if request.sandbox_runner:
        config.sandbox.runner = request.sandbox_runner
    if request.sandbox_docker_image:
        config.sandbox.docker_image = request.sandbox_docker_image
    if request.sandbox_docker_context:
        config.sandbox.docker_context = request.sandbox_docker_context
    if request.sandbox_docker_host:
        config.sandbox.docker_host = request.sandbox_docker_host
    config.poc_repair.enabled = request.llm_poc_repair
    config.poc_repair.max_repair_attempts = request.max_repair_attempts
    config.poc_repair.effective_source = (
        "explicit"
        if {"llm_poc_repair", "max_repair_attempts"} & set(request.model_fields_set)
        else "default"
    )
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
    if request.include_patterns is not None:
        config.audit_scope.include_patterns = list(request.include_patterns)
    if request.exclude_patterns is not None:
        config.audit_scope.exclude_patterns = list(request.exclude_patterns)
    config.validate_poc_repair_prerequisites()
    return config


class ScanJobRunner:
    def __init__(
        self,
        job_store: JobStore,
        run_audit_func: RunAuditFunc = run_audit,
        max_workers: int = 1,
        config: AuditConfig | None = None,
        acquisition_service: RepositoryAcquisitionService | None = None,
    ):
        self.job_store = job_store
        self.run_audit_func = run_audit_func
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="audit-web")
        self.config = config or AuditConfig.default()
        self.acquisition_service = acquisition_service or RepositoryAcquisitionService(
            self.config.remote_acquisition
        )
        self._tokens: dict[str, CancellationToken] = {}
        self._futures = {}

    def submit(self, job_id: str, request: ScanRunRequest) -> None:
        self._tokens[job_id] = CancellationToken()
        self._futures[job_id] = self.executor.submit(self.run_job, job_id, request)

    def cancel(self, job_id: str):
        token = self._tokens.setdefault(job_id, CancellationToken())
        token.cancel()
        future = self._futures.get(job_id)
        if future is not None:
            future.cancel()
        return self.job_store.mark_cancelled(job_id)

    def run_job(self, job_id: str, request: ScanRunRequest) -> None:
        if self._tokens.get(job_id) and self._tokens[job_id].cancelled:
            self.job_store.mark_cancelled(job_id)
            return
        job = self.job_store.mark_running(job_id)
        config = build_audit_config(request, base_config=self.config)
        output_dir = Path(request.output or job.output_dir)
        try:
            target = request.display_target
            common_kwargs = {"resume_run_id": request.resume_run_id} if request.resume_run_id else {}
            if request.source and request.source.kind in {"github", "gitlab"}:
                kwargs = {
                    "requested_revision": request.requested_revision,
                    "job_id": job_id,
                    "acquisition_service": self.acquisition_service,
                    "progress_callback": lambda phase: self.job_store.update_phase(job_id, phase),
                    **common_kwargs,
                }
                summary = self._invoke_run(target, config, output_dir, job_id, **kwargs)
            else:
                self.job_store.update_phase(job_id, "analyzing")
                summary = self._invoke_run(target, config, output_dir, job_id, **common_kwargs)
            if summary.get("status") == "cancelled":
                self.job_store.mark_cancelled(job_id, summary)
            elif summary.get("status") == "degraded":
                self.job_store.mark_degraded(job_id, summary)
            else:
                self.job_store.mark_succeeded(job_id, summary)
        except Exception as exc:
            self.job_store.mark_failed(
                job_id,
                str(exc),
                run_dir=getattr(exc, "run_dir", None),
                summary=getattr(exc, "summary", None),
            )

    def _invoke_run(self, target, config, output_dir, web_job_id: str, **kwargs):
        signature = inspect.signature(self.run_audit_func)
        accepts_kwargs = any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in signature.parameters.values()
        )
        if accepts_kwargs or "cancellation_token" in signature.parameters:
            kwargs["cancellation_token"] = self._tokens.setdefault(web_job_id, CancellationToken())
        return self.run_audit_func(target, config, output_dir, **kwargs)
