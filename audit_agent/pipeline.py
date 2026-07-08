from __future__ import annotations

from pathlib import Path

from .config import AuditConfig
from .runtime import AgentRuntime


def run_audit(target: str, config: AuditConfig | None = None, output_dir: str | Path = "runs") -> dict:
    """Backward-compatible pipeline entrypoint backed by the runtime kernel."""
    return AgentRuntime(config or AuditConfig.default(), output_dir=output_dir).run_audit(target)
