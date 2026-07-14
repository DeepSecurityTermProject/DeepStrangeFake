from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from typing import Any

from .models import ToolObservation, VulnerabilityIntelligence


class CveMcpAdapter:
    tool_name = "cve-mcp-server"

    def __init__(
        self,
        enabled: bool = True,
        command: list[str] | None = None,
        endpoint: str | None = None,
        env: dict[str, str] | None = None,
        timeout: int = 15,
        query_budget: int = 50,
        degraded_mode: bool = True,
    ):
        self.enabled = enabled
        self.command = command or ["cve-mcp-server"]
        self.endpoint = endpoint
        self.env = env or {}
        self.timeout = timeout
        self.query_budget = query_budget
        self.degraded_mode = degraded_mode
        self.query_count = 0

    def query(self, tool: str, payload: dict[str, Any]) -> ToolObservation:
        if not self.enabled:
            return self._degraded("CVE MCP adapter disabled.", {"tool": tool, "payload": payload})
        if self.query_count >= self.query_budget:
            return self._degraded("CVE MCP query budget exhausted.", {"tool": tool, "payload": payload})
        self.query_count += 1
        executable = self.command[0] if self.command else ""
        if not executable or (not shutil.which(executable) and "/" not in executable and "\\" not in executable):
            return self._degraded(f"CVE MCP server unavailable: {executable}", {"tool": tool, "payload": payload})

        command = self.command + [tool, json.dumps(payload)]
        started = time.monotonic()
        try:
            result = subprocess.run(
                command,
                check=False,
                timeout=self.timeout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env={**os.environ, **self.env} if self.env else None,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return self._degraded(f"CVE MCP server unavailable: {exc}", {"tool": tool, "payload": payload})

        success = result.returncode == 0
        message = result.stdout.strip() if success else (result.stderr.strip() or result.stdout.strip())
        return ToolObservation(
            tool_name=self.tool_name,
            kind="vulnerability-intelligence",
            message=message or f"{tool} completed",
            success=success,
            degraded=not success,
            raw={
                "tool": tool,
                "payload": payload,
                "exit_status": result.returncode,
                "duration_ms": int((time.monotonic() - started) * 1000),
            },
        )

    def _degraded(self, message: str, raw: dict[str, Any]) -> ToolObservation:
        return ToolObservation(
            tool_name=self.tool_name,
            kind="vulnerability-intelligence",
            message=message,
            success=False,
            degraded=self.degraded_mode,
            raw=raw,
        )


def normalize_cve_mcp_output(
    raw: dict[str, Any],
    query: dict[str, Any] | None = None,
    tool_name: str = "cve-mcp-server",
) -> VulnerabilityIntelligence:
    cvss = raw.get("cvss")
    if isinstance(cvss, dict):
        cvss = cvss.get("score") or cvss.get("baseScore")
    epss = raw.get("epss")
    if isinstance(epss, dict):
        epss = epss.get("score") or epss.get("epss")
    cwe_ids = raw.get("cwe_ids") or raw.get("cwes") or []
    if isinstance(cwe_ids, str):
        cwe_ids = [cwe_ids]
    references = raw.get("references") or raw.get("refs") or []
    if isinstance(references, str):
        references = [references]
    cve_id = raw.get("cve_id") or raw.get("id")
    kev = raw.get("kev")
    if kev is None:
        kev = raw.get("cisa_kev")
    return VulnerabilityIntelligence(
        tool_name=tool_name,
        query=query or {},
        cve_id=cve_id,
        cwe_ids=list(cwe_ids),
        cvss=float(cvss) if cvss is not None else None,
        epss=float(epss) if epss is not None else None,
        kev=bool(kev) if kev is not None else None,
        public_poc_available=raw.get("public_poc_available"),
        risk_score=float(raw["risk_score"]) if raw.get("risk_score") is not None else None,
        references=list(references),
        contextual=True,
        validation_evidence=False,
        raw=raw,
    )
