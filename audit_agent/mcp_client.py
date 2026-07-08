from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any

from .models import MCPCallRecord, MCPSessionRecord, VulnerabilityIntelligence
from .redaction import redact_secrets


@dataclass
class MCPToolInfo:
    name: str
    description: str = ""
    input_schema: dict[str, Any] | None = None


@dataclass
class MCPToolResult:
    tool_name: str
    success: bool
    response: dict[str, Any]
    call_record: MCPCallRecord
    message: str = ""


class MCPClient:
    def __init__(
        self,
        command: list[str],
        timeout_seconds: int = 15,
        query_budget: int = 50,
        allowed_tools: list[str] | set[str] | tuple[str, ...] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ):
        self.command = command
        self.timeout_seconds = timeout_seconds
        self.query_budget = query_budget
        self.allowed_tools = set(allowed_tools or [])
        self.cwd = cwd
        self.env = env or {}
        self.query_count = 0
        self.process: subprocess.Popen[str] | None = None
        self.stderr_output = ""
        self._request_id = 0
        self.session = MCPSessionRecord(command=command)

    def __enter__(self) -> "MCPClient":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def start(self) -> None:
        try:
            self.process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                cwd=self.cwd,
                env={**os.environ, **self.env} if self.env else None,
            )
            response = self._send(
                "initialize",
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "audit-agent", "version": "0.1.0"},
                },
            )
            result = response.get("result", {})
            self.session.initialized = True
            self.session.server_info = result.get("serverInfo", {})
            self.session.capabilities = result.get("capabilities", {})
        except Exception as exc:
            self.session.degraded = True
            self.session.message = redact_secrets(f"MCP server unavailable: {exc}")
            self.close()

    def close(self) -> None:
        if self.process:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
            if self.process.stderr and not self.process.stderr.closed:
                try:
                    self.stderr_output = redact_secrets(self.process.stderr.read() or "")
                except OSError:
                    pass
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                try:
                    if stream:
                        stream.close()
                except OSError:
                    pass
        self.process = None

    def list_tools(self) -> list[MCPToolInfo]:
        if not self.session.initialized:
            return []
        response = self._send("tools/list", {})
        tools = response.get("result", {}).get("tools", [])
        return [
            MCPToolInfo(
                name=item.get("name", ""),
                description=item.get("description", ""),
                input_schema=item.get("inputSchema") or item.get("input_schema") or {},
            )
            for item in tools
        ]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> MCPToolResult:
        started = time.monotonic()
        if self.allowed_tools and name not in self.allowed_tools:
            record = MCPCallRecord(
                session_id=self.session.id or "",
                tool_name=name,
                arguments=arguments,
                success=False,
                degraded=True,
                duration_ms=int((time.monotonic() - started) * 1000),
                message=f"policy-denied: MCP tool {name} is not in the safe allowlist.",
            )
            return MCPToolResult(name, False, {}, record, record.message)
        if self.query_count >= self.query_budget:
            record = MCPCallRecord(
                session_id=self.session.id or "",
                tool_name=name,
                arguments=arguments,
                success=False,
                degraded=True,
                message="MCP query budget exhausted.",
            )
            return MCPToolResult(name, False, {}, record, record.message)
        self.query_count += 1
        if not self.session.initialized:
            record = MCPCallRecord(
                session_id=self.session.id or "",
                tool_name=name,
                arguments=arguments,
                success=False,
                degraded=True,
                message=self.session.message or "MCP session is not initialized.",
            )
            return MCPToolResult(name, False, {}, record, record.message)
        request_params = {"name": name, "arguments": arguments}
        try:
            raw = self._send("tools/call", request_params)
            response = _extract_mcp_payload(raw.get("result", {}))
            record = MCPCallRecord(
                session_id=self.session.id or "",
                tool_name=name,
                arguments=arguments,
                success=True,
                response=redact_secrets(response),
                duration_ms=int((time.monotonic() - started) * 1000),
                raw_response=redact_secrets(raw),
            )
            return MCPToolResult(name, True, response, record)
        except Exception as exc:
            record = MCPCallRecord(
                session_id=self.session.id or "",
                tool_name=name,
                arguments=arguments,
                success=False,
                degraded=True,
                duration_ms=int((time.monotonic() - started) * 1000),
                message=redact_secrets(str(exc)),
            )
            return MCPToolResult(name, False, {}, record, str(exc))

    def _send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if not self.process or not self.process.stdin or not self.process.stdout:
            raise RuntimeError("MCP process is not running")
        self._request_id += 1
        request = {"jsonrpc": "2.0", "id": self._request_id, "method": method, "params": params}
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        line = self._readline_with_timeout()
        if not line:
            raise RuntimeError("MCP server closed stdout")
        response = json.loads(line)
        if "error" in response:
            raise RuntimeError(str(response["error"]))
        return response

    def _readline_with_timeout(self) -> str:
        if not self.process or not self.process.stdout:
            raise RuntimeError("MCP process is not running")
        result: dict[str, str] = {}
        error: dict[str, BaseException] = {}

        def read_line() -> None:
            try:
                result["line"] = self.process.stdout.readline()
            except BaseException as exc:
                error["error"] = exc

        thread = threading.Thread(target=read_line, daemon=True)
        thread.start()
        thread.join(self.timeout_seconds)
        if thread.is_alive():
            self.session.degraded = True
            self.session.message = "MCP read timeout."
            self.close()
            raise TimeoutError("MCP read timeout")
        if error:
            raise error["error"]
        return result.get("line", "")


class CveMcpClient:
    def __init__(
        self,
        command: list[str],
        timeout_seconds: int = 15,
        query_budget: int = 50,
        allowed_tools: list[str] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ):
        self.command = command
        self.timeout_seconds = timeout_seconds
        self.query_budget = query_budget
        self.allowed_tools = allowed_tools
        self.cwd = cwd
        self.env = env or {}

    def lookup_cve(self, cve_id: str) -> VulnerabilityIntelligence:
        try:
            with MCPClient(
                self.command,
                self.timeout_seconds,
                self.query_budget,
                allowed_tools=self.allowed_tools,
                cwd=self.cwd,
                env=self.env,
            ) as client:
                result = client.call_tool("lookup_cve", {"cve_id": cve_id})
        except Exception as exc:
            return self._degraded({"cve_id": cve_id}, str(exc))
        if not result.success:
            return self._degraded({"cve_id": cve_id}, result.message)
        return _intelligence_from_response(result.response, {"cve_id": cve_id}, result.call_record.to_dict())

    def scan_dependency(self, dependency: dict[str, Any]) -> VulnerabilityIntelligence:
        try:
            with MCPClient(
                self.command,
                self.timeout_seconds,
                self.query_budget,
                allowed_tools=self.allowed_tools,
                cwd=self.cwd,
                env=self.env,
            ) as client:
                tools = {tool.name for tool in client.list_tools()}
                tool_name = "scan_dependencies" if "scan_dependencies" in tools else "lookup_cve"
                args = dependency if tool_name == "scan_dependencies" else {"cve_id": dependency.get("cve_id", "")}
                result = client.call_tool(tool_name, args)
        except Exception as exc:
            return self._degraded(dependency, str(exc))
        if not result.success:
            return self._degraded(dependency, result.message)
        return _intelligence_from_response(result.response, dependency, result.call_record.to_dict())

    def _degraded(self, query: dict[str, Any], message: str) -> VulnerabilityIntelligence:
        return VulnerabilityIntelligence(
            tool_name="cve-mcp-server",
            query=redact_secrets(query),
            contextual=True,
            validation_evidence=False,
            raw={"degraded": True, "message": redact_secrets(message)},
        )


def _extract_mcp_payload(result: dict[str, Any]) -> dict[str, Any]:
    content = result.get("content")
    if isinstance(content, list) and content:
        text = content[0].get("text", "")
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return {"text": text}
    return result if isinstance(result, dict) else {"value": result}


def _intelligence_from_response(
    response: dict[str, Any], query: dict[str, Any], raw: dict[str, Any]
) -> VulnerabilityIntelligence:
    cwe_ids = response.get("cwe_ids") or response.get("cwes") or []
    if isinstance(cwe_ids, str):
        cwe_ids = [cwe_ids]
    cvss = _first_number(response, "cvss", "cvss_score", "base_score")
    if cvss is None and isinstance(response.get("cvss"), dict):
        cvss = _first_number(response["cvss"], "base_score", "score")
    epss = _first_number(response, "epss", "epss_score", "probability")
    kev = response.get("kev") if response.get("kev") is not None else response.get("cisa_kev")
    if kev is None:
        kev = response.get("known_exploited") or response.get("is_known_exploited")
    return VulnerabilityIntelligence(
        tool_name="cve-mcp-server",
        query=redact_secrets(query),
        cve_id=response.get("cve_id") or response.get("id") or response.get("CVE_ID"),
        cwe_ids=list(cwe_ids),
        cvss=cvss,
        epss=epss,
        kev=kev,
        public_poc_available=response.get("public_poc_available"),
        risk_score=_first_number(response, "risk_score", "risk"),
        references=response.get("references") or [],
        contextual=True,
        validation_evidence=False,
        raw=redact_secrets({"degraded": False, "mcp_call": raw, "response": response}),
    )


def _first_number(value: dict[str, Any], *keys: str) -> float | None:
    for key in keys:
        if value.get(key) is not None:
            try:
                return float(value[key])
            except (TypeError, ValueError):
                continue
    return None
