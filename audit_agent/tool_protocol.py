from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .config import AuditConfig
from .dataflow.scanner import DataflowScanner
from .models import ToolCallRequest, ToolCallResult, ToolDeclaration, ToolObservation, ToolResult, to_plain
from .storage import immutable_path
from .tools import PatternScanner, RepositorySearchTool, SourceContextTool


class ToolPermissionError(RuntimeError):
    pass


Handler = Callable[[dict[str, Any]], Any]


@dataclass
class ToolBudget:
    per_agent: dict[str, int] = field(default_factory=dict)
    used: dict[str, int] = field(default_factory=dict)
    total_limit: int | None = None
    total_used: int = 0

    def consume(self, agent: str) -> bool:
        if self.total_limit is not None and self.total_used >= self.total_limit:
            return False
        limit = self.per_agent.get(agent)
        current = self.used.get(agent, 0)
        if limit is not None and current >= limit:
            return False
        self.used[agent] = current + 1
        self.total_used += 1
        return True


@dataclass
class RegisteredTool:
    declaration: ToolDeclaration
    handler: Handler


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, RegisteredTool] = {}

    def register(
        self,
        name: str,
        description: str,
        input_schema: dict[str, Any],
        permission_group: str,
        handler: Handler,
        output_kind: str = "tool-result",
        timeout_seconds: int = 30,
        safety_classification: str = "read-only",
    ) -> None:
        if name in self._tools:
            raise ValueError(f"Duplicate tool name: {name}")
        declaration = ToolDeclaration(
            name=name,
            description=description,
            input_schema=input_schema,
            permission_group=permission_group,
            output_kind=output_kind,
            timeout_seconds=timeout_seconds,
            safety_classification=safety_classification,
        )
        self._tools[name] = RegisteredTool(declaration=declaration, handler=handler)

    def get(self, name: str) -> RegisteredTool | None:
        return self._tools.get(name)

    def declarations(self) -> list[ToolDeclaration]:
        return [tool.declaration for tool in self._tools.values()]


class ToolRuntime:
    DEFAULT_PERMISSIONS = {
        "orchestrator": {"repository-read", "memory", "mcp-intelligence"},
        "recon": {"repository-read", "static-scan", "memory", "mcp-intelligence"},
        "analysis": {"repository-read", "static-scan", "memory", "mcp-intelligence"},
        "verification": {"repository-read", "static-scan", "memory", "mcp-intelligence", "validation"},
        "reporting": {"repository-read", "memory"},
        "validation": {"validation"},
    }

    def __init__(
        self,
        registry: ToolRegistry,
        artifact_root: Path | str | None = None,
        budget: ToolBudget | None = None,
        permissions: dict[str, set[str]] | None = None,
    ):
        self.registry = registry
        self.artifact_root = Path(artifact_root) if artifact_root else None
        self.budget = budget or ToolBudget()
        self.permissions = permissions or self.DEFAULT_PERMISSIONS

    def call(self, agent: str, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        request = ToolCallRequest(agent=agent, tool_name=tool_name, arguments=arguments)
        registered = self.registry.get(tool_name)
        if not registered:
            return self._result(request, False, "missing-tool", f"Tool not found: {tool_name}")
        permission_group = registered.declaration.permission_group
        if permission_group not in self.permissions.get(agent, set()):
            return self._result(
                request,
                False,
                "denied",
                f"Tool {tool_name} is not permitted for agent {agent}",
            )
        if not self.budget.consume(agent):
            return self._result(request, False, "budget-exhausted", f"Tool budget exhausted for {agent}")

        started = time.monotonic()
        executor = ThreadPoolExecutor(max_workers=1)
        try:
            future = executor.submit(registered.handler, arguments)
            output = future.result(timeout=registered.declaration.timeout_seconds)
            result = self._normalize_output(request, output, int((time.monotonic() - started) * 1000))
            self._persist(result)
            return result
        except FutureTimeout:
            executor.shutdown(wait=False, cancel_futures=True)
            result = self._result(
                request,
                False,
                "timeout",
                f"Tool timed out after {registered.declaration.timeout_seconds} seconds",
                duration_ms=int((time.monotonic() - started) * 1000),
            )
            self._persist(result)
            return result
        except Exception as exc:  # pragma: no cover - defensive normalization
            result = self._result(request, False, "error", str(exc), duration_ms=int((time.monotonic() - started) * 1000))
            self._persist(result)
            return result
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    def _normalize_output(self, request: ToolCallRequest, output: Any, duration_ms: int) -> ToolCallResult:
        if isinstance(output, ToolCallResult):
            return output
        if isinstance(output, ToolResult):
            return ToolCallResult(
                request_id=request.id or "",
                tool_name=output.tool_name,
                success=output.success,
                status="ok" if output.success else "error",
                message=output.message,
                observations=output.observations,
                output=output.to_dict(),
                duration_ms=output.duration_ms or duration_ms,
                artifact_paths=output.artifact_paths,
            )
        if isinstance(output, dict):
            return ToolCallResult(
                request_id=request.id or "",
                tool_name=request.tool_name,
                success=True,
                status="ok",
                output=output,
                duration_ms=duration_ms,
            )
        return ToolCallResult(
            request_id=request.id or "",
            tool_name=request.tool_name,
            success=True,
            status="ok",
            output={"value": output},
            duration_ms=duration_ms,
        )

    def _result(
        self, request: ToolCallRequest, success: bool, status: str, message: str, duration_ms: int = 0
    ) -> ToolCallResult:
        result = ToolCallResult(
            request_id=request.id or "",
            tool_name=request.tool_name,
            success=success,
            status=status,
            message=message,
            duration_ms=duration_ms,
        )
        self._persist(result)
        return result

    def _persist(self, result: ToolCallResult) -> None:
        if not self.artifact_root:
            return
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        path = immutable_path(self.artifact_root / f"{result.tool_name}-{result.id}.json")
        path.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        result.artifact_paths.append(str(path))


def _positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _run_dataflow_scan(arguments: dict[str, Any]) -> ToolResult:
    scanner = DataflowScanner(
        max_files=_positive_int(arguments.get("max_files"), 500),
        max_traces=_positive_int(arguments.get("max_traces"), 200),
    )
    return scanner.scan(
        arguments["metadata"],
        artifact_root=arguments.get("artifact_root"),
        language_filter=arguments.get("language_filter"),
    )


def build_default_tool_registry(config: AuditConfig | None = None) -> ToolRegistry:
    registry = ToolRegistry()
    search_tool = RepositorySearchTool()
    context_tool = SourceContextTool()
    scanner = PatternScanner()
    registry.register(
        "repository-search",
        "Search repository text using a regular expression.",
        {"type": "object"},
        "repository-read",
        lambda arguments: search_tool.search(arguments["metadata"], arguments["pattern"]),
    )
    registry.register(
        "source-context",
        "Read source context around a line range.",
        {"type": "object"},
        "repository-read",
        lambda arguments: context_tool.slice(
            arguments["metadata"], arguments["path"], arguments["start_line"], arguments["end_line"]
        ),
    )
    registry.register(
        "pattern-scan",
        "Run built-in static pattern scan.",
        {"type": "object"},
        "static-scan",
        lambda arguments: scanner.scan(arguments["metadata"]),
    )
    registry.register(
        "dataflow-scan",
        "Run built-in AST-backed source-to-sink dataflow scan.",
        {
            "type": "object",
            "properties": {
                "max_files": {"type": "integer"},
                "max_traces": {"type": "integer"},
            },
        },
        "static-scan",
        _run_dataflow_scan,
    )
    registry.register(
        "memory.retrieve",
        "Retrieve cited memory context.",
        {"type": "object"},
        "memory",
        lambda arguments: {"results": [to_plain(item) for item in arguments["store"].retrieve(arguments["query"])]},
    )
    registry.register(
        "mcp.cve.lookup",
        "Lookup CVE through MCP client.",
        {"type": "object"},
        "mcp-intelligence",
        lambda arguments: arguments["client"].lookup_cve(arguments["cve_id"]).to_dict(),
    )
    registry.register(
        "validation.sandbox",
        "Run configured sandbox validation.",
        {"type": "object"},
        "validation",
        lambda arguments: {"status": "delegated", "arguments": arguments},
        safety_classification="controlled-execution",
    )
    return registry
