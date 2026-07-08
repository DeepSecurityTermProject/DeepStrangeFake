from __future__ import annotations

import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Iterable

from .models import RepositoryMetadata, ToolObservation, ToolResult


SEVERITY_BY_CLASS = {
    "sql-injection": "high",
    "command-injection": "high",
    "path-traversal": "medium",
    "hardcoded-secret": "medium",
}


class PatternScanner:
    name = "pattern-scanner"

    def scan(self, metadata: RepositoryMetadata) -> ToolResult:
        started = time.monotonic()
        observations: list[ToolObservation] = []
        root = Path(metadata.root_path or ".")
        for relative in metadata.file_tree:
            path = root / relative
            if not path.exists() or path.stat().st_size > 2_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            observations.extend(self._scan_text(relative, text))
        duration_ms = int((time.monotonic() - started) * 1000)
        return ToolResult(
            tool_name=self.name,
            inputs={"target": metadata.target.source, "file_count": len(metadata.file_tree)},
            success=True,
            exit_status=0,
            duration_ms=duration_ms,
            observations=observations,
            message=f"{len(observations)} observations",
        )

    def _scan_text(self, relative: str, text: str) -> Iterable[ToolObservation]:
        for line_number, line in enumerate(text.splitlines(), start=1):
            if self._looks_like_sql_injection(line):
                yield self._observation(relative, line_number, line, "sql-injection", "SQL string uses user-controlled input.")
            if self._looks_like_command_injection(line):
                yield self._observation(
                    relative,
                    line_number,
                    line,
                    "command-injection",
                    "Command execution sink receives dynamic input.",
                )
            if self._looks_like_path_traversal(line):
                yield self._observation(
                    relative,
                    line_number,
                    line,
                    "path-traversal",
                    "File path construction appears to include user-controlled traversal input.",
                )
            if re.search(r"(?i)(api[_-]?key|secret|password|token)\s*=\s*['\"][^'\"]{8,}", line):
                yield self._observation(relative, line_number, line, "hardcoded-secret", "Hardcoded secret-like value.")

    def _observation(
        self, relative: str, line_number: int, line: str, vulnerability_class: str, message: str
    ) -> ToolObservation:
        return ToolObservation(
            tool_name=self.name,
            kind="sast-warning",
            message=message,
            path=relative,
            line=line_number,
            severity=SEVERITY_BY_CLASS.get(vulnerability_class, "medium"),
            vulnerability_class=vulnerability_class,
            evidence=line.strip(),
        )

    def _looks_like_sql_injection(self, line: str) -> bool:
        lowered = line.lower()
        return (
            ("select " in lowered or "insert " in lowered or "update " in lowered or "delete " in lowered)
            and ("%" in line or "format(" in line or "request." in line or "args.get" in line or "f\"" in line)
        )

    def _looks_like_command_injection(self, line: str) -> bool:
        return any(token in line for token in ["os.system", "subprocess.", "Runtime.getRuntime", "child_process"]) and (
            "request." in line or "args.get" in line or "+" in line or "input(" in line
        )

    def _looks_like_path_traversal(self, line: str) -> bool:
        return ("open(" in line or "send_file" in line or "readfile" in line) and (
            "../" in line or "request." in line or "args.get" in line
        )


class RepositorySearchTool:
    name = "repository-search"

    def search(self, metadata: RepositoryMetadata, pattern: str) -> ToolResult:
        started = time.monotonic()
        observations: list[ToolObservation] = []
        regex = re.compile(pattern)
        root = Path(metadata.root_path or ".")
        for relative in metadata.file_tree:
            path = root / relative
            if not path.exists():
                continue
            for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
                if regex.search(line):
                    observations.append(
                        ToolObservation(
                            tool_name=self.name,
                            kind="search-hit",
                            message=f"Pattern matched: {pattern}",
                            path=relative,
                            line=line_number,
                            evidence=line.strip(),
                        )
                    )
        return ToolResult(
            tool_name=self.name,
            inputs={"pattern": pattern},
            success=True,
            exit_status=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
        )


class SourceContextTool:
    name = "source-context"

    def slice(self, metadata: RepositoryMetadata, path: str, start_line: int, end_line: int, context: int = 3) -> ToolResult:
        root = Path(metadata.root_path or ".")
        source = root / path
        if not source.exists():
            return ToolResult(self.name, {"path": path}, False, exit_status=1, message="source file missing")
        lines = source.read_text(encoding="utf-8", errors="ignore").splitlines()
        begin = max(start_line - context, 1)
        finish = min(end_line + context, len(lines))
        snippet = "\n".join(f"{i}: {lines[i - 1]}" for i in range(begin, finish + 1))
        observation = ToolObservation(
            tool_name=self.name,
            kind="source-slice",
            message=f"{path}:{begin}-{finish}",
            path=path,
            line=start_line,
            evidence=snippet,
        )
        return ToolResult(self.name, {"path": path, "start": start_line, "end": end_line}, True, 0, observations=[observation])


class ExternalCommandTool:
    def __init__(self, name: str, command: list[str], timeout: int = 30):
        self.name = name
        self.command = command
        self.timeout = timeout

    def run(self, cwd: str | Path, extra_args: list[str] | None = None) -> ToolResult:
        executable = self.command[0] if self.command else ""
        if not executable or not shutil.which(executable):
            return ToolResult(
                tool_name=self.name,
                inputs={"command": self.command},
                success=False,
                exit_status=None,
                message=f"Tool unavailable: {executable}",
            )
        started = time.monotonic()
        command = self.command + list(extra_args or [])
        try:
            result = subprocess.run(
                command,
                cwd=str(cwd),
                timeout=self.timeout,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=self.name,
                inputs={"command": command},
                success=False,
                exit_status=None,
                duration_ms=int((time.monotonic() - started) * 1000),
                message="Tool timed out",
            )
        return ToolResult(
            tool_name=self.name,
            inputs={"command": command},
            success=result.returncode == 0,
            exit_status=result.returncode,
            duration_ms=int((time.monotonic() - started) * 1000),
            message=(result.stdout + result.stderr)[-4000:],
        )


class SemgrepAdapter(ExternalCommandTool):
    def __init__(self, timeout: int = 60):
        super().__init__("semgrep", ["semgrep", "--json", "--config", "auto"], timeout=timeout)


class BanditAdapter(ExternalCommandTool):
    def __init__(self, timeout: int = 60):
        super().__init__("bandit", ["bandit", "-r", ".", "-f", "json"], timeout=timeout)


class GitleaksAdapter(ExternalCommandTool):
    def __init__(self, timeout: int = 60):
        super().__init__("gitleaks", ["gitleaks", "detect", "--no-git", "--report-format", "json"], timeout=timeout)


class DependencyAuditAdapter(ExternalCommandTool):
    def __init__(self, ecosystem: str, timeout: int = 60):
        commands = {
            "npm": ["npm", "audit", "--json"],
            "python": ["pip-audit", "--format", "json"],
            "osv": ["osv-scanner", "--format", "json", "."],
        }
        super().__init__(f"{ecosystem}-dependency-audit", commands.get(ecosystem, ["osv-scanner", "."]), timeout=timeout)


class NullContextRetriever:
    name = "null-context-retriever"

    def retrieve(self, query: str, limit: int = 5) -> list[dict[str, str]]:
        return []
