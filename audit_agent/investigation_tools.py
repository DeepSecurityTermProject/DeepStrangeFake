from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .dataflow.scanner import DataflowScanner
from .investigation_models import (
    EvidenceItem,
    INVESTIGATION_ACTIONS,
    SUPPORTED_INVESTIGATION_CLASSES,
)
from .models import RepositoryMetadata, ToolObservation, ToolResult, stable_id, to_plain
from .redaction import redact_text


TEXT_FILE_LIMIT = 2_000_000
TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,63}")
JS_TS_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
SINK_HINTS = {
    "sql-injection": ("execute", "query", "cursor", "select", "insert", "update", "delete"),
    "command-injection": ("system", "popen", "subprocess", "exec", "spawn", "child_process"),
    "path-traversal": ("open", "readfile", "send_file", "path", "join", "resolve"),
    "hardcoded-secret": ("secret", "password", "token", "api_key", "apikey", "credential"),
}


class InvestigationToolError(RuntimeError):
    pass


@dataclass(frozen=True)
class CallGraphSymbol:
    symbol_id: str
    name: str
    path: str
    line: int
    language: str
    kind: str = "function"

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass(frozen=True)
class CallGraphEdge:
    caller_id: str
    callee_name: str
    path: str
    line: int
    resolved_callee_ids: tuple[str, ...] = ()
    unresolved: bool = False

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class CallGraphIndex:
    symbols: list[CallGraphSymbol] = field(default_factory=list)
    edges: list[CallGraphEdge] = field(default_factory=list)
    imports: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)

    def callers(self, symbol: str) -> list[dict[str, Any]]:
        target_ids = {item.symbol_id for item in self.symbols if item.name == symbol or item.symbol_id == symbol}
        target_names = {item.name for item in self.symbols if item.symbol_id in target_ids}
        if not target_names and symbol:
            target_names.add(symbol)
        return [
            edge.to_dict()
            for edge in self.edges
            if edge.callee_name in target_names or bool(target_ids.intersection(edge.resolved_callee_ids))
        ]

    def callees(self, symbol: str) -> list[dict[str, Any]]:
        caller_ids = {item.symbol_id for item in self.symbols if item.name == symbol or item.symbol_id == symbol}
        return [edge.to_dict() for edge in self.edges if edge.caller_id in caller_ids]


class RepositoryView:
    def __init__(self, metadata: RepositoryMetadata, *, secret_values: list[str] | None = None):
        if not metadata.root_path:
            raise InvestigationToolError("repository metadata has no materialized root")
        self.metadata = metadata
        self.root = Path(metadata.root_path).resolve()
        self.allowed = {self._normalize(item) for item in metadata.file_tree}
        self.secret_values = [item for item in (secret_values or []) if item]

    @staticmethod
    def _normalize(path: str) -> str:
        normalized = str(PurePosixPath(path.replace("\\", "/")))
        if normalized in {"", "."} or normalized.startswith("/"):
            raise InvestigationToolError("repository path must be relative")
        if any(part in {"", ".", ".."} for part in normalized.split("/")):
            raise InvestigationToolError("repository path contains traversal")
        if ":" in normalized.split("/", 1)[0]:
            raise InvestigationToolError("repository path must not contain a drive")
        return normalized

    def resolve(self, path: str) -> tuple[str, Path]:
        relative = self._normalize(path)
        if relative not in self.allowed:
            raise InvestigationToolError("path is outside RepositoryMetadata.file_tree")
        candidate = (self.root / Path(relative)).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise InvestigationToolError("path resolves outside repository root") from exc
        if not candidate.is_file():
            raise InvestigationToolError("repository file is missing or unreadable")
        return relative, candidate

    def read(self, path: str) -> tuple[str, str, str]:
        relative, candidate = self.resolve(path)
        if candidate.stat().st_size > TEXT_FILE_LIMIT:
            raise InvestigationToolError("repository file exceeds investigation text limit")
        raw = candidate.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        return relative, text, hashlib.sha256(raw).hexdigest()

    def source_evidence(
        self,
        path: str,
        start_line: int,
        end_line: int | None = None,
        *,
        context: int = 0,
        origin: str = "source",
        vulnerability_class: str | None = None,
        message: str = "",
        counterevidence: bool = False,
    ) -> EvidenceItem:
        if isinstance(start_line, bool) or not isinstance(start_line, int) or start_line < 1:
            raise InvestigationToolError("start_line must be a positive integer")
        selected_end = start_line if end_line is None else end_line
        if isinstance(selected_end, bool) or not isinstance(selected_end, int) or selected_end < start_line:
            raise InvestigationToolError("end_line must not precede start_line")
        relative, text, content_hash = self.read(path)
        lines = text.splitlines()
        if start_line > max(1, len(lines)):
            raise InvestigationToolError("source line is outside the file")
        begin = max(1, start_line - max(0, context))
        finish = min(len(lines), selected_end + max(0, context))
        excerpt = "\n".join(f"{index}: {lines[index - 1]}" for index in range(begin, finish + 1))
        redacted = redact_text(excerpt, self.secret_values)
        identity = stable_id("SRC", relative, start_line, selected_end, content_hash)
        return EvidenceItem(
            evidence_id=stable_id("EVI", origin, identity, message),
            origin=origin,
            path=relative,
            start_line=start_line,
            end_line=selected_end,
            excerpt=redacted,
            content_hash=content_hash,
            source_identity=identity,
            vulnerability_class=vulnerability_class,
            message=message,
            counterevidence=counterevidence,
        )

    def search(self, query: str, *, limit: int = 100) -> list[EvidenceItem]:
        query = str(query).strip()
        if not query or len(query) > 256:
            raise InvestigationToolError("search query must contain 1..256 characters")
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        matches: list[EvidenceItem] = []
        for relative in sorted(self.allowed):
            try:
                _, text, _ = self.read(relative)
            except (OSError, InvestigationToolError):
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                if pattern.search(line):
                    matches.append(
                        self.source_evidence(
                            relative,
                            line_number,
                            origin="source",
                            message=f"literal search matched {query!r}",
                        )
                    )
                    if len(matches) >= limit:
                        return matches
        return matches

    def bootstrap_context(
        self,
        *,
        max_files: int = 12,
        max_lines_per_file: int = 40,
        max_bytes: int = 16_000,
    ) -> list[dict[str, Any]]:
        """Return bounded source excerpts selected without benchmark labels or findings."""
        results: list[dict[str, Any]] = []
        used = 0
        for relative in sorted(self.allowed):
            if len(results) >= max_files or used >= max_bytes:
                break
            try:
                _path, source, content_hash = self.read(relative)
            except (OSError, InvestigationToolError):
                continue
            lines = source.splitlines()[:max_lines_per_file]
            if not lines:
                continue
            excerpt = "\n".join(f"{index}: {line}" for index, line in enumerate(lines, start=1))
            remaining = max_bytes - used
            encoded = excerpt.encode("utf-8")[:remaining]
            excerpt = encoded.decode("utf-8", errors="ignore")
            if not excerpt:
                break
            redacted = redact_text(excerpt, self.secret_values)
            used += len(redacted.encode("utf-8"))
            results.append(
                {
                    "path": relative,
                    "start_line": 1,
                    "end_line": len(lines),
                    "content_hash": content_hash,
                    "excerpt": redacted,
                }
            )
        return results

    def lexical(self, query: str, *, limit: int = 10) -> list[EvidenceItem]:
        tokens = {item.lower() for item in TOKEN_RE.findall(str(query))}
        if not tokens:
            raise InvestigationToolError("lexical query contains no searchable tokens")
        ranked: list[tuple[float, str, int, str]] = []
        for relative in sorted(self.allowed):
            try:
                _, text, _ = self.read(relative)
            except (OSError, InvestigationToolError):
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                line_tokens = {item.lower() for item in TOKEN_RE.findall(line)}
                overlap = tokens.intersection(line_tokens)
                if not overlap:
                    continue
                score = len(overlap) / max(1, len(tokens)) + min(len(overlap), 4) * 0.05
                ranked.append((score, relative, line_number, line))
        ranked.sort(key=lambda item: (-item[0], item[1], item[2]))
        output: list[EvidenceItem] = []
        for score, relative, line_number, _line in ranked[:limit]:
            evidence = self.source_evidence(
                relative,
                line_number,
                origin="lexical-memory",
                message=f"lexical score={score:.3f}",
            )
            evidence.raw["score"] = score
            output.append(evidence)
        return output


class RepositoryCallGraphBuilder:
    def build(self, view: RepositoryView) -> CallGraphIndex:
        index = CallGraphIndex()
        pending_edges: list[tuple[str, str, str, int, bool]] = []
        for relative in sorted(view.allowed):
            suffix = Path(relative).suffix.lower()
            try:
                _, text, _ = view.read(relative)
            except (OSError, InvestigationToolError):
                continue
            if suffix == ".py":
                self._parse_python(relative, text, index, pending_edges)
            elif suffix in JS_TS_SUFFIXES:
                self._parse_js_ts(relative, text, index, pending_edges)
        names: dict[str, list[str]] = {}
        for symbol in index.symbols:
            names.setdefault(symbol.name, []).append(symbol.symbol_id)
        for caller_id, callee_name, path, line, dynamic in pending_edges:
            resolved = tuple(sorted(names.get(callee_name, ())))
            index.edges.append(
                CallGraphEdge(
                    caller_id=caller_id,
                    callee_name=callee_name,
                    path=path,
                    line=line,
                    resolved_callee_ids=resolved,
                    unresolved=dynamic or not bool(resolved),
                )
            )
        index.edges.sort(key=lambda item: (item.path, item.line, item.caller_id, item.callee_name))
        index.symbols.sort(key=lambda item: (item.path, item.line, item.name))
        return index

    def _parse_python(
        self,
        path: str,
        text: str,
        index: CallGraphIndex,
        pending: list[tuple[str, str, str, int, bool]],
    ) -> None:
        try:
            tree = ast.parse(text, filename=path)
        except SyntaxError:
            return
        module_id = stable_id("SYM", path, "<module>", 1)
        index.symbols.append(CallGraphSymbol(module_id, "<module>", path, 1, "python", "module"))
        stack = [module_id]

        class Visitor(ast.NodeVisitor):
            def visit_Import(self, node: ast.Import) -> None:
                for alias in node.names:
                    index.imports.append({"path": path, "line": node.lineno, "module": alias.name, "name": alias.asname or alias.name})

            def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
                for alias in node.names:
                    index.imports.append({"path": path, "line": node.lineno, "module": node.module or "", "name": alias.asname or alias.name})

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                symbol_id = stable_id("SYM", path, node.name, node.lineno)
                index.symbols.append(CallGraphSymbol(symbol_id, node.name, path, node.lineno, "python"))
                stack.append(symbol_id)
                self.generic_visit(node)
                stack.pop()

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Call(self, node: ast.Call) -> None:
                name, dynamic = _python_call_name(node.func)
                pending.append((stack[-1], name, path, node.lineno, dynamic))
                self.generic_visit(node)

        Visitor().visit(tree)

    def _parse_js_ts(
        self,
        path: str,
        text: str,
        index: CallGraphIndex,
        pending: list[tuple[str, str, str, int, bool]],
    ) -> None:
        language = "typescript" if Path(path).suffix.lower() in {".ts", ".tsx"} else "javascript"
        module_id = stable_id("SYM", path, "<module>", 1)
        index.symbols.append(CallGraphSymbol(module_id, "<module>", path, 1, language, "module"))
        current_by_line: list[tuple[int, str]] = [(1, module_id)]
        function_patterns = (
            re.compile(r"\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\("),
            re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>"),
        )
        import_pattern = re.compile(r"\b(?:import\s+.+?\s+from\s+|require\s*\()(['\"])(.+?)\1")
        call_pattern = re.compile(r"(?<!\bfunction\s)([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(")
        dynamic_pattern = re.compile(r"\[[^\]]+\]\s*\(")
        keywords = {"if", "for", "while", "switch", "catch", "function", "return", "typeof", "new"}
        for line_number, line in enumerate(text.splitlines(), start=1):
            for match in import_pattern.finditer(line):
                index.imports.append({"path": path, "line": line_number, "module": match.group(2), "name": match.group(2)})
            for pattern in function_patterns:
                match = pattern.search(line)
                if match:
                    name = match.group(1)
                    symbol_id = stable_id("SYM", path, name, line_number)
                    index.symbols.append(CallGraphSymbol(symbol_id, name, path, line_number, language))
                    current_by_line.append((line_number, symbol_id))
                    break
            caller_id = current_by_line[-1][1]
            for match in call_pattern.finditer(line):
                full_name = match.group(1)
                base_name = full_name.split(".")[-1]
                if base_name in keywords:
                    continue
                pending.append((caller_id, base_name, path, line_number, "." in full_name))
            if dynamic_pattern.search(line):
                pending.append((caller_id, "<dynamic>", path, line_number, True))


def _python_call_name(node: ast.AST) -> tuple[str, bool]:
    if isinstance(node, ast.Name):
        return node.id, False
    if isinstance(node, ast.Attribute):
        return node.attr, True
    return "<dynamic>", True


@dataclass
class ExternalToolObservation:
    tool: str
    status: str
    observations: list[EvidenceItem] = field(default_factory=list)
    message: str = ""
    duration_ms: int = 0
    version: str = ""
    command_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


class FixedSastAdapter:
    COMMANDS = {
        "semgrep": ("semgrep", "scan", "--json", "--config", "auto", "."),
        "bandit": ("bandit", "-r", ".", "-f", "json"),
        "gitleaks": (
            "gitleaks",
            "detect",
            "--no-git",
            "--report-format",
            "json",
            "--report-path",
            "-",
        ),
    }

    def __init__(
        self,
        tool: str,
        *,
        timeout_seconds: int = 60,
        output_limit: int = 1_000_000,
        runner: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
        cancelled: Callable[[], bool] | None = None,
    ):
        if tool not in self.COMMANDS:
            raise ValueError(f"unsupported SAST adapter: {tool}")
        self.tool = tool
        self.command = self.COMMANDS[tool]
        self.timeout_seconds = timeout_seconds
        self.output_limit = output_limit
        self.runner = runner
        self.cancelled = cancelled or (lambda: False)

    def run(self, view: RepositoryView) -> ExternalToolObservation:
        executable = self.command[0]
        if self.runner is None and not shutil.which(executable):
            return ExternalToolObservation(
                self.tool,
                "unavailable",
                message=f"registered executable unavailable: {executable}",
                command_id=stable_id("CMD", self.tool, self.command),
            )
        started = time.monotonic()
        try:
            if self.runner is None:
                from .benchmark_runtime import ProcessTreeRunner

                completed = ProcessTreeRunner().run(
                    list(self.command),
                    cwd=str(view.root),
                    env=dict(os.environ),
                    timeout_seconds=self.timeout_seconds,
                    cancelled=self.cancelled,
                )
                if completed.cancelled:
                    return ExternalToolObservation(
                        self.tool,
                        "cancelled",
                        message="tool process tree terminated after cancellation",
                        duration_ms=int((time.monotonic() - started) * 1000),
                        command_id=stable_id("CMD", self.tool, self.command),
                    )
            else:
                completed = self.runner(
                    list(self.command),
                    cwd=str(view.root),
                    shell=False,
                    check=False,
                    timeout=self.timeout_seconds,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
        except subprocess.TimeoutExpired:
            return ExternalToolObservation(
                self.tool,
                "timeout",
                message=f"tool timed out after {self.timeout_seconds}s",
                duration_ms=int((time.monotonic() - started) * 1000),
                command_id=stable_id("CMD", self.tool, self.command),
            )
        except OSError as exc:
            return ExternalToolObservation(
                self.tool,
                "unavailable",
                message=f"tool launch failed: {type(exc).__name__}",
                duration_ms=int((time.monotonic() - started) * 1000),
                command_id=stable_id("CMD", self.tool, self.command),
            )
        stdout_value = completed.stdout or b""
        stderr_value = completed.stderr or b""
        stdout = stdout_value.encode("utf-8") if isinstance(stdout_value, str) else bytes(stdout_value)
        stderr = stderr_value.encode("utf-8") if isinstance(stderr_value, str) else bytes(stderr_value)
        if len(stdout) + len(stderr) > self.output_limit:
            return ExternalToolObservation(
                self.tool,
                "output-capped",
                message=f"tool output exceeded {self.output_limit} bytes",
                duration_ms=int((time.monotonic() - started) * 1000),
                command_id=stable_id("CMD", self.tool, self.command),
            )
        if completed.returncode not in {0, 1}:
            return ExternalToolObservation(
                self.tool,
                "error",
                message=f"tool exited with registered non-result code {completed.returncode}",
                duration_ms=int((time.monotonic() - started) * 1000),
                command_id=stable_id("CMD", self.tool, self.command),
            )
        try:
            payload = json.loads(stdout.decode("utf-8", errors="strict") or "[]")
            observations = self._normalize(payload, view)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, KeyError, TypeError) as exc:
            return ExternalToolObservation(
                self.tool,
                "malformed",
                message=f"unsupported or malformed JSON output: {type(exc).__name__}",
                duration_ms=int((time.monotonic() - started) * 1000),
                command_id=stable_id("CMD", self.tool, self.command),
            )
        return ExternalToolObservation(
            self.tool,
            "ok",
            observations=observations,
            message=f"{len(observations)} normalized observations",
            duration_ms=int((time.monotonic() - started) * 1000),
            command_id=stable_id("CMD", self.tool, self.command),
        )

    def _normalize(self, payload: Any, view: RepositoryView) -> list[EvidenceItem]:
        if self.tool == "semgrep":
            if not isinstance(payload, dict) or not isinstance(payload.get("results", []), list):
                raise ValueError("unsupported semgrep result shape")
            records = payload.get("results", [])
        elif self.tool == "bandit":
            if not isinstance(payload, dict) or not isinstance(payload.get("results", []), list):
                raise ValueError("unsupported bandit result shape")
            records = payload.get("results", [])
        else:
            records = payload.get("findings", []) if isinstance(payload, dict) else payload
            if not isinstance(records, list):
                raise ValueError("unsupported gitleaks result shape")
        normalized: list[EvidenceItem] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            path, line, rule, message = self._fields(record)
            try:
                relative, _candidate = view.resolve(path)
                vulnerability_class = _classify_sast(self.tool, rule, message)
                if vulnerability_class not in SUPPORTED_INVESTIGATION_CLASSES:
                    continue
                evidence = view.source_evidence(
                    relative,
                    max(1, line),
                    origin=self.tool,
                    vulnerability_class=vulnerability_class,
                    message=message or rule,
                )
                evidence.raw.update({"rule_id": rule, "tool": self.tool})
                normalized.append(evidence)
            except (OSError, InvestigationToolError):
                continue
        return normalized

    def _fields(self, record: dict[str, Any]) -> tuple[str, int, str, str]:
        if self.tool == "semgrep":
            extra = record.get("extra") or {}
            return (
                str(record.get("path") or ""),
                int((record.get("start") or {}).get("line") or 1),
                str(record.get("check_id") or ""),
                str(extra.get("message") or ""),
            )
        if self.tool == "bandit":
            return (
                str(record.get("filename") or ""),
                int(record.get("line_number") or 1),
                str(record.get("test_id") or ""),
                str(record.get("issue_text") or ""),
            )
        return (
            str(record.get("File") or record.get("file") or ""),
            int(record.get("StartLine") or record.get("startLine") or record.get("line") or 1),
            str(record.get("RuleID") or record.get("ruleID") or record.get("rule") or ""),
            str(record.get("Description") or record.get("description") or "hardcoded secret"),
        )


def _classify_sast(tool: str, rule: str, message: str) -> str | None:
    if tool == "gitleaks":
        return "hardcoded-secret"
    material = f"{rule} {message}".lower()
    for vulnerability_class, hints in SINK_HINTS.items():
        if any(hint in material for hint in hints):
            return vulnerability_class
    cwe_map = {
        "cwe-89": "sql-injection",
        "cwe-78": "command-injection",
        "cwe-22": "path-traversal",
        "cwe-798": "hardcoded-secret",
    }
    return next((value for key, value in cwe_map.items() if key in material), None)


class InvestigationActionRegistry:
    def __init__(
        self,
        metadata: RepositoryMetadata,
        *,
        run_dir: str | Path,
        secret_values: list[str] | None = None,
        max_search_results: int = 100,
        max_context_lines: int = 200,
        external_timeout: int = 60,
        external_output_limit: int = 1_000_000,
        cancelled: Callable[[], bool] | None = None,
    ):
        self.view = RepositoryView(metadata, secret_values=secret_values)
        self.run_dir = Path(run_dir)
        self.max_search_results = max_search_results
        self.max_context_lines = max_context_lines
        self.call_graph = RepositoryCallGraphBuilder().build(self.view)
        self.cancelled = cancelled or (lambda: False)
        self.sast = {
            name: FixedSastAdapter(
                name,
                timeout_seconds=external_timeout,
                output_limit=external_output_limit,
                cancelled=self.cancelled,
            )
            for name in ("semgrep", "bandit", "gitleaks")
        }
        self._cache: dict[str, dict[str, Any]] = {}

    @staticmethod
    def action_key(action: str, arguments: dict[str, Any]) -> str:
        return stable_id("ACT", action, json.dumps(arguments, sort_keys=True, ensure_ascii=False))

    def restore_completed_actions(self, steps: list[Any]) -> None:
        """Restore no-dispatch cache entries from validated checkpoint steps.

        Evidence already lives on the restored hypothesis. A repeated model
        action therefore receives a cached acknowledgement and cannot launch or
        bill the underlying tool again.
        """
        for step in steps:
            if getattr(step, "status", None) != "completed":
                continue
            action = str(getattr(step, "action", ""))
            arguments = dict(getattr(step, "arguments", {}) or {})
            if action not in INVESTIGATION_ACTIONS:
                continue
            action_key = self.action_key(action, arguments)
            if action_key != getattr(step, "action_key", None):
                continue
            self._cache[action_key] = {
                "action": action,
                "action_key": action_key,
                "duration_ms": 0,
                "evidence": [],
                "restored": True,
                "message": "completed action restored from validated checkpoint",
            }

    def declarations(self) -> dict[str, dict[str, Any]]:
        return {
            "search": {"required": ["query"], "optional": []},
            "source_context": {"required": ["path", "start_line"], "optional": ["end_line", "context"]},
            "callers": {"required": ["symbol"], "optional": []},
            "callees": {"required": ["symbol"], "optional": []},
            "dataflow": {"required": [], "optional": ["language", "max_files", "max_traces"]},
            "sast": {"required": ["tool"], "optional": []},
            "lexical_memory": {"required": ["query"], "optional": ["limit"]},
            "submit_gate": {"required": [], "optional": []},
            "abandon": {"required": [], "optional": ["reason"]},
        }

    def dispatch(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if self.cancelled():
            raise InvestigationToolError("investigation cancelled before tool dispatch")
        if action not in INVESTIGATION_ACTIONS:
            raise InvestigationToolError(f"unregistered investigation action: {action}")
        if not isinstance(arguments, dict):
            raise InvestigationToolError("investigation arguments must be an object")
        self._validate_arguments(action, arguments)
        action_key = self.action_key(action, arguments)
        if action_key in self._cache:
            return {**self._cache[action_key], "cached": True, "action_key": action_key}
        started = time.monotonic()
        if action == "search":
            output = {"evidence": [item.to_dict() for item in self.view.search(str(arguments["query"]), limit=self.max_search_results)]}
        elif action == "source_context":
            start = int(arguments["start_line"])
            end = int(arguments.get("end_line", start))
            context = min(int(arguments.get("context", 3)), self.max_context_lines)
            output = {
                "evidence": [
                    self.view.source_evidence(
                        str(arguments["path"]), start, end, context=context, origin="source"
                    ).to_dict()
                ]
            }
        elif action == "lexical_memory":
            limit = min(int(arguments.get("limit", 10)), self.max_search_results)
            output = {"evidence": [item.to_dict() for item in self.view.lexical(str(arguments["query"]), limit=limit)]}
        elif action == "callers":
            output = self._call_graph_output("callers", str(arguments["symbol"]))
        elif action == "callees":
            output = self._call_graph_output("callees", str(arguments["symbol"]))
        elif action == "dataflow":
            scanner = DataflowScanner(
                max_files=min(int(arguments.get("max_files", 500)), 1000),
                max_traces=min(int(arguments.get("max_traces", 200)), 500),
            )
            result = scanner.scan(
                self.view.metadata,
                artifact_root=self.run_dir / "dataflow" / "traces",
                language_filter=arguments.get("language"),
            )
            output = self._dataflow_output(result)
        elif action == "sast":
            observation = self.sast[str(arguments["tool"])].run(self.view)
            output = observation.to_dict()
            output["evidence"] = [item.to_dict() for item in observation.observations]
        else:
            output = {"evidence": [], "control": action, "message": str(arguments.get("reason") or "")}
        output.update(
            {
                "action": action,
                "action_key": action_key,
                "duration_ms": int((time.monotonic() - started) * 1000),
                "cached": False,
            }
        )
        if self.cancelled():
            raise InvestigationToolError("investigation cancelled during tool execution")
        self._cache[action_key] = output
        return output

    def _validate_arguments(self, action: str, arguments: dict[str, Any]) -> None:
        declaration = self.declarations()[action]
        allowed = set(declaration["required"]) | set(declaration["optional"])
        unknown = set(arguments) - allowed
        missing = set(declaration["required"]) - set(arguments)
        if unknown:
            raise InvestigationToolError(f"unknown {action} arguments: {sorted(unknown)}")
        if missing:
            raise InvestigationToolError(f"missing {action} arguments: {sorted(missing)}")
        serialized = json.dumps(arguments, sort_keys=True, ensure_ascii=False).lower()
        for forbidden in ("shell", "argv", "command", "executable", "docker", "container", "source_code", "script"):
            if forbidden in serialized:
                raise InvestigationToolError(f"untrusted execution authority is forbidden: {forbidden}")
        if "path" in arguments:
            self.view.resolve(str(arguments["path"]))
        if action == "sast" and arguments.get("tool") not in self.sast:
            raise InvestigationToolError("SAST tool must be semgrep, bandit, or gitleaks")

    def _call_graph_output(self, direction: str, symbol: str) -> dict[str, Any]:
        edges = self.call_graph.callers(symbol) if direction == "callers" else self.call_graph.callees(symbol)
        evidence: list[EvidenceItem] = []
        for edge in edges[: self.max_search_results]:
            try:
                item = self.view.source_evidence(
                    edge["path"],
                    int(edge["line"]),
                    origin="call-graph",
                    message=f"{direction}:{symbol}; unresolved={edge['unresolved']}",
                )
                item.raw["edge"] = edge
                evidence.append(item)
            except InvestigationToolError:
                continue
        return {"edges": edges[: self.max_search_results], "evidence": [item.to_dict() for item in evidence]}

    def _dataflow_output(self, result: ToolResult) -> dict[str, Any]:
        evidence: list[EvidenceItem] = []
        for observation in result.observations:
            if not observation.path or not observation.line:
                continue
            try:
                item = self.view.source_evidence(
                    observation.path,
                    observation.line,
                    origin="dataflow",
                    vulnerability_class=observation.vulnerability_class,
                    message=observation.message,
                    counterevidence=observation.raw.get("dataflow_status") == "sanitized-flow",
                )
                item.artifact_ref = observation.raw.get("dataflow_trace_ref") or observation.raw.get("trace_artifact")
                item.raw.update(observation.raw)
                evidence.append(item)
            except InvestigationToolError:
                continue
        return {
            "tool_result": result.to_dict(),
            "evidence": [item.to_dict() for item in evidence],
        }
