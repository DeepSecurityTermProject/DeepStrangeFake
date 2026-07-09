from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .ir import DataflowTrace, FlowStep, SanitizerNode, SinkNode, SourceNode
from .rules import JS_REQUEST_MARKERS

ParserProvider = Callable[[str], Any | None]


def _default_parser_provider(language: str) -> Any | None:
    try:
        from tree_sitter_language_pack import get_parser
    except Exception:
        return None

    try:
        return get_parser(language)
    except Exception:
        return None


@dataclass
class _Taint:
    source: SourceNode
    steps: list[FlowStep] = field(default_factory=list)
    sanitizers: list[SanitizerNode] = field(default_factory=list)

    @property
    def sanitized(self) -> bool:
        return bool(self.sanitizers)

    def extend(self, step: FlowStep) -> "_Taint":
        return _Taint(self.source, self.steps + [step], list(self.sanitizers))


class JsTsDataflowFrontend:
    language = "javascript-typescript"

    def __init__(self, parser_provider: ParserProvider | None = None):
        self.parser_provider = parser_provider or _default_parser_provider
        self.last_parse_backend = "unparsed"
        self.last_parse_error: str | None = None

    def analyze(self, relative: str, text: str) -> list[DataflowTrace]:
        self.relative = relative
        self.lines = text.splitlines()
        self.last_parse_error = None
        parser = self._parser_for(relative)
        if parser is not None:
            try:
                self.last_parse_backend = "tree-sitter"
                return self._analyze_tree_sitter(text, parser)
            except Exception as exc:
                self.last_parse_error = str(exc)
        self.last_parse_backend = "line-fallback"
        return self._analyze_line_fallback()

    def _parser_for(self, relative: str) -> Any | None:
        suffix = Path(relative).suffix.lower()
        candidates_by_suffix = {
            ".js": ("javascript",),
            ".jsx": ("javascript", "tsx"),
            ".ts": ("typescript",),
            ".tsx": ("tsx", "typescript"),
        }
        for language in candidates_by_suffix.get(suffix, ()):
            parser = self.parser_provider(language)
            if parser is not None:
                return parser
        return None

    def _analyze_tree_sitter(self, text: str, parser: Any) -> list[DataflowTrace]:
        source_bytes = text.encode("utf-8")
        tree = parser.parse(source_bytes)
        root = tree.root_node
        tainted: dict[str, _Taint] = {}
        traces: list[DataflowTrace] = []
        for node in self._walk(root):
            line = self._node_text(node, source_bytes).strip()
            if not line:
                continue
            line_number = self._node_start_line(node)
            if node.type in {"variable_declarator", "assignment_expression", "lexical_declaration"}:
                self._apply_assignment(line_number, line, tainted)
            if node.type in {"if_statement", "call_expression", "binary_expression"}:
                self._apply_guard(line_number, line, tainted)
            if node.type != "call_expression":
                continue
            trace = self._trace_from_line(line_number, line, tainted)
            if trace:
                traces.append(trace)
        return traces

    def _analyze_line_fallback(self) -> list[DataflowTrace]:
        tainted: dict[str, _Taint] = {}
        traces: list[DataflowTrace] = []
        for line_number, line in enumerate(self.lines, start=1):
            self._apply_assignment(line_number, line, tainted)
            self._apply_guard(line_number, line, tainted)
            trace = self._trace_from_line(line_number, line, tainted)
            if trace:
                traces.append(trace)
        return traces

    def _walk(self, node: Any):
        yield node
        for child in getattr(node, "children", []) or []:
            yield from self._walk(child)

    def _node_text(self, node: Any, source_bytes: bytes) -> str:
        return source_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")

    def _node_start_line(self, node: Any) -> int:
        point = getattr(node, "start_point", None)
        if point is None:
            return 1
        return int(point[0]) + 1

    def _apply_assignment(self, line_number: int, line: str, tainted: dict[str, _Taint]) -> None:
        match = re.search(r"(?:\b(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(.+?);?\s*$", line)
        if not match:
            return
        symbol, expression = match.group(1), match.group(2).strip()
        source_expr = self._source_expression(expression)
        if source_expr:
            tainted[symbol] = _Taint(self._source_node(symbol, line_number, source_expr))
            return
        taint = self._line_taint(expression, tainted)
        if taint:
            step = FlowStep(
                path=self.relative,
                start_line=line_number,
                end_line=line_number,
                expression=line.strip(),
                step_type="assignment",
                language=self.language,
                from_id=taint.source.id,
                description=f"Tainted value assigned to {symbol}.",
                snippet=line.strip(),
            )
            tainted[symbol] = taint.extend(step)

    def _apply_guard(self, line_number: int, line: str, tainted: dict[str, _Taint]) -> None:
        if not any(token in line for token in (".includes(", ".has(", ".test(", "startsWith(")):
            return
        for name, taint in list(tainted.items()):
            if name in line:
                sanitizer = SanitizerNode(
                    path=self.relative,
                    start_line=line_number,
                    end_line=line_number,
                    expression=line.strip(),
                    language=self.language,
                    symbol=name,
                    snippet=line.strip(),
                    sanitizer_type="guard",
                )
                tainted[name] = _Taint(taint.source, list(taint.steps), taint.sanitizers + [sanitizer])

    def _trace_from_line(self, line_number: int, line: str, tainted: dict[str, _Taint]) -> DataflowTrace | None:
        taint = self._line_taint(line, tainted)
        if not taint:
            return None
        if self._is_sql_sink(line):
            return self._build_trace(taint, line_number, line, "sql", "sql-injection", "JS.SQL.RAW")
        if self._is_command_sink(line):
            return self._build_trace(taint, line_number, line, "command", "command-injection", "JS.CMD.EXEC")
        if self._is_file_sink(line):
            return self._build_trace(taint, line_number, line, "file-read", "path-traversal", "JS.PATH.READ")
        return None

    def _build_trace(
        self,
        taint: _Taint,
        line_number: int,
        line: str,
        sink_type: str,
        vulnerability_class: str,
        rule_id: str,
    ) -> DataflowTrace:
        sink = SinkNode(
            path=self.relative,
            start_line=line_number,
            end_line=line_number,
            expression=line.strip(),
            language=self.language,
            symbol=sink_type,
            snippet=line.strip(),
            sink_type=sink_type,
            vulnerability_class=vulnerability_class,
        )
        return DataflowTrace(
            vulnerability_class=vulnerability_class,
            language=self.language,
            path=self.relative,
            source=taint.source,
            sink=sink,
            steps=taint.steps,
            sanitizers=taint.sanitizers,
            status="sanitized-flow" if taint.sanitized else "complete-flow",
            confidence=0.45 if taint.sanitized else 0.82,
            rule_ids=[rule_id],
            metadata={
                "parse_backend": self.last_parse_backend,
                "parse_error": self.last_parse_error,
            },
        )

    def _source_expression(self, expression: str) -> str:
        return expression if any(marker in expression for marker in JS_REQUEST_MARKERS) else ""

    def _line_taint(self, line: str, tainted: dict[str, _Taint]) -> _Taint | None:
        source_expr = self._source_expression(line)
        if source_expr:
            return _Taint(self._source_node(source_expr, 1, source_expr))
        for name, taint in tainted.items():
            if re.search(rf"\b{re.escape(name)}\b", line):
                return taint
        return None

    def _source_node(self, symbol: str, line_number: int, expression: str) -> SourceNode:
        return SourceNode(
            path=self.relative,
            start_line=line_number,
            end_line=line_number,
            expression=expression.strip(),
            language=self.language,
            symbol=symbol,
            snippet=self.lines[line_number - 1].strip() if 1 <= line_number <= len(self.lines) else "",
            framework="js-web",
            source_type="request",
        )

    def _is_sql_sink(self, line: str) -> bool:
        lowered = line.lower()
        return (".query(" in lowered or ".$queryrawunsafe" in lowered or "sequelize.query" in lowered) and any(
            keyword in lowered for keyword in ("select ", "insert ", "update ", "delete ")
        )

    def _is_command_sink(self, line: str) -> bool:
        return "child_process.exec" in line or "execSync(" in line

    def _is_file_sink(self, line: str) -> bool:
        return "fs.readFile" in line or "createReadStream" in line or "sendFile" in line
