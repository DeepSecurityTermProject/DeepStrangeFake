from __future__ import annotations

import ast
from dataclasses import dataclass, field

from .engine import HelperReturnSummary, classify_flow_status, match_helper_return
from .ir import DataflowTrace, FlowStep, SanitizerNode, SinkNode, SourceNode
from .rules import PYTHON_REQUEST_MARKERS


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

    def with_sanitizer(self, sanitizer: SanitizerNode) -> "_Taint":
        return _Taint(self.source, list(self.steps), self.sanitizers + [sanitizer])


class PythonDataflowFrontend:
    language = "python"

    def analyze(self, relative: str, text: str) -> list[DataflowTrace]:
        self.relative = relative
        self.lines = text.splitlines()
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return []
        self.helper_returns = self._collect_helper_returns(tree.body)
        traces: list[DataflowTrace] = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                traces.extend(self._analyze_function(node))
        return traces

    def _collect_helper_returns(self, statements: list[ast.stmt]) -> dict[str, HelperReturnSummary]:
        helpers: dict[str, HelperReturnSummary] = {}
        for statement in statements:
            if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            parameters = tuple(arg.arg for arg in statement.args.args if arg.arg not in {"self", "cls"})
            if not parameters:
                continue
            returns = [node for node in ast.walk(statement) if isinstance(node, ast.Return) and node.value is not None]
            if not returns:
                continue
            first_return = returns[0]
            referenced = sorted(
                {
                    node.id
                    for node in ast.walk(first_return.value)
                    if isinstance(node, ast.Name) and node.id in parameters
                }
            )
            helpers[statement.name] = HelperReturnSummary(
                name=statement.name,
                parameters=parameters,
                return_expression=self._unparse(first_return.value),
                path=self.relative,
                start_line=getattr(first_return, "lineno", statement.lineno),
                end_line=getattr(first_return, "end_lineno", getattr(first_return, "lineno", statement.lineno)),
                language=self.language,
                snippet=self._line(getattr(first_return, "lineno", statement.lineno)),
                referenced_parameters=tuple(referenced),
            )
        return helpers

    def _analyze_function(self, function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[DataflowTrace]:
        tainted: dict[str, _Taint] = {}
        traces: list[DataflowTrace] = []
        if self._is_route_handler(function):
            for arg in function.args.args:
                if arg.arg in {"self", "cls", "request"}:
                    continue
                source = self._source_node(arg.arg, function.lineno, f"route parameter {arg.arg}", arg.arg)
                tainted[arg.arg] = _Taint(source)
        for statement in function.body:
            self._apply_sanitizers(statement, tainted)
            traces.extend(self._traces_from_statement(statement, tainted))
            self._propagate_assignment(statement, tainted)
        return traces

    def _propagate_assignment(self, statement: ast.stmt, tainted: dict[str, _Taint]) -> None:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            return
        value = statement.value
        if value is None:
            return
        taint = self._expr_taint(value, tainted)
        if not taint:
            return
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        for target in targets:
            if isinstance(target, ast.Name):
                step = FlowStep(
                    path=self.relative,
                    start_line=getattr(statement, "lineno", taint.source.start_line),
                    end_line=getattr(statement, "end_lineno", getattr(statement, "lineno", taint.source.end_line)),
                    expression=self._unparse(statement),
                    step_type="assignment",
                    language=self.language,
                    from_id=taint.source.id,
                    description=f"Tainted value assigned to {target.id}.",
                    snippet=self._line(getattr(statement, "lineno", taint.source.start_line)),
                )
                tainted[target.id] = taint.extend(step)

    def _traces_from_statement(self, statement: ast.stmt, tainted: dict[str, _Taint]) -> list[DataflowTrace]:
        traces: list[DataflowTrace] = []
        for call in [node for node in ast.walk(statement) if isinstance(node, ast.Call)]:
            trace = self._trace_from_call(call, tainted)
            if trace:
                traces.append(trace)
        return traces

    def _trace_from_call(self, call: ast.Call, tainted: dict[str, _Taint]) -> DataflowTrace | None:
        func_name = self._call_name(call.func)
        args = list(call.args)
        if self._is_sql_sink(func_name):
            first = self._expr_taint(args[0], tainted) if args else None
            if first:
                return self._build_trace(first, call, "sql", "sql-injection", "PY.SQL.RAW")
            if len(args) > 1:
                param_taint = self._expr_taint(args[1], tainted)
                if param_taint:
                    sanitizer = self._sanitizer_node(call, "sql-parameter-binding")
                    return self._build_trace(
                        param_taint.with_sanitizer(sanitizer),
                        call,
                        "sql",
                        "sql-injection",
                        "PY.SQL.PARAM",
                    )
        if self._is_command_sink(func_name):
            command_taint = self._expr_taint(args[0], tainted) if args else None
            if command_taint:
                if self._has_shell_false_safe_argv(call):
                    command_taint = command_taint.with_sanitizer(self._sanitizer_node(call, "safe-argv"))
                return self._build_trace(command_taint, call, "command", "command-injection", "PY.CMD.EXEC")
        if self._is_file_sink(func_name):
            path_taint = self._expr_taint(args[0], tainted) if args else None
            if path_taint:
                return self._build_trace(path_taint, call, "file-read", "path-traversal", "PY.PATH.READ")
        return None

    def _build_trace(
        self,
        taint: _Taint,
        call: ast.Call,
        sink_type: str,
        vulnerability_class: str,
        rule_id: str,
    ) -> DataflowTrace:
        line = getattr(call, "lineno", taint.source.start_line)
        sink = SinkNode(
            path=self.relative,
            start_line=line,
            end_line=getattr(call, "end_lineno", line),
            expression=self._unparse(call),
            language=self.language,
            symbol=self._call_name(call.func),
            snippet=self._line(line),
            sink_type=sink_type,
            vulnerability_class=vulnerability_class,
        )
        status = classify_flow_status(taint.source, sink, taint.sanitizers)
        return DataflowTrace(
            vulnerability_class=vulnerability_class,
            language=self.language,
            path=self.relative,
            source=taint.source,
            sink=sink,
            steps=taint.steps,
            sanitizers=taint.sanitizers,
            status=status,
            confidence=0.45 if taint.sanitized else 0.86,
            rule_ids=[rule_id],
        )

    def _expr_taint(self, expression: ast.AST, tainted: dict[str, _Taint]) -> _Taint | None:
        if self._is_request_source(expression):
            line = getattr(expression, "lineno", 1)
            return _Taint(self._source_node(self._unparse(expression), line, self._unparse(expression)))
        if isinstance(expression, ast.Name) and expression.id in tainted:
            return tainted[expression.id]
        if isinstance(expression, ast.Call):
            helper_taint = self._helper_call_taint(expression, tainted)
            if helper_taint:
                return helper_taint
            if self._call_name(expression.func) in getattr(self, "helper_returns", {}):
                return None
        for child in ast.iter_child_nodes(expression):
            child_taint = self._expr_taint(child, tainted)
            if child_taint:
                return child_taint
        return None

    def _helper_call_taint(self, call: ast.Call, tainted: dict[str, _Taint]) -> _Taint | None:
        helper = getattr(self, "helper_returns", {}).get(self._call_name(call.func))
        if not helper:
            return None
        argument_taints: dict[int, _Taint] = {}
        for index, argument in enumerate(call.args):
            argument_taint = self._expr_taint(argument, tainted)
            if argument_taint:
                argument_taints[index] = argument_taint
        match = match_helper_return(helper, argument_taints)
        if not match:
            return None
        taint = argument_taints[match.argument_index]
        line = getattr(call, "lineno", helper.start_line)
        step = FlowStep(
            path=self.relative,
            start_line=line,
            end_line=getattr(call, "end_lineno", line),
            expression=f"{self._unparse(call)} -> {helper.return_expression}",
            step_type="helper-return",
            language=self.language,
            from_id=taint.source.id,
            description=(
                f"Same-file helper {helper.name} returns data derived from parameter {match.parameter}."
            ),
            snippet=self._line(line),
        )
        return taint.extend(step)

    def _apply_sanitizers(self, statement: ast.stmt, tainted: dict[str, _Taint]) -> None:
        if not isinstance(statement, ast.If):
            return
        test = self._unparse(statement.test)
        if not any(token in test for token in (" in ", "match(", "fullmatch(", "startswith(", "relative_to(")):
            return
        for name, taint in list(tainted.items()):
            if name in test:
                tainted[name] = taint.with_sanitizer(
                    SanitizerNode(
                        path=self.relative,
                        start_line=statement.lineno,
                        end_line=getattr(statement, "end_lineno", statement.lineno),
                        expression=test,
                        language=self.language,
                        symbol=name,
                        snippet=self._line(statement.lineno),
                        sanitizer_type="guard",
                    )
                )

    def _is_request_source(self, expression: ast.AST) -> bool:
        rendered = self._unparse(expression)
        return any(marker in rendered for marker in PYTHON_REQUEST_MARKERS)

    def _source_node(self, symbol: str, line: int, expression: str, source_type: str = "request") -> SourceNode:
        return SourceNode(
            path=self.relative,
            start_line=line,
            end_line=line,
            expression=expression,
            language=self.language,
            symbol=symbol,
            snippet=self._line(line),
            framework="python-web",
            source_type=source_type,
        )

    def _sanitizer_node(self, call: ast.Call, sanitizer_type: str) -> SanitizerNode:
        line = getattr(call, "lineno", 1)
        return SanitizerNode(
            path=self.relative,
            start_line=line,
            end_line=getattr(call, "end_lineno", line),
            expression=self._unparse(call),
            language=self.language,
            symbol=self._call_name(call.func),
            snippet=self._line(line),
            sanitizer_type=sanitizer_type,
        )

    def _is_route_handler(self, function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        return any("route(" in self._unparse(decorator) or ".get(" in self._unparse(decorator) for decorator in function.decorator_list)

    def _is_sql_sink(self, func_name: str) -> bool:
        return func_name.endswith(".execute") or func_name.endswith(".query")

    def _is_command_sink(self, func_name: str) -> bool:
        return func_name in {
            "os.system",
            "os.popen",
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_output",
            "subprocess.Popen",
        }

    def _is_file_sink(self, func_name: str) -> bool:
        return func_name in {"open", "send_file"} or func_name.endswith(".read_text") or func_name.endswith(".read_bytes")

    def _has_shell_false_safe_argv(self, call: ast.Call) -> bool:
        shell_false = any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is False for keyword in call.keywords)
        return shell_false and call.args and isinstance(call.args[0], (ast.List, ast.Tuple))

    def _call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._call_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Call):
            return self._call_name(node.func)
        return self._unparse(node)

    def _unparse(self, node: ast.AST) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return ""

    def _line(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1].strip()
        return ""
