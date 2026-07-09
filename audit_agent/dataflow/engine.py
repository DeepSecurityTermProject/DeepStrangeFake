from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Sequence

from .ir import DataflowTrace, SanitizerNode, SinkNode, SourceNode


@dataclass(frozen=True)
class HelperReturnSummary:
    name: str
    parameters: tuple[str, ...]
    return_expression: str
    path: str
    start_line: int
    end_line: int
    language: str
    snippet: str | None = None
    referenced_parameters: tuple[str, ...] = ()


@dataclass(frozen=True)
class HelperReturnMatch:
    argument_index: int
    parameter: str
    return_expression: str


def classify_flow_status(
    source: SourceNode | None,
    sink: SinkNode | None,
    sanitizers: Sequence[SanitizerNode] | None = None,
) -> str:
    if source is None and sink is not None:
        return "sink-only"
    if source is None or sink is None:
        return "no-flow"
    if sanitizers:
        return "sanitized-flow"
    return "complete-flow"


def match_helper_return(
    helper: HelperReturnSummary,
    tainted_argument_indexes: Iterable[int],
) -> HelperReturnMatch | None:
    referenced = set(helper.referenced_parameters) or {
        parameter
        for parameter in helper.parameters
        if re.search(rf"\b{re.escape(parameter)}\b", helper.return_expression)
    }
    for index in sorted(set(tainted_argument_indexes)):
        if 0 <= index < len(helper.parameters):
            parameter = helper.parameters[index]
            if parameter in referenced:
                return HelperReturnMatch(
                    argument_index=index,
                    parameter=parameter,
                    return_expression=helper.return_expression,
                )
    return None


def bounded_traces(
    traces: list[DataflowTrace],
    max_traces: int = 200,
    include_statuses: set[str] | None = None,
) -> list[DataflowTrace]:
    statuses = include_statuses or {"complete-flow", "sanitized-flow", "sink-only"}
    selected = [trace for trace in traces if trace.status in statuses]
    return selected[:max_traces]
