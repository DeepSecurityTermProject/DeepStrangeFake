from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from audit_agent.models import stable_id, to_plain


@dataclass
class DataflowNode:
    path: str
    start_line: int
    end_line: int
    expression: str
    language: str
    kind: str = "node"
    symbol: str | None = None
    snippet: str | None = None
    framework: str | None = None
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id(
                "DFN",
                self.kind,
                self.language,
                self.path,
                self.start_line,
                self.end_line,
                self.expression,
                self.symbol,
            )

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class SourceNode(DataflowNode):
    source_type: str = "request"

    def __post_init__(self) -> None:
        self.kind = "source"
        super().__post_init__()


@dataclass
class SinkNode(DataflowNode):
    sink_type: str = "sink"
    vulnerability_class: str = "unknown"

    def __post_init__(self) -> None:
        self.kind = "sink"
        super().__post_init__()


@dataclass
class SanitizerNode(DataflowNode):
    sanitizer_type: str = "guard"

    def __post_init__(self) -> None:
        self.kind = "sanitizer"
        super().__post_init__()


@dataclass
class FlowStep:
    path: str
    start_line: int
    end_line: int
    expression: str
    step_type: str
    language: str
    from_id: str | None = None
    to_id: str | None = None
    description: str = ""
    snippet: str | None = None
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id(
                "DFS",
                self.step_type,
                self.language,
                self.path,
                self.start_line,
                self.expression,
                self.from_id,
                self.to_id,
            )

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class DataflowTrace:
    vulnerability_class: str
    language: str
    path: str
    source: SourceNode
    sink: SinkNode
    steps: list[FlowStep] = field(default_factory=list)
    sanitizers: list[SanitizerNode] = field(default_factory=list)
    status: str = "complete-flow"
    confidence: float = 0.8
    rule_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    explanation: str = ""
    artifact_path: str | None = None
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.explanation:
            self.explanation = (
                f"{self.source.expression} reaches {self.sink.expression}"
                + (" through sanitizer" if self.sanitizers else "")
            )
        if not self.id:
            self.id = stable_id(
                "DFT",
                self.vulnerability_class,
                self.language,
                self.path,
                self.source.id,
                self.sink.id,
                self.status,
            )

    def compact_call_path(self) -> list[str]:
        values = [
            f"source:{self.source.path}:{self.source.start_line}:{self.source.expression}",
        ]
        values.extend(
            f"{step.step_type}:{step.path}:{step.start_line}:{step.expression}" for step in self.steps
        )
        for sanitizer in self.sanitizers:
            values.append(f"sanitizer:{sanitizer.path}:{sanitizer.start_line}:{sanitizer.expression}")
        values.append(f"sink:{self.sink.path}:{self.sink.start_line}:{self.sink.expression}")
        return values

    def summary(self) -> dict[str, Any]:
        return {
            "trace_id": self.id,
            "status": self.status,
            "vulnerability_class": self.vulnerability_class,
            "language": self.language,
            "source": {
                "path": self.source.path,
                "line": self.source.start_line,
                "expression": self.source.expression,
                "symbol": self.source.symbol,
            },
            "sink": {
                "path": self.sink.path,
                "line": self.sink.start_line,
                "expression": self.sink.expression,
                "symbol": self.sink.symbol,
            },
            "sanitizer_status": "present" if self.sanitizers else "absent",
            "sanitizers": [
                {
                    "path": sanitizer.path,
                    "line": sanitizer.start_line,
                    "expression": sanitizer.expression,
                    "type": sanitizer.sanitizer_type,
                }
                for sanitizer in self.sanitizers
            ],
            "rule_ids": list(self.rule_ids),
            "confidence": self.confidence,
            "artifact_path": self.artifact_path,
        }

    def source_locations(self) -> list[dict[str, Any]]:
        locations = [
            {
                "path": self.source.path,
                "start_line": self.source.start_line,
                "end_line": self.source.end_line,
                "symbol": self.source.symbol,
                "snippet": self.source.snippet,
            }
        ]
        locations.extend(
            {
                "path": step.path,
                "start_line": step.start_line,
                "end_line": step.end_line,
                "symbol": None,
                "snippet": step.snippet,
            }
            for step in self.steps
        )
        locations.extend(
            {
                "path": sanitizer.path,
                "start_line": sanitizer.start_line,
                "end_line": sanitizer.end_line,
                "symbol": sanitizer.symbol,
                "snippet": sanitizer.snippet,
            }
            for sanitizer in self.sanitizers
        )
        locations.append(
            {
                "path": self.sink.path,
                "start_line": self.sink.start_line,
                "end_line": self.sink.end_line,
                "symbol": self.sink.symbol,
                "snippet": self.sink.snippet,
            }
        )
        return locations

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)
