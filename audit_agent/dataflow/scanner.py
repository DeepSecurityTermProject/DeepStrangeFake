from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Iterable

from audit_agent.models import RepositoryMetadata, ToolObservation, ToolResult, to_plain
from audit_agent.storage import immutable_path

from .engine import bounded_traces
from .ir import DataflowTrace
from .js_ts_frontend import JsTsDataflowFrontend
from .python_frontend import PythonDataflowFrontend
from .rules import JS_TS_EXTENSIONS, PYTHON_EXTENSIONS, SEVERITY_BY_CLASS, SUPPORTED_EXTENSIONS


class DataflowScanner:
    name = "dataflow-scanner"

    def __init__(self, max_files: int = 500, max_traces: int = 200):
        self.max_files = max_files
        self.max_traces = max_traces
        self.python = PythonDataflowFrontend()
        self.js_ts = JsTsDataflowFrontend()

    def scan(
        self,
        metadata: RepositoryMetadata,
        artifact_root: str | Path | None = None,
        language_filter: Iterable[str] | None = None,
    ) -> ToolResult:
        started = time.monotonic()
        observations: list[ToolObservation] = []
        artifact_paths: list[str] = []
        root = Path(metadata.root_path or ".")
        traces: list[DataflowTrace] = []
        languages = set(language_filter or [])
        scanned_files = 0
        for relative in metadata.file_tree:
            suffix = Path(relative).suffix.lower()
            if suffix not in SUPPORTED_EXTENSIONS:
                continue
            if languages and suffix not in languages:
                continue
            if scanned_files >= self.max_files:
                observations.append(
                    ToolObservation(
                        tool_name=self.name,
                        kind="dataflow-degraded",
                        message=f"Dataflow file budget exhausted at {self.max_files} files.",
                        success=False,
                        degraded=True,
                    )
                )
                break
            path = root / relative
            if not path.exists() or path.stat().st_size > 2_000_000:
                continue
            scanned_files += 1
            text = path.read_text(encoding="utf-8", errors="ignore")
            traces.extend(self._analyze_file(relative, suffix, text))

        selected = bounded_traces(traces, max_traces=self.max_traces)
        trace_root = Path(artifact_root) if artifact_root else None
        for trace in selected:
            if trace_root:
                artifact_paths.append(str(self._persist_trace(trace_root, trace)))
            observations.append(self._observation_for_trace(trace))
        duration_ms = int((time.monotonic() - started) * 1000)
        return ToolResult(
            tool_name=self.name,
            inputs={
                "target": metadata.target.source,
                "file_count": len(metadata.file_tree),
                "scanned_files": scanned_files,
                "max_files": self.max_files,
                "max_traces": self.max_traces,
            },
            success=True,
            exit_status=0,
            duration_ms=duration_ms,
            artifact_paths=artifact_paths,
            observations=observations,
            message=f"{len(observations)} dataflow observations",
        )

    def _analyze_file(self, relative: str, suffix: str, text: str) -> list[DataflowTrace]:
        if suffix in PYTHON_EXTENSIONS:
            return self.python.analyze(relative, text)
        if suffix in JS_TS_EXTENSIONS:
            return self.js_ts.analyze(relative, text)
        return []

    def _persist_trace(self, root: Path, trace: DataflowTrace) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        path = immutable_path(root / f"{trace.id}.json")
        trace.artifact_path = str(path)
        path.write_text(json.dumps(trace.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def _observation_for_trace(self, trace: DataflowTrace) -> ToolObservation:
        summary = trace.summary()
        return ToolObservation(
            tool_name=self.name,
            kind=f"dataflow-{trace.status}",
            message=trace.explanation,
            path=trace.sink.path,
            line=trace.sink.start_line,
            severity=SEVERITY_BY_CLASS.get(trace.vulnerability_class, "medium"),
            vulnerability_class=trace.vulnerability_class
            if trace.status in {"complete-flow", "sanitized-flow"}
            else None,
            evidence=f"{trace.source.expression} -> {trace.sink.expression}",
            raw={
                "dataflow_trace_id": trace.id,
                "dataflow_trace_ref": trace.artifact_path,
                "dataflow_status": trace.status,
                "dataflow_summary": summary,
                "call_path": trace.compact_call_path(),
                "dataflow_locations": trace.source_locations(),
                "rule_ids": list(trace.rule_ids),
                "sanitizer_status": summary["sanitizer_status"],
                "trace_artifact": trace.artifact_path,
                "trace_payload_stored_in_artifact": bool(trace.artifact_path),
                "trace_inline_preview": to_plain(summary),
            },
        )
