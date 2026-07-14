from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import to_plain, utc_now


RUN_DIRS = [
    "metadata",
    "logs",
    "tool_outputs",
    "intelligence",
    "agent_traces",
    "handoffs",
    "findings",
    "evidence",
    "poc",
    "reports",
    "prompts",
    "llm",
    "decisions",
    "messages",
    "memory",
    "mcp",
    "runtime_state",
    "runtime_errors",
    "signals",
    "investigations",
    "evidence-gates",
    "verification-plans",
]


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-").lower()
    return slug or "target"


@dataclass
class RunContext:
    path: Path
    run_id: str
    target_name: str

    def write_json_artifact(self, category: str, name: str, payload: Any) -> Path:
        target_dir = self.path / category
        target_dir.mkdir(parents=True, exist_ok=True)
        output = immutable_path(target_dir / name)
        output.write_text(json.dumps(to_plain(payload), ensure_ascii=False, indent=2), encoding="utf-8")
        return output


class RunStore:
    def __init__(self, root: Path | str):
        self.root = Path(root)

    def create_run(self, target_name: str) -> RunContext:
        self.root.mkdir(parents=True, exist_ok=True)
        timestamp = utc_now().replace(":", "").replace("+00:00", "Z")
        run_id = f"{timestamp}-{slugify(target_name)[:48]}"
        path = immutable_path(self.root / run_id)
        path.mkdir(parents=True, exist_ok=False)
        for dirname in RUN_DIRS:
            (path / dirname).mkdir()
        context = RunContext(path=path, run_id=path.name, target_name=target_name)
        context.write_json_artifact(
            "metadata",
            "run.json",
            {"run_id": context.run_id, "target_name": target_name, "created_at": utc_now()},
        )
        return context

    def open_run(self, run_id: str) -> RunContext:
        """Open an existing run while enforcing the configured output-root boundary."""
        if not run_id or run_id != Path(run_id).name or run_id in {".", ".."}:
            raise ValueError("resume run ID must be one directory name")
        root = self.root.resolve()
        path = (root / run_id).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError("resume run escapes the configured output root") from exc
        if not path.is_dir():
            raise ValueError(f"resume run does not exist: {run_id}")
        metadata_path = path / "metadata" / "run.json"
        if not metadata_path.is_file():
            raise ValueError("resume run metadata is missing")
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
        if payload.get("run_id") != run_id or not str(payload.get("target_name") or ""):
            raise ValueError("resume run metadata does not match its directory")
        for dirname in RUN_DIRS:
            if not (path / dirname).is_dir():
                raise ValueError(f"resume run is missing required directory: {dirname}")
        return RunContext(path=path, run_id=run_id, target_name=str(payload["target_name"]))


def immutable_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    parent = path.parent
    index = 1
    while True:
        candidate = parent / f"{stem}-{index}{suffix}"
        if not candidate.exists():
            return candidate
        index += 1
