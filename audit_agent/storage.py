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
