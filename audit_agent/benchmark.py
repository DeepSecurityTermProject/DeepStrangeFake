from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .models import BenchmarkSummary, BenchmarkTarget


@dataclass
class BenchmarkConfig:
    targets: list[BenchmarkTarget]

    @classmethod
    def load(cls, path: str | Path) -> "BenchmarkConfig":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        targets = [BenchmarkTarget(**item) for item in payload.get("targets", [])]
        return cls(targets=targets)

    @classmethod
    def load_default(cls) -> "BenchmarkConfig":
        root = Path(__file__).resolve().parent.parent
        return cls.load(root / "benchmarks" / "projects.json")


class BenchmarkRunner:
    def __init__(self, targets: list[BenchmarkTarget]):
        self.targets = targets

    def run(self, audit_callable: Callable[[BenchmarkTarget], dict[str, Any]]) -> BenchmarkSummary:
        results: list[dict[str, Any]] = []
        completed = 0
        failed = 0
        candidate_count = 0
        rejected_count = 0
        validated_count = 0
        level_distribution: dict[str, int] = {}
        for target in self.targets:
            try:
                result = audit_callable(target)
                completed += 1
                status = "completed"
            except Exception as exc:  # pragma: no cover - defensive batch isolation
                result = {"error": str(exc)}
                failed += 1
                status = "failed"
            candidate_count += int(result.get("candidate_count", 0))
            rejected_count += int(result.get("rejected_count", 0))
            validated_count += int(result.get("validated_count", 0))
            for level, count in result.get("validation_level_distribution", {}).items():
                level_distribution[level] = level_distribution.get(level, 0) + int(count)
            results.append({"target": target.to_dict(), "status": status, "metrics": result})
        return BenchmarkSummary(
            total_projects=len(self.targets),
            completed_projects=completed,
            failed_projects=failed,
            candidate_count=candidate_count,
            rejected_count=rejected_count,
            validated_count=validated_count,
            validation_level_distribution=level_distribution,
            project_results=results,
        )

