from __future__ import annotations

import json
import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .benchmark_evaluation import (
    FindingMatcher,
    build_benchmark_report,
    compare_reports,
    compute_macro_metrics,
    compute_metrics,
    load_adjudications,
    load_truth,
    promotion_readiness,
    render_markdown,
)
from .benchmark_models import BenchmarkCorpus, canonical_digest, is_full_commit, utc_now
from .benchmark_runtime import AtomicJsonStore, BenchmarkCoordinator
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

    def to_unresolved_corpus(self) -> BenchmarkCorpus:
        cases = []
        for target in self.targets:
            cases.append(
                {
                    "case_id": f"legacy-{target.name}",
                    "project_id": target.name,
                    "source": target.source,
                    "commit": target.ref or "unresolved",
                    "language": target.expected_language or "unknown",
                    "variant": "placeholder",
                    "scope": {"include": ["**/*"], "exclude": [], "max_files": 5000, "max_bytes": 50000000},
                    "budgets": {"llm_requests": 0, "llm_tokens": 0, "tool_calls": 20, "docker_starts": 0, "repair_attempts": 0},
                    "timeout_seconds": 300,
                    "safety": {"network": False, "target_writes": False, "project_execution": False, "docker": False, "follow_external_links": False, "secret_env_names": []},
                    "truth_ref": None,
                    "support_level": "unsupported",
                    "effectiveness_eligible": False,
                    "required": True,
                    "vulnerability_classes": [],
                    "executable": False,
                    "support_reason": "legacy mutable ref requires reviewed lock",
                }
            )
        return BenchmarkCorpus(
            schema_version="benchmark-corpus.v1",
            corpus_id="legacy-projects-unresolved",
            corpus_version="1",
            profiles=[{"profile_id": "legacy-unresolved", "kind": "full", "case_ids": [item["case_id"] for item in cases], "defaults": {}, "promotion_status": "not-reviewed", "promotion_review_ref": None, "max_parallel": 1}],
            cases=cases,
            provenance={"conversion": "legacy-list", "execution_allowed": False},
        )


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
                if result.get("setup_status") == "remote-download-skipped":
                    failed += 1
                    status = "not-run"
                    result = {
                        "setup_status": "remote-download-skipped",
                        "candidate_count": None,
                        "rejected_count": None,
                        "validated_count": None,
                        "unavailable_reason": "remote-download-skipped",
                    }
                else:
                    completed += 1
                    status = "completed"
            except Exception as exc:  # pragma: no cover - defensive batch isolation
                result = {"error": str(exc)}
                failed += 1
                status = "failed"
            candidate_count += int(result.get("candidate_count") or 0)
            rejected_count += int(result.get("rejected_count") or 0)
            validated_count += int(result.get("validated_count") or 0)
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


def load_corpus(path: str | Path) -> BenchmarkCorpus:
    corpus = BenchmarkCorpus.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
    corpus.validate()
    return corpus


def default_corpus_path() -> Path:
    return Path(__file__).resolve().parent.parent / "benchmarks" / "corpus.v1.json"


def build_engine_identity(
    *,
    root: str | Path | None = None,
    prompt_version: str = "v1",
    template_dir: str | Path = "audit_agent/prompt_templates",
    provider: str = "disabled",
    model: str = "disabled",
    repetition: str | None = None,
) -> dict[str, Any]:
    repository_root = Path(root or Path(__file__).resolve().parent.parent).resolve()
    engine_files = sorted((repository_root / "audit_agent").rglob("*.py"))
    pyproject = repository_root / "pyproject.toml"
    if pyproject.is_file():
        engine_files.append(pyproject)
    prompt_root = Path(template_dir)
    if not prompt_root.is_absolute():
        prompt_root = repository_root / prompt_root
    prompt_files = sorted(prompt_root.rglob("*.json")) if prompt_root.is_dir() else []
    engine_sources = _content_identity(repository_root, engine_files)
    prompt_sources = _content_identity(repository_root, prompt_files)
    commit = None
    dirty = True
    try:
        head = subprocess.run(
            ["git", "-C", str(repository_root), "rev-parse", "HEAD"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=5, shell=False, check=False,
        )
        commit = head.stdout.strip() if head.returncode == 0 else None
        status = subprocess.run(
            ["git", "-C", str(repository_root), "status", "--porcelain", "--untracked-files=all", "--", "audit_agent", "pyproject.toml"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=5, shell=False, check=False,
        )
        dirty = status.returncode != 0 or bool(status.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    return {
        "engine_commit": commit,
        "engine_dirty": dirty,
        "engine_worktree_digest": canonical_digest(engine_sources),
        "engine_file_count": len(engine_sources),
        "prompt_version": prompt_version,
        "prompt_content_digest": canonical_digest(prompt_sources),
        "prompt_file_count": len(prompt_sources),
        "provider": provider,
        "model": model,
        "repetition": repetition,
    }


def _content_identity(root: Path, paths: list[Path]) -> dict[str, str]:
    identity: dict[str, str] = {}
    for path in paths:
        try:
            relative = path.resolve().relative_to(root).as_posix()
            identity[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        except (OSError, ValueError):
            continue
    return identity


def run_benchmark(
    *,
    corpus_path: str | Path,
    profile_id: str,
    output_root: str | Path,
    cache_root: str | Path,
    truth_path: str | Path | None = None,
    adjudication_path: str | Path | None = None,
    case_ids: list[str] | None = None,
    allow_network: bool = False,
    allow_docker: bool = False,
    allow_partial: bool = False,
    resume_run_id: str | None = None,
    comparison_dimensions: list[str] | None = None,
    engine_identity: dict[str, Any] | None = None,
    timeout_seconds: int | None = None,
) -> tuple[dict[str, Any], int]:
    corpus = load_corpus(corpus_path)
    truth_manifest = load_truth(truth_path) if truth_path else None
    truths = truth_manifest.parsed_records() if truth_manifest else []
    truth_identity = (
        {
            "schema_version": truth_manifest.schema_version,
            "truth_version": truth_manifest.truth_version,
            "content_digest": canonical_digest(truth_manifest.to_dict()),
        }
        if truth_manifest
        else None
    )
    adjudications = (
        load_adjudications(adjudication_path)
        if adjudication_path and Path(adjudication_path).exists()
        else []
    )
    adjudication_identity = (
        {
            "schema_version": "benchmark-adjudication.v1",
            "content_digest": canonical_digest(
                {
                    "schema_version": "benchmark-adjudication.v1",
                    "records": [item.to_dict() for item in adjudications],
                }
            ),
            "record_count": len(adjudications),
        }
        if adjudication_path and Path(adjudication_path).exists()
        else None
    )
    engine_identity = engine_identity or build_engine_identity()
    coordinator = BenchmarkCoordinator(
        corpus,
        profile_id=profile_id,
        output_root=output_root,
        cache_root=cache_root,
        allow_network=allow_network,
        allow_docker=allow_docker,
        allow_partial=allow_partial,
        case_ids=case_ids,
        resume_run_id=resume_run_id,
        comparison_dimensions=comparison_dimensions,
        engine_identity=engine_identity,
        truth_identity=truth_identity,
    )
    if timeout_seconds is not None:
        if timeout_seconds < 1:
            raise ValueError("benchmark timeout must be positive")
        for case in coordinator.cases:
            case.timeout_seconds = min(case.timeout_seconds, timeout_seconds)
    cases, exit_code = coordinator.run()
    matcher = FindingMatcher()
    matches = [record for case in cases for record in matcher.match_case(case["case_id"], case.get("findings", []), truths)]
    metrics = compute_metrics(cases, truths, matches, adjudications)
    macro_metrics = compute_macro_metrics(cases, truths, matches, adjudications)
    reuse_fingerprint = canonical_digest(sorted(item.get("reuse_fingerprint", "") for item in cases))
    protocol_fingerprint = canonical_digest(
        {
            "case_protocol_fingerprints": sorted(
                item.get("comparison_protocol_fingerprint", "") for item in cases
            ),
            "evaluation_identity": {
                "truth": truth_identity,
                "adjudication": adjudication_identity,
            },
        }
    )
    report = build_benchmark_report(
        run_id=coordinator.run_id,
        corpus={
            "id": corpus.corpus_id,
            "version": corpus.corpus_version,
            "digest": corpus.digest,
            "profile_id": profile_id,
            "truth": truth_identity,
            "adjudication": adjudication_identity,
        },
        cases=cases,
        matches=matches,
        metrics=metrics,
        macro_metrics=macro_metrics,
        reuse_fingerprint=reuse_fingerprint,
        protocol_fingerprint=protocol_fingerprint,
        comparison_dimensions=comparison_dimensions or ["engine"],
        provenance=engine_identity,
    )
    AtomicJsonStore.write(coordinator.run_dir / "benchmark.json", report)
    (coordinator.run_dir / "benchmark.md").write_text(render_markdown(report), encoding="utf-8")
    return report, exit_code


def lock_manifest(
    corpus_path: str | Path,
    output_path: str | Path,
    *,
    resolver: str,
    resolutions: dict[str, str],
    review_refs: dict[str, str],
) -> dict[str, Any]:
    corpus = BenchmarkCorpus.from_dict(json.loads(Path(corpus_path).read_text(encoding="utf-8")))
    raw = corpus.to_dict()
    for case in raw["cases"]:
        if case["case_id"] not in resolutions:
            continue
        commit = resolutions[case["case_id"]]
        if not is_full_commit(commit):
            raise ValueError(f"resolution for {case['case_id']} is not a full commit")
        if case["case_id"] not in review_refs:
            raise ValueError(f"resolution for {case['case_id']} lacks review provenance")
        case["commit"] = commit.lower()
        case["license_review_ref"] = review_refs[case["case_id"]]
        case["executable"] = True
    raw["generated_at"] = utc_now()
    raw["provenance"] = {**raw.get("provenance", {}), "resolver": resolver, "resolved_at": utc_now(), "review_refs": review_refs}
    locked = BenchmarkCorpus.from_dict(raw)
    locked.validate()
    payload = locked.to_dict()
    payload["provenance"]["lock_digest"] = canonical_digest(payload)
    AtomicJsonStore.write(output_path, payload)
    return payload


def compare_files(baseline_path: str | Path, candidate_path: str | Path, dimensions: list[str]) -> dict[str, Any]:
    baseline = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    candidate = json.loads(Path(candidate_path).read_text(encoding="utf-8"))
    return compare_reports(baseline, candidate, dimensions)


def readiness_for_profile(corpus_path: str | Path, profile_id: str) -> dict[str, Any]:
    corpus = load_corpus(corpus_path)
    profile, cases = corpus.select(profile_id)
    effective_projects = {
        item.project_id for item in cases
        if item.effectiveness_eligible and item.support_level != "unsupported" and item.executable and is_full_commit(item.commit)
    }
    blockers = []
    required = 20 if profile.kind == "full" else 3 if profile.kind == "pilot" else 0
    if len(effective_projects) < required:
        blockers.append({"reason": "insufficient-effective-projects", "required": required, "actual": len(effective_projects)})
    if profile.kind in {"pilot", "full"} and profile.promotion_status != "approved":
        blockers.append({"reason": "promotion-not-approved"})
    return {
        "schema_version": "benchmark-profile-readiness.v1",
        "profile_id": profile_id,
        "unique_project_count": len({item.project_id for item in cases}),
        "case_count": len(cases),
        "effectiveness_eligible_project_count": len(effective_projects),
        "ready": not blockers,
        "blockers": blockers,
    }
