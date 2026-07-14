from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field, fields
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, TypeVar

from .models import stable_id, utc_now


SCHEMA_VERSION = "benchmark-corpus.v1"
REPORT_SCHEMA_VERSION = "benchmark-report.v1"
RESOURCE_SCHEMA_VERSION = "run-resource-summary.v1"
MATCHER_VERSION = "benchmark-matcher.v1"
METRIC_VERSION = "benchmark-metrics.v2"


class StrictModel:
    @classmethod
    def from_dict(cls, payload: dict[str, Any]):
        if not isinstance(payload, dict):
            raise ValueError(f"{cls.__name__} must be an object")
        allowed = {item.name for item in fields(cls)}
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise ValueError(f"{cls.__name__} has unknown fields: {', '.join(unknown)}")
        try:
            return cls(**payload)
        except TypeError as exc:
            raise ValueError(f"Invalid {cls.__name__}: {exc}") from exc

    def to_dict(self) -> dict[str, Any]:
        return _plain(asdict(self))


class CaseVariant(str, Enum):
    VULNERABLE = "vulnerable"
    FIXED = "fixed"
    SAFE_NEGATIVE = "safe-negative"
    FIXTURE = "fixture"
    PLACEHOLDER = "placeholder"


class SupportLevel(str, Enum):
    FULL_DATAFLOW = "full-dataflow"
    PATTERN_ONLY = "pattern-only"
    UNSUPPORTED = "unsupported"


class CaseStatus(str, Enum):
    PENDING = "pending"
    ACQUIRING = "acquiring"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    NOT_RUN = "not-run"


TERMINAL_CASE_STATUSES = {
    CaseStatus.COMPLETED.value,
    CaseStatus.FAILED.value,
    CaseStatus.TIMED_OUT.value,
    CaseStatus.NOT_RUN.value,
}


@dataclass
class ScanScope(StrictModel):
    include: list[str] = field(default_factory=lambda: ["**/*"])
    exclude: list[str] = field(default_factory=list)
    max_files: int = 5000
    max_bytes: int = 50_000_000

    def validate(self) -> None:
        if not self.include:
            raise ValueError("scan scope include must not be empty")
        if self.max_files < 1 or self.max_bytes < 1:
            raise ValueError("scan scope bounds must be positive")
        for pattern in [*self.include, *self.exclude]:
            _validate_relative_pattern(pattern)


@dataclass
class CaseBudgets(StrictModel):
    llm_requests: int = 0
    llm_tokens: int = 0
    tool_calls: int = 20
    docker_starts: int = 0
    repair_attempts: int = 0

    def validate(self) -> None:
        if any(value < 0 for value in asdict(self).values()):
            raise ValueError("case budgets must be non-negative")


@dataclass
class SafetyPolicy(StrictModel):
    network: bool = False
    target_writes: bool = False
    project_execution: bool = False
    docker: bool = False
    follow_external_links: bool = False
    secret_env_names: list[str] = field(default_factory=list)

    def validate(self) -> None:
        for name in self.secret_env_names:
            if not name or "=" in name or any(ch.isspace() for ch in name):
                raise ValueError("secret_env_names may contain names only")


@dataclass
class BenchmarkCase(StrictModel):
    case_id: str
    project_id: str
    source: str
    commit: str
    language: str
    variant: str
    scope: dict[str, Any]
    budgets: dict[str, Any]
    timeout_seconds: int
    safety: dict[str, Any]
    truth_ref: str | None
    support_level: str
    effectiveness_eligible: bool
    required: bool = True
    pair_id: str | None = None
    vulnerability_classes: list[str] = field(default_factory=list)
    executable: bool = True
    version: str = ""
    support_reason: str = ""
    license_review_ref: str | None = None
    validation_level: str = "static-only"

    def validate(self, *, profile_kind: str = "fixture") -> None:
        if not self.case_id or not self.project_id:
            raise ValueError("case_id and project_id are required")
        if self.variant not in {item.value for item in CaseVariant}:
            raise ValueError(f"invalid variant: {self.variant}")
        if self.support_level not in {item.value for item in SupportLevel}:
            raise ValueError(f"invalid support_level: {self.support_level}")
        if self.timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")
        if self.validation_level not in {"static-only", "poc-generate", "sandbox", "manual"}:
            raise ValueError(f"invalid validation_level: {self.validation_level}")
        ScanScope.from_dict(self.scope).validate()
        CaseBudgets.from_dict(self.budgets).validate()
        SafetyPolicy.from_dict(self.safety).validate()
        if self.executable and profile_kind != "fixture" and not is_full_commit(self.commit):
            raise ValueError(f"case {self.case_id} requires a full 40-64 hex commit lock")
        if self.executable and profile_kind == "fixture" and not (is_full_commit(self.commit) or self.commit.startswith("fixture:")):
            raise ValueError(f"fixture case {self.case_id} requires a fixture digest or full commit")
        if self.support_level == SupportLevel.UNSUPPORTED.value and self.effectiveness_eligible:
            raise ValueError("unsupported case cannot be effectiveness eligible")
        if self.variant == CaseVariant.PLACEHOLDER.value and (self.executable or self.effectiveness_eligible):
            raise ValueError("placeholder cannot be executable or effectiveness eligible")
        if self.effectiveness_eligible and not self.truth_ref:
            raise ValueError("effectiveness eligible case requires truth_ref")
        if self.safety.get("target_writes") or self.safety.get("project_execution"):
            raise ValueError("benchmark cases must deny target writes and project execution")


@dataclass
class BenchmarkProfile(StrictModel):
    profile_id: str
    kind: str
    case_ids: list[str]
    defaults: dict[str, Any] = field(default_factory=dict)
    promotion_status: str = "not-reviewed"
    promotion_review_ref: str | None = None
    max_parallel: int = 1

    def validate(self) -> None:
        if self.kind not in {"fixture", "pilot", "full"}:
            raise ValueError(f"invalid profile kind: {self.kind}")
        if self.max_parallel != 1:
            raise ValueError("MVP benchmark max_parallel must be 1")
        if len(set(self.case_ids)) != len(self.case_ids):
            raise ValueError(f"profile {self.profile_id} contains duplicate case IDs")


@dataclass
class BenchmarkCorpus(StrictModel):
    schema_version: str
    corpus_id: str
    corpus_version: str
    profiles: list[dict[str, Any]]
    cases: list[dict[str, Any]]
    generated_at: str | None = None
    provenance: dict[str, Any] = field(default_factory=dict)

    def parsed_profiles(self) -> list[BenchmarkProfile]:
        return [BenchmarkProfile.from_dict(item) for item in self.profiles]

    def parsed_cases(self) -> list[BenchmarkCase]:
        return [BenchmarkCase.from_dict(item) for item in self.cases]

    def validate(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported corpus schema: {self.schema_version}")
        profiles = self.parsed_profiles()
        cases = self.parsed_cases()
        if len({item.profile_id for item in profiles}) != len(profiles):
            raise ValueError("duplicate profile_id")
        if len({item.case_id for item in cases}) != len(cases):
            raise ValueError("duplicate case_id")
        case_map = {item.case_id: item for item in cases}
        for profile in profiles:
            profile.validate()
            missing = sorted(set(profile.case_ids) - set(case_map))
            if missing:
                raise ValueError(f"profile {profile.profile_id} references missing cases: {missing}")
            for case_id in profile.case_ids:
                case_map[case_id].validate(profile_kind=profile.kind)
        pair_map: dict[str, list[BenchmarkCase]] = {}
        for case in cases:
            if case.pair_id:
                pair_map.setdefault(case.pair_id, []).append(case)
        for pair_id, members in pair_map.items():
            if len({item.project_id for item in members}) != 1:
                raise ValueError(f"pair {pair_id} spans multiple project IDs")

    def select(self, profile_id: str, case_ids: list[str] | None = None) -> tuple[BenchmarkProfile, list[BenchmarkCase]]:
        self.validate()
        profile = next((item for item in self.parsed_profiles() if item.profile_id == profile_id), None)
        if not profile:
            raise ValueError(f"unknown benchmark profile: {profile_id}")
        selected_ids = case_ids or profile.case_ids
        outside = sorted(set(selected_ids) - set(profile.case_ids))
        if outside:
            raise ValueError(f"cases not in profile {profile_id}: {outside}")
        case_map = {item.case_id: item for item in self.parsed_cases()}
        selected = [merge_case_defaults(case_map[item], profile.defaults) for item in selected_ids]
        return profile, selected

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())


@dataclass
class NullableNumber(StrictModel):
    value: int | float | None
    reason: str | None = None

    def validate(self) -> None:
        if self.value is None and not self.reason:
            raise ValueError("unavailable numeric value requires reason")
        if self.value is not None and self.reason:
            raise ValueError("available numeric value must not have an unavailable reason")


@dataclass
class AcquisitionRecord(StrictModel):
    case_id: str
    status: str
    method: str
    source_identity: str
    expected_commit: str
    resolved_commit: str | None = None
    export_path: str | None = None
    network_allowed: bool = False
    cache_status: str = "unknown"
    safety_checks: dict[str, bool] = field(default_factory=dict)
    failure_reason: str | None = None
    duration_ms: int = 0
    commands: list[list[str]] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now)
    record_id: str | None = None

    def __post_init__(self) -> None:
        self.record_id = self.record_id or stable_id("BAQ", self.case_id, self.expected_commit, self.status, self.created_at)


@dataclass
class CaseState(StrictModel):
    schema_version: str
    benchmark_run_id: str
    case_id: str
    status: str = CaseStatus.PENDING.value
    acquisition_status: str = "pending"
    execution_status: str = "pending"
    evaluation_status: str = "pending"
    baseline_eligible: bool = False
    attempts: int = 0
    reuse_fingerprint: str = ""
    comparison_protocol_fingerprint: str = ""
    failures: list[dict[str, Any]] = field(default_factory=list)
    artifact_refs: list[str] = field(default_factory=list)
    reuse_decision: str = "not-considered"
    updated_at: str = field(default_factory=utc_now)
    state_id: str | None = None

    def __post_init__(self) -> None:
        self.state_id = self.state_id or stable_id("BCS", self.benchmark_run_id, self.case_id)


@dataclass
class RunResourceSummary(StrictModel):
    schema_version: str
    run_id: str
    target_identity: str
    target_commit: str | None
    terminal_status: str
    scanned_files: int | None
    scanned_bytes: int | None
    stage_durations_ms: dict[str, int | None]
    final_status_counts: dict[str, int]
    llm_requests: int | None
    llm_tokens: int | None
    tool_calls: int | None
    docker_starts: int | None
    docker_results: int | None
    repair_attempts: int | None
    timeouts: int | None
    budget_consumption: dict[str, int | float | None]
    accounting_gaps: list[dict[str, str]]
    contributing_refs: list[str]
    ledger_present: bool = False
    accounting_source: str = "legacy-artifact-scan"
    llm_total_request_groups: int | None = None
    llm_dispatched_request_groups: int | None = None
    llm_provider_attempts: int | None = None
    llm_retries: int | None = None
    llm_pre_dispatch_denials: int | None = None
    llm_terminal_status_counts: dict[str, int] = field(default_factory=dict)
    llm_reconciliation_status: str = "legacy-unavailable"
    llm_gap_ids: list[str] = field(default_factory=list)
    llm_contributing_refs: list[str] = field(default_factory=list)
    provider: str | None = None
    model: str | None = None
    prompt_schema_version: str | None = None
    engine_commit: str | None = None
    language: str | None = None
    scope: dict[str, Any] = field(default_factory=dict)
    safety: dict[str, Any] = field(default_factory=dict)
    docker_policy: dict[str, Any] = field(default_factory=dict)
    environment: dict[str, Any] = field(default_factory=dict)
    elapsed_seconds: float | None = None
    acquisition: dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(default_factory=utc_now)

    def validate(self) -> None:
        if self.schema_version != RESOURCE_SCHEMA_VERSION:
            raise ValueError(f"unsupported resource summary schema: {self.schema_version}")
        gap_fields = {item.get("field") for item in self.accounting_gaps}
        for name in (
            "scanned_files", "scanned_bytes", "elapsed_seconds", "llm_requests", "llm_tokens", "tool_calls",
            "docker_starts", "docker_results", "repair_attempts", "timeouts",
        ):
            if getattr(self, name) is None and name not in gap_fields:
                raise ValueError(f"resource field {name} is null without accounting gap")
        if self.elapsed_seconds is not None and self.elapsed_seconds < 0:
            raise ValueError("resource elapsed_seconds must be non-negative")
        if self.accounting_source not in {
            "lifecycle-ledger",
            "compatibility-observer",
            "legacy-artifact-scan",
            "disabled-zero",
            "unknown",
        }:
            raise ValueError(f"unsupported LLM accounting source: {self.accounting_source}")
        if self.llm_reconciliation_status not in {
            "complete",
            "incomplete",
            "legacy-unavailable",
        }:
            raise ValueError(
                f"unsupported LLM reconciliation status: {self.llm_reconciliation_status}"
            )


@dataclass
class MetricValue(StrictModel):
    metric_id: str
    value: float | None
    numerator: int | None
    denominator: int | None
    reason: str | None = None
    metric_version: str = METRIC_VERSION


@dataclass
class FailureRecord(StrictModel):
    case_id: str
    stage: str
    reason: str
    details: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)
    failure_id: str | None = None

    def __post_init__(self) -> None:
        self.failure_id = self.failure_id or stable_id("BFL", self.case_id, self.stage, self.reason, self.created_at)


@dataclass
class MatchRecord(StrictModel):
    case_id: str
    finding_id: str | None
    finding_group_id: str | None
    outcome: str
    truth_ids: list[str]
    evidence: dict[str, Any] = field(default_factory=dict)
    matcher_version: str = MATCHER_VERSION
    match_id: str | None = None

    def __post_init__(self) -> None:
        self.match_id = self.match_id or stable_id("BM", self.case_id, self.finding_id, self.truth_ids, self.outcome)


@dataclass
class EvaluationRecord(StrictModel):
    case_id: str
    status: str
    match_refs: list[str] = field(default_factory=list)
    reason: str | None = None
    evaluation_id: str | None = None

    def __post_init__(self) -> None:
        self.evaluation_id = self.evaluation_id or stable_id("BEV", self.case_id, self.status, self.match_refs)


@dataclass
class PromotionRecord(StrictModel):
    run_id: str
    profile_id: str
    status: str
    blockers: list[dict[str, Any]] = field(default_factory=list)
    reviewed_by: str | None = None
    reviewed_at: str | None = None
    promotion_id: str | None = None

    def __post_init__(self) -> None:
        self.promotion_id = self.promotion_id or stable_id("BPR", self.run_id, self.profile_id, self.status)


@dataclass
class ComparisonRecord(StrictModel):
    baseline_run_id: str
    candidate_run_id: str
    dimensions: list[str]
    compatible: bool
    mismatches: list[str] = field(default_factory=list)
    comparison_id: str | None = None

    def __post_init__(self) -> None:
        self.comparison_id = self.comparison_id or stable_id(
            "BCM", self.baseline_run_id, self.candidate_run_id, sorted(self.dimensions)
        )


def merge_case_defaults(case: BenchmarkCase, defaults: dict[str, Any]) -> BenchmarkCase:
    raw = case.to_dict()
    for nested in ("scope", "budgets", "safety"):
        merged = dict(defaults.get(nested, {}))
        merged.update(raw.get(nested, {}))
        raw[nested] = merged
    for key, value in defaults.items():
        if key not in {"scope", "budgets", "safety"} and key not in raw:
            raw[key] = value
    return BenchmarkCase.from_dict(raw)


def is_full_commit(value: str) -> bool:
    return len(value) in range(40, 65) and all(ch in "0123456789abcdefABCDEF" for ch in value)


def canonical_json(value: Any) -> str:
    return json.dumps(_plain(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def contained_path(root: str | Path, *parts: str) -> Path:
    base = Path(root).resolve()
    candidate = base.joinpath(*parts).resolve()
    if candidate != base and base not in candidate.parents:
        raise ValueError("path escapes configured root")
    return candidate


def _validate_relative_pattern(pattern: str) -> None:
    normalized = pattern.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"scope pattern escapes source root: {pattern}")


def _plain(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, list):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    return value
