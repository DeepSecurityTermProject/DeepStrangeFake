from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .benchmark_models import (
    MATCHER_VERSION,
    METRIC_VERSION,
    REPORT_SCHEMA_VERSION,
    MetricValue,
    StrictModel,
    canonical_digest,
)
from .models import stable_id, utc_now


CLASS_ALIASES = {
    "cwe-89": "sql-injection",
    "sqli": "sql-injection",
    "sql_injection": "sql-injection",
    "cwe-78": "command-injection",
    "cmdi": "command-injection",
    "cwe-22": "path-traversal",
}


@dataclass
class TruthRecord(StrictModel):
    truth_id: str
    project_id: str
    case_id: str
    expected_presence: bool
    vulnerability_class: str
    path: str
    evidence_refs: list[str]
    source: str
    reviewed_by: str
    reviewed_at: str
    pair_id: str | None = None
    cwe: str | None = None
    symbol: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    vulnerable_commit: str | None = None
    fixed_commit: str | None = None
    in_scope: bool = True

    def validate(self) -> None:
        if not self.truth_id or not self.project_id or not self.case_id:
            raise ValueError("truth IDs are required")
        if not self.evidence_refs or not self.reviewed_by or not self.reviewed_at:
            raise ValueError(f"truth {self.truth_id} lacks review provenance")
        self.path = normalize_path(self.path)
        if self.start_line is not None and self.start_line < 1:
            raise ValueError("truth start_line must be positive")
        if self.end_line is not None and self.start_line is not None and self.end_line < self.start_line:
            raise ValueError("truth line range is invalid")


@dataclass
class TruthManifest(StrictModel):
    schema_version: str
    truth_version: str
    records: list[dict[str, Any]]

    def parsed_records(self) -> list[TruthRecord]:
        records = [TruthRecord.from_dict(item) for item in self.records]
        for item in records:
            item.validate()
        if len({item.truth_id for item in records}) != len(records):
            raise ValueError("duplicate truth_id")
        return records


@dataclass
class AdjudicationRecord(StrictModel):
    adjudication_id: str
    case_id: str
    finding_id: str
    finding_group_id: str
    decision: str
    reviewer: str
    rationale: str
    timestamp: str
    evidence_refs: list[str]
    match_refs: list[str] = field(default_factory=list)

    def validate(self) -> None:
        if self.decision not in {"true-positive", "false-positive", "duplicate", "out-of-scope", "unresolved"}:
            raise ValueError(f"invalid adjudication decision: {self.decision}")
        if not self.reviewer or not self.rationale or not self.evidence_refs:
            raise ValueError("adjudication requires reviewer, rationale, and evidence")


def load_truth(path: str | Path) -> TruthManifest:
    manifest = TruthManifest.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
    if manifest.schema_version != "benchmark-truth.v1":
        raise ValueError(f"unsupported truth schema: {manifest.schema_version}")
    manifest.parsed_records()
    return manifest


def load_adjudications(path: str | Path) -> list[AdjudicationRecord]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    allowed = {"schema_version", "records"}
    unknown = set(payload) - allowed
    if unknown:
        raise ValueError(f"adjudication manifest has unknown fields: {sorted(unknown)}")
    if payload.get("schema_version") != "benchmark-adjudication.v1":
        raise ValueError("unsupported adjudication schema")
    records = [AdjudicationRecord.from_dict(item) for item in payload.get("records", [])]
    for item in records:
        item.validate()
    return records


class FindingMatcher:
    def __init__(self, line_drift: int = 3):
        self.line_drift = line_drift

    def match_case(self, case_id: str, findings: list[dict[str, Any]], truths: list[TruthRecord]) -> list[dict[str, Any]]:
        case_truths = [item for item in truths if item.case_id == case_id and item.in_scope]
        records: list[dict[str, Any]] = []
        seen_groups: dict[str, str] = {}
        matched_truths: set[str] = set()
        for finding in findings:
            finding_id = str(finding.get("id") or stable_id("F", case_id, finding))
            group_id = finding_group_id(case_id, finding)
            candidates = [truth for truth in case_truths if self._matches(finding, truth)]
            if group_id in seen_groups:
                outcome = "duplicate"
            elif len(candidates) == 1:
                outcome = "matched" if candidates[0].expected_presence else "unexpected"
                matched_truths.add(candidates[0].truth_id)
            elif len(candidates) > 1:
                outcome = "ambiguous"
            elif not _finding_in_scope(finding):
                outcome = "out-of-scope"
            else:
                outcome = "unexpected"
            match_id = stable_id("BM", case_id, finding_id, group_id, outcome)
            records.append(
                {
                    "match_id": match_id,
                    "matcher_version": MATCHER_VERSION,
                    "case_id": case_id,
                    "finding_id": finding_id,
                    "finding_group_id": group_id,
                    "outcome": outcome,
                    "truth_ids": [item.truth_id for item in candidates],
                    "evidence": {
                        "class": normalize_class(str(finding.get("vulnerability_class", ""))),
                        "path": normalize_path(str((finding.get("location") or {}).get("path", ""))),
                    },
                }
            )
            seen_groups.setdefault(group_id, finding_id)
        for truth in case_truths:
            if truth.expected_presence and truth.truth_id not in matched_truths:
                records.append(
                    {
                        "match_id": stable_id("BM", case_id, truth.truth_id, "missed"),
                        "matcher_version": MATCHER_VERSION,
                        "case_id": case_id,
                        "finding_id": None,
                        "finding_group_id": None,
                        "outcome": "missed",
                        "truth_ids": [truth.truth_id],
                        "evidence": {},
                    }
                )
        return records

    def _matches(self, finding: dict[str, Any], truth: TruthRecord) -> bool:
        location = finding.get("location") or {}
        finding_class = normalize_class(str(finding.get("vulnerability_class", "")))
        truth_class = normalize_class(truth.vulnerability_class or truth.cwe or "")
        if finding_class != truth_class or normalize_path(str(location.get("path", ""))) != normalize_path(truth.path):
            return False
        finding_symbol = location.get("symbol")
        if truth.symbol and finding_symbol:
            return str(truth.symbol) == str(finding_symbol)
        if truth.start_line is None:
            return True
        start = int(location.get("start_line") or 0)
        end = int(location.get("end_line") or start)
        truth_end = truth.end_line or truth.start_line
        return start <= truth_end + self.line_drift and end >= truth.start_line - self.line_drift


def compute_metrics(
    cases: list[dict[str, Any]],
    truths: list[TruthRecord],
    matches: list[dict[str, Any]],
    adjudications: list[AdjudicationRecord],
) -> list[MetricValue]:
    eligible_completed = {
        item["case_id"]
        for item in cases
        if item.get("status") == "completed" and item.get("effectiveness_eligible", False)
    }
    positive_truths = {item.truth_id for item in truths if item.case_id in eligible_completed and item.expected_presence and item.in_scope}
    candidate_matched = {
        truth_id
        for match in matches
        if match.get("outcome") == "matched"
        for truth_id in match.get("truth_ids", [])
    }
    finding_status = {
        (str(case.get("case_id")), str(finding.get("id"))): finding.get("verification_status") or finding.get("final_status")
        for case in cases
        for finding in case.get("findings", [])
    }
    confirmed_matched = {
        truth_id
        for match in matches
        if match.get("outcome") == "matched"
        and finding_status.get((str(match.get("case_id")), str(match.get("finding_id")))) == "confirmed"
        for truth_id in match.get("truth_ids", [])
    }
    metrics = [
        _ratio("candidate-recall", len(candidate_matched & positive_truths), len(positive_truths)),
        _ratio("confirmed-recall", len(confirmed_matched & positive_truths), len(positive_truths)),
    ]
    confirmed_groups = {
        finding_group_id(case["case_id"], finding)
        for case in cases
        if case.get("case_id") in eligible_completed
        for finding in case.get("findings", [])
        if (finding.get("verification_status") or finding.get("final_status")) == "confirmed"
    }
    adjudicated_groups: dict[str, str] = {}
    for item in adjudications:
        if item.finding_group_id in confirmed_groups and item.decision in {"true-positive", "false-positive"}:
            adjudicated_groups[item.finding_group_id] = item.decision
    true_positive = sum(1 for value in adjudicated_groups.values() if value == "true-positive")
    false_positive = sum(1 for value in adjudicated_groups.values() if value == "false-positive")
    metrics.append(_ratio("adjudicated-confirmed-precision", true_positive, true_positive + false_positive, "adjudication-missing"))

    negative_cases = {
        item["case_id"]
        for item in cases
        if item.get("status") == "completed"
        and item.get("effectiveness_eligible", False)
        and item.get("variant") in {"fixed", "safe-negative"}
    }
    false_positive_cases = {
        str(case["case_id"])
        for case in cases
        if case.get("case_id") in negative_cases
        and any(
            (finding.get("verification_status") or finding.get("final_status")) == "confirmed"
            for finding in case.get("findings", [])
        )
    }
    metrics.append(_ratio("negative-control-false-positive-rate", len(false_positive_cases), len(negative_cases)))

    negative_truth_ids = {item.truth_id for item in truths if item.case_id in eligible_completed and not item.expected_presence}
    terminal_negative: set[str] = set()
    rejected_negative: set[str] = set()
    for match in matches:
        overlap = set(match.get("truth_ids", [])) & negative_truth_ids
        if not overlap or not match.get("finding_id"):
            continue
        status = finding_status.get((str(match.get("case_id")), str(match["finding_id"])))
        if status in {"confirmed", "likely", "rejected", "manual-required"}:
            terminal_negative.update(overlap)
        if status == "rejected":
            rejected_negative.update(overlap)
    metrics.append(_ratio("negative-location-rejection-accuracy", len(rejected_negative), len(terminal_negative)))

    terminal = [status for status in finding_status.values() if status in {"confirmed", "likely", "rejected", "manual-required"}]
    metrics.append(_ratio("manual-required-rate", terminal.count("manual-required"), len(terminal)))
    truth_case_ids = {item.case_id for item in truths}
    metrics.append(_ratio("truth-coverage", len(eligible_completed & truth_case_ids), len(eligible_completed)))
    metrics.append(_ratio("adjudication-coverage", len(confirmed_groups & set(adjudicated_groups)), len(confirmed_groups), "adjudication-missing"))
    return metrics


def compute_macro_metrics(
    cases: list[dict[str, Any]],
    truths: list[TruthRecord],
    matches: list[dict[str, Any]],
    adjudications: list[AdjudicationRecord],
) -> list[dict[str, Any]]:
    per_project: dict[str, dict[str, float | None]] = {}
    for project_id in sorted({str(item.get("project_id")) for item in cases}):
        project_cases = [item for item in cases if str(item.get("project_id")) == project_id]
        case_ids = {item["case_id"] for item in project_cases}
        values = compute_metrics(
            project_cases,
            [item for item in truths if item.case_id in case_ids],
            [item for item in matches if item.get("case_id") in case_ids],
            [item for item in adjudications if item.case_id in case_ids],
        )
        per_project[project_id] = {item.metric_id: item.value for item in values}
    metric_ids = sorted({name for values in per_project.values() for name in values})
    output = []
    for metric_id in metric_ids:
        available = [float(values[metric_id]) for values in per_project.values() if values.get(metric_id) is not None]
        output.append(
            {
                "metric_id": metric_id,
                "aggregation": "macro-project-mean",
                "value": sum(available) / len(available) if available else None,
                "project_count": len(available),
                "reason": None if available else "no-project-value",
                "metric_version": METRIC_VERSION,
            }
        )
    return output


def evaluate_pairs(cases: list[dict[str, Any]], matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pairs: dict[str, list[dict[str, Any]]] = {}
    for case in cases:
        if case.get("pair_id"):
            pairs.setdefault(str(case["pair_id"]), []).append(case)
    output = []
    for pair_id, members in sorted(pairs.items()):
        case_results = []
        for case in sorted(members, key=lambda item: item["case_id"]):
            case_matches = [item for item in matches if item.get("case_id") == case["case_id"]]
            expected = "presence" if case.get("variant") == "vulnerable" else "absence-or-rejection"
            if expected == "presence":
                satisfied = any(item.get("outcome") == "matched" for item in case_matches)
            else:
                confirmed = [
                    finding for finding in case.get("findings", [])
                    if (finding.get("verification_status") or finding.get("final_status")) == "confirmed"
                ]
                satisfied = not confirmed
            case_results.append(
                {
                    "case_id": case["case_id"],
                    "variant": case.get("variant"),
                    "expected": expected,
                    "satisfied": satisfied,
                    "match_refs": [item.get("match_id") for item in case_matches],
                }
            )
        output.append(
            {
                "pair_id": pair_id,
                "project_id": members[0].get("project_id"),
                "cases": case_results,
                "satisfied": bool(case_results) and all(item["satisfied"] for item in case_results),
            }
        )
    return output


def build_benchmark_report(
    *,
    run_id: str,
    corpus: dict[str, Any],
    cases: list[dict[str, Any]],
    matches: list[dict[str, Any]],
    metrics: list[MetricValue],
    macro_metrics: list[dict[str, Any]] | None = None,
    reuse_fingerprint: str,
    protocol_fingerprint: str,
    comparison_dimensions: list[str],
    provenance: dict[str, Any],
) -> dict[str, Any]:
    completed = sum(item.get("status") == "completed" for item in cases)
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": utc_now(),
        "corpus": corpus,
        "fingerprints": {
            "reuse_fingerprint": reuse_fingerprint,
            "comparison_protocol_fingerprint": protocol_fingerprint,
        },
        "comparison_dimensions": sorted(comparison_dimensions),
        "provenance": provenance,
        "summary": {
            "case_count": len(cases),
            "unique_project_count": len({item.get("project_id") for item in cases}),
            "completed": completed,
            "failed": sum(item.get("status") == "failed" for item in cases),
            "timed_out": sum(item.get("status") == "timed-out" for item in cases),
            "not_run": sum(item.get("status") == "not-run" for item in cases),
            "complete": completed == len(cases),
            "baseline_eligible": bool(cases) and all(item.get("baseline_eligible", False) for item in cases),
        },
        "cases": cases,
        "matches": matches,
        "metrics": [item.to_dict() for item in metrics],
        "macro_metrics": macro_metrics or [],
        "pairs": evaluate_pairs(cases, matches),
    }
    report["digest"] = canonical_digest(report)
    return report


def render_markdown(report: dict[str, Any]) -> str:
    if report.get("schema_version") != REPORT_SCHEMA_VERSION:
        raise ValueError("Markdown input is not a validated benchmark report")
    summary = report["summary"]
    lines = [
        "# Benchmark Report", "", f"- Run: `{report['run_id']}`",
        f"- Complete: `{str(summary['complete']).lower()}`",
        f"- Baseline eligible: `{str(summary['baseline_eligible']).lower()}`", "",
        "## Completion", "", "| Case | Project | Variant | Status | Coverage | Failure |",
        "| --- | --- | --- | --- | ---: | --- |",
    ]
    for case in report["cases"]:
        resources = case.get("resources") or {}
        coverage = resources.get("scanned_files")
        coverage_text = str(coverage) if coverage is not None else "N/A"
        failure = case.get("failure_reason") or ""
        lines.append(f"| {case['case_id']} | {case['project_id']} | {case.get('variant','')} | {case['status']} | {coverage_text} | {failure} |")
    lines.extend(["", "## Effectiveness", "", "| Metric | Value | Numerator | Denominator | Reason |", "| --- | ---: | ---: | ---: | --- |"])
    for metric in report["metrics"]:
        value = "N/A" if metric["value"] is None else f"{metric['value']:.4f}"
        lines.append(f"| {metric['metric_id']} | {value} | {metric['numerator']} | {metric['denominator']} | {metric.get('reason') or ''} |")
    lines.extend(
        [
            "",
            "## Resources",
            "",
            "| Case | Seconds | LLM tokens | Docker starts | LLM accounting source | Reconciliation | Blocking IDs | Accounting gaps |",
            "| --- | ---: | ---: | ---: | --- | --- | --- | --- |",
        ]
    )
    for case in report["cases"]:
        resources = case.get("resources") or {}
        gaps = ", ".join(item.get("field", "") for item in resources.get("accounting_gaps", []))
        blockers = ", ".join(resources.get("llm_gap_ids") or [])
        llm_tokens = resources.get("llm_tokens")
        lines.append(
            f"| {case['case_id']} | {resources.get('elapsed_seconds', 'N/A')} | "
            f"{'N/A' if llm_tokens is None else llm_tokens} | {resources.get('docker_starts', 'N/A')} | "
            f"{resources.get('accounting_source', 'unknown')} | "
            f"{resources.get('llm_reconciliation_status', 'unknown')} | {blockers} | {gaps} |"
        )
    return "\n".join(lines) + "\n"


def compare_reports(baseline: dict[str, Any], candidate: dict[str, Any], dimensions: list[str]) -> dict[str, Any]:
    if baseline.get("fingerprints", {}).get("comparison_protocol_fingerprint") != candidate.get("fingerprints", {}).get("comparison_protocol_fingerprint"):
        raise ValueError("comparison_protocol_fingerprint mismatch")
    declared = sorted(set(dimensions))
    baseline_dims = sorted(baseline.get("comparison_dimensions", []))
    candidate_dims = sorted(candidate.get("comparison_dimensions", []))
    if baseline_dims != candidate_dims or baseline_dims != declared:
        raise ValueError("comparison_dimensions mismatch")
    mismatches = _undeclared_mismatches(baseline.get("provenance", {}), candidate.get("provenance", {}), declared)
    if mismatches:
        raise ValueError("undeclared comparison differences: " + ", ".join(mismatches))
    base_metrics = {item["metric_id"]: item for item in baseline.get("metrics", [])}
    candidate_metrics = {item["metric_id"]: item for item in candidate.get("metrics", [])}
    deltas = {}
    for metric_id in sorted(set(base_metrics) | set(candidate_metrics)):
        before = base_metrics.get(metric_id, {}).get("value")
        after = candidate_metrics.get(metric_id, {}).get("value")
        absolute = None if before is None or after is None else after - before
        relative = None if absolute is None or before == 0 else absolute / abs(before)
        deltas[metric_id] = {"baseline": before, "candidate": after, "absolute": absolute, "relative": relative}
    baseline_cases = {item["case_id"]: item for item in baseline.get("cases", [])}
    candidate_cases = {item["case_id"]: item for item in candidate.get("cases", [])}
    case_deltas: dict[str, Any] = {}
    for case_id in sorted(set(baseline_cases) | set(candidate_cases)):
        before_case = baseline_cases.get(case_id)
        after_case = candidate_cases.get(case_id)
        if not before_case or not after_case:
            case_deltas[case_id] = {"missing": "baseline" if not before_case else "candidate"}
            continue
        before_resources = before_case.get("resources") or {}
        after_resources = after_case.get("resources") or {}
        resource_deltas = {}
        for name in ("scanned_files", "elapsed_seconds", "llm_tokens", "docker_starts"):
            before_value = before_resources.get(name)
            after_value = after_resources.get(name)
            absolute, relative = _delta(before_value, after_value)
            resource_deltas[name] = {"baseline": before_value, "candidate": after_value, "absolute": absolute, "relative": relative}
        case_deltas[case_id] = {
            "status": {"baseline": before_case.get("status"), "candidate": after_case.get("status")},
            "resources": resource_deltas,
            "failures": {"baseline": before_case.get("failure_reason"), "candidate": after_case.get("failure_reason")},
        }
    comparison = {
        "schema_version": "benchmark-comparison.v1",
        "baseline_run_id": baseline.get("run_id"),
        "candidate_run_id": candidate.get("run_id"),
        "comparison_dimensions": declared,
        "compatible": True,
        "metric_deltas": deltas,
        "completion_delta": candidate.get("summary", {}).get("completed", 0) - baseline.get("summary", {}).get("completed", 0),
        "case_deltas": case_deltas,
    }
    aggregate_resources = {}
    for resource_name in ("scanned_files", "elapsed_seconds", "llm_tokens", "docker_starts"):
        before_values = [
            (item.get("resources") or {}).get(resource_name) for item in baseline.get("cases", [])
        ]
        after_values = [
            (item.get("resources") or {}).get(resource_name) for item in candidate.get("cases", [])
        ]
        before_total = sum(value for value in before_values if isinstance(value, (int, float))) if any(isinstance(value, (int, float)) for value in before_values) else None
        after_total = sum(value for value in after_values if isinstance(value, (int, float))) if any(isinstance(value, (int, float)) for value in after_values) else None
        absolute, relative = _delta(before_total, after_total)
        aggregate_resources[resource_name] = {
            "baseline": before_total, "candidate": after_total,
            "absolute": absolute, "relative": relative,
        }
    comparison["aggregate_resource_deltas"] = aggregate_resources
    comparison["gates"] = evaluate_comparison_gates(baseline, candidate, comparison)
    return comparison


def evaluate_comparison_gates(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    comparison: dict[str, Any],
    thresholds: dict[str, float] | None = None,
) -> dict[str, Any]:
    thresholds = thresholds or {}
    failures: list[dict[str, Any]] = []
    baseline_ids = {item["case_id"] for item in baseline.get("cases", [])}
    candidate_ids = {item["case_id"] for item in candidate.get("cases", [])}
    for case_id in sorted(baseline_ids - candidate_ids):
        failures.append({"gate": "missing-case", "case_id": case_id})
    for case in candidate.get("cases", []):
        case_id = case.get("case_id")
        if case.get("status") == "completed":
            resources = case.get("resources") or {}
            if not resources.get("scanned_files"):
                failures.append({"gate": "false-completion", "case_id": case_id})
        if case.get("variant") in {"fixed", "safe-negative"} and (case.get("counts") or {}).get("confirmed", 0) > 0:
            failures.append({"gate": "false-confirmed-safe-negative", "case_id": case_id})
        if (case.get("cleanup") or {}).get("success") is False:
            failures.append({"gate": "cleanup-failed", "case_id": case_id})
        if (case.get("resources") or {}).get("accounting_gaps"):
            failures.append({"gate": "accounting-gap", "case_id": case_id})
        resources = case.get("resources") or {}
        if resources.get("llm_reconciliation_status") == "incomplete":
            for gap_id in resources.get("llm_gap_ids") or ["unknown-gap"]:
                failures.append(
                    {"gate": "llm-accounting-gap", "case_id": case_id, "gap_id": gap_id}
                )
    for metric_id, delta in comparison.get("metric_deltas", {}).items():
        minimum = thresholds.get(f"min:{metric_id}")
        maximum = thresholds.get(f"max:{metric_id}")
        value = delta.get("candidate")
        if value is not None and minimum is not None and value < minimum:
            failures.append({"gate": "metric-minimum", "metric_id": metric_id, "value": value, "threshold": minimum})
        if value is not None and maximum is not None and value > maximum:
            failures.append({"gate": "metric-maximum", "metric_id": metric_id, "value": value, "threshold": maximum})
    for resource_name, delta in comparison.get("aggregate_resource_deltas", {}).items():
        maximum_relative = thresholds.get(f"max-relative:{resource_name}")
        relative = delta.get("relative")
        if relative is not None and maximum_relative is not None and relative > maximum_relative:
            failures.append(
                {"gate": "resource-regression", "resource": resource_name, "relative": relative, "threshold": maximum_relative}
            )
    return {"passed": not failures, "failures": failures, "thresholds": thresholds}


def aggregate_repetitions(reports: list[dict[str, Any]]) -> dict[str, Any]:
    if not reports:
        raise ValueError("at least one repetition report is required")
    protocol = reports[0].get("fingerprints", {}).get("comparison_protocol_fingerprint")
    base_provenance = {key: value for key, value in reports[0].get("provenance", {}).items() if key != "repetition"}
    for report in reports:
        if report.get("fingerprints", {}).get("comparison_protocol_fingerprint") != protocol:
            raise ValueError("repetition protocol mismatch")
        provenance = {key: value for key, value in report.get("provenance", {}).items() if key != "repetition"}
        if provenance != base_provenance:
            raise ValueError("repetition effective settings mismatch")
    metric_ids = sorted({item["metric_id"] for report in reports for item in report.get("metrics", [])})
    aggregates = []
    for metric_id in metric_ids:
        values = [
            item["value"] for report in reports for item in report.get("metrics", [])
            if item["metric_id"] == metric_id and item.get("value") is not None
        ]
        aggregates.append(
            {
                "metric_id": metric_id,
                "mean": sum(values) / len(values) if values else None,
                "min": min(values) if values else None,
                "max": max(values) if values else None,
                "repetition_count": len(values),
            }
        )
    return {
        "schema_version": "benchmark-repetitions.v1",
        "comparison_protocol_fingerprint": protocol,
        "run_ids": [item.get("run_id") for item in reports],
        "metrics": aggregates,
        "pooled_findings": False,
    }


def normalize_class(value: str) -> str:
    normalized = value.strip().lower().replace("_", "-")
    return CLASS_ALIASES.get(normalized, normalized)


def normalize_path(value: str) -> str:
    normalized = value.replace("\\", "/").lstrip("./")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe finding/truth path: {value}")
    return str(path).lower()


def finding_group_id(case_id: str, finding: dict[str, Any]) -> str:
    location = finding.get("location") or {}
    location_key = location.get("symbol") or f"{location.get('start_line', '')}:{location.get('end_line', '')}"
    return stable_id(
        "BFG", case_id, normalize_class(str(finding.get("vulnerability_class", ""))),
        normalize_path(str(location.get("path", ""))), location_key,
    )


def promotion_readiness(report: dict[str, Any], *, profile_kind: str, required_projects: int | None = None) -> dict[str, Any]:
    blockers: list[dict[str, str]] = []
    if not report.get("summary", {}).get("complete"):
        blockers.append({"field": "summary.complete", "reason": "partial-run"})
    if not report.get("summary", {}).get("baseline_eligible"):
        blockers.append({"field": "summary.baseline_eligible", "reason": "case-gate-failed"})
    for case in report.get("cases", []):
        if case.get("cleanup", {}).get("success") is False:
            blockers.append({"field": case["case_id"], "reason": "cleanup-failed"})
        resources = case.get("resources") or {}
        if resources.get("accounting_gaps"):
            blockers.append({"field": case["case_id"], "reason": "required-accounting-incomplete"})
        if resources.get("llm_reconciliation_status") == "incomplete":
            for gap_id in resources.get("llm_gap_ids") or ["unknown-gap"]:
                blockers.append(
                    {
                        "field": f"{case['case_id']}.llm_accounting",
                        "reason": f"required-accounting-incomplete:{gap_id}",
                    }
                )
    eligible_projects = {
        item.get("project_id") for item in report.get("cases", [])
        if item.get("effectiveness_eligible") and item.get("support_level") != "unsupported"
    }
    quota = required_projects if required_projects is not None else (20 if profile_kind == "full" else 3 if profile_kind == "pilot" else 0)
    if len(eligible_projects) < quota:
        blockers.append({"field": "unique_project_count", "reason": f"requires-{quota}-eligible-projects"})
    return {
        "schema_version": "benchmark-readiness.v1",
        "profile_kind": profile_kind,
        "eligible_project_count": len(eligible_projects),
        "required_project_count": quota,
        "ready": not blockers,
        "blockers": blockers,
    }


def _ratio(metric_id: str, numerator: int, denominator: int, reason: str = "denominator-zero") -> MetricValue:
    if denominator == 0:
        return MetricValue(metric_id, None, numerator, denominator, reason, METRIC_VERSION)
    return MetricValue(metric_id, numerator / denominator, numerator, denominator, None, METRIC_VERSION)


def _finding_in_scope(finding: dict[str, Any]) -> bool:
    return bool(finding.get("in_scope", True))


def _undeclared_mismatches(left: dict[str, Any], right: dict[str, Any], dimensions: list[str]) -> list[str]:
    keys = set(left) | set(right)
    allowed = set(dimensions)
    if "engine" in dimensions:
        allowed.update(key for key in keys if key == "engine" or key.startswith("engine_"))
    if "prompt" in dimensions:
        allowed.update(key for key in keys if key == "prompt" or key.startswith("prompt_"))
    if "model" in dimensions:
        allowed.update({"model", "provider"})
    return sorted(key for key in keys if key not in allowed and left.get(key) != right.get(key))


def _delta(before: Any, after: Any) -> tuple[float | None, float | None]:
    if not isinstance(before, (int, float)) or not isinstance(after, (int, float)):
        return None, None
    absolute = float(after) - float(before)
    relative = None if before == 0 else absolute / abs(float(before))
    return absolute, relative
