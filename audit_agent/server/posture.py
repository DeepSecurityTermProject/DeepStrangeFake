from __future__ import annotations

import hashlib
import json
import math
import posixpath
import re
import unicodedata
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

from ..models import utc_now
from ..redaction import redact_secrets
from .limits import DASHBOARD_HIGH_RISK_LIMIT, DASHBOARD_RECENT_RUN_LIMIT
from .workspace_store import Project, WorkspaceStore


POSTURE_SCHEMA_VERSION = "project-security-posture.v1"
COMPLETENESS_SCHEMA_VERSION = "posture-completeness.v1"
RISK_FORMULA_VERSION = "validated-severity-confidence.v1"
FINGERPRINT_VERSION = "finding-fingerprint.v1"
TREND_SCHEMA_VERSION = "finding-trend.v1"
UNAVAILABLE_SCHEMA_VERSION = "unavailable-data.v1"

SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 7,
    "low": 2,
    "informational": 0,
}
CONFIDENCE_FALLBACK = 1.0
TERMINAL_STATUSES = {"succeeded", "degraded", "failed", "cancelled"}
PUBLIC_ARTIFACT_CATEGORIES = {
    "reports",
    "evidence",
    "findings",
    "runtime_state",
    "verification-plans",
    "evidence-gates",
}


def unavailable(reason: str, **details: Any) -> dict[str, Any]:
    return {
        "schema_version": UNAVAILABLE_SCHEMA_VERSION,
        "status": "unavailable",
        "reason": reason,
        "details": details,
    }


def normalize_vulnerability_class(value: Any) -> str:
    text = unicodedata.normalize("NFKC", str(value or "unknown")).casefold().strip()
    return re.sub(r"[^a-z0-9]+", "-", text).strip("-") or "unknown"


def normalize_repository_path(value: Any) -> str:
    raw = unicodedata.normalize("NFKC", str(value or "unknown")).replace("\\", "/")
    normalized = posixpath.normpath("/" + raw.lstrip("/"))[1:]
    while normalized.startswith("../"):
        normalized = normalized[3:]
    return normalized or "unknown"


def _normalize_identity_token(value: Any, fallback: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).strip().casefold()
    text = re.sub(r"\s+", " ", text)
    return text[:240] or fallback


def build_fingerprint(finding: dict[str, Any]) -> dict[str, Any]:
    location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
    metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    dataflow = finding.get("dataflow_summary") or metadata.get("dataflow_summary") or {}
    dataflow = dataflow if isinstance(dataflow, dict) else {}
    sink = dataflow.get("sink") if isinstance(dataflow.get("sink"), dict) else {}
    vulnerability_class = normalize_vulnerability_class(finding.get("vulnerability_class"))
    path = normalize_repository_path(location.get("path"))

    raw_symbol = (
        finding.get("affected_function")
        or metadata.get("enclosing_symbol")
        or metadata.get("function")
        or location.get("symbol")
    )
    if raw_symbol:
        symbol = _normalize_identity_token(raw_symbol, "")
        symbol_quality = "reported"
    else:
        symbol = f"module:{path}"
        symbol_quality = "fallback-module-anchor"

    primitive = metadata.get("trusted_verification_primitive")
    primitive_id = primitive.get("primitive_id") if isinstance(primitive, dict) else None
    rule_ids = finding.get("dataflow_rule_ids") or metadata.get("dataflow_rule_ids") or []
    raw_sink = (
        metadata.get("sink_identity")
        or metadata.get("dangerous_operation")
        or sink.get("symbol")
        or primitive_id
        or (rule_ids[0] if isinstance(rule_ids, list) and rule_ids else None)
    )
    if raw_sink:
        sink_identity = _normalize_identity_token(raw_sink, "")
        sink_quality = "reported"
    else:
        sink_identity = f"class:{vulnerability_class}"
        sink_quality = "fallback-class-anchor"

    components = {
        "vulnerability_class": vulnerability_class,
        "repository_path": path,
        "enclosing_symbol": symbol,
        "sink_identity": sink_identity,
    }
    canonical = json.dumps(components, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {
        "fingerprint": f"FP-{digest[:24]}",
        "fingerprint_version": FINGERPRINT_VERSION,
        "components": components,
        "quality": {
            "overall": "fallback" if any(
                value.startswith("fallback") for value in (symbol_quality, sink_quality)
            ) else "reported",
            "symbol": symbol_quality,
            "sink": sink_quality,
        },
    }


def _confidence(value: Any) -> dict[str, Any]:
    fallback = False
    clamped = False
    try:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("non-finite")
    except (TypeError, ValueError, OverflowError):
        parsed = CONFIDENCE_FALLBACK
        fallback = True
    effective = min(1.0, max(0.0, parsed))
    clamped = effective != parsed
    return {
        "raw": value if isinstance(value, (int, float)) and math.isfinite(float(value)) else None,
        "effective": effective,
        "fallback_applied": fallback,
        "clamped": clamped,
    }


def calculate_risk(validated_findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    total = 0.0
    fallback_count = 0
    clamped_count = 0
    for finding in validated_findings:
        severity = str(finding.get("severity") or "informational").casefold()
        weight = SEVERITY_WEIGHTS.get(severity, 0)
        confidence = _confidence(finding.get("confidence"))
        contribution = weight * confidence["effective"]
        total += contribution
        fallback_count += int(confidence["fallback_applied"])
        clamped_count += int(confidence["clamped"])
        components.append(
            {
                "finding_id": finding.get("finding_id") or finding.get("id"),
                "fingerprint": finding.get("fingerprint"),
                "severity": severity,
                "weight": weight,
                "confidence": confidence,
                "contribution": contribution,
            }
        )
    score = min(100, int(math.floor(total + 0.5)))
    return {
        "schema_version": RISK_FORMULA_VERSION,
        "formula_version": RISK_FORMULA_VERSION,
        "formula": "min(100, round_half_up(sum(severity_weight * clamped_confidence)))",
        "severity_weights": dict(SEVERITY_WEIGHTS),
        "confidence_rule": "clamp-to-[0,1]",
        "confidence_fallback_rule": "validated-missing-or-invalid-confidence=1.0",
        "score": score,
        "uncapped_total": total,
        "cap": 100,
        "fallback_count": fallback_count,
        "clamped_count": clamped_count,
        "components": components,
    }


def _status(candidate: dict[str, Any]) -> str:
    validation = candidate.get("validation") if isinstance(candidate.get("validation"), dict) else {}
    metadata = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
    raw = (
        candidate.get("verification_status")
        or validation.get("verification_status")
        or validation.get("final_status")
        or validation.get("status")
        or metadata.get("verification_status")
        or "pending"
    )
    return str(raw).strip().casefold().replace("_", "-")


def _strings(values: Any) -> list[str]:
    if isinstance(values, str):
        return [values]
    if not isinstance(values, list):
        return []
    output: list[str] = []
    for value in values:
        if isinstance(value, str):
            output.append(value)
        elif isinstance(value, dict):
            for key in ("id", "path", "ref"):
                if isinstance(value.get(key), str):
                    output.append(value[key])
                    break
    return output


def _evidence_refs(candidate: dict[str, Any], chain: dict[str, Any] | None) -> list[str]:
    metadata = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
    validation = candidate.get("validation") if isinstance(candidate.get("validation"), dict) else {}
    refs: list[str] = []
    for value in (
        candidate.get("evidence_chain_id"),
        candidate.get("local_evidence_refs"),
        candidate.get("dataflow_trace_refs"),
        validation.get("poc_refs"),
        validation.get("sandbox_result_refs"),
        validation.get("attempt_refs"),
        validation.get("artifacts"),
        metadata.get("evidence_package_ref"),
        metadata.get("evidence_gate_ref"),
        metadata.get("verification_plan_ref"),
    ):
        refs.extend(_strings(value))
    if chain:
        refs.extend(_strings(chain.get("id")))
        refs.extend(_strings(chain.get("artifact_refs")))
        refs.extend(_strings(chain.get("dataflow_trace_refs")))
        refs.extend(_strings(chain.get("tool_refs")))
    return list(dict.fromkeys(item for item in refs if item))[:96]


def _chain_confirms(chain: dict[str, Any] | None) -> bool:
    if not chain:
        return False
    validation = chain.get("validation") if isinstance(chain.get("validation"), dict) else {}
    return str(
        validation.get("verification_status")
        or validation.get("final_status")
        or validation.get("status")
        or ""
    ).casefold() == "confirmed"


def _artifact_links(run_id: str, run_dir: Path | None, refs: list[str]) -> list[dict[str, str]]:
    if run_dir is None:
        return []
    root = run_dir.resolve(strict=False)
    links: list[dict[str, str]] = []
    for ref in refs:
        candidate = Path(ref)
        if not candidate.is_absolute():
            candidate = root / candidate
        resolved = candidate.resolve(strict=False)
        try:
            relative = resolved.relative_to(root)
        except ValueError:
            continue
        if not relative.parts or relative.parts[0] not in PUBLIC_ARTIFACT_CATEGORIES:
            continue
        if not resolved.is_file():
            continue
        path = "/".join(relative.parts)
        links.append(
            {
                "path": path,
                "url": f"/api/runs/{quote(run_id, safe='')}/artifacts/{quote(path, safe='/')}",
            }
        )
    return links[:32]


def project_report_findings(
    report: dict[str, Any] | None,
    *,
    run_id: str,
    run_dir: Path | None = None,
) -> dict[str, Any]:
    if not isinstance(report, dict):
        return {
            "schema_version": POSTURE_SCHEMA_VERSION,
            "contract_available": False,
            "validated": [],
            "states": {key: [] for key in ("candidate", "pending", "manual", "rejected", "inconclusive")},
            "validation_counts": {key: 0 for key in ("validated", "candidate", "pending", "manual", "rejected", "inconclusive")},
            "evidence_gate_failures": 0,
            "unavailable": unavailable("report-unavailable"),
        }
    candidates = report.get("verification_candidates")
    if not isinstance(candidates, list):
        return {
            "schema_version": POSTURE_SCHEMA_VERSION,
            "contract_available": False,
            "validated": [],
            "states": {key: [] for key in ("candidate", "pending", "manual", "rejected", "inconclusive")},
            "validation_counts": {key: 0 for key in ("validated", "candidate", "pending", "manual", "rejected", "inconclusive")},
            "evidence_gate_failures": 0,
            "unavailable": unavailable("legacy-verification-contract-unavailable"),
        }
    chains = {
        str(item.get("finding_id") or ""): item
        for item in (report.get("evidence_chains") or [])
        if isinstance(item, dict)
    }
    validated: list[dict[str, Any]] = []
    states = {key: [] for key in ("candidate", "pending", "manual", "rejected", "inconclusive")}
    gate_failures = 0
    for raw in candidates:
        if not isinstance(raw, dict):
            continue
        candidate = raw
        finding_id = str(candidate.get("id") or "")
        chain = chains.get(finding_id)
        refs = _evidence_refs(candidate, chain)
        status = _status(candidate)
        gate_confirmed = status == "confirmed" and _chain_confirms(chain) and bool(refs)
        fingerprint = build_fingerprint(candidate)
        location = candidate.get("location") if isinstance(candidate.get("location"), dict) else {}
        item = {
            "finding_id": finding_id,
            "title": str(candidate.get("title") or candidate.get("vulnerability_class") or "Finding")[:240],
            "vulnerability_class": normalize_vulnerability_class(candidate.get("vulnerability_class")),
            "severity": str(candidate.get("severity") or "informational").casefold(),
            "confidence": candidate.get("confidence"),
            "location": {
                "path": normalize_repository_path(location.get("path")),
                "start_line": location.get("start_line"),
                "end_line": location.get("end_line"),
                "symbol": location.get("symbol"),
            },
            "verification_status": status,
            "evidence_state": "complete" if gate_confirmed else "not-confirmed",
            "evidence_refs": refs,
            "artifact_refs": _artifact_links(run_id, run_dir, refs),
            "run_id": run_id,
            **fingerprint,
        }
        if gate_confirmed:
            item["confidence_metadata"] = _confidence(candidate.get("confidence"))
            validated.append(item)
        elif status == "confirmed":
            gate_failures += 1
            item["posture_reason"] = "confirmed-status-without-complete-evidence-chain"
            states["inconclusive"].append(item)
        elif status in {"likely", "candidate", "unverified", "static-only"}:
            states["candidate"].append(item)
        elif status in {"pending", "queued", "running", "not-started"}:
            states["pending"].append(item)
        elif status in {"manual", "manual-required", "manual-review"}:
            states["manual"].append(item)
        elif status in {"rejected", "false-positive", "not-vulnerable"}:
            states["rejected"].append(item)
        else:
            states["inconclusive"].append(item)
    counts = {"validated": len(validated), **{key: len(value) for key, value in states.items()}}
    return {
        "schema_version": POSTURE_SCHEMA_VERSION,
        "contract_available": True,
        "validated": validated,
        "states": states,
        "validation_counts": counts,
        "evidence_gate_failures": gate_failures,
        "unavailable": None,
    }


def _runtime_quality(report: dict[str, Any] | None, resource: dict[str, Any] | None) -> dict[str, Any]:
    runtime = report.get("runtime") if isinstance(report, dict) and isinstance(report.get("runtime"), dict) else {}
    investigation = runtime.get("investigation") if isinstance(runtime.get("investigation"), dict) else {}
    graph = runtime.get("graph") if isinstance(runtime.get("graph"), dict) else {}
    budget = investigation.get("investigation_budget") or (resource or {}).get("budget_consumption")
    degraded_reasons = list(investigation.get("degraded_reasons") or [])
    fallback_reason = investigation.get("fallback_reason") or graph.get("fallback_reason") or ""
    return {
        "schema_version": "investigation-quality.v1",
        "requested_mode": investigation.get("requested_mode"),
        "effective_mode": investigation.get("effective_mode") or graph.get("mode"),
        "fallback_reason": fallback_reason or None,
        "degraded_reasons": degraded_reasons,
        "budget": budget if isinstance(budget, dict) else unavailable("budget-metadata-unavailable"),
        "accounting_status": (resource or {}).get("llm_reconciliation_status"),
        "accounting_gaps": list((resource or {}).get("accounting_gaps") or []),
        "evidence_gate_counts": dict(investigation.get("evidence_gate_counts") or {}),
    }


def evaluate_completeness(
    run: dict[str, Any],
    report: dict[str, Any] | None,
    resource: dict[str, Any] | None,
    projection: dict[str, Any],
) -> dict[str, Any]:
    executive = report.get("executive_summary") if isinstance(report, dict) and isinstance(report.get("executive_summary"), dict) else {}
    quality = _runtime_quality(report, resource)
    report_scanned = executive.get("scanned_file_count")
    resource_scanned = (resource or {}).get("scanned_files")
    coverage_ok = (
        isinstance(report_scanned, int)
        and report_scanned >= 0
        and isinstance(resource_scanned, int)
        and resource_scanned >= 0
        and report_scanned == resource_scanned
    )
    validation_counts = projection.get("validation_counts") or {}
    validation_ok = bool(projection.get("contract_available")) and not any(
        int(validation_counts.get(name, 0) or 0) > 0
        for name in ("pending", "manual", "inconclusive")
    )
    checks = {
        "terminal_success": run.get("status") == "succeeded",
        "report_present": isinstance(report, dict),
        "report_completed": isinstance(report, dict) and report.get("run_status") == "completed",
        "non_degraded": (
            run.get("status") == "succeeded"
            and not quality["degraded_reasons"]
            and (report or {}).get("run_status") != "degraded"
        ),
        "coverage_evidence": coverage_ok,
        "validation_complete": validation_ok,
        "evidence_complete": (
            isinstance(report, dict)
            and bool(projection.get("contract_available"))
            and int(projection.get("evidence_gate_failures", 0) or 0) == 0
        ),
        "accounting_complete": (
            isinstance(resource, dict)
            and resource.get("terminal_status") == "succeeded"
            and resource.get("llm_reconciliation_status") == "complete"
            and isinstance(resource.get("budget_consumption"), dict)
        ),
    }
    reason_map = {
        "terminal_success": "terminal-status-not-succeeded",
        "report_present": "report-unavailable",
        "report_completed": "report-not-completed",
        "non_degraded": "run-degraded",
        "coverage_evidence": "coverage-evidence-incomplete",
        "validation_complete": "validation-incomplete",
        "evidence_complete": "evidence-gate-incomplete",
        "accounting_complete": "accounting-incomplete",
    }
    reasons = [reason_map[name] for name, passed in checks.items() if not passed]
    return {
        "schema_version": COMPLETENESS_SCHEMA_VERSION,
        "complete": not reasons,
        "status": "complete" if not reasons else "incomplete",
        "checks": checks,
        "reasons": reasons,
    }


def classify_trend(snapshot: dict[str, Any], earlier: list[dict[str, Any]]) -> dict[str, Any]:
    current = deepcopy(snapshot.get("findings", {}).get("validated", []))
    current_by_fp = {item["fingerprint"]: item for item in current}
    complete_earlier = [item for item in earlier if item.get("completeness", {}).get("complete")]
    previous = complete_earlier[-1] if complete_earlier else None
    counts = {key: 0 for key in ("new", "persistent", "resolved", "reintroduced", "unconfirmed")}
    finding_lists = {key: [] for key in counts}
    if previous is None:
        status = "baseline" if snapshot.get("completeness", {}).get("complete") else "incomplete-current"
        bucket = "new" if status == "baseline" else "unconfirmed"
        for finding in current:
            finding["trend_status"] = bucket
            finding_lists[bucket].append(finding)
        counts[bucket] = len(current)
        return {
            "schema_version": TREND_SCHEMA_VERSION,
            "comparison_status": status,
            "comparable": status == "baseline",
            "basis_run_id": None,
            "fingerprint_version": snapshot.get("versions", {}).get("fingerprint"),
            "counts": counts,
            "findings": finding_lists,
            "limitations": [] if status == "baseline" else ["no-complete-baseline"],
        }

    previous_version = previous.get("versions", {}).get("fingerprint")
    current_version = snapshot.get("versions", {}).get("fingerprint")
    previous_findings = deepcopy(previous.get("findings", {}).get("validated", []))
    previous_by_fp = {item["fingerprint"]: item for item in previous_findings}
    if previous_version != current_version:
        union = {**previous_by_fp, **current_by_fp}
        for finding in union.values():
            finding["trend_status"] = "unconfirmed"
            finding_lists["unconfirmed"].append(finding)
        counts["unconfirmed"] = len(union)
        return {
            "schema_version": TREND_SCHEMA_VERSION,
            "comparison_status": "incompatible-fingerprint-version",
            "comparable": False,
            "basis_run_id": previous.get("run_id"),
            "fingerprint_version": current_version,
            "counts": counts,
            "findings": finding_lists,
            "limitations": [f"fingerprint-version-mismatch:{previous_version}:{current_version}"],
        }

    previous_set = set(previous_by_fp)
    current_set = set(current_by_fp)
    if not snapshot.get("completeness", {}).get("complete"):
        for fingerprint in sorted(current_set & previous_set):
            finding = current_by_fp[fingerprint]
            finding["trend_status"] = "persistent"
            finding_lists["persistent"].append(finding)
        for fingerprint in sorted(current_set ^ previous_set):
            finding = current_by_fp.get(fingerprint) or previous_by_fp[fingerprint]
            finding["trend_status"] = "unconfirmed"
            finding_lists["unconfirmed"].append(finding)
        counts["persistent"] = len(finding_lists["persistent"])
        counts["unconfirmed"] = len(finding_lists["unconfirmed"])
        return {
            "schema_version": TREND_SCHEMA_VERSION,
            "comparison_status": "incomplete-current",
            "comparable": False,
            "basis_run_id": previous.get("run_id"),
            "fingerprint_version": current_version,
            "counts": counts,
            "findings": finding_lists,
            "limitations": ["incomplete-run-cannot-resolve-findings"],
        }

    seen_before_previous = {
        finding["fingerprint"]
        for historic in complete_earlier[:-1]
        for finding in historic.get("findings", {}).get("validated", [])
    }
    for fingerprint in sorted(current_set & previous_set):
        finding = current_by_fp[fingerprint]
        finding["trend_status"] = "persistent"
        finding_lists["persistent"].append(finding)
    for fingerprint in sorted(current_set - previous_set):
        bucket = "reintroduced" if fingerprint in seen_before_previous else "new"
        finding = current_by_fp[fingerprint]
        finding["trend_status"] = bucket
        finding_lists[bucket].append(finding)
    for fingerprint in sorted(previous_set - current_set):
        finding = previous_by_fp[fingerprint]
        finding["trend_status"] = "resolved"
        finding_lists["resolved"].append(finding)
    for name in counts:
        counts[name] = len(finding_lists[name])
    return {
        "schema_version": TREND_SCHEMA_VERSION,
        "comparison_status": "comparable",
        "comparable": True,
        "basis_run_id": previous.get("run_id"),
        "fingerprint_version": current_version,
        "counts": counts,
        "findings": finding_lists,
        "limitations": [],
    }


class PostureService:
    def __init__(self, workspace: WorkspaceStore):
        self.workspace = workspace

    def project_run(self, run: dict[str, Any], *, force: bool = False) -> dict[str, Any] | None:
        if run.get("status") not in TERMINAL_STATUSES:
            return None
        run_dir = Path(run["run_dir"]) if run.get("run_dir") else None
        report, report_bytes = self._read_artifact(run_dir, "report.json")
        resource, resource_bytes = self._read_resource(run_dir)
        digest = self._source_digest(run, report_bytes, resource_bytes)
        existing = self.workspace.get_posture_snapshot(str(run["job_id"]))
        if (
            existing
            and not force
            and existing.get("source_digest") == digest
            and existing.get("schema_version") == POSTURE_SCHEMA_VERSION
            and existing.get("versions") == {
                "completeness": COMPLETENESS_SCHEMA_VERSION,
                "risk_formula": RISK_FORMULA_VERSION,
                "fingerprint": FINGERPRINT_VERSION,
                "trend": TREND_SCHEMA_VERSION,
            }
        ):
            return existing

        projection = project_report_findings(
            report,
            run_id=str(run["job_id"]),
            run_dir=run_dir,
        )
        completeness = evaluate_completeness(run, report, resource, projection)
        risk = calculate_risk(projection["validated"])
        risk["available"] = completeness["complete"]
        risk["authoritative"] = completeness["complete"]
        if not completeness["complete"]:
            risk["score"] = None
            risk["unavailable"] = unavailable("posture-incomplete", reasons=completeness["reasons"])
        severity_counts = {key: 0 for key in SEVERITY_WEIGHTS}
        for finding in projection["validated"]:
            severity = finding["severity"]
            severity_counts[severity if severity in severity_counts else "informational"] += 1
        executive = report.get("executive_summary") if isinstance(report, dict) and isinstance(report.get("executive_summary"), dict) else {}
        target_metadata = report.get("target_metadata") if isinstance(report, dict) and isinstance(report.get("target_metadata"), dict) else {}
        coverage = {
            "schema_version": "posture-coverage.v1",
            "available": completeness["checks"]["coverage_evidence"],
            "scanned_files": (resource or {}).get("scanned_files", executive.get("scanned_file_count")),
            "scanned_bytes": (resource or {}).get("scanned_bytes"),
            "language": (resource or {}).get("language") or target_metadata.get("dominant_language"),
            "scope": (resource or {}).get("scope"),
        }
        snapshot = {
            "schema_version": POSTURE_SCHEMA_VERSION,
            "run_id": str(run["job_id"]),
            "project_id": str(run["project_id"]),
            "created_at": str(run.get("finished_at") or run.get("created_at") or utc_now()),
            "source_digest": digest,
            "versions": {
                "completeness": COMPLETENESS_SCHEMA_VERSION,
                "risk_formula": RISK_FORMULA_VERSION,
                "fingerprint": FINGERPRINT_VERSION,
                "trend": TREND_SCHEMA_VERSION,
            },
            "availability": {
                "schema_version": UNAVAILABLE_SCHEMA_VERSION,
                "status": "available" if completeness["complete"] else "partial" if report else "unavailable",
                "reasons": list(completeness["reasons"]),
            },
            "run": self._run_summary(run),
            "repository": {
                "resolved_commit": run.get("resolved_commit") or executive.get("resolved_commit"),
                "languages": executive.get("languages") or target_metadata.get("languages") or {},
                "dependency_count": len(target_metadata.get("dependencies") or []),
            },
            "coverage": coverage,
            "findings": projection,
            "severity_counts": severity_counts,
            "risk": risk,
            "completeness": completeness,
            "quality": {
                **_runtime_quality(report, resource),
                "evidence_complete": completeness["checks"]["evidence_complete"],
                "validation_complete": completeness["checks"]["validation_complete"],
            },
            "trend": {},
        }
        earlier = self._earlier_snapshots(snapshot)
        self._set_snapshot_trend(snapshot, earlier)
        snapshot = redact_secrets(snapshot)
        self.workspace.upsert_posture_snapshot(snapshot)
        if completeness["complete"]:
            for finding in snapshot["findings"]["validated"]:
                self.workspace.upsert_finding_identity(
                    project_id=snapshot["project_id"],
                    fingerprint=finding["fingerprint"],
                    fingerprint_version=FINGERPRINT_VERSION,
                    run_id=snapshot["run_id"],
                    metadata={
                        "components": finding["components"],
                        "quality": finding["quality"],
                        "last_seen_at": snapshot["created_at"],
                    },
                )
        return snapshot

    def backfill_project(self, project_id: str) -> list[dict[str, Any]]:
        for run in self.workspace.list_job_records(project_id=project_id):
            if run.get("status") in TERMINAL_STATUSES:
                self.project_run(run)
        output: list[dict[str, Any]] = []
        for snapshot in self.workspace.list_posture_snapshots(project_id):
            self._set_snapshot_trend(snapshot, output)
            self.workspace.upsert_posture_snapshot(snapshot)
            output.append(snapshot)
        return output

    def dashboard(self, project: Project) -> dict[str, Any]:
        self.backfill_project(project.project_id)
        runs = self.workspace.list_job_records(project_id=project.project_id)
        snapshots = self.workspace.list_posture_snapshots(project.project_id)
        by_run = {item.get("run_id"): item for item in snapshots}
        latest_run = runs[-1] if runs else None
        latest_snapshot = by_run.get(latest_run.get("job_id")) if latest_run else None
        complete = [item for item in snapshots if item.get("completeness", {}).get("complete")]
        latest_complete = complete[-1] if complete else None
        if not runs:
            state = "no-runs"
        elif latest_complete and latest_run and latest_complete.get("run_id") != latest_run.get("job_id"):
            state = "stale-historical-posture"
        elif latest_complete:
            state = "complete"
        elif all(run.get("status") in {"queued", "running"} for run in runs):
            state = "running-only"
        else:
            state = "no-complete-posture"
        active_runs = [self._run_summary(run) for run in runs if run.get("status") in {"queued", "running"}]
        recent_runs = []
        for run in reversed(runs[-DASHBOARD_RECENT_RUN_LIMIT:]):
            snapshot = by_run.get(run["job_id"])
            recent_runs.append(
                {
                    "run": self._run_summary(run),
                    "posture_status": (
                        snapshot.get("availability", {}).get("status") if snapshot else "unavailable"
                    ),
                    "completeness": snapshot.get("completeness") if snapshot else unavailable("run-not-terminal"),
                    "risk_score": snapshot.get("risk", {}).get("score") if snapshot else None,
                    "confirmed_count": len(snapshot.get("findings", {}).get("validated", [])) if snapshot else None,
                    "trend_counts": snapshot.get("trend", {}).get("counts") if snapshot else None,
                }
            )
        trend_series = [
            {
                "run_id": item["run_id"],
                "created_at": item["created_at"],
                "complete": bool(item.get("completeness", {}).get("complete")),
                "risk_score": item.get("risk", {}).get("score"),
                "confirmed_count": len(item.get("findings", {}).get("validated", [])),
                "severity_counts": item.get("severity_counts", {}),
                "trend_counts": item.get("trend", {}).get("counts", {}),
                "comparison_status": item.get("trend", {}).get("comparison_status"),
            }
            for item in snapshots[-DASHBOARD_RECENT_RUN_LIMIT:]
        ]
        high_risk = list((latest_complete or {}).get("findings", {}).get("validated", []))
        high_risk.sort(
            key=lambda item: (
                SEVERITY_WEIGHTS.get(str(item.get("severity")), 0),
                _confidence(item.get("confidence"))["effective"],
            ),
            reverse=True,
        )
        for item in high_risk:
            item["run_url"] = (
                f"/projects/{quote(project.project_id, safe='')}/runs/"
                f"{quote(str(item.get('run_id') or latest_complete.get('run_id')), safe='')}"
                f"?finding={quote(str(item.get('finding_id') or ''), safe='')}"
            )
        return redact_secrets(
            {
                "schema_version": "project-security-dashboard.v1",
                "state": state,
                "project": {
                    "project_id": project.project_id,
                    "display_name": project.display_name,
                    "source_kind": project.source_kind,
                    "source": project.source,
                    "source_identity": project.source_identity,
                    "source_display": project.source_display,
                    "status": project.status,
                    "languages": project.languages,
                    "metadata": project.metadata,
                    "created_at": project.created_at,
                    "updated_at": project.updated_at,
                    "archived_at": project.archived_at,
                    "latest_run": self._run_summary(latest_run) if latest_run else None,
                },
                "latest_run": self._run_summary(latest_run) if latest_run else None,
                "latest_run_posture": latest_snapshot,
                "latest_complete_posture": latest_complete,
                "posture": latest_complete,
                "posture_is_historical": bool(
                    latest_complete and latest_run and latest_complete.get("run_id") != latest_run.get("job_id")
                ),
                "active_runs": active_runs,
                "recent_runs": recent_runs,
                "trend_series": trend_series,
                "high_risk_findings": high_risk[:DASHBOARD_HIGH_RISK_LIMIT],
                "limitations": (
                    latest_snapshot.get("completeness", {}).get("reasons", [])
                    if latest_snapshot
                    else ["no-terminal-posture"] if latest_run else ["no-runs"]
                ),
            }
        )

    def _earlier_snapshots(self, snapshot: dict[str, Any]) -> list[dict[str, Any]]:
        ordered_run_ids = [
            run["job_id"]
            for run in self.workspace.list_job_records(project_id=snapshot["project_id"])
        ]
        try:
            current_index = ordered_run_ids.index(snapshot["run_id"])
        except ValueError:
            return []
        earlier_ids = set(ordered_run_ids[:current_index])
        return [
            item
            for item in self.workspace.list_posture_snapshots(snapshot["project_id"])
            if item.get("run_id") in earlier_ids
        ]

    @staticmethod
    def _set_snapshot_trend(snapshot: dict[str, Any], earlier: list[dict[str, Any]]) -> None:
        snapshot["trend"] = classify_trend(snapshot, earlier)
        trend_by_fp = {
            finding["fingerprint"]: bucket
            for bucket, findings in snapshot["trend"]["findings"].items()
            for finding in findings
        }
        for finding in snapshot.get("findings", {}).get("validated", []):
            finding["trend_status"] = trend_by_fp.get(finding["fingerprint"], "unconfirmed")

    @staticmethod
    def _run_summary(run: dict[str, Any] | None) -> dict[str, Any] | None:
        if not run:
            return None
        return {
            key: run.get(key)
            for key in (
                "job_id",
                "project_id",
                "status",
                "phase",
                "created_at",
                "started_at",
                "finished_at",
                "requested_revision",
                "resolved_commit",
                "cleanup_status",
            )
        }

    @staticmethod
    def _read_artifact(run_dir: Path | None, name: str) -> tuple[dict[str, Any] | None, bytes]:
        if run_dir is None:
            return None, b""
        path = run_dir / "reports" / name
        if not path.is_file():
            return None, b""
        try:
            raw = path.read_bytes()
            payload = json.loads(raw.decode("utf-8"))
            return (payload if isinstance(payload, dict) else None), raw
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None, b""

    def _read_resource(self, run_dir: Path | None) -> tuple[dict[str, Any] | None, bytes]:
        for name in ("run-resource-summary-final.v1.json", "run-resource-summary.v1.json"):
            payload, raw = self._read_artifact(run_dir, name)
            if payload is not None:
                return payload, raw
        return None, b""

    @staticmethod
    def _source_digest(run: dict[str, Any], report: bytes, resource: bytes) -> str:
        digest = hashlib.sha256()
        digest.update(str(run.get("job_id") or "").encode("utf-8"))
        digest.update(str(run.get("status") or "").encode("utf-8"))
        digest.update(report or b"report-missing")
        digest.update(resource or b"resource-missing")
        return digest.hexdigest()
