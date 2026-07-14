from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

from .agent_led_runtime import provider_is_usable
from .config import AuditConfig
from .investigation_models import VerificationPlan
from .llm import build_llm_client
from .models import utc_now
from .pipeline import run_audit


BLINDSPOT_SCHEMA = "agent-led-blindspots.v1"
BLINDSPOT_REPORT_SCHEMA = "agent-led-blindspot-report.v1"
STABILITY_SCHEMA = "agent-led-real-model-stability.v1"
STABILITY_REPORT_SCHEMA = "agent-led-real-model-stability-report.v1"
SUPPORTED_CLASSES = {
    "sql-injection",
    "command-injection",
    "path-traversal",
    "hardcoded-secret",
}


def default_blindspot_manifest_path() -> Path:
    return Path(__file__).resolve().parent.parent / "benchmarks" / "agent_led_blindspots.v1.json"


def default_stability_manifest_path() -> Path:
    return Path(__file__).resolve().parent.parent / "benchmarks" / "agent_led_real_model_repos.v1.json"


def load_blindspot_manifest(path: str | Path) -> dict[str, Any]:
    manifest_path = Path(path).resolve()
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if set(payload) != {"schema_version", "cases"}:
        raise ValueError("blind-spot manifest must contain only schema_version and cases")
    if payload["schema_version"] != BLINDSPOT_SCHEMA:
        raise ValueError("unsupported blind-spot manifest schema")
    cases = payload["cases"]
    if not isinstance(cases, list) or len(cases) != 24:
        raise ValueError("blind-spot corpus must contain exactly 24 cases")
    expected_fields = {"id", "class", "family", "expected", "path"}
    ids: set[str] = set()
    distribution: dict[tuple[str, str], int] = {}
    for case in cases:
        if not isinstance(case, dict) or set(case) != expected_fields:
            raise ValueError("blind-spot case has unknown or missing fields")
        case_id = str(case["id"])
        if not case_id or case_id in ids:
            raise ValueError("blind-spot case IDs must be non-empty and unique")
        ids.add(case_id)
        vulnerability_class = str(case["class"])
        expected = str(case["expected"])
        if vulnerability_class not in SUPPORTED_CLASSES or expected not in {"vulnerable", "safe"}:
            raise ValueError("blind-spot case class or expected result is unsupported")
        if str(case["family"]) not in {"cross-file-wrapper", "indirect-call", "config-driven"}:
            raise ValueError("blind-spot family is unsupported")
        relative = str(case["path"]).replace("\\", "/")
        candidate = (manifest_path.parent / relative).resolve()
        try:
            candidate.relative_to(manifest_path.parent)
        except ValueError as exc:
            raise ValueError("blind-spot path escapes the manifest root") from exc
        if not candidate.is_file():
            raise ValueError(f"blind-spot fixture is missing: {relative}")
        distribution[(vulnerability_class, expected)] = distribution.get((vulnerability_class, expected), 0) + 1
    for vulnerability_class in sorted(SUPPORTED_CLASSES):
        if distribution.get((vulnerability_class, "vulnerable")) != 3:
            raise ValueError(f"{vulnerability_class} must have three vulnerable cases")
        if distribution.get((vulnerability_class, "safe")) != 3:
            raise ValueError(f"{vulnerability_class} must have three safe cases")
    return payload


def evaluate_blindspot_corpus(
    path: str | Path | None = None,
    *,
    config: AuditConfig | None = None,
    output_root: str | Path = "runs/agent-led-blindspots",
    execute_live: bool = False,
    audit_callable: Callable[..., dict[str, Any]] = run_audit,
) -> dict[str, Any]:
    """Run both modes through the public audit pipeline without exposing truth labels.

    Manifest labels are consumed only after both runs finish.  Each fixture is copied
    to a neutral ``case/app.py`` target, so case IDs, expected results, source line
    numbers, symbols, and fixture filenames cannot become Coordinator input.
    """
    manifest_path = Path(path or default_blindspot_manifest_path()).resolve()
    manifest = load_blindspot_manifest(manifest_path)
    selected = config or AuditConfig.default()
    reasons: list[str] = []
    if not execute_live:
        reasons.append("live-execution-not-requested")
    if execute_live and audit_callable is run_audit and not provider_is_usable(selected):
        reasons.append("real-model-provider-not-configured")
    if execute_live and selected.graph.mode != "agent-led":
        reasons.append("agent-led-mode-not-selected")
    if execute_live and (
        not selected.runtime_enabled
        or not selected.llm_decisions.enabled
        or "analysis" not in selected.llm_decisions.roles
    ):
        reasons.append("agent-analysis-role-not-enabled")
    if reasons:
        return {
            "schema_version": BLINDSPOT_REPORT_SCHEMA,
            "generated_at": utc_now(),
            "status": "deferred",
            "manifest": str(manifest_path),
            "reasons": sorted(set(reasons)),
            "case_count": len(manifest["cases"]),
            "cases": [],
            "gates": {},
            "passed": False,
        }

    started = time.monotonic()
    cases: list[dict[str, Any]] = []
    deterministic_positive_hits = 0
    promoted_positives = 0
    agent_candidate_positive_hits = 0
    confirmed_positives = 0
    safe_promotions = 0
    false_confirmed_safe = 0
    complete_promotions = 0
    scanner_no_signal_promotions = 0
    deterministic_duration_ms = 0.0
    agent_duration_ms = 0.0
    output_path = Path(output_root).resolve()
    output_path.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="agent-led-blindspots-") as temporary:
        staging_root = Path(temporary)
        for ordinal, case in enumerate(manifest["cases"]):
            neutral = staging_root / f"case-{ordinal:02d}"
            neutral.mkdir()
            shutil.copyfile(manifest_path.parent / str(case["path"]), neutral / "app.py")
            deterministic_config = deepcopy(selected)
            deterministic_config.graph.mode = "deterministic-graph"
            deterministic_config.runtime_enabled = False
            deterministic_config.llm_decisions.enabled = False
            deterministic_started = time.monotonic()
            deterministic_summary = audit_callable(str(neutral), deterministic_config, output_path / "deterministic")
            deterministic_duration_ms += (time.monotonic() - deterministic_started) * 1000
            deterministic = _collect_blindspot_run(deterministic_summary, str(case["class"]))

            agent_config = deepcopy(selected)
            agent_config.graph.mode = "agent-led"
            agent_started = time.monotonic()
            agent_summary = audit_callable(str(neutral), agent_config, output_path / "agent-led")
            agent_duration_ms += (time.monotonic() - agent_started) * 1000
            agent = _collect_blindspot_run(agent_summary, str(case["class"]))
            if agent_summary.get("effective_mode") != "agent-led":
                raise RuntimeError("blind-spot benchmark did not execute AgentLedInvestigationCoordinator")

            expected_vulnerable = case["expected"] == "vulnerable"
            deterministic_positive_hits += int(expected_vulnerable and deterministic["candidate"])
            agent_candidate_positive_hits += int(expected_vulnerable and agent["candidate"])
            promoted_positives += int(expected_vulnerable and agent["promoted"])
            confirmed_positives += int(expected_vulnerable and agent["confirmed"])
            safe_promotions += int(not expected_vulnerable and agent["promoted"])
            false_confirmed_safe += int(not expected_vulnerable and agent["confirmed"])
            complete_promotions += int(expected_vulnerable and agent["promoted"] and agent["evidence_complete"])
            scanner_no_signal_promotions += int(
                expected_vulnerable and not deterministic["candidate"] and agent["promoted"]
            )
            cases.append(
                {
                    "id": case["id"],
                    "class": case["class"],
                    "family": case["family"],
                    "expected": case["expected"],
                    "deterministic": deterministic,
                    "agent_led": agent,
                    "deterministic_run_dir": deterministic_summary.get("run_dir"),
                    "agent_led_run_dir": agent_summary.get("run_dir"),
                }
            )

    positive_count = sum(item["expected"] == "vulnerable" for item in manifest["cases"])
    safe_count = sum(item["expected"] == "safe" for item in manifest["cases"])
    deterministic_recall = deterministic_positive_hits / positive_count
    agent_recall = agent_candidate_positive_hits / positive_count
    recall_delta = agent_recall - deterministic_recall
    elapsed_seconds = time.monotonic() - started
    latency_limit_seconds = max(60.0, (deterministic_duration_ms / 1000.0) * 3.0)
    budget_limits = {
        "max_hypotheses": len(manifest["cases"]) * selected.investigation.max_hypotheses,
        "max_tool_calls_per_hypothesis": selected.investigation.max_tool_calls_per_hypothesis,
        "max_llm_requests": len(manifest["cases"]) * selected.investigation.request_budget,
        "max_llm_tokens": len(manifest["cases"]) * selected.investigation.token_budget,
        "absolute_timeout_seconds": len(manifest["cases"]) * selected.investigation.absolute_timeout_seconds,
    }
    used_budgets = [item["agent_led"]["budget"] for item in cases]
    budget_used = {
        "hypotheses": sum(int(item.get("hypotheses", 0)) for item in used_budgets),
        "tool_calls": sum(int(item.get("tool_calls", 0)) for item in used_budgets),
        "llm_requests": sum(int(item.get("llm_requests", 0)) for item in used_budgets),
        "llm_tokens": sum(int(item.get("llm_tokens", 0)) for item in used_budgets),
        "elapsed_seconds": round(elapsed_seconds, 6),
    }
    gates = {
        "reviewed_24_case_shape": len(cases) == 24 and positive_count == 12 and safe_count == 12,
        "recall_delta_at_least_0_30": recall_delta >= 0.30,
        "zero_safe_false_confirmation": false_confirmed_safe == 0,
        "scanner_no_signal_promotion": scanner_no_signal_promotions >= 1,
        "complete_promoted_evidence": complete_promotions == promoted_positives,
        "latency_within_limit": elapsed_seconds <= latency_limit_seconds,
        "hard_budgets_respected": (
            budget_used["llm_requests"] <= budget_limits["max_llm_requests"]
            and budget_used["llm_tokens"] <= budget_limits["max_llm_tokens"]
            and elapsed_seconds <= budget_limits["absolute_timeout_seconds"]
        ),
        "agent_led_model_and_accounting": all(
            item["agent_led"]["llm_requests"] > 0 and item["agent_led"]["accounting_complete"]
            for item in cases
        ),
    }
    return {
        "schema_version": BLINDSPOT_REPORT_SCHEMA,
        "generated_at": utc_now(),
        "status": "passed" if all(gates.values()) else "failed",
        "manifest": str(manifest_path),
        "case_count": len(cases),
        "positive_count": positive_count,
        "safe_count": safe_count,
        "deterministic": {
            "positive_hits": deterministic_positive_hits,
            "recall": deterministic_recall,
            "duration_ms": deterministic_duration_ms,
        },
        "agent_led": {
            "candidate_positive_hits": agent_candidate_positive_hits,
            "promoted_positives": promoted_positives,
            "confirmed_positives": confirmed_positives,
            "safe_promotions": safe_promotions,
            "false_confirmed_safe": false_confirmed_safe,
            "recall": agent_recall,
            "scanner_no_signal_promotions": scanner_no_signal_promotions,
            "complete_promotions": complete_promotions,
            "duration_ms": agent_duration_ms,
        },
        "recall_delta": recall_delta,
        "latency_limit_seconds": latency_limit_seconds,
        "budgets": {"limits": budget_limits, "used": budget_used},
        "gates": gates,
        "passed": all(gates.values()),
        "cases": cases,
    }


def _collect_blindspot_run(summary: dict[str, Any], vulnerability_class: str) -> dict[str, Any]:
    run_dir = Path(str(summary.get("run_dir") or ""))
    report = _load_json_ref(summary.get("report_ref"))
    findings = report.get("findings", []) if isinstance(report, dict) else []
    matching = [item for item in findings if item.get("vulnerability_class") == vulnerability_class]
    candidates: list[dict[str, Any]] = []
    if run_dir.is_dir():
        for candidate_path in sorted((run_dir / "findings").glob("candidates*.json")):
            payload = json.loads(candidate_path.read_text(encoding="utf-8"))
            if isinstance(payload, list):
                candidates.extend(item for item in payload if isinstance(item, dict))
    matching_candidates = [item for item in candidates if item.get("vulnerability_class") == vulnerability_class]
    promoted = [item for item in matching if str(item.get("verification_status", "")).lower() != "rejected"]
    confirmed = [item for item in matching if str(item.get("verification_status", "")).lower() == "confirmed"]
    chain_ids = {
        str(item.get("id"))
        for item in report.get("evidence_chains", [])
        if isinstance(item, dict) and item.get("id")
    }
    evidence_complete = any(
        bool((item.get("metadata") or {}).get("evidence_package_ref"))
        and bool((item.get("metadata") or {}).get("verification_plan_ref"))
        and str(item.get("evidence_chain_id") or "") in chain_ids
        and bool((item.get("metadata") or {}).get("validation_summary"))
        for item in promoted
    )
    resource = _load_json_ref(summary.get("resource_summary_ref"))
    budget = dict(summary.get("investigation_budget") or {})
    used = dict(budget.get("used") or {})
    llm_requests = int(used.get("requests", used.get("llm_requests", 0)) or 0)
    llm_tokens = int(used.get("tokens", used.get("llm_tokens", 0)) or 0)
    return {
        "candidate": bool(matching_candidates or matching),
        "promoted": bool(promoted),
        "confirmed": bool(confirmed),
        "evidence_complete": evidence_complete,
        "llm_requests": llm_requests,
        "accounting_complete": bool(
            resource.get("ledger_present") is True
            and resource.get("llm_reconciliation_status") == "complete"
            and not resource.get("llm_gap_ids")
        ),
        "budget": {
            "hypotheses": int(used.get("hypotheses", 0) or 0),
            "tool_calls": int(used.get("tool_calls", 0) or 0),
            "llm_requests": llm_requests,
            "llm_tokens": llm_tokens,
        },
    }


def load_stability_manifest(path: str | Path) -> dict[str, Any]:
    manifest_path = Path(path).resolve()
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = {"schema_version", "repetitions", "targets", "safety"}
    if set(payload) != expected or payload["schema_version"] != STABILITY_SCHEMA:
        raise ValueError("unsupported or malformed real-model stability manifest")
    if payload["repetitions"] != 3 or not isinstance(payload["targets"], list) or len(payload["targets"]) != 3:
        raise ValueError("real-model stability manifest requires three targets and three repetitions")
    target_fields = {"id", "source", "commit", "local_path"}
    ids: set[str] = set()
    for target in payload["targets"]:
        if not isinstance(target, dict) or set(target) != target_fields:
            raise ValueError("stability target has unknown or missing fields")
        if target["id"] in ids:
            raise ValueError("stability target IDs must be unique")
        ids.add(target["id"])
        commit = str(target["commit"]).lower()
        if len(commit) not in {40, 64} or any(char not in "0123456789abcdef" for char in commit):
            raise ValueError("stability targets require full 40/64 character commits")
        if not str(target["source"]).startswith("https://github.com/"):
            raise ValueError("stability targets must use canonical GitHub HTTPS sources")
        local = (manifest_path.parent.parent / str(target["local_path"])).resolve()
        if not local.is_dir():
            raise ValueError(f"stability target checkout is unavailable: {target['local_path']}")
    required_safety = {
        "target_writes": False,
        "target_network": False,
        "project_execution": False,
        "model_code_authority": False,
        "provider_api": True,
    }
    if payload["safety"] != required_safety:
        raise ValueError("stability safety policy must match the fixed defensive profile")
    return payload


def run_real_model_stability(
    config: AuditConfig,
    *,
    manifest_path: str | Path | None = None,
    output_root: str | Path = "runs/agent-led-stability",
    execute_live: bool = False,
    audit_callable: Callable[..., dict[str, Any]] = run_audit,
) -> dict[str, Any]:
    selected_manifest = Path(manifest_path or default_stability_manifest_path()).resolve()
    manifest = load_stability_manifest(selected_manifest)
    preflight_errors = _stability_preflight(config, manifest, selected_manifest)
    if not execute_live or preflight_errors:
        reasons = list(preflight_errors)
        if not execute_live:
            reasons.append("live-execution-not-requested")
        return {
            "schema_version": STABILITY_REPORT_SCHEMA,
            "generated_at": utc_now(),
            "status": "deferred",
            "manifest": str(selected_manifest),
            "provider": config.llm.provider,
            "model": config.llm.model,
            "reasons": sorted(set(reasons)),
            "records": [],
            "gates": {},
            "passed": False,
        }

    records: list[dict[str, Any]] = []
    output_path = Path(output_root).resolve()
    output_path.mkdir(parents=True, exist_ok=True)
    for repetition in range(1, manifest["repetitions"] + 1):
        for target in manifest["targets"]:
            checkout = (selected_manifest.parent.parent / target["local_path"]).resolve()
            before_digest = _tree_digest(checkout)
            before_head = _git_head(checkout)
            old_environment = {
                name: os.environ.get(name)
                for name in ("AUDIT_BENCHMARK_CASE_ID", "AUDIT_BENCHMARK_PROJECT_ID", "AUDIT_BENCHMARK_EXPECTED_COMMIT")
            }
            os.environ["AUDIT_BENCHMARK_CASE_ID"] = f"{target['id']}-rep-{repetition}"
            os.environ["AUDIT_BENCHMARK_PROJECT_ID"] = str(target["id"])
            os.environ["AUDIT_BENCHMARK_EXPECTED_COMMIT"] = str(target["commit"])
            try:
                summary = audit_callable(str(checkout), config, output_path)
            finally:
                for name, value in old_environment.items():
                    if value is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = value
            after_digest = _tree_digest(checkout)
            after_head = _git_head(checkout)
            report = _load_json_ref(summary.get("report_ref"))
            resource = _load_json_ref(summary.get("resource_summary_ref"))
            plan_authority_ok = _verification_plans_are_typed(summary.get("verification_plan_refs", []))
            normalized = _normalized_confirmed_high_critical(report)
            safety = resource.get("safety", {}) if isinstance(resource, dict) else {}
            accounting_ok = bool(
                resource
                and resource.get("ledger_present") is True
                and resource.get("llm_reconciliation_status") == "complete"
                and not resource.get("llm_gap_ids")
            )
            records.append(
                {
                    "target_id": target["id"],
                    "repetition": repetition,
                    "run_dir": summary.get("run_dir"),
                    "terminal_status": summary.get("status", "succeeded"),
                    "requested_mode": summary.get("requested_mode"),
                    "effective_mode": summary.get("effective_mode"),
                    "resolved_commit": summary.get("resolved_commit"),
                    "normalized_high_critical": normalized,
                    "target_integrity_ok": before_digest == after_digest and before_head == after_head == target["commit"],
                    "safety_ok": bool(
                        safety.get("target_writes") is False
                        and safety.get("network") is False
                        and safety.get("project_execution") is False
                    ),
                    "plan_authority_ok": plan_authority_ok,
                    "accounting_ok": accounting_ok,
                    "resource_summary_ref": summary.get("resource_summary_ref"),
                    "report_ref": summary.get("report_ref"),
                }
            )
    evaluated = evaluate_stability_records(
        records,
        target_ids=[str(item["id"]) for item in manifest["targets"]],
        repetitions=int(manifest["repetitions"]),
    )
    report = {
        "schema_version": STABILITY_REPORT_SCHEMA,
        "generated_at": utc_now(),
        "status": "passed" if evaluated["passed"] else "failed",
        "manifest": str(selected_manifest),
        "provider": config.llm.provider,
        "model": config.llm.model,
        "reasons": [],
        **evaluated,
    }
    _write_json(output_path / "agent-led-real-model-stability-report.v1.json", report)
    return report


def evaluate_stability_records(
    records: list[dict[str, Any]], *, target_ids: list[str], repetitions: int
) -> dict[str, Any]:
    expected_count = len(target_ids) * repetitions
    stable_by_target: dict[str, bool] = {}
    for target_id in target_ids:
        target_records = sorted(
            [item for item in records if item.get("target_id") == target_id],
            key=lambda item: int(item.get("repetition", 0)),
        )
        normalized = [
            json.dumps(item.get("normalized_high_critical", []), ensure_ascii=False, sort_keys=True)
            for item in target_records
        ]
        stable_by_target[target_id] = len(target_records) == repetitions and len(set(normalized)) == 1
    gates = {
        "complete_three_by_three_matrix": len(records) == expected_count,
        "normalized_high_critical_stable": bool(stable_by_target) and all(stable_by_target.values()),
        "at_least_one_expected_high_critical_confirmed": any(
            bool(item.get("normalized_high_critical")) for item in records
        ),
        "target_integrity_preserved": bool(records) and all(item.get("target_integrity_ok") is True for item in records),
        "target_network_and_execution_blocked": bool(records) and all(item.get("safety_ok") is True for item in records),
        "typed_plan_authority_preserved": bool(records) and all(item.get("plan_authority_ok") is True for item in records),
        "accounting_complete": bool(records) and all(item.get("accounting_ok") is True for item in records),
        "agent_led_effective": bool(records) and all(
            item.get("terminal_status") == "succeeded" and item.get("effective_mode") == "agent-led"
            for item in records
        ),
    }
    return {
        "record_count": len(records),
        "stable_by_target": stable_by_target,
        "records": records,
        "gates": gates,
        "passed": all(gates.values()),
    }


def _stability_preflight(config: AuditConfig, manifest: dict[str, Any], manifest_path: Path) -> list[str]:
    reasons: list[str] = []
    if not provider_is_usable(config) or str(config.llm.provider).lower() == "mock":
        reasons.append("real-model-provider-not-configured")
    else:
        try:
            build_llm_client(config.llm)
        except Exception as exc:
            reasons.append(f"provider-preflight:{type(exc).__name__}")
    if not config.runtime_enabled:
        reasons.append("runtime-not-enabled")
    if config.graph.mode != "agent-led":
        reasons.append("agent-led-mode-not-selected")
    if not config.llm_decisions.enabled or not {"analysis", "verification"}.issubset(set(config.llm_decisions.roles)):
        reasons.append("agent-decision-roles-not-enabled")
    if (
        not config.sandbox.enabled
        or str(config.sandbox.runner).lower() != "docker"
        or str(config.sandbox.network).lower() != "none"
        or config.default_validation_level != "sandbox"
    ):
        reasons.append("bounded-docker-sandbox-not-configured")
    if config.tool_permissions.live_network_validation:
        reasons.append("live-network-validation-forbidden")
    for target in manifest["targets"]:
        checkout = (manifest_path.parent.parent / target["local_path"]).resolve()
        if _git_head(checkout) != target["commit"]:
            reasons.append(f"target-commit-mismatch:{target['id']}")
        if _git_dirty(checkout):
            reasons.append(f"target-dirty:{target['id']}")
    return reasons


def _git_head(path: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            shell=False,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = result.stdout.strip().lower()
    return value if result.returncode == 0 and len(value) in {40, 64} else None


def _git_dirty(path: Path) -> bool:
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "status", "--porcelain", "--untracked-files=no"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            shell=False,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return True
    return result.returncode != 0 or bool(result.stdout.strip())


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file() and ".git" not in item.parts):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _load_json_ref(value: Any) -> dict[str, Any]:
    if not value:
        return {}
    path = Path(str(value))
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def _verification_plans_are_typed(refs: list[str]) -> bool:
    if not refs:
        return False
    for ref in refs:
        path = Path(ref)
        if not path.is_file():
            return False
        try:
            VerificationPlan.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return False
    return True


def _normalized_confirmed_high_critical(report: dict[str, Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for finding in report.get("findings", []) if isinstance(report, dict) else []:
        if str(finding.get("severity", "")).lower() not in {"high", "critical"}:
            continue
        if str(finding.get("verification_status", "")).lower() != "confirmed":
            continue
        location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
        normalized.append(
            {
                "class": finding.get("vulnerability_class"),
                "severity": str(finding.get("severity", "")).lower(),
                "path": str(location.get("path", "")).replace("\\", "/"),
                "line": int(location.get("start_line", 0) or 0),
            }
        )
    return sorted(normalized, key=lambda item: (item["class"] or "", item["path"], item["line"], item["severity"]))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)
