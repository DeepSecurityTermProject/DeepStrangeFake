from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .investigation_models import (
    EvidenceGateDecision,
    EvidenceItem,
    InvestigationHypothesis,
    PROMOTING_CORROBORATORS,
    SecuritySignal,
    VerificationEvidencePackage,
)
from .investigation_tools import InvestigationToolError, RepositoryView
from .models import Finding, SourceLocation, stable_id


SEVERITY_BY_CLASS = {
    "sql-injection": "high",
    "command-injection": "high",
    "path-traversal": "medium",
    "hardcoded-secret": "medium",
}
TITLE_BY_CLASS = {
    "sql-injection": "Potential SQL injection",
    "command-injection": "Potential command injection",
    "path-traversal": "Potential path traversal",
    "hardcoded-secret": "Potential hardcoded secret",
}
REMEDIATION_BY_CLASS = {
    "sql-injection": "Use parameterized queries and avoid dynamic SQL construction.",
    "command-injection": "Use fixed argv arrays and strict allowlists; do not invoke a shell with user input.",
    "path-traversal": "Resolve paths under a trusted base and reject results outside that root.",
    "hardcoded-secret": "Move secrets to managed configuration and rotate exposed credentials.",
}
NON_PROMOTING_ORIGINS = {"pattern", "lexical-memory", "model", "cve", "tool-error"}


@dataclass
class EvidenceGateResult:
    decision: EvidenceGateDecision
    finding: Finding | None = None
    evidence_package: VerificationEvidencePackage | None = None


class EvidenceGate:
    """Trusted deterministic promotion gate; no model output can bypass it."""

    def __init__(self, view: RepositoryView):
        self.view = view

    def evaluate(self, hypothesis: InvestigationHypothesis) -> EvidenceGateResult:
        local: list[EvidenceItem] = []
        corroborating: list[EvidenceItem] = []
        counterevidence: list[EvidenceItem] = []
        invalid_refs: list[str] = []

        for item in hypothesis.evidence:
            if item.counterevidence or self._looks_safe(hypothesis.vulnerability_class, item):
                counterevidence.append(item)
                continue
            if self._valid_local(item):
                if item.origin in {"source", "pattern"}:
                    local.append(item)
                if self._is_independent_corroborator(item, local):
                    corroborating.append(item)
            elif item.origin not in NON_PROMOTING_ORIGINS:
                invalid_refs.append(item.evidence_id)

        # A trusted corroborator can also be the exact local evidence. Ensure a
        # separate exact source slice exists in the normative package.
        if not local:
            for item in hypothesis.evidence:
                if item.origin in PROMOTING_CORROBORATORS and self._valid_local(item):
                    try:
                        local.append(
                            self.view.source_evidence(
                                item.path or "",
                                item.start_line or 1,
                                item.end_line,
                                origin="source",
                                vulnerability_class=hypothesis.vulnerability_class,
                                message="trusted exact source materialization for evidence gate",
                            )
                        )
                    except InvestigationToolError:
                        pass
                    break

        # Re-evaluate source-origin corroboration now that local identity is known.
        corroborating = [
            item
            for item in hypothesis.evidence
            if self._valid_local(item) and self._is_independent_corroborator(item, local)
        ]
        corroborating = _dedupe_evidence(corroborating)
        local = _dedupe_evidence(local)
        counterevidence = _dedupe_evidence(counterevidence)

        predicates = {
            "supported_class": hypothesis.vulnerability_class in SEVERITY_BY_CLASS,
            "exact_local_source": bool(local),
            "independent_corroboration": bool(corroborating),
            "no_counterevidence": not bool(counterevidence),
            "no_scope_or_drift_error": not bool(invalid_refs),
        }
        reasons: list[str] = []
        if not predicates["exact_local_source"]:
            reasons.append("missing-exact-local-source")
        if not predicates["independent_corroboration"]:
            reasons.append("missing-independent-corroboration")
        if counterevidence:
            reasons.append("class-specific-counterevidence")
        if invalid_refs:
            reasons.append("scope-drift-or-unreadable-evidence")

        if counterevidence or invalid_refs:
            state = "rejected"
        elif not local or not corroborating:
            state = "refine" if hypothesis.round_count > 0 else "rejected"
        else:
            state = "promoted"

        candidate_id = None
        finding = None
        package = None
        if state == "promoted":
            primary = local[0]
            candidate_id = stable_id(
                "F",
                hypothesis.vulnerability_class,
                primary.path,
                primary.start_line,
                primary.content_hash,
            )
            finding = Finding(
                id=candidate_id,
                vulnerability_class=hypothesis.vulnerability_class,
                severity=SEVERITY_BY_CLASS[hypothesis.vulnerability_class],
                confidence=min(max(hypothesis.confidence, 0.55), 0.95),
                location=SourceLocation(
                    path=primary.path or "",
                    start_line=primary.start_line or 1,
                    end_line=primary.end_line or primary.start_line or 1,
                    snippet=primary.excerpt,
                ),
                title=TITLE_BY_CLASS[hypothesis.vulnerability_class],
                description=hypothesis.claim,
                evidence=[item.excerpt or item.message for item in [*local, *corroborating]],
                remediation=REMEDIATION_BY_CLASS[hypothesis.vulnerability_class],
                call_path=_call_path(corroborating),
                tool_refs=[item.artifact_ref or item.evidence_id for item in corroborating],
                metadata={
                    "decision_source": "agent-led-evidence-gate",
                    "hypothesis_id": hypothesis.hypothesis_id,
                    "local_evidence_refs": [item.evidence_id for item in local],
                    "corroboration_refs": [item.evidence_id for item in corroborating],
                    "content_hash": primary.content_hash,
                    "dataflow_trace_refs": [
                        item.artifact_ref for item in corroborating if item.origin == "dataflow" and item.artifact_ref
                    ],
                },
            )
            package = VerificationEvidencePackage(
                run_id=hypothesis.run_id,
                hypothesis_id=hypothesis.hypothesis_id or "",
                candidate_id=candidate_id,
                vulnerability_class=hypothesis.vulnerability_class,
                claim=hypothesis.claim,
                severity=finding.severity,
                local_evidence=local,
                corroborating_evidence=corroborating,
                counterevidence=counterevidence,
                scope={
                    "repository_root_hash": stable_id("ROOT", str(self.view.root), sorted(self.view.allowed)),
                    "target_paths": list(hypothesis.target_paths),
                },
            )

        decision = EvidenceGateDecision(
            run_id=hypothesis.run_id,
            hypothesis_id=hypothesis.hypothesis_id or "",
            state=state,
            predicate_results=predicates,
            reasons=reasons or ["trusted-dual-evidence-satisfied"],
            local_evidence_refs=[item.evidence_id for item in local],
            corroboration_refs=[item.evidence_id for item in corroborating],
            counterevidence_refs=[item.evidence_id for item in counterevidence],
            candidate_id=candidate_id,
        )
        return EvidenceGateResult(decision=decision, finding=finding, evidence_package=package)

    def _valid_local(self, item: EvidenceItem) -> bool:
        if not item.success or not item.path or not item.start_line or not item.content_hash:
            return False
        try:
            relative, _text, current_hash = self.view.read(item.path)
            if current_hash != item.content_hash or relative != item.path.replace("\\", "/"):
                return False
            current = self.view.source_evidence(
                relative,
                item.start_line,
                item.end_line,
                origin="source",
            )
        except (OSError, InvestigationToolError):
            return False
        expected_line = _line_for_number(item.excerpt, item.start_line)
        current_line = _line_for_number(current.excerpt, item.start_line)
        return not expected_line or expected_line == current_line

    @staticmethod
    def _is_independent_corroborator(item: EvidenceItem, local: list[EvidenceItem]) -> bool:
        if item.origin not in PROMOTING_CORROBORATORS:
            return False
        if item.origin in {"independent-source", "config", "manifest"}:
            return all(item.source_identity != source.source_identity for source in local)
        # Dataflow/call graph/SAST are independent analysis origins even if the
        # terminal observation points at the same sink line.
        return True

    @staticmethod
    def _looks_safe(vulnerability_class: str, item: EvidenceItem) -> bool:
        material = f"{item.excerpt} {item.message}".lower()
        if vulnerability_class == "sql-injection":
            return bool(
                re.search(
                    r"execute\s*\(\s*[^,\r\n()]+,\s*(?:\(|\[|\{|[a-z_])",
                    material,
                )
                or "parameterized" in material
                or "sanitized-flow" in material
            )
        if vulnerability_class == "command-injection":
            return "shell=false" in material or "shell = false" in material or "allowlist" in material
        if vulnerability_class == "path-traversal":
            return any(token in material for token in ("is_relative_to", "commonpath", "safe_root", "resolve()"))
        if vulnerability_class == "hardcoded-secret":
            return any(token in material for token in ("example", "fixture", "test token", "dummy", "placeholder", "os.environ", "process.env"))
        return False


def signal_to_evidence(signal: SecuritySignal) -> EvidenceItem:
    return EvidenceItem(
        evidence_id=signal.signal_id or stable_id("EVI", signal.path, signal.line),
        origin="pattern",
        path=signal.path,
        start_line=signal.line,
        end_line=signal.line,
        excerpt=signal.excerpt,
        content_hash=signal.content_hash,
        source_identity=stable_id("SRC", signal.path, signal.line, signal.line, signal.content_hash),
        vulnerability_class=signal.vulnerability_class,
        artifact_ref=signal.observation_ref,
        message="lightweight pattern signal",
    )


def _strip_line_numbers(value: str) -> list[str]:
    return [re.sub(r"^\s*\d+:\s?", "", line).rstrip() for line in value.splitlines()]


def _line_for_number(value: str, line_number: int) -> str:
    prefix = re.compile(rf"^\s*{line_number}:\s?(.*)$")
    for line in value.splitlines():
        match = prefix.match(line)
        if match:
            return match.group(1).rstrip()
    stripped = _strip_line_numbers(value)
    return stripped[0] if len(stripped) == 1 else ""


def _dedupe_evidence(items: list[EvidenceItem]) -> list[EvidenceItem]:
    output: list[EvidenceItem] = []
    seen: set[tuple[str, str, str]] = set()
    for item in items:
        key = (item.origin, item.source_identity, item.artifact_ref or "")
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def _call_path(items: list[EvidenceItem]) -> list[str]:
    path: list[str] = []
    for item in items:
        edge = item.raw.get("edge") if isinstance(item.raw, dict) else None
        if not isinstance(edge, dict):
            continue
        path.append(f"{edge.get('caller_id')}->{edge.get('callee_name')}@{edge.get('path')}:{edge.get('line')}")
    return path
