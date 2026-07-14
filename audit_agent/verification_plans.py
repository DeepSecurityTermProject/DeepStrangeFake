from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import AuditConfig
from .investigation_models import (
    PRIMITIVES_BY_CLASS,
    VerificationEvidencePackage,
    VerificationPlan,
    VerificationPrimitiveCall,
)
from .investigation_tools import InvestigationToolError, RepositoryView
from .models import Finding, ValidationResult, VerificationDecision, stable_id, to_plain, utc_now
from .storage import immutable_path
from .verification import VerificationEngine, VerificationStatus


PRIMITIVE_PARAMETER_SCHEMAS = {
    "sql.sqlite-parameter-binding": {
        "required": {"path", "line", "mode"},
        "optional": set(),
    },
    "command.argv-marker": {
        "required": {"path", "line", "sink"},
        "optional": set(),
    },
    "path.safe-root-boundary": {
        "required": {"path", "line", "transform"},
        "optional": set(),
    },
    "secret.static-semantic": {
        "required": {"path", "line"},
        "optional": {"minimum_length", "minimum_entropy"},
    },
}


@dataclass
class CompiledVerification:
    plan: VerificationPlan
    finding: Finding
    decision: VerificationDecision
    artifact_ref: str
    verification_type: str
    compiler_rules: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


class VerificationPrimitiveRegistry:
    def validate(self, vulnerability_class: str, call: VerificationPrimitiveCall, view: RepositoryView) -> None:
        if call.primitive_id not in PRIMITIVES_BY_CLASS.get(vulnerability_class, set()):
            raise ValueError("verification primitive is not registered for the vulnerability class")
        schema = PRIMITIVE_PARAMETER_SCHEMAS[call.primitive_id]
        keys = set(call.parameters)
        missing = schema["required"] - keys
        unknown = keys - schema["required"] - schema["optional"]
        if missing:
            raise ValueError(f"verification primitive missing parameters: {sorted(missing)}")
        if unknown:
            raise ValueError(f"verification primitive has unknown parameters: {sorted(unknown)}")
        path = str(call.parameters["path"])
        view.resolve(path)
        line = call.parameters["line"]
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            raise ValueError("verification primitive line must be a positive integer")
        if "mode" in call.parameters and call.parameters["mode"] not in {"vulnerable", "parameterized"}:
            raise ValueError("SQL verification mode must be vulnerable or parameterized")
        if "sink" in call.parameters and call.parameters["sink"] not in {
            "os.system", "subprocess", "child_process", "runtime-exec"
        }:
            raise ValueError("command verification sink is not registered")
        if "transform" in call.parameters and call.parameters["transform"] not in {
            "join", "resolve", "open", "send-file"
        }:
            raise ValueError("path verification transform is not registered")
        if "minimum_length" in call.parameters:
            value = call.parameters["minimum_length"]
            if isinstance(value, bool) or not isinstance(value, int) or not 8 <= value <= 128:
                raise ValueError("secret minimum_length must be in 8..128")
        if "minimum_entropy" in call.parameters:
            value = call.parameters["minimum_entropy"]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 1.0 <= float(value) <= 6.0:
                raise ValueError("secret minimum_entropy must be in 1.0..6.0")


class TrustedVerificationCompiler:
    """Compiles model-selected primitive IDs; never compiles model-authored code."""

    def __init__(
        self,
        config: AuditConfig,
        view: RepositoryView,
        run_dir: str | Path,
        *,
        registry: VerificationPrimitiveRegistry | None = None,
    ):
        self.config = config
        self.view = view
        self.run_dir = Path(run_dir)
        self.registry = registry or VerificationPrimitiveRegistry()

    def default_plan(
        self,
        package: VerificationEvidencePackage,
        evidence_package_ref: str,
    ) -> VerificationPlan:
        primary = package.local_evidence[0]
        primitive_id = next(iter(PRIMITIVES_BY_CLASS[package.vulnerability_class]))
        parameters: dict[str, Any] = {
            "path": primary.path,
            "line": primary.start_line,
        }
        if primitive_id == "sql.sqlite-parameter-binding":
            parameters["mode"] = "parameterized" if _package_has_sanitized_flow(package) else "vulnerable"
        elif primitive_id == "command.argv-marker":
            parameters["sink"] = _command_sink(primary.excerpt)
        elif primitive_id == "path.safe-root-boundary":
            parameters["transform"] = _path_transform(primary.excerpt)
        elif primitive_id == "secret.static-semantic":
            parameters.update({"minimum_length": 8, "minimum_entropy": 2.5})
        return VerificationPlan(
            run_id=package.run_id,
            candidate_id=package.candidate_id,
            vulnerability_class=package.vulnerability_class,
            evidence_package_ref=evidence_package_ref,
            primitives=[
                VerificationPrimitiveCall(
                    primitive_id=primitive_id,
                    parameters=parameters,
                    expected_observations=[_expected_observation(primitive_id)],
                    evidence_refs=[
                        item.evidence_id for item in [*package.local_evidence, *package.corroborating_evidence]
                    ],
                )
            ],
            confidence=0.85,
            rationale="Trusted default plan selected from the promoted normative evidence package.",
        )

    def compile(
        self,
        plan: VerificationPlan,
        package: VerificationEvidencePackage,
        finding: Finding,
    ) -> CompiledVerification:
        if plan.candidate_id != package.candidate_id or finding.id != package.candidate_id:
            raise ValueError("verification plan candidate does not match evidence package")
        if plan.vulnerability_class != package.vulnerability_class or finding.vulnerability_class != package.vulnerability_class:
            raise ValueError("verification class mismatch")
        if plan.evidence_package_ref != (finding.metadata.get("evidence_package_ref") or plan.evidence_package_ref):
            raise ValueError("verification evidence package ref mismatch")
        normative_refs = {
            item.evidence_id for item in [*package.local_evidence, *package.corroborating_evidence]
        }
        rules = ["class-compatible", "normative-evidence-only", "registered-primitives-only"]
        for call in plan.primitives:
            self.registry.validate(plan.vulnerability_class, call, self.view)
            if not set(call.evidence_refs).issubset(normative_refs):
                raise ValueError("verification plan cites non-normative evidence")
            current = self.view.source_evidence(
                str(call.parameters["path"]), int(call.parameters["line"]), origin="source"
            )
            matching = [
                item
                for item in package.local_evidence
                if item.path == current.path and item.start_line == current.start_line
            ]
            if not matching or any(item.content_hash != current.content_hash for item in matching):
                raise ValueError("verification plan source evidence is stale")
            self._validate_semantic_parameters(call, package, current.excerpt)
        self._attach_plan_metadata(finding, plan, package)
        verification_type = (
            "static-semantic"
            if plan.vulnerability_class == "hardcoded-secret"
            else "sandbox-primitive"
        )
        validation_level = "static-only" if verification_type == "static-semantic" else "sandbox"
        if verification_type == "sandbox-primitive" and not self.config.sandbox.enabled:
            validation_level = "manual"
        decision = VerificationDecision(
            finding=finding,
            decision="accept",
            reason="Trusted compiler accepted a registered verification plan.",
            confidence=plan.confidence,
            validation_level=validation_level,
            priority="high" if finding.severity in {"critical", "high"} else "normal",
            decision_source="trusted-verification-compiler",
            policy_gate={"status": "accepted", "rules": rules},
        )
        artifact_ref = self._persist_compilation(plan, package, finding, verification_type, rules)
        finding.metadata.update(
            {
                "verification_plan_ref": artifact_ref,
                "verification_type": verification_type,
                "trusted_compiler_rules": rules,
            }
        )
        return CompiledVerification(plan, finding, decision, artifact_ref, verification_type, rules)

    def execute(
        self,
        compiled: CompiledVerification,
        package: VerificationEvidencePackage,
        metadata,
        *,
        llm_client: Any | None = None,
        message_bus: Any | None = None,
        cancellation_token: Any | None = None,
    ) -> ValidationResult:
        if compiled.verification_type == "static-semantic":
            return self._execute_secret_semantics(compiled, package)
        if compiled.decision.validation_level != "sandbox":
            reason = "Registered dynamic primitive requires an enabled bounded sandbox."
            result = ValidationResult(
                finding_id=compiled.finding.id or "",
                level="manual",
                status=VerificationStatus.MANUAL_REQUIRED,
                verification_status=VerificationStatus.MANUAL_REQUIRED,
                verification_reason=reason,
                message=reason,
                artifacts=[compiled.artifact_ref],
            )
            _apply_validation(compiled.finding, result)
            return result
        engine = VerificationEngine(
            self.config,
            self.run_dir,
            llm_client=llm_client,
            message_bus=message_bus,
            cancellation_token=cancellation_token,
        )
        engine.begin_validation_phase(metadata)
        provisional = engine.verify(compiled.decision, metadata, "sandbox")
        return engine.finalize_validation_phase(metadata, [(compiled.finding, provisional)])[0]

    def _attach_plan_metadata(
        self,
        finding: Finding,
        plan: VerificationPlan,
        package: VerificationEvidencePackage,
    ) -> None:
        finding.metadata["verification_plan_id"] = plan.plan_id
        finding.metadata["evidence_package_ref"] = plan.evidence_package_ref
        primitive_calls = [
            {
                "primitive_id": item.primitive_id,
                "parameters": dict(item.parameters),
                "evidence_refs": list(item.evidence_refs),
            }
            for item in plan.primitives
        ]
        finding.metadata["trusted_verification_primitives"] = primitive_calls
        finding.metadata["trusted_verification_primitive"] = primitive_calls[0]
        dataflow = [item for item in package.corroborating_evidence if item.origin == "dataflow"]
        if dataflow:
            finding.metadata["dataflow_status"] = str(
                dataflow[0].raw.get("dataflow_status") or "complete-flow"
            )
            finding.metadata["dataflow_trace_refs"] = [
                item.artifact_ref for item in dataflow if item.artifact_ref
            ]

    def _validate_semantic_parameters(
        self,
        call: VerificationPrimitiveCall,
        package: VerificationEvidencePackage,
        excerpt: str,
    ) -> None:
        if call.primitive_id == "sql.sqlite-parameter-binding":
            expected = "parameterized" if _package_has_sanitized_flow(package) else "vulnerable"
            if call.parameters["mode"] != expected:
                raise ValueError("SQL verification mode contradicts normative dataflow evidence")
        elif call.primitive_id == "command.argv-marker":
            detected = _command_sink(excerpt, default="")
            if not detected or call.parameters["sink"] != detected:
                raise ValueError("command verification sink does not match the cited source")
        elif call.primitive_id == "path.safe-root-boundary":
            detected = _path_transform(excerpt, default="")
            if not detected or call.parameters["transform"] != detected:
                raise ValueError("path verification transform does not match the cited source")

    def _persist_compilation(
        self,
        plan: VerificationPlan,
        package: VerificationEvidencePackage,
        finding: Finding,
        verification_type: str,
        rules: list[str],
    ) -> str:
        root = self.run_dir / "verification-plans"
        root.mkdir(parents=True, exist_ok=True)
        path = immutable_path(root / f"compiled-{plan.plan_id}.json")
        payload = {
            "schema_version": "trusted-verification-compilation.v1",
            "plan_id": plan.plan_id,
            "candidate_id": finding.id,
            "evidence_package_id": package.package_id,
            "verification_type": verification_type,
            "primitive_ids": [item.primitive_id for item in plan.primitives],
            "primitive_calls": [item.to_dict() for item in plan.primitives],
            "compiler_rules": rules,
            "model_authored_code": False,
            "model_authored_command": False,
            "model_verdict_authority": False,
            "created_at": utc_now(),
        }
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(path)

    def _execute_secret_semantics(
        self,
        compiled: CompiledVerification,
        package: VerificationEvidencePackage,
    ) -> ValidationResult:
        call = compiled.plan.primitives[0]
        path = str(call.parameters["path"])
        line_number = int(call.parameters["line"])
        _relative, text, content_hash = self.view.read(path)
        lines = text.splitlines()
        if line_number > len(lines):
            return self._secret_result(compiled, VerificationStatus.MANUAL_REQUIRED, "Secret source line drifted.", {})
        line = lines[line_number - 1]
        literal = _extract_secret_literal(line)
        minimum_length = int(call.parameters.get("minimum_length", 8))
        minimum_entropy = float(call.parameters.get("minimum_entropy", 2.5))
        entropy = _shannon_entropy(literal) if literal else 0.0
        material = f"{path} {line}".lower()
        example_or_test = any(
            token in material
            for token in ("test", "fixture", "example", "sample", "dummy", "placeholder", "fake")
        )
        override_present = any(
            token in line for token in ("os.environ", "os.getenv", "process.env", "getenv(")
        )
        predicates = {
            "literal_present": bool(literal),
            "minimum_length": bool(literal and len(literal) >= minimum_length),
            "minimum_entropy": entropy >= minimum_entropy,
            "not_test_or_example": not example_or_test,
            "no_configuration_override": not override_present,
            "content_hash_current": content_hash == package.local_evidence[0].content_hash,
            "no_live_network_use": True,
        }
        if all(predicates.values()):
            status = VerificationStatus.CONFIRMED
            reason = "Judge confirmed hardcoded-secret static-semantic predicates with dual evidence."
        elif example_or_test or override_present:
            status = VerificationStatus.REJECTED
            reason = "Judge rejected the secret claim due to example/test or configuration-override counterevidence."
        else:
            status = VerificationStatus.MANUAL_REQUIRED
            reason = "Static-semantic predicates were insufficient for safe confirmation."
        judge = {
            "schema_version": "static-semantic-judge.v1",
            "candidate_id": compiled.finding.id,
            "status": status,
            "reason": reason,
            "predicates": predicates,
            "literal_sha256": hashlib.sha256((literal or "").encode("utf-8")).hexdigest(),
            "literal_length": len(literal or ""),
            "entropy": round(entropy, 4),
            "verification_type": "static-semantic",
            "network_attempts": 0,
            "created_at": utc_now(),
        }
        return self._secret_result(compiled, status, reason, judge)

    def _secret_result(
        self,
        compiled: CompiledVerification,
        status: str,
        reason: str,
        judge: dict[str, Any],
    ) -> ValidationResult:
        root = self.run_dir / "verification-plans"
        root.mkdir(parents=True, exist_ok=True)
        judge_ref = immutable_path(root / f"judge-{compiled.finding.id}.json")
        judge_ref.write_text(json.dumps(judge, ensure_ascii=False, indent=2), encoding="utf-8")
        result = ValidationResult(
            finding_id=compiled.finding.id or "",
            level="static-semantic",
            status=status,
            verification_status=status,
            verification_reason=reason,
            judge_reason=reason,
            environment={"runner": "trusted-static-semantic", "network": "none"},
            artifacts=[compiled.artifact_ref, str(judge_ref)],
            message=reason,
        )
        _apply_validation(compiled.finding, result)
        return result


def plan_from_payload(
    payload: dict[str, Any],
    *,
    run_id: str,
    candidate_id: str,
    vulnerability_class: str,
    evidence_package_ref: str,
) -> VerificationPlan:
    forbidden = {"code", "script", "shell", "command", "argv", "docker", "container", "verdict", "status"}
    if forbidden.intersection(payload):
        raise ValueError("verification model output attempted forbidden authority")
    values = dict(payload)
    values.update(
        {
            "run_id": run_id,
            "candidate_id": candidate_id,
            "vulnerability_class": vulnerability_class,
            "evidence_package_ref": evidence_package_ref,
        }
    )
    return VerificationPlan.from_dict(values)


def _apply_validation(finding: Finding, validation: ValidationResult) -> None:
    finding.validation_level = validation.level
    finding.validation_status = validation.status
    finding.verification_status = validation.verification_status or validation.status
    finding.verification_reason = validation.verification_reason
    finding.metadata["validation_summary"] = validation.to_dict()
    finding.metadata["verification_status"] = finding.verification_status


def _package_has_sanitized_flow(package: VerificationEvidencePackage) -> bool:
    return any(
        item.raw.get("dataflow_status") == "sanitized-flow"
        for item in package.corroborating_evidence
        if isinstance(item.raw, dict)
    )


def _command_sink(excerpt: str, *, default: str = "subprocess") -> str:
    lowered = excerpt.lower()
    if "os.system" in lowered:
        return "os.system"
    if "child_process" in lowered:
        return "child_process"
    if "runtime.getruntime" in lowered:
        return "runtime-exec"
    if "subprocess" in lowered:
        return "subprocess"
    return default


def _path_transform(excerpt: str, *, default: str = "open") -> str:
    lowered = excerpt.lower()
    if "send_file" in lowered:
        return "send-file"
    if "resolve" in lowered:
        return "resolve"
    if "join" in lowered:
        return "join"
    if "open(" in lowered:
        return "open"
    return default


def _expected_observation(primitive_id: str) -> str:
    return {
        "sql.sqlite-parameter-binding": "structured SQLite parameter-binding result",
        "command.argv-marker": "harmless command marker and shell-use observation",
        "path.safe-root-boundary": "controlled safe-root boundary observation",
        "secret.static-semantic": "literal, format/entropy, exclusion, and override predicates",
    }[primitive_id]


def _extract_secret_literal(line: str) -> str | None:
    match = re.search(
        r"(?i)(?:api[_-]?key|secret|password|token|credential)\s*[:=]\s*(['\"])([^'\"]+)\1",
        line,
    )
    return match.group(2) if match else None


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    frequencies = {character: value.count(character) / len(value) for character in set(value)}
    return -sum(probability * math.log2(probability) for probability in frequencies.values())
