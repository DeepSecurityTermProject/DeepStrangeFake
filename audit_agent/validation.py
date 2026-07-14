from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .config import AuditConfig
from .models import Finding, RepositoryMetadata, ValidationResult
from .verification import VerificationStatus


class Validator:
    def __init__(self, config: AuditConfig):
        self.config = config

    def validate(self, finding: Finding, metadata: RepositoryMetadata, level: str | None = None) -> ValidationResult:
        selected = level or self.config.default_validation_level
        if selected not in self.config.validation_levels:
            return ValidationResult(
                finding_id=finding.id or "",
                level="manual",
                status="skipped",
                message=f"Unsupported validation level requested: {selected}",
            )
        if selected == "sandbox" and not _sandbox_materialization_allowed(self.config, metadata):
            return ValidationResult(
                finding_id=finding.id or "",
                level="manual",
                status="blocked",
                message="No-live-target policy blocked sandbox validation for a remote target.",
            )
        if selected == "static-only":
            finding.validation_status = VerificationStatus.LIKELY
            finding.verification_status = VerificationStatus.LIKELY
            finding.verification_reason = "Static evidence reviewed; no runtime proof-of-concept executed."
            return ValidationResult(
                finding_id=finding.id or "",
                level=selected,
                status=VerificationStatus.LIKELY,
                verification_status=VerificationStatus.LIKELY,
                verification_reason=finding.verification_reason,
                environment={"target_kind": metadata.target.kind},
                artifacts=list(finding.metadata.get("dataflow_trace_refs", [])),
                message=finding.verification_reason,
            )
        if selected == "poc-generate":
            artifact = self._write_poc(finding)
            finding.validation_status = "poc-generated"
            finding.verification_status = VerificationStatus.LIKELY
            finding.verification_reason = "PoC artifact generated but not executed; runtime confirmation is absent."
            return ValidationResult(
                finding_id=finding.id or "",
                level=selected,
                status="generated",
                verification_status=VerificationStatus.LIKELY,
                verification_reason=finding.verification_reason,
                environment={"target_kind": metadata.target.kind, "non_destructive": True},
                artifacts=[str(artifact)],
                message="Non-destructive local proof-of-concept artifact generated.",
            )
        if selected == "sandbox":
            if not self.config.sandbox.enabled:
                return ValidationResult(
                    finding_id=finding.id or "",
                    level="manual",
                    status=VerificationStatus.MANUAL_REQUIRED,
                    verification_status=VerificationStatus.MANUAL_REQUIRED,
                    verification_reason="Sandbox validation requested but sandbox execution is disabled.",
                    message="Sandbox validation requested but sandbox execution is disabled.",
                )
            return ValidationResult(
                finding_id=finding.id or "",
                level="manual",
                status=VerificationStatus.MANUAL_REQUIRED,
                verification_status=VerificationStatus.MANUAL_REQUIRED,
                verification_reason="Sandbox validation requires a PoCArtifact and LocalSandboxRunner.",
                message="Sandbox validation requires a PoCArtifact and LocalSandboxRunner.",
            )
        return ValidationResult(
            finding_id=finding.id or "",
            level="manual",
            status=VerificationStatus.MANUAL_REQUIRED,
            verification_status=VerificationStatus.MANUAL_REQUIRED,
            verification_reason="Safe automated validation is unavailable; manual reproduction steps are required.",
            message="Safe automated validation is unavailable; manual reproduction steps are required.",
        )
    def _write_poc(self, finding: Finding) -> Path:
        root = Path(tempfile.mkdtemp(prefix="audit-agent-poc-"))
        artifact = root / f"poc-{finding.id}.json"
        payload = {
            "finding_id": finding.id,
            "vulnerability_class": finding.vulnerability_class,
            "location": finding.location.to_dict(),
            "safe_reproduction": True,
            "notes": "Controlled local validation artifact. Do not use against unauthorized live systems.",
        }
        artifact.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return artifact


def _sandbox_materialization_allowed(config: AuditConfig, metadata: RepositoryMetadata) -> bool:
    if metadata.target.kind == "local":
        return True
    return bool(
        metadata.target.kind in {"github", "gitlab"}
        and metadata.target.materialization == "verified-remote-snapshot"
        and metadata.materialization.get("status") == "verified"
        and str(config.sandbox.runner).lower() == "docker"
        and str(config.sandbox.network).lower() == "none"
        and not config.sandbox.allow_live_targets
    )
