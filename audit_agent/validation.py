from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from .config import AuditConfig
from .models import Finding, RepositoryMetadata, ValidationResult


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
        if selected == "sandbox" and metadata.target.kind != "local":
            return ValidationResult(
                finding_id=finding.id or "",
                level="manual",
                status="blocked",
                message="No-live-target policy blocked sandbox validation for a remote target.",
            )
        if selected == "static-only":
            finding.validation_status = "static-reviewed"
            return ValidationResult(
                finding_id=finding.id or "",
                level=selected,
                status="not-executed",
                environment={"target_kind": metadata.target.kind},
                message="Static evidence reviewed; no runtime proof-of-concept executed.",
            )
        if selected == "poc-generate":
            artifact = self._write_poc(finding)
            finding.validation_status = "poc-generated"
            return ValidationResult(
                finding_id=finding.id or "",
                level=selected,
                status="generated",
                environment={"target_kind": metadata.target.kind, "non_destructive": True},
                artifacts=[str(artifact)],
                message="Non-destructive local proof-of-concept artifact generated.",
            )
        if selected == "sandbox":
            if not self.config.sandbox.enabled:
                return ValidationResult(
                    finding_id=finding.id or "",
                    level="manual",
                    status="skipped",
                    message="Sandbox validation requested but sandbox execution is disabled.",
                )
            if not self.config.sandbox.safe_commands:
                return ValidationResult(
                    finding_id=finding.id or "",
                    level="manual",
                    status="skipped",
                    message="Sandbox validation requested but no safe commands are configured.",
                )
            command = self.config.sandbox.safe_commands[0]
            if not _safe_command(command):
                return ValidationResult(
                    finding_id=finding.id or "",
                    level="manual",
                    status="blocked",
                    message="Configured sandbox command failed safety checks.",
                )
            workspace = Path(tempfile.mkdtemp(prefix=f"{self.config.sandbox.workspace_prefix}-"))
            result = subprocess.run(
                command,
                cwd=str(workspace),
                timeout=self.config.sandbox.timeout_seconds,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=True,
            )
            artifact = workspace / f"sandbox-result-{finding.id}.json"
            artifact.write_text(
                json.dumps(
                    {
                        "finding_id": finding.id,
                        "command": command,
                        "exit_status": result.returncode,
                        "stdout": result.stdout[-4000:],
                        "stderr": result.stderr[-4000:],
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            return ValidationResult(
                finding_id=finding.id or "",
                level=selected,
                status="passed" if result.returncode == 0 else "failed",
                command=command,
                environment={"sandbox": str(workspace), "allow_live_targets": False},
                artifacts=[str(artifact)],
                message="Configured local sandbox command executed.",
            )
        return ValidationResult(
            finding_id=finding.id or "",
            level="manual",
            status="manual-required",
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


def _safe_command(command: str) -> bool:
    lowered = command.lower()
    blocked_tokens = [
        "http://",
        "https://",
        "curl ",
        "wget ",
        " nc ",
        "netcat",
        "rm ",
        "del ",
        "remove-item",
        "format ",
    ]
    blocked_control = ["&&", "||", "|", ">", "<", ";"]
    return not any(token in lowered for token in blocked_tokens + blocked_control)
