from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import AuditConfig
from .models import (
    Finding,
    PoCArtifact,
    RepositoryMetadata,
    SandboxRunResult,
    ValidationResult,
    VerificationAttempt,
    VerificationDecision,
    stable_id,
    to_plain,
    utc_now,
)
from .storage import immutable_path


class VerificationStatus:
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    REJECTED = "rejected"
    MANUAL_REQUIRED = "manual-required"


FINAL_STATUSES = {
    VerificationStatus.CONFIRMED,
    VerificationStatus.LIKELY,
    VerificationStatus.REJECTED,
    VerificationStatus.MANUAL_REQUIRED,
}


@dataclass
class JudgeOutcome:
    status: str
    reason: str
    evidence_refs: list[str]


class PathTraversalPoCGenerator:
    generator_id = "path-traversal-dataflow-v1"

    def generate(
        self,
        finding: Finding,
        metadata: RepositoryMetadata,
        run_dir: str | Path,
        attempt_index: int = 1,
        repair_context: dict[str, Any] | None = None,
    ) -> PoCArtifact | None:
        if finding.vulnerability_class != "path-traversal":
            return None
        if finding.metadata.get("dataflow_status") != "complete-flow":
            return None
        trace = _load_first_trace(finding)
        plan = _build_path_traversal_harness_plan(trace, finding, metadata)
        if plan is None:
            return None
        root = _attempt_dir(run_dir, finding.id or stable_id("F", finding.title), attempt_index)
        root.mkdir(parents=True, exist_ok=True)
        script = immutable_path(root / "poc_path_traversal.py")
        script.write_text(_path_traversal_script(plan, repair_context=repair_context), encoding="utf-8")
        expected_signal = {
            "kind": "stdout-contains",
            "value": "PATH_TRAVERSAL_CONFIRMED",
            "rejected_value": "PATH_TRAVERSAL_BLOCKED",
            "target_expression": plan["sink_expression"],
            "path_expression": plan["path_expression"],
            "transformed_path_expression": plan["transformed_path_expression"],
        }
        if repair_context:
            expected_signal["repair_context"] = {
                "reason": repair_context.get("reason", ""),
                "diagnostic": repair_context.get("diagnostic", ""),
                "prepend_lines": repair_context.get("prepend_lines", []),
            }
        poc = PoCArtifact(
            finding_id=finding.id or "",
            vulnerability_class=finding.vulnerability_class,
            generator_id=self.generator_id,
            script_path=str(script),
            command_argv=[sys.executable, str(script)],
            expected_signal=expected_signal,
            safety_profile={
                "non_destructive": True,
                "local_only": True,
                "writes_under_attempt_dir": True,
                "target_kind": metadata.target.kind,
                "repair_applied": bool(repair_context),
            },
            source_refs=list(finding.metadata.get("local_evidence_refs", [])),
            dataflow_trace_refs=list(finding.metadata.get("dataflow_trace_refs", [])),
            target_file_refs=[finding.location.path],
        )
        metadata_path = immutable_path(root / "poc.json")
        poc.metadata_path = str(metadata_path)
        metadata_path.write_text(json.dumps(poc.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        return poc


class SQLInjectionPoCGenerator:
    generator_id = "sql-injection-dataflow-v1"

    def __init__(self) -> None:
        self.failure_reason = ""

    def generate(
        self,
        finding: Finding,
        metadata: RepositoryMetadata,
        run_dir: str | Path,
        attempt_index: int = 1,
        repair_context: dict[str, Any] | None = None,
    ) -> PoCArtifact | None:
        self.failure_reason = ""
        if finding.vulnerability_class != "sql-injection":
            return None
        if finding.metadata.get("dataflow_status") not in {"complete-flow", "sanitized-flow"}:
            self.failure_reason = "SQLi PoC requires complete-flow or parameterized sanitized-flow dataflow evidence."
            return None
        trace = _load_first_trace(finding)
        plan, reason = _build_sqli_harness_plan(trace, finding, metadata)
        if plan is None:
            self.failure_reason = reason
            return None
        root = _attempt_dir(run_dir, finding.id or stable_id("F", finding.title), attempt_index)
        root.mkdir(parents=True, exist_ok=True)
        script = immutable_path(root / "poc_sql_injection.py")
        script.write_text(_sqli_script(plan, repair_context=repair_context), encoding="utf-8")
        expected_signal = {
            "kind": "sqli-semantic-result",
            "result_filename": "sqli-result.json",
            "target_status": plan["expected_status"],
            "mode": plan["mode"],
            "target_expression": plan["sink_expression"],
            "query_expression": plan["query_expression"],
        }
        if repair_context:
            expected_signal["repair_context"] = {
                "reason": repair_context.get("reason", ""),
                "diagnostic": repair_context.get("diagnostic", ""),
                "prepend_lines": repair_context.get("prepend_lines", []),
            }
        poc = PoCArtifact(
            finding_id=finding.id or "",
            vulnerability_class=finding.vulnerability_class,
            generator_id=self.generator_id,
            script_path=str(script),
            command_argv=[sys.executable, str(script)],
            expected_signal=expected_signal,
            safety_profile={
                "non_destructive": True,
                "local_only": True,
                "writes_under_attempt_dir": True,
                "sqlite_harness": True,
                "target_kind": metadata.target.kind,
                "repair_applied": bool(repair_context),
            },
            source_refs=list(finding.metadata.get("local_evidence_refs", [])),
            dataflow_trace_refs=list(finding.metadata.get("dataflow_trace_refs", [])),
            target_file_refs=[finding.location.path],
        )
        metadata_path = immutable_path(root / "poc.json")
        poc.metadata_path = str(metadata_path)
        metadata_path.write_text(json.dumps(poc.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        return poc


class LocalSandboxRunner:
    def __init__(self, config: AuditConfig, run_dir: str | Path):
        self.config = config
        self.run_dir = Path(run_dir)

    def run(self, poc: PoCArtifact | dict[str, Any], attempt_index: int = 1) -> SandboxRunResult:
        poc_data = _record_dict(poc)
        finding_id = str(poc_data.get("finding_id") or "unknown")
        poc_id = str(poc_data.get("id") or "poc")
        attempt_id = stable_id("ATT", finding_id, attempt_index, poc_id)
        attempt_dir = _attempt_dir(self.run_dir, finding_id, attempt_index)
        attempt_dir.mkdir(parents=True, exist_ok=True)
        argv = [str(item) for item in poc_data.get("command_argv") or []]
        timeout = int(getattr(self.config.sandbox, "timeout_seconds", 10) or 10)
        stdout_path = attempt_dir / "stdout.txt"
        stderr_path = attempt_dir / "stderr.txt"
        started = time.monotonic()
        started_at = utc_now()

        allowed, reason = self._command_allowed(argv)
        if not allowed:
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            result = SandboxRunResult(
                poc_id=poc_id,
                finding_id=finding_id,
                attempt_id=attempt_id,
                status="policy-denied",
                cwd=str(attempt_dir),
                argv=argv,
                timeout_seconds=timeout,
                environment=self._environment_summary(),
                stdout_ref=str(stdout_path),
                stderr_ref=str(stderr_path),
                policy={"allowed": False, "reason": reason},
                message=f"Command denied by sandbox allowlist: {reason}",
                started_at=started_at,
                finished_at=utc_now(),
            )
            return self._persist_result(result, attempt_dir)

        try:
            completed = subprocess.run(
                argv,
                cwd=str(attempt_dir),
                timeout=timeout,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                env=self._sanitized_env(),
            )
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
            stdout_path.write_text(stdout, encoding="utf-8", errors="ignore")
            stderr_path.write_text(stderr, encoding="utf-8", errors="ignore")
            result = SandboxRunResult(
                poc_id=poc_id,
                finding_id=finding_id,
                attempt_id=attempt_id,
                status="completed",
                cwd=str(attempt_dir),
                argv=argv,
                timeout_seconds=timeout,
                environment=self._environment_summary(),
                exit_code=completed.returncode,
                timed_out=False,
                duration_ms=int((time.monotonic() - started) * 1000),
                stdout_ref=str(stdout_path),
                stderr_ref=str(stderr_path),
                stdout_preview=_preview(stdout),
                stderr_preview=_preview(stderr),
                artifact_refs=self._collect_artifacts(attempt_dir, {stdout_path, stderr_path}),
                policy={"allowed": True, "network": "best-effort-deny"},
                message="PoC executed in local attempt directory.",
                started_at=started_at,
                finished_at=utc_now(),
            )
            return self._persist_result(result, attempt_dir)
        except subprocess.TimeoutExpired as exc:
            stdout = _decode_timeout_output(exc.stdout)
            stderr = _decode_timeout_output(exc.stderr)
            stdout_path.write_text(stdout, encoding="utf-8", errors="ignore")
            stderr_path.write_text(stderr, encoding="utf-8", errors="ignore")
            result = SandboxRunResult(
                poc_id=poc_id,
                finding_id=finding_id,
                attempt_id=attempt_id,
                status="timed-out",
                cwd=str(attempt_dir),
                argv=argv,
                timeout_seconds=timeout,
                environment=self._environment_summary(),
                exit_code=None,
                timed_out=True,
                duration_ms=int((time.monotonic() - started) * 1000),
                stdout_ref=str(stdout_path),
                stderr_ref=str(stderr_path),
                stdout_preview=_preview(stdout),
                stderr_preview=_preview(stderr),
                artifact_refs=self._collect_artifacts(attempt_dir, {stdout_path, stderr_path}),
                policy={"allowed": True, "network": "best-effort-deny"},
                message="PoC execution timed out.",
                started_at=started_at,
                finished_at=utc_now(),
            )
            return self._persist_result(result, attempt_dir)

    def _command_allowed(self, argv: list[str]) -> tuple[bool, str]:
        if not argv:
            return False, "empty argv"
        executable = Path(argv[0])
        executable_name = executable.name.lower()
        configured = [str(item).lower() for item in getattr(self.config.sandbox, "command_allowlist", [])]
        allowed_names = set(configured) | {"python", "python.exe", "python3", "python3.exe", "py", "py.exe"}
        current = Path(sys.executable)
        if executable.exists():
            try:
                if executable.resolve() == current.resolve():
                    return True, ""
            except OSError:
                pass
        if executable_name in allowed_names:
            return True, ""
        return False, f"{argv[0]} is not in the argv allowlist"

    def _sanitized_env(self) -> dict[str, str]:
        blocked = {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "REQUESTS_CA_BUNDLE"}
        return {key: value for key, value in os.environ.items() if key.upper() not in blocked}

    def _environment_summary(self) -> dict[str, Any]:
        return {
            "network": "best-effort-deny",
            "shell": False,
            "python": sys.executable,
            "proxy_env_removed": True,
        }

    def _collect_artifacts(self, attempt_dir: Path, excluded: set[Path]) -> list[str]:
        refs: list[str] = []
        root = attempt_dir.resolve()
        excluded_resolved = {path.resolve() for path in excluded if path.exists()}
        for path in sorted(attempt_dir.rglob("*")):
            if not path.is_file():
                continue
            resolved = path.resolve()
            if resolved in excluded_resolved:
                continue
            if not resolved.is_relative_to(root):
                continue
            refs.append(str(path))
        return refs

    def _persist_result(self, result: SandboxRunResult, attempt_dir: Path) -> SandboxRunResult:
        metadata_path = immutable_path(attempt_dir / "sandbox-result.json")
        result.metadata_path = str(metadata_path)
        metadata_path.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        if str(metadata_path) not in result.artifact_refs:
            result.artifact_refs.append(str(metadata_path))
            metadata_path.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        return result


class VerificationJudge:
    def judge(self, poc: PoCArtifact | dict[str, Any], sandbox_result: SandboxRunResult | dict[str, Any]) -> JudgeOutcome:
        poc_data = _record_dict(poc)
        result_data = _record_dict(sandbox_result)
        evidence_refs = [
            ref
            for ref in [
                result_data.get("stdout_ref"),
                result_data.get("stderr_ref"),
                result_data.get("metadata_path"),
            ]
            if ref
        ]
        evidence_refs.extend(result_data.get("artifact_refs") or [])
        if result_data.get("status") == "policy-denied":
            return JudgeOutcome(
                VerificationStatus.MANUAL_REQUIRED,
                result_data.get("message") or "Sandbox policy blocked PoC execution.",
                evidence_refs,
            )
        if result_data.get("timed_out") or result_data.get("status") == "timed-out":
            return JudgeOutcome(
                VerificationStatus.MANUAL_REQUIRED,
                "Sandbox execution timed out before a Judge signal was available.",
                evidence_refs,
            )
        expected = poc_data.get("expected_signal") or {}
        if expected.get("kind") == "sqli-semantic-result":
            return _judge_sqli_semantic_result(expected, result_data, evidence_refs)
        value = str(expected.get("value") or "")
        rejected_value = str(expected.get("rejected_value") or "")
        combined = "\n".join(
            [
                str(result_data.get("stdout_preview") or ""),
                str(result_data.get("stderr_preview") or ""),
                _read_text_ref(result_data.get("stdout_ref")),
                _read_text_ref(result_data.get("stderr_ref")),
            ]
        )
        if rejected_value and rejected_value in combined:
            return JudgeOutcome(
                VerificationStatus.REJECTED,
                f"PoC contradiction evidence observed: {rejected_value}.",
                evidence_refs,
            )
        if value and value in combined:
            return JudgeOutcome(
                VerificationStatus.CONFIRMED,
                "Traversal signal observed from sandbox execution evidence.",
                evidence_refs,
            )
        return JudgeOutcome(
            VerificationStatus.MANUAL_REQUIRED,
            f"Expected signal {value or '<missing>'} was not observed in sandbox execution evidence.",
            evidence_refs,
        )


class VerificationEngine:
    def __init__(self, config: AuditConfig, run_dir: str | Path):
        self.config = config
        self.run_dir = Path(run_dir)
        self.generator = PathTraversalPoCGenerator()
        self.generators = {
            "path-traversal": self.generator,
            "sql-injection": SQLInjectionPoCGenerator(),
        }
        self.runner = LocalSandboxRunner(config, self.run_dir)
        self.judge = VerificationJudge()

    def verify(
        self,
        decision: VerificationDecision,
        metadata: RepositoryMetadata,
        level: str | None = None,
    ) -> ValidationResult:
        selected = level or decision.validation_level or self.config.default_validation_level
        finding = decision.finding
        if decision.decision == "reject":
            return self._finalize(
                finding,
                ValidationResult(
                    finding_id=finding.id or "",
                    level="manual",
                    status=VerificationStatus.REJECTED,
                    verification_status=VerificationStatus.REJECTED,
                    verification_reason=decision.reason,
                    message=decision.reason,
                    artifacts=_local_evidence_refs(finding),
                ),
            )
        if selected != "sandbox":
            reason = "Static evidence reviewed; no runtime proof-of-concept executed."
            return self._finalize(
                finding,
                ValidationResult(
                    finding_id=finding.id or "",
                    level=selected,
                    status=VerificationStatus.LIKELY,
                    verification_status=VerificationStatus.LIKELY,
                    verification_reason=reason,
                    message=reason,
                    environment={"target_kind": metadata.target.kind},
                    artifacts=_local_evidence_refs(finding),
                ),
            )
        if metadata.target.kind != "local":
            return self._manual_required(finding, selected, "No-live-target policy blocked sandbox validation.")
        if not self.config.sandbox.enabled:
            return self._manual_required(finding, selected, "Sandbox validation requested but sandbox execution is disabled.")
        generator = self._generator_for(finding)
        if generator is None:
            return self._likely(
                finding,
                selected,
                f"Unsupported vulnerability class for MVP PoC execution: {finding.vulnerability_class}; static/dataflow evidence retained.",
            )
        max_attempts = max(1, 1 + int(getattr(self.config.llm_decisions, "max_repair_attempts", 0) or 0))
        last_validation: ValidationResult | None = None
        repair_context: dict[str, Any] | None = None
        for attempt_index in range(1, max_attempts + 1):
            poc = generator.generate(
                finding,
                metadata,
                self.run_dir,
                attempt_index=attempt_index,
                repair_context=repair_context,
            )
            if poc is None:
                reason = getattr(generator, "failure_reason", "") or (
                    f"Target {finding.vulnerability_class} harness unavailable; trace must match target code and expose a supported expression."
                )
                return self._likely(
                    finding,
                    selected,
                    reason,
                )
            sandbox_result = self.runner.run(poc, attempt_index=attempt_index)
            judge = self.judge.judge(poc, sandbox_result)
            repair_reason = str(repair_context.get("reason") or "") if repair_context else ""
            attempt = self._persist_attempt(
                finding=finding,
                attempt_index=attempt_index,
                poc=poc,
                sandbox_result=sandbox_result,
                judge=judge,
                repair_reason=repair_reason,
            )
            last_validation = self._validation_from_attempt(
                finding=finding,
                level=selected,
                poc=poc,
                sandbox_result=sandbox_result,
                judge=judge,
                attempt=attempt,
            )
            if judge.status in {VerificationStatus.CONFIRMED, VerificationStatus.REJECTED}:
                return self._finalize(finding, last_validation)
            repair_context = _repair_context_from_sandbox_failure(sandbox_result)
            if attempt_index >= max_attempts or repair_context is None:
                return self._finalize(finding, last_validation)
        return self._finalize(finding, last_validation or self._manual_required(finding, selected, "PoC validation did not produce an attempt."))

    def _generator_for(self, finding: Finding):
        if finding.vulnerability_class == "path-traversal":
            return self.generator
        return self.generators.get(finding.vulnerability_class)

    def _manual_required(self, finding: Finding, level: str, reason: str) -> ValidationResult:
        return self._finalize(
            finding,
            ValidationResult(
                finding_id=finding.id or "",
                level=level,
                status=VerificationStatus.MANUAL_REQUIRED,
                verification_status=VerificationStatus.MANUAL_REQUIRED,
                verification_reason=reason,
                message=reason,
                artifacts=_local_evidence_refs(finding),
            ),
        )

    def _likely(self, finding: Finding, level: str, reason: str) -> ValidationResult:
        return self._finalize(
            finding,
            ValidationResult(
                finding_id=finding.id or "",
                level=level,
                status=VerificationStatus.LIKELY,
                verification_status=VerificationStatus.LIKELY,
                verification_reason=reason,
                message=reason,
                artifacts=_local_evidence_refs(finding),
            ),
        )

    def _persist_attempt(
        self,
        finding: Finding,
        attempt_index: int,
        poc: PoCArtifact,
        sandbox_result: SandboxRunResult,
        judge: JudgeOutcome,
        repair_reason: str = "",
    ) -> VerificationAttempt:
        attempt = VerificationAttempt(
            finding_id=finding.id or "",
            attempt_index=attempt_index,
            status=judge.status,
            reason=judge.reason,
            poc_ref=poc.metadata_path,
            sandbox_result_ref=sandbox_result.metadata_path,
            stdout_ref=sandbox_result.stdout_ref,
            stderr_ref=sandbox_result.stderr_ref,
            exit_code=sandbox_result.exit_code,
            judge_reason=judge.reason,
            repair_reason=repair_reason,
            blocking_reason=judge.reason if judge.status == VerificationStatus.MANUAL_REQUIRED else "",
            evidence_refs=judge.evidence_refs,
        )
        attempt_dir = _attempt_dir(self.run_dir, finding.id or "unknown", attempt_index)
        attempt_path = immutable_path(attempt_dir / "verification-attempt.json")
        attempt.metadata_path = str(attempt_path)
        attempt_path.write_text(json.dumps(attempt.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        return attempt

    def _validation_from_attempt(
        self,
        finding: Finding,
        level: str,
        poc: PoCArtifact,
        sandbox_result: SandboxRunResult,
        judge: JudgeOutcome,
        attempt: VerificationAttempt,
    ) -> ValidationResult:
        refs = _dedupe(
            [
                poc.metadata_path,
                poc.script_path,
                sandbox_result.metadata_path,
                sandbox_result.stdout_ref,
                sandbox_result.stderr_ref,
                attempt.metadata_path,
                *sandbox_result.artifact_refs,
                *finding.metadata.get("dataflow_trace_refs", []),
            ]
        )
        return ValidationResult(
            finding_id=finding.id or "",
            level=level,
            status=judge.status,
            verification_status=judge.status,
            verification_reason=judge.reason,
            judge_reason=judge.reason,
            exit_code=sandbox_result.exit_code,
            timed_out=sandbox_result.timed_out,
            stdout_preview=sandbox_result.stdout_preview,
            stderr_preview=sandbox_result.stderr_preview,
            poc_refs=_dedupe([poc.metadata_path, poc.script_path]),
            sandbox_result_refs=[sandbox_result.metadata_path] if sandbox_result.metadata_path else [],
            attempt_refs=[attempt.metadata_path] if attempt.metadata_path else [],
            command_argv=list(sandbox_result.argv),
            command=" ".join(sandbox_result.argv),
            environment=sandbox_result.environment,
            artifacts=refs,
            message=judge.reason,
        )

    @staticmethod
    def _finalize(finding: Finding, validation: ValidationResult) -> ValidationResult:
        status = validation.verification_status or validation.status
        finding.validation_level = validation.level
        finding.validation_status = validation.status
        finding.verification_status = status
        finding.verification_reason = validation.verification_reason or validation.message
        finding.metadata["verification_status"] = status
        finding.metadata["verification_reason"] = finding.verification_reason
        finding.metadata["validation_summary"] = validation.to_dict()
        return validation


def verification_status_counts(items: list[Any]) -> dict[str, int]:
    counts = {
        "confirmed_count": 0,
        "likely_count": 0,
        "rejected_count": 0,
        "manual_required_count": 0,
    }
    for item in items:
        status = _status_from_item(item)
        if status == VerificationStatus.CONFIRMED:
            counts["confirmed_count"] += 1
        elif status == VerificationStatus.LIKELY:
            counts["likely_count"] += 1
        elif status == VerificationStatus.REJECTED:
            counts["rejected_count"] += 1
        elif status == VerificationStatus.MANUAL_REQUIRED:
            counts["manual_required_count"] += 1
    return counts


def artifact_refs_under_run(refs: list[str], run_dir: str | Path) -> bool:
    root = Path(run_dir).resolve()
    for ref in refs:
        path = Path(ref)
        if not path.exists():
            return False
        try:
            if not path.resolve().is_relative_to(root):
                return False
        except OSError:
            return False
    return True


def _status_from_item(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("verification_status") or item.get("status") or "")
    return str(getattr(item, "verification_status", None) or getattr(item, "status", ""))


def _judge_sqli_semantic_result(
    expected: dict[str, Any],
    result_data: dict[str, Any],
    evidence_refs: list[str],
) -> JudgeOutcome:
    result_name = str(expected.get("result_filename") or "sqli-result.json")
    result_ref = _find_artifact_by_name(result_data, result_name)
    if not result_ref:
        return JudgeOutcome(
            VerificationStatus.MANUAL_REQUIRED,
            f"SQLi semantic evidence artifact {result_name} was not produced.",
            evidence_refs,
        )
    try:
        payload = json.loads(Path(result_ref).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return JudgeOutcome(
            VerificationStatus.MANUAL_REQUIRED,
            f"SQLi semantic evidence artifact {result_name} could not be read.",
            _dedupe([*evidence_refs, result_ref]),
        )
    evidence = _dedupe([*evidence_refs, result_ref])
    status = str(payload.get("status") or "")
    if status == VerificationStatus.CONFIRMED and payload.get("marker_seen") and payload.get("attack_count", 0) > payload.get("baseline_count", 0):
        return JudgeOutcome(
            VerificationStatus.CONFIRMED,
            "SQL injection semantic widening observed from sqli-result.json.",
            evidence,
        )
    if status == VerificationStatus.REJECTED:
        mode = str(payload.get("mode") or "")
        reason = "SQL injection contradiction observed from sqli-result.json."
        if mode == "parameterized":
            reason = "SQL injection rejected: parameter binding kept the payload as data."
        return JudgeOutcome(VerificationStatus.REJECTED, reason, evidence)
    return JudgeOutcome(
        VerificationStatus.MANUAL_REQUIRED,
        f"SQLi semantic evidence artifact {result_name} did not contain confirming or rejecting semantics.",
        evidence,
    )


def _find_artifact_by_name(result_data: dict[str, Any], name: str) -> str | None:
    for ref in result_data.get("artifact_refs") or []:
        path = Path(str(ref))
        if path.name == name and path.is_file():
            return str(path)
    cwd = result_data.get("cwd")
    if cwd:
        candidate = Path(str(cwd)) / name
        if candidate.is_file():
            return str(candidate)
    return None


def _repair_context_from_sandbox_failure(result: SandboxRunResult) -> dict[str, Any] | None:
    if result.status in {"policy-denied", "timed-out"}:
        return None
    diagnostic_text = "\n".join([result.stderr_preview, result.stdout_preview])
    diagnostic = diagnostic_text.lower()
    prepend_lines: list[str] = []
    reasons: list[str] = []
    if "nameerror" in diagnostic and "name 'path' is not defined" in diagnostic:
        prepend_lines.append("from pathlib import Path")
        reasons.append("NameError for Path")
    if "nameerror" in diagnostic and "name 'os' is not defined" in diagnostic:
        prepend_lines.append("import os")
        reasons.append("NameError for os")
    if not prepend_lines:
        return None
    return {
        "reason": "Patched generated PoC harness after " + ", ".join(reasons) + ".",
        "diagnostic": _preview(diagnostic_text, limit=800),
        "prepend_lines": prepend_lines,
    }


def _attempt_dir(run_dir: str | Path, finding_id: str, attempt_index: int) -> Path:
    safe_id = "".join(char if char.isalnum() or char in "-_." else "-" for char in finding_id)
    return Path(run_dir) / "verification" / safe_id / f"attempt-{attempt_index}"


def _path_traversal_script(plan: dict[str, str], repair_context: dict[str, Any] | None = None) -> str:
    lines = [
            "from pathlib import Path",
            "import os",
            "",
            f"# target sink expression: {plan['sink_expression']}",
            f"# target path expression: {plan['path_expression']}",
            "attempt = Path.cwd()",
            "intended_root = attempt / 'target_base' / 'files'",
            "intended_root.mkdir(parents=True, exist_ok=True)",
            "outside = intended_root.parent / 'outside-secret.txt'",
            "outside.write_text('sandbox sentinel', encoding='utf-8')",
            "_payload = '../outside-secret.txt'",
            "_safe_prefix = str(intended_root) + os.sep",
            f"{plan['source_symbol']} = _payload",
            f"candidate = {plan['transformed_path_expression']}",
            "resolved = Path(str(candidate)).resolve()",
            "try:",
            "    resolved.relative_to(intended_root.resolve())",
            "    inside = True",
            "except ValueError:",
            "    inside = False",
            "if not inside and resolved == outside.resolve() and resolved.exists():",
            "    print('PATH_TRAVERSAL_CONFIRMED ' + str(resolved))",
            "else:",
            "    print('PATH_TRAVERSAL_BLOCKED ' + str(resolved))",
        ]
    lines = _prepend_repair_lines(lines, repair_context)
    return "\n".join(lines)


def _prepend_repair_lines(lines: list[str], repair_context: dict[str, Any] | None) -> list[str]:
    if not repair_context:
        return lines
    prepend = [str(line) for line in repair_context.get("prepend_lines", []) if str(line).strip()]
    for line in reversed(prepend):
        if line not in lines:
            lines.insert(0, line)
    return lines


def _sqli_script(plan: dict[str, Any], repair_context: dict[str, Any] | None = None) -> str:
    source_assignments = [f"    {name} = _value" for name in plan.get("source_variables", [])]
    if not source_assignments:
        source_assignments = ["    _unused_source = _value"]
    if plan["mode"] == "raw":
        execution_lines = [
            "baseline_query = _build_raw_query(BASELINE_VALUE)",
            "attack_query = _build_raw_query(ATTACK_PAYLOAD)",
            "baseline_rows = _fetch_rows(cursor, baseline_query)",
            "attack_rows = _fetch_rows(cursor, attack_query)",
        ]
    else:
        execution_lines = [
            f"baseline_query = {json.dumps(plan['query_sql'])}",
            "attack_query = baseline_query",
            "baseline_rows = _fetch_rows(cursor, baseline_query, (BASELINE_VALUE,))",
            "attack_rows = _fetch_rows(cursor, attack_query, (ATTACK_PAYLOAD,))",
        ]
    lines = [
        "import json",
        "import sqlite3",
        "from pathlib import Path",
        "",
        "BASELINE_VALUE = 'alice'",
        "ATTACK_PAYLOAD = \"' OR '1'='1\"",
        f"MODE = {json.dumps(plan['mode'])}",
        f"QUERY_EXPRESSION = {json.dumps(plan['query_expression'])}",
        f"SINK_EXPRESSION = {json.dumps(plan['sink_expression'])}",
        f"TRACE_REF = {json.dumps(plan.get('trace_ref', ''))}",
        "",
        "def _seed(cursor):",
        "    cursor.execute('create table users (id integer, name text, role text)')",
        "    cursor.executemany(",
        "        'insert into users (id, name, role) values (?, ?, ?)',",
        "        [(1, 'alice', 'user'), (2, 'bob', 'marker'), (3, 'charlie', 'marker')],",
        "    )",
        "",
        "def _fetch_rows(cursor, query, params=None):",
        "    if not str(query).lstrip().lower().startswith('select'):",
        "        raise RuntimeError('non-select SQL blocked by harness')",
        "    if params is None:",
        "        cursor.execute(query)",
        "    else:",
        "        cursor.execute(query, params)",
        "    return cursor.fetchall()",
        "",
        "def _build_raw_query(_value):",
        *source_assignments,
        f"    return {plan['query_expression']}",
        "",
        "connection = sqlite3.connect(':memory:')",
        "cursor = connection.cursor()",
        "_seed(cursor)",
        *execution_lines,
        "marker_seen = any(str(value) == 'marker' for row in attack_rows for value in row)",
        "baseline_count = len(baseline_rows)",
        "attack_count = len(attack_rows)",
        "status = 'confirmed' if marker_seen and attack_count > baseline_count else 'rejected'",
        "result = {",
        "    'status': status,",
        "    'mode': MODE,",
        "    'baseline_count': baseline_count,",
        "    'attack_count': attack_count,",
        "    'marker_seen': marker_seen,",
        "    'query_expression': QUERY_EXPRESSION,",
        "    'sink_expression': SINK_EXPRESSION,",
        "    'trace_ref': TRACE_REF,",
        "    'baseline_query': baseline_query,",
        "    'attack_query': attack_query,",
        "}",
        "Path('sqli-result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')",
        "print('SQLI_CONFIRMED' if status == 'confirmed' else 'SQLI_REJECTED')",
    ]
    lines = _prepend_repair_lines(lines, repair_context)
    return "\n".join(lines)


def _load_first_trace(finding: Finding) -> dict[str, Any] | None:
    for ref in finding.metadata.get("dataflow_trace_refs", []):
        path = Path(str(ref))
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return None
    return None


def _build_sqli_harness_plan(
    trace: dict[str, Any] | None,
    finding: Finding,
    metadata: RepositoryMetadata,
) -> tuple[dict[str, Any] | None, str]:
    if not trace:
        return None, "SQLi PoC requires an openable dataflow trace artifact."
    if trace.get("vulnerability_class") != "sql-injection":
        return None, "SQLi PoC requires a sql-injection dataflow trace."
    language = str(trace.get("language") or "")
    if language != "python":
        return None, f"Unsupported SQLi language for PoC execution: {language or 'unknown'}."
    sink = trace.get("sink") or {}
    sink_expression = str(sink.get("expression") or "")
    if not sink_expression:
        return None, "SQLi dataflow trace is missing a sink expression."
    target_path = Path(metadata.root_path or ".") / str(sink.get("path") or finding.location.path)
    if not target_path.is_file():
        return None, "Target SQLi source file could not be opened."
    target_text = target_path.read_text(encoding="utf-8", errors="ignore")
    steps = trace.get("steps") or []
    expressions = [sink_expression, *[str(step.get("expression") or "") for step in steps]]
    if not any(expr and _normalize_code(expr) in _normalize_code(target_text) for expr in expressions):
        return None, "Target SQLi expression mismatch; trace sink/query expression was not found in target source."

    call = _parse_python_call(sink_expression)
    if call is None or not call.args:
        return None, "Unsupported SQLi sink shape: no executable SQL argument was found."
    call_name = _call_name(call.func)
    if _is_orm_sql_call(call_name):
        return None, f"Unsupported ORM or query-builder SQLi sink: {call_name}."
    parameterized = len(call.args) > 1 or bool(trace.get("sanitizers"))
    source_vars = _source_variables_from_trace(trace)

    if parameterized:
        query_sql = _literal_string(call.args[0])
        if not query_sql:
            return None, "Unsupported parameterized SQLi shape: SQL text is dynamic."
        if not _sql_starts_with_select(query_sql):
            return None, "Unsupported SQLi query shape: non-SELECT statements are not executed."
        return (
            {
                "mode": "parameterized",
                "expected_status": VerificationStatus.REJECTED,
                "sink_expression": sink_expression,
                "query_expression": ast.unparse(call.args[0]),
                "query_sql": query_sql,
                "source_variables": source_vars,
                "trace_ref": str(trace.get("artifact_path") or ""),
            },
            "",
        )

    query_expression = _query_expression_from_sink(call, steps)
    if not query_expression:
        return None, "Unsupported SQLi query shape: query expression could not be extracted from the trace."
    query_sql_preview = _static_sql_preview(query_expression)
    if not query_sql_preview:
        return None, "Unsupported SQLi query shape: SQL text is too dynamic for the sqlite harness."
    if not _sql_starts_with_select(query_sql_preview):
        return None, "Unsupported SQLi query shape: non-SELECT statements are not executed."
    if _expression_names(query_expression) and not source_vars:
        return None, "Unsupported SQLi query shape: source variable could not be recovered from the trace."
    return (
        {
            "mode": "raw",
            "expected_status": VerificationStatus.CONFIRMED,
            "sink_expression": sink_expression,
            "query_expression": query_expression,
            "query_sql": query_sql_preview,
            "source_variables": source_vars,
            "trace_ref": str(trace.get("artifact_path") or ""),
        },
        "",
    )


def _parse_python_call(expression: str) -> ast.Call | None:
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            return node
    return None


def _is_orm_sql_call(call_name: str) -> bool:
    lowered = call_name.lower()
    return lowered.startswith("session.") or "sequelize" in lowered or "querybuilder" in lowered


def _query_expression_from_sink(call: ast.Call, steps: list[dict[str, Any]]) -> str | None:
    first = call.args[0]
    if isinstance(first, ast.Name):
        target = first.id
        for step in reversed(steps):
            expression = str(step.get("expression") or "")
            assignment = _assignment_parts(expression)
            if assignment and assignment[0] == target:
                return assignment[1]
        return None
    return ast.unparse(first)


def _source_variables_from_trace(trace: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for step in trace.get("steps") or []:
        expression = str(step.get("expression") or "")
        assignment = _assignment_parts(expression)
        if not assignment:
            continue
        target, value = assignment
        if target.isidentifier() and ("request.args" in value or "request.GET" in value or "query_params" in value):
            names.append(target)
    source = trace.get("source") or {}
    symbol = str(source.get("symbol") or "")
    if symbol.isidentifier():
        names.append(symbol)
    return _dedupe(names)


def _assignment_parts(expression: str) -> tuple[str, str] | None:
    try:
        tree = ast.parse(expression)
    except SyntaxError:
        return None
    if not tree.body or not isinstance(tree.body[0], (ast.Assign, ast.AnnAssign)):
        return None
    statement = tree.body[0]
    if isinstance(statement, ast.Assign):
        if not statement.targets or not isinstance(statement.targets[0], ast.Name):
            return None
        return statement.targets[0].id, ast.unparse(statement.value)
    if isinstance(statement.target, ast.Name) and statement.value is not None:
        return statement.target.id, ast.unparse(statement.value)
    return None


def _literal_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _static_sql_preview(expression: str) -> str | None:
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            parts = [part.value for part in node.values if isinstance(part, ast.Constant) and isinstance(part.value, str)]
            if parts:
                return "".join(parts)
    return None


def _sql_starts_with_select(sql: str) -> bool:
    return sql.lstrip().lower().startswith("select")


def _expression_names(expression: str) -> list[str]:
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        return []
    return sorted({node.id for node in ast.walk(tree) if isinstance(node, ast.Name)})


def _build_path_traversal_harness_plan(
    trace: dict[str, Any] | None,
    finding: Finding,
    metadata: RepositoryMetadata,
) -> dict[str, str] | None:
    if not trace or trace.get("vulnerability_class") != "path-traversal":
        return None
    if trace.get("language") != "python":
        return None
    sink = trace.get("sink") or {}
    source = trace.get("source") or {}
    sink_expression = str(sink.get("expression") or "")
    source_symbol = str(source.get("symbol") or "")
    if not sink_expression or not source_symbol or not source_symbol.isidentifier():
        return None
    target_path = Path(metadata.root_path or ".") / str(sink.get("path") or finding.location.path)
    if not target_path.is_file():
        return None
    target_text = target_path.read_text(encoding="utf-8", errors="ignore")
    if _normalize_code(sink_expression) not in _normalize_code(target_text):
        return None
    path_expression = _extract_python_path_argument(sink_expression)
    if not path_expression:
        return None
    transformed = _transform_path_expression(path_expression, source_symbol)
    if not transformed:
        return None
    return {
        "sink_expression": sink_expression,
        "path_expression": path_expression,
        "transformed_path_expression": transformed,
        "source_symbol": source_symbol,
    }


def _extract_python_path_argument(sink_expression: str) -> str | None:
    try:
        tree = ast.parse(sink_expression, mode="eval")
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node.func) in {"open", "send_file"} and node.args:
            return ast.unparse(node.args[0])
    return None


class _PathExpressionTransformer(ast.NodeTransformer):
    def __init__(self, source_symbol: str):
        self.source_symbol = source_symbol
        self.replaced_base = False
        self.replaced_source = False

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str) and _looks_like_base_path(node.value):
            self.replaced_base = True
            return ast.copy_location(ast.Name(id="_safe_prefix", ctx=ast.Load()), node)
        return node

    def visit_Name(self, node: ast.Name):
        if node.id == self.source_symbol:
            self.replaced_source = True
            return ast.copy_location(ast.Name(id="_payload", ctx=ast.Load()), node)
        return node

    def visit_Call(self, node: ast.Call):
        rendered = ast.unparse(node)
        if "request.args.get" in rendered or "request.GET.get" in rendered:
            self.replaced_source = True
            return ast.copy_location(ast.Name(id="_payload", ctx=ast.Load()), node)
        return self.generic_visit(node)


def _transform_path_expression(path_expression: str, source_symbol: str) -> str | None:
    try:
        expression = ast.parse(path_expression, mode="eval")
    except SyntaxError:
        return None
    transformer = _PathExpressionTransformer(source_symbol)
    transformed = transformer.visit(expression)
    ast.fix_missing_locations(transformed)
    if not transformer.replaced_source or not transformer.replaced_base:
        return None
    return ast.unparse(transformed.body)


def _looks_like_base_path(value: str) -> bool:
    if ".." in value:
        return False
    normalized = value.replace("\\", "/")
    return normalized.startswith("/") or normalized.endswith("/") or "/files" in normalized


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _normalize_code(value: str) -> str:
    return "".join(value.split())


def _record_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    return dict(value or {})


def _preview(value: str, limit: int = 4000) -> str:
    return value[-limit:] if len(value) > limit else value


def _decode_timeout_output(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def _read_text_ref(ref: Any) -> str:
    if not ref:
        return ""
    path = Path(str(ref))
    if not path.exists() or not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def _local_evidence_refs(finding: Finding) -> list[str]:
    return _dedupe(
        [
            *finding.tool_refs,
            *finding.metadata.get("local_evidence_refs", []),
            *finding.metadata.get("dataflow_trace_refs", []),
        ]
    )


def _dedupe(values: list[Any]) -> list[str]:
    result: list[str] = []
    for value in values:
        if not value:
            continue
        text = str(value)
        if text not in result:
            result.append(text)
    return result
