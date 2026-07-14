from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .benchmark_acquisition import RepositoryAcquirer
from .benchmark_models import (
    CaseState,
    CaseStatus,
    MATCHER_VERSION,
    METRIC_VERSION,
    RESOURCE_SCHEMA_VERSION,
    BenchmarkCase,
    BenchmarkCorpus,
    RunResourceSummary,
    canonical_digest,
    contained_path,
    utc_now,
)
from .llm_accounting import reconcile_llm_lifecycle
from .models import stable_id
from .config import AuditConfig
from .integration import load_integration_environment
from .pipeline import run_audit
from .redaction import redact_secrets, redact_text


ALLOWED_TRANSITIONS = {
    "pending": {"acquiring", "not-run", "failed"},
    "acquiring": {"ready", "not-run", "failed", "timed-out"},
    "ready": {"running", "not-run", "failed"},
    "running": {"completed", "failed", "timed-out"},
    "completed": set(),
    "failed": set(),
    "timed-out": set(),
    "not-run": set(),
}


@dataclass
class ProcessResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    cleanup: dict[str, Any]
    cancelled: bool = False


@dataclass
class DockerCleanupResult:
    success: bool
    labels: dict[str, str]
    matched_resources: list[str] = field(default_factory=list)
    removed_resources: list[str] = field(default_factory=list)
    reason: str | None = None


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    class _JobBasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _JobExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JobBasicLimitInformation),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class _JobBasicAccountingInformation(ctypes.Structure):
        _fields_ = [
            ("TotalUserTime", ctypes.c_longlong),
            ("TotalKernelTime", ctypes.c_longlong),
            ("ThisPeriodTotalUserTime", ctypes.c_longlong),
            ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
            ("TotalPageFaultCount", wintypes.DWORD),
            ("TotalProcesses", wintypes.DWORD),
            ("ActiveProcesses", wintypes.DWORD),
            ("TotalTerminatedProcesses", wintypes.DWORD),
        ]

    class _WindowsJob:
        _KILL_ON_JOB_CLOSE = 0x00002000
        _BASIC_ACCOUNTING = 1
        _EXTENDED_LIMIT = 9

        def __init__(self) -> None:
            self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self.ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
            self._configure_signatures()
            self.handle = self.kernel32.CreateJobObjectW(None, None)
            if not self.handle:
                self._raise_last_error("CreateJobObjectW")
            limits = _JobExtendedLimitInformation()
            limits.BasicLimitInformation.LimitFlags = self._KILL_ON_JOB_CLOSE
            if not self.kernel32.SetInformationJobObject(
                self.handle,
                self._EXTENDED_LIMIT,
                ctypes.byref(limits),
                ctypes.sizeof(limits),
            ):
                self.close()
                self._raise_last_error("SetInformationJobObject")

        def assign_and_resume(self, process: subprocess.Popen) -> None:
            process_handle = wintypes.HANDLE(int(process._handle))
            if not self.kernel32.AssignProcessToJobObject(self.handle, process_handle):
                self._raise_last_error("AssignProcessToJobObject")
            status = int(self.ntdll.NtResumeProcess(process_handle))
            if status < 0:
                raise OSError(f"NtResumeProcess failed with NTSTATUS {status:#x}")

        def terminate_and_verify(self, process: subprocess.Popen, timeout_seconds: float = 5.0) -> dict[str, Any]:
            if not self.kernel32.TerminateJobObject(self.handle, 1):
                return {
                    "attempted": True,
                    "success": False,
                    "method": "windows-job-object",
                    "pid": process.pid,
                    "descendants_verified_gone": False,
                    "reason": self._last_error("TerminateJobObject"),
                }
            deadline = time.monotonic() + timeout_seconds
            active_processes: int | None = None
            while time.monotonic() < deadline:
                active_processes = self.active_processes()
                if active_processes == 0 and process.poll() is not None:
                    break
                time.sleep(0.05)
            descendants_gone = active_processes == 0
            return {
                "attempted": True,
                "success": descendants_gone and process.poll() is not None,
                "method": "windows-job-object",
                "pid": process.pid,
                "active_processes": active_processes,
                "descendants_verified_gone": descendants_gone,
            }

        def active_processes(self) -> int:
            accounting = _JobBasicAccountingInformation()
            if not self.kernel32.QueryInformationJobObject(
                self.handle,
                self._BASIC_ACCOUNTING,
                ctypes.byref(accounting),
                ctypes.sizeof(accounting),
                None,
            ):
                self._raise_last_error("QueryInformationJobObject")
            return int(accounting.ActiveProcesses)

        def close(self) -> None:
            handle = getattr(self, "handle", None)
            if handle:
                self.kernel32.CloseHandle(handle)
                self.handle = None

        def _configure_signatures(self) -> None:
            self.kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
            self.kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            self.kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
            self.kernel32.SetInformationJobObject.restype = wintypes.BOOL
            self.kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            self.kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
            self.kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
            self.kernel32.TerminateJobObject.restype = wintypes.BOOL
            self.kernel32.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
            self.kernel32.QueryInformationJobObject.restype = wintypes.BOOL
            self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            self.kernel32.CloseHandle.restype = wintypes.BOOL
            self.ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
            self.ntdll.NtResumeProcess.restype = ctypes.c_long

        @staticmethod
        def _last_error(operation: str) -> str:
            code = ctypes.get_last_error()
            return f"{operation} failed: {ctypes.FormatError(code).strip()} ({code})"

        @classmethod
        def _raise_last_error(cls, operation: str) -> None:
            raise OSError(cls._last_error(operation))

else:
    _WindowsJob = None


class AtomicJsonStore:
    @staticmethod
    def write(path: str | Path, payload: Any) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = target.with_name(f".{target.name}.{os.getpid()}.tmp")
        data = json.dumps(redact_secrets(payload), ensure_ascii=False, indent=2)
        with temp.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(data)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        os.replace(temp, target)
        try:
            directory_fd = os.open(str(target.parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
        return target

    @staticmethod
    def read(path: str | Path) -> dict[str, Any]:
        target = Path(path)
        try:
            payload = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"malformed atomic state: {target.name}") from exc
        if not isinstance(payload, dict):
            raise ValueError("atomic state must be an object")
        return payload

    @staticmethod
    def recover(directory: str | Path) -> list[str]:
        ignored = []
        for path in Path(directory).glob(".*.tmp"):
            ignored.append(path.name)
        return sorted(ignored)


class ProcessTreeRunner:
    def run(
        self,
        argv: list[str],
        *,
        env: dict[str, str],
        cwd: str | Path | None,
        timeout_seconds: int,
        secret_values: list[str] | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> ProcessResult:
        windows_job = None
        kwargs: dict[str, Any] = {
            "cwd": cwd,
            "env": env,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "shell": False,
        }
        if os.name == "nt":
            windows_job = _WindowsJob()
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000004  # CREATE_SUSPENDED
        else:
            kwargs["start_new_session"] = True
        try:
            process = subprocess.Popen(argv, **kwargs)
        except Exception:
            if windows_job is not None:
                windows_job.close()
            raise
        if windows_job is not None:
            try:
                windows_job.assign_and_resume(process)
            except Exception:
                windows_job.close()
                try:
                    process.wait(timeout=3)
                except subprocess.SubprocessError:
                    process.kill()
                for stream in (process.stdout, process.stderr):
                    if stream:
                        stream.close()
                raise
        try:
            deadline = time.monotonic() + timeout_seconds
            while True:
                if cancelled is not None and cancelled():
                    cleanup = self.terminate_tree(process, windows_job=windows_job)
                    try:
                        stdout, stderr = process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        stdout, stderr = "", ""
                    return ProcessResult(
                        returncode=process.returncode,
                        stdout=redact_text(stdout, secret_values)[:20_000],
                        stderr=redact_text(stderr, secret_values)[:20_000],
                        timed_out=False,
                        cleanup=cleanup,
                        cancelled=True,
                    )
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout_seconds)
                try:
                    stdout, stderr = process.communicate(timeout=min(0.2, remaining))
                    return ProcessResult(
                        returncode=process.returncode,
                        stdout=redact_text(stdout, secret_values)[:20_000],
                        stderr=redact_text(stderr, secret_values)[:20_000],
                        timed_out=False,
                        cleanup={"attempted": False, "success": True, "method": "not-needed", "pid": process.pid},
                    )
                except subprocess.TimeoutExpired:
                    continue
        except subprocess.TimeoutExpired:
            cleanup = self.terminate_tree(process, windows_job=windows_job)
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)
                for stream in (process.stdout, process.stderr):
                    if stream:
                        stream.close()
                stdout, stderr = "", ""
                cleanup = {
                    **cleanup,
                    "success": False,
                    "reason": cleanup.get("reason") or "descendant-pipes-remained-open",
                }
            return ProcessResult(
                returncode=process.returncode,
                stdout=redact_text(stdout, secret_values)[:20_000],
                stderr=redact_text(stderr, secret_values)[:20_000],
                timed_out=True,
                cleanup=cleanup,
            )
        finally:
            if windows_job is not None:
                windows_job.close()

    def terminate_tree(self, process: subprocess.Popen, *, windows_job: Any = None) -> dict[str, Any]:
        if windows_job is not None:
            try:
                return windows_job.terminate_and_verify(process)
            except (OSError, subprocess.SubprocessError) as exc:
                return {
                    "attempted": True,
                    "success": False,
                    "method": "windows-job-object",
                    "pid": process.pid,
                    "descendants_verified_gone": False,
                    "reason": str(exc),
                }
        if process.poll() is not None:
            return {"attempted": False, "success": True, "method": "already-exited", "pid": process.pid}
        try:
            if os.name == "nt":
                completed = subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    shell=False,
                    check=False,
                )
                process.wait(timeout=5)
                success = process.poll() is not None and completed.returncode in {0, 128}
                return {
                    "attempted": True,
                    "success": success,
                    "method": "taskkill-tree",
                    "pid": process.pid,
                    "descendants_verified_gone": False,
                    "reason": None if success else (completed.stderr.strip() or completed.stdout.strip() or "taskkill-failed"),
                }
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process_group = os.getpgid(process.pid)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process_group, signal.SIGKILL)
                process.wait(timeout=3)
            group_gone = False
            try:
                os.killpg(process_group, 0)
            except ProcessLookupError:
                group_gone = True
            return {
                "attempted": True,
                "success": process.poll() is not None and group_gone,
                "method": "process-group",
                "pid": process.pid,
                "descendants_verified_gone": group_gone,
            }
        except (OSError, subprocess.SubprocessError) as exc:
            return {"attempted": True, "success": False, "method": "process-tree", "pid": process.pid, "reason": str(exc)}


class DockerLabelCleaner:
    def __init__(self, *, enabled: bool = False, command_runner: Callable[..., subprocess.CompletedProcess] | None = None):
        self.enabled = enabled
        self.command_runner = command_runner or subprocess.run

    def cleanup(self, benchmark_id: str, run_id: str, case_id: str) -> DockerCleanupResult:
        labels = {
            "audit.benchmark_id": benchmark_id,
            "audit.benchmark_run_id": run_id,
            "audit.benchmark_case_id": case_id,
        }
        if not self.enabled:
            return DockerCleanupResult(success=True, labels=labels, reason="docker-disabled")
        filters = [item for key, value in labels.items() for item in ("--filter", f"label={key}={value}")]
        try:
            listed = self.command_runner(
                ["docker", "ps", "-aq", *filters], capture_output=True, text=True,
                timeout=15, shell=False, check=False,
            )
            if listed.returncode != 0:
                return DockerCleanupResult(False, labels, reason="docker-list-failed")
            resource_ids = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
            if not resource_ids:
                return DockerCleanupResult(True, labels, reason="no-matching-resources")
            removed = self.command_runner(
                ["docker", "rm", "-f", *resource_ids], capture_output=True, text=True,
                timeout=30, shell=False, check=False,
            )
            if removed.returncode != 0:
                return DockerCleanupResult(False, labels, matched_resources=resource_ids, reason="docker-remove-failed")
            removed_ids = [line.strip() for line in removed.stdout.splitlines() if line.strip()]
            return DockerCleanupResult(True, labels, matched_resources=resource_ids, removed_resources=removed_ids)
        except (OSError, subprocess.SubprocessError):
            return DockerCleanupResult(False, labels, reason="docker-cleanup-error")


class BenchmarkCoordinator:
    def __init__(
        self,
        corpus: BenchmarkCorpus,
        *,
        profile_id: str,
        output_root: str | Path,
        cache_root: str | Path,
        allow_network: bool = False,
        allow_docker: bool = False,
        allow_partial: bool = False,
        case_ids: list[str] | None = None,
        resume_run_id: str | None = None,
        comparison_dimensions: list[str] | None = None,
        engine_identity: dict[str, Any] | None = None,
        truth_identity: dict[str, Any] | None = None,
        process_runner: ProcessTreeRunner | None = None,
        docker_cleaner: DockerLabelCleaner | None = None,
        acquirer: RepositoryAcquirer | None = None,
    ):
        self.corpus = corpus
        self.profile, self.cases = corpus.select(profile_id, case_ids)
        self.output_root = Path(output_root).resolve()
        self.cache_root = Path(cache_root).resolve()
        self.allow_network = allow_network
        self.allow_docker = allow_docker
        self.allow_partial = allow_partial
        self.comparison_dimensions = sorted(comparison_dimensions or ["engine"])
        self.engine_identity = engine_identity or {"engine": "working-tree", "prompt": "default", "model": "disabled"}
        self.truth_identity = truth_identity
        self.process_runner = process_runner or ProcessTreeRunner()
        self.docker_cleaner = docker_cleaner or DockerLabelCleaner(enabled=allow_docker)
        self.acquirer = acquirer or RepositoryAcquirer(self.cache_root, allow_network=allow_network)
        self.run_id = resume_run_id or f"benchmark-{utc_now().replace(':', '').replace('+00:00', 'Z')}"
        self.run_dir = contained_path(self.output_root, self.run_id)

    def prepare(self) -> dict[str, Any]:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "cases").mkdir(exist_ok=True)
        resolved = {
            "schema_version": "benchmark-resolved-manifest.v1",
            "run_id": self.run_id,
            "profile": self.profile.to_dict(),
            "cases": [item.to_dict() for item in self.cases],
            "corpus_digest": self.corpus.digest,
            "unique_project_count": len({item.project_id for item in self.cases}),
            "case_count": len(self.cases),
            "comparison_dimensions": self.comparison_dimensions,
            "engine_identity": self.engine_identity,
            "truth_identity": self.truth_identity,
            "network_allowed": self.allow_network,
            "docker_allowed": self.allow_docker,
        }
        manifest_path = self.run_dir / "resolved-manifest.json"
        if manifest_path.exists():
            existing = AtomicJsonStore.read(manifest_path)
            if canonical_digest(existing) != canonical_digest(resolved):
                resume_request_fields = {
                    "engine_identity",
                    "comparison_dimensions",
                    "network_allowed",
                    "docker_allowed",
                    "truth_identity",
                }
                immutable_existing = {
                    key: value for key, value in existing.items() if key not in resume_request_fields
                }
                immutable_resolved = {
                    key: value for key, value in resolved.items() if key not in resume_request_fields
                }
                if canonical_digest(immutable_existing) != canonical_digest(immutable_resolved):
                    raise ValueError("resume corpus/case manifest differs from immutable resolved manifest")
                AtomicJsonStore.write(
                    self.run_dir / f"resume-request-{canonical_digest(resolved)[:12]}.json",
                    {"original_manifest_digest": canonical_digest(existing), "requested": resolved},
                )
        else:
            AtomicJsonStore.write(manifest_path, resolved)
        return resolved

    def run(self) -> tuple[list[dict[str, Any]], int]:
        resolved = self.prepare()
        results = [self._run_case(case, resolved) for case in self.cases]
        incomplete = [item for item in results if item["status"] != CaseStatus.COMPLETED.value and item.get("required", True)]
        exit_code = 0 if not incomplete or self.allow_partial else 2
        AtomicJsonStore.write(
            self.run_dir / "coordinator.json",
            {
                "schema_version": "benchmark-coordinator.v1",
                "run_id": self.run_id,
                "max_parallel": 1,
                "allow_partial": self.allow_partial,
                "partial": bool(incomplete),
                "baseline_eligible": not incomplete and all(item.get("baseline_eligible") for item in results),
                "exit_code": exit_code,
            },
        )
        return results, exit_code

    def _run_case(self, case: BenchmarkCase, resolved: dict[str, Any]) -> dict[str, Any]:
        case_dir = contained_path(self.run_dir, "cases", case.case_id)
        case_dir.mkdir(parents=True, exist_ok=True)
        state_path = case_dir / "state.json"
        result_path = case_dir / "result.json"
        reuse_fingerprint = canonical_digest(
            {
                "case": case.to_dict(),
                "corpus_digest": self.corpus.digest,
                "engine": self.engine_identity,
                "network_allowed": self.allow_network,
                "docker_allowed": self.allow_docker,
                "resource_schema": RESOURCE_SCHEMA_VERSION,
                "truth": self.truth_identity,
            }
        )
        protocol_fingerprint = canonical_digest(
            {
                "case": {
                    "project_id": case.project_id,
                    "case_id": case.case_id,
                    "commit": case.commit,
                    "scope": case.scope,
                    "truth_ref": case.truth_ref,
                    "support_level": case.support_level,
                    "safety": case.safety,
                },
                "corpus_version": self.corpus.corpus_version,
                "truth": self.truth_identity,
                "schemas": [RESOURCE_SCHEMA_VERSION, MATCHER_VERSION, METRIC_VERSION],
            }
        )
        if state_path.exists() and result_path.exists():
            old_state = CaseState.from_dict(AtomicJsonStore.read(state_path))
            old_result = AtomicJsonStore.read(result_path)
            if (
                old_state.status == "completed"
                and old_state.reuse_fingerprint == reuse_fingerprint
                and validate_case_completion(case, old_result)[0]
            ):
                old_state.reuse_decision = "reused-compatible-completed-result"
                old_state.updated_at = utc_now()
                AtomicJsonStore.write(state_path, old_state.to_dict())
                old_result["reuse_decision"] = old_state.reuse_decision
                return old_result
            AtomicJsonStore.write(
                case_dir / f"stale-result-{old_state.attempts or 1}.json",
                {**old_result, "stale_reason": "reuse-fingerprint-or-artifact-mismatch"},
            )
        prior_attempts = 0
        if state_path.exists():
            try:
                prior_attempts = int(AtomicJsonStore.read(state_path).get("attempts", 0))
            except ValueError:
                prior_attempts = 0
        state = CaseState(
            schema_version="benchmark-case-state.v1",
            benchmark_run_id=self.run_id,
            case_id=case.case_id,
            attempts=prior_attempts + 1,
            reuse_fingerprint=reuse_fingerprint,
            comparison_protocol_fingerprint=protocol_fingerprint,
            reuse_decision="rerun-new-or-stale",
        )
        AtomicJsonStore.write(state_path, state.to_dict())
        self._transition(state, "acquiring", state_path)
        source_dir = case_dir / ("source" if state.attempts == 1 else f"source-attempt-{state.attempts}")
        acquisition = self.acquirer.acquire(case, source_dir, profile_kind=self.profile.kind)
        acquisition_path = AtomicJsonStore.write(case_dir / "acquisition.json", acquisition.to_dict())
        state.artifact_refs.append(str(acquisition_path))
        if acquisition.status != "ready":
            terminal = "not-run" if acquisition.status in {"not-run", "denied"} else "failed"
            state.acquisition_status = acquisition.status
            state.execution_status = "not-run"
            state.evaluation_status = "not-run"
            state.failures.append({"reason": acquisition.failure_reason or "acquisition-failed"})
            self._transition(state, terminal, state_path)
            result = _incomplete_result(case, state, acquisition.failure_reason or "acquisition-failed")
            AtomicJsonStore.write(result_path, result)
            return result
        state.acquisition_status = "ready"
        self._transition(state, "ready", state_path)
        effective_config = self._effective_case_config(case, acquisition.export_path or str(source_dir), case_dir)
        config_path = AtomicJsonStore.write(case_dir / "effective-case.json", effective_config)
        state.artifact_refs.append(str(config_path))
        self._transition(state, "running", state_path)
        env = dict(os.environ)
        for key in list(env):
            if key.upper().endswith(("API_KEY", "TOKEN", "PASSWORD", "SECRET")) and key not in case.safety.get("secret_env_names", []):
                env.pop(key, None)
        env.update(
            {
                "AUDIT_BENCHMARK_CASE_ID": case.case_id,
                "AUDIT_BENCHMARK_PROJECT_ID": case.project_id,
                "AUDIT_BENCHMARK_EXPECTED_COMMIT": case.commit,
            }
        )
        argv = [sys.executable, "-m", "audit_agent", "benchmark-child", "--case-config", str(config_path)]
        secret_values = [
            env[name]
            for name in case.safety.get("secret_env_names", [])
            if name in env and env[name]
        ]
        process = self.process_runner.run(
            argv,
            env=env,
            cwd=Path(__file__).resolve().parent.parent,
            timeout_seconds=case.timeout_seconds,
            secret_values=secret_values,
        )
        AtomicJsonStore.write(
            case_dir / "process.json",
            {"argv": argv, "returncode": process.returncode, "stdout": process.stdout, "stderr": process.stderr, "timed_out": process.timed_out, "cleanup": process.cleanup},
        )
        cleanup = self.docker_cleaner.cleanup(self.corpus.corpus_id, self.run_id, case.case_id)
        AtomicJsonStore.write(case_dir / "cleanup.json", cleanup.__dict__)
        if process.timed_out:
            state.execution_status = "timed-out"
            state.failures.append({"reason": "project-timeout"})
            self._transition(state, "timed-out", state_path)
            result = _incomplete_result(case, state, "project-timeout", cleanup=cleanup.__dict__)
        elif process.returncode != 0:
            state.execution_status = "failed"
            state.failures.append({"reason": "child-nonzero-exit"})
            self._transition(state, "failed", state_path)
            result = _incomplete_result(case, state, "child-nonzero-exit", cleanup=cleanup.__dict__)
        else:
            child_result_path = case_dir / "child-result.json"
            if not child_result_path.exists():
                state.execution_status = "failed"
                state.failures.append({"reason": "missing-child-result"})
                self._transition(state, "failed", state_path)
                result = _incomplete_result(case, state, "missing-child-result", cleanup=cleanup.__dict__)
            else:
                child_result = AtomicJsonStore.read(child_result_path)
                result = normalize_child_result(case, child_result, acquisition.to_dict(), cleanup.__dict__, reuse_fingerprint, protocol_fingerprint)
                valid, reason = validate_case_completion(case, result)
                if valid and cleanup.success:
                    state.execution_status = "succeeded"
                    state.evaluation_status = "pending"
                    state.baseline_eligible = True
                    self._transition(state, "completed", state_path)
                    result["status"] = "completed"
                    result["baseline_eligible"] = True
                else:
                    state.execution_status = "failed"
                    state.failures.append({"reason": reason or "completion-proof-failed"})
                    self._transition(state, "failed", state_path)
                    result = _incomplete_result(case, state, reason or "completion-proof-failed", cleanup=cleanup.__dict__)
        AtomicJsonStore.write(result_path, result)
        return result

    def _effective_case_config(self, case: BenchmarkCase, source_path: str, case_dir: Path) -> dict[str, Any]:
        budgets = {
            "llm_requests": int(case.budgets.get("llm_requests", 0)),
            "llm_tokens": int(case.budgets.get("llm_tokens", 0)),
            "tool_calls": int(case.budgets.get("tool_calls", 0)),
            "docker_starts": int(case.budgets.get("docker_starts", 0)),
            "repair_attempts": int(case.budgets.get("repair_attempts", 0)),
        }
        docker_enabled = bool(
            case.validation_level == "sandbox"
            and case.safety.get("docker", False)
            and self.allow_docker
            and budgets["docker_starts"] > 0
        )
        return {
            "schema_version": "benchmark-effective-case.v1",
            "case_id": case.case_id,
            "project_id": case.project_id,
            "expected_commit": case.commit,
            "source_path": source_path,
            "output_dir": str(case_dir / "scan-runs"),
            "include": case.scope.get("include", ["**/*"]),
            "exclude": case.scope.get("exclude", []),
            "max_files": int(case.scope.get("max_files", 5000)),
            "max_bytes": int(case.scope.get("max_bytes", 50_000_000)),
            "vulnerability_classes": list(case.vulnerability_classes),
            "budgets": budgets,
            "validation_level": case.validation_level,
            "runtime_enabled": budgets["llm_requests"] > 0 and budgets["llm_tokens"] > 0,
            "llm_provider": self.engine_identity.get("provider", "mock"),
            "model": self.engine_identity.get("model", "mock"),
            "secret_env_names": list(case.safety.get("secret_env_names", [])),
            "sandbox_enabled": docker_enabled,
            "sandbox_runner": "docker" if docker_enabled else "local",
            "network_allowed": False,
            "target_writes": False,
            "project_execution": False,
        }

    @staticmethod
    def _transition(state: CaseState, new_status: str, state_path: Path) -> None:
        if new_status not in ALLOWED_TRANSITIONS.get(state.status, set()):
            raise ValueError(f"invalid case state transition: {state.status} -> {new_status}")
        state.status = new_status
        state.updated_at = utc_now()
        AtomicJsonStore.write(state_path, state.to_dict())


def run_child_scan(case_config_path: str | Path) -> int:
    config_path = Path(case_config_path).resolve()
    payload = AtomicJsonStore.read(config_path)
    required = {"schema_version", "case_id", "project_id", "expected_commit", "source_path", "output_dir", "include", "exclude"}
    if payload.get("schema_version") != "benchmark-effective-case.v1" or not required.issubset(payload):
        raise ValueError("invalid benchmark child configuration")
    if payload.get("network_allowed") or payload.get("target_writes") or payload.get("project_execution"):
        raise ValueError("unsafe benchmark child policy")
    source = Path(payload["source_path"]).resolve()
    case_dir = config_path.parent
    if case_dir not in source.parents:
        raise ValueError("benchmark child source escapes case directory")
    config, authorized_secrets = build_child_audit_config(
        payload,
        environment=dict(os.environ),
        environment_root=Path(__file__).resolve().parent.parent,
    )
    previous = {name: os.environ.get(name) for name in authorized_secrets}
    try:
        os.environ.update(authorized_secrets)
        result = run_audit(str(source), config, payload["output_dir"])
        AtomicJsonStore.write(case_dir / "child-result.json", {"case_id": payload["case_id"], "project_id": payload["project_id"], "expected_commit": payload["expected_commit"], **result})
        return 0
    finally:
        for name, old_value in previous.items():
            if old_value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = old_value


def build_child_audit_config(
    payload: dict[str, Any],
    *,
    environment: dict[str, str] | None = None,
    environment_root: str | Path | None = None,
) -> tuple[AuditConfig, dict[str, str]]:
    budgets = payload.get("budgets") or {}
    required_budgets = {"llm_requests", "llm_tokens", "tool_calls", "docker_starts", "repair_attempts"}
    if set(budgets) != required_budgets:
        raise ValueError("effective benchmark case requires exact budget fields")
    values = {name: int(budgets[name]) for name in required_budgets}
    if any(value < 0 for value in values.values()):
        raise ValueError("effective benchmark budgets must be non-negative")
    if values["repair_attempts"] > 2:
        raise ValueError("repair_attempts must be in 0..2")
    config = AuditConfig.default()
    # The general product default is agent-led. Existing benchmark corpus cases
    # are deterministic, zero-LLM protocol cases unless a future versioned case
    # contract explicitly declares another graph mode.
    config.graph.mode = "deterministic-graph"
    env_map = dict(environment or os.environ)
    load_integration_environment(
        config,
        cwd=environment_root or Path(__file__).resolve().parent.parent,
        env=env_map,
    )
    config.audit_scope.include_patterns = list(payload.get("include", []))
    config.audit_scope.exclude_patterns.extend(payload.get("exclude", []))
    config.audit_scope.vulnerability_classes = list(payload.get("vulnerability_classes", []))
    config.audit_scope.max_files = int(payload.get("max_files") or 0)
    config.audit_scope.max_bytes = int(payload.get("max_bytes") or 0)
    if config.audit_scope.max_files < 1 or config.audit_scope.max_bytes < 1:
        raise ValueError("effective benchmark scope bounds must be positive")
    config.audit_scope.tool_budget = values["tool_calls"]
    config.tools.per_agent_budgets = {
        role: values["tool_calls"] for role in config.tools.per_agent_budgets
    }
    config.default_validation_level = str(payload.get("validation_level") or "static-only")
    if config.default_validation_level not in config.validation_levels:
        raise ValueError("invalid benchmark validation level")
    config.runtime_enabled = bool(payload.get("runtime_enabled", False))
    config.llm.request_budget = values["llm_requests"]
    config.llm.token_budget = values["llm_tokens"]
    if values["llm_tokens"] > 0:
        config.llm.max_tokens = min(config.llm.max_tokens, values["llm_tokens"])
    if config.runtime_enabled:
        config.llm.provider = str(payload.get("llm_provider") or "mock")
        config.llm.model = str(payload.get("model") or "mock")
    config.sandbox.enabled = bool(payload.get("sandbox_enabled", False))
    config.sandbox.runner = str(payload.get("sandbox_runner") or "local")
    config.sandbox.max_starts = values["docker_starts"]
    if config.sandbox.enabled and config.sandbox.runner != "docker":
        raise ValueError("enabled benchmark sandbox must use Docker runner")
    config.poc_repair.max_repair_attempts = values["repair_attempts"]
    config.llm_decisions.max_repair_attempts = values["repair_attempts"]
    config.poc_repair.enabled = bool(
        values["repair_attempts"] > 0
        and config.runtime_enabled
        and config.sandbox.enabled
        and config.default_validation_level == "sandbox"
    )
    allowed_secret_names = set(payload.get("secret_env_names") or [])
    authorized_secrets = {
        name: env_map[name] for name in allowed_secret_names if name in env_map and env_map[name]
    }
    real_provider = config.runtime_enabled and config.llm.provider != "mock"
    if real_provider and config.llm.model.strip().lower() in {"", "disabled", "mock"}:
        raise ValueError("real provider requires a non-placeholder model")
    if real_provider and config.llm.api_key_env not in allowed_secret_names:
        raise ValueError("provider API key environment name is not allowed by case safety policy")
    if real_provider and config.llm.api_key_env not in authorized_secrets:
        raise ValueError(f"required provider credential environment is unavailable: {config.llm.api_key_env}")
    config.validate_poc_repair_prerequisites()
    return config, authorized_secrets


def normalize_child_result(
    case: BenchmarkCase,
    child: dict[str, Any],
    acquisition: dict[str, Any],
    cleanup: dict[str, Any],
    reuse_fingerprint: str,
    protocol_fingerprint: str,
) -> dict[str, Any]:
    run_dir = Path(str(child.get("run_dir", "")))
    report_path = run_dir / "reports" / "report.json"
    runtime_path = run_dir / "runtime_state" / "state.json"
    resource_path = run_dir / "reports" / "run-resource-summary.v1.json"
    report = _read_optional(report_path)
    runtime = _read_optional(runtime_path)
    resources = _read_optional(resource_path)
    findings = (report or {}).get("verification_candidates", [])
    return {
        "case_id": case.case_id,
        "project_id": case.project_id,
        "variant": case.variant,
        "pair_id": case.pair_id,
        "required": case.required,
        "support_level": case.support_level,
        "effectiveness_eligible": case.effectiveness_eligible,
        "status": "pending-validation",
        "baseline_eligible": False,
        "counts": {
            "candidates": len(findings) if report is not None else None,
            "confirmed": (report or {}).get("executive_summary", {}).get("confirmed_count"),
            "likely": (report or {}).get("executive_summary", {}).get("likely_count"),
            "rejected": (report or {}).get("executive_summary", {}).get("rejected_count"),
            "manual_required": (report or {}).get("executive_summary", {}).get("manual_required_count"),
        } if report is not None else None,
        "findings": findings,
        "resources": resources,
        "acquisition": acquisition,
        "runtime": runtime,
        "cleanup": cleanup,
        "artifact_refs": {"run_dir": str(run_dir), "report": str(report_path), "runtime_state": str(runtime_path), "resource_summary": str(resource_path)},
        "reuse_fingerprint": reuse_fingerprint,
        "comparison_protocol_fingerprint": protocol_fingerprint,
        "failure_reason": None,
    }


def validate_case_completion(case: BenchmarkCase, result: dict[str, Any]) -> tuple[bool, str | None]:
    if result.get("status") == "completed" and result.get("failure_reason") == "remote-download-skipped":
        return False, "remote-download-skipped"
    acquisition = result.get("acquisition") or {}
    if acquisition.get("status") != "ready" or acquisition.get("resolved_commit") != case.commit:
        return False, "acquisition-or-commit-proof-missing"
    runtime = result.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("status") != "succeeded":
        return False, "runtime-state-missing-or-unsuccessful"
    resources = result.get("resources")
    if not isinstance(resources, dict):
        return False, "resource-summary-missing"
    try:
        summary = RunResourceSummary.from_dict(resources)
        summary.validate()
    except ValueError:
        return False, "resource-summary-invalid"
    if summary.target_identity != case.case_id or summary.target_commit != case.commit:
        return False, "resource-identity-mismatch"
    refs = result.get("artifact_refs") or {}
    for name in ("report", "runtime_state", "resource_summary"):
        if not refs.get(name) or not Path(refs[name]).is_file():
            return False, f"missing-{name}"
    if int(case.budgets.get("llm_requests", 0)) > 0:
        if not summary.ledger_present:
            return False, "llm-accounting-incomplete:legacy-accounting"
        if summary.llm_reconciliation_status != "complete":
            blocker = summary.llm_gap_ids[0] if summary.llm_gap_ids else "unknown-gap"
            return False, f"llm-accounting-incomplete:{blocker}"
        run_dir = _benchmark_result_run_dir(refs)
        if run_dir is None:
            return False, "llm-accounting-incomplete:run-dir-unavailable"
        counters = _benchmark_runtime_llm_counters(Path(refs["runtime_state"]))
        if counters is None:
            blocker = stable_id(
                "LLMGAP",
                "benchmark_summary",
                "runtime-budget-counters-unavailable",
                case.case_id,
            )
            return False, f"llm-accounting-incomplete:{blocker}"
        live = reconcile_llm_lifecycle(
            run_dir,
            llm_enabled=True,
            budget_counters=counters,
        )
        if not live.complete:
            blocker = live.gap_ids[0] if live.gap_ids else "unknown-gap"
            return False, f"llm-accounting-incomplete:{blocker}"
        mismatch = _benchmark_summary_mismatch(summary, live)
        if mismatch:
            blocker = stable_id(
                "LLMGAP",
                "benchmark_summary",
                "live-reconciliation-mismatch",
                case.case_id,
                mismatch,
            )
            return False, f"llm-accounting-incomplete:{blocker}"
    if not summary.scanned_files or summary.scanned_files < 1:
        return False, "empty-scan-scope"
    budget_fields = {
        "llm_requests": summary.llm_requests,
        "llm_tokens": summary.llm_tokens,
        "tool_calls": summary.tool_calls,
        "docker_starts": summary.docker_starts,
        "repair_attempts": summary.repair_attempts,
    }
    for name, used in budget_fields.items():
        if used is None:
            return False, f"budget-accounting-missing:{name}"
        if int(used) > int(case.budgets.get(name, 0)):
            return False, f"budget-exceeded:{name}"
    cleanup = result.get("cleanup") or {}
    if cleanup.get("success") is not True:
        return False, "cleanup-failed"
    return True, None


def _benchmark_result_run_dir(refs: dict[str, Any]) -> Path | None:
    explicit = refs.get("run_dir")
    if explicit and Path(explicit).is_dir():
        return Path(explicit).resolve()
    resource_ref = refs.get("resource_summary")
    if resource_ref:
        path = Path(resource_ref).resolve()
        candidate = path.parent.parent if path.parent.name == "reports" else None
        if candidate and candidate.is_dir():
            return candidate
    return None


def _benchmark_runtime_llm_counters(path: Path) -> dict[str, int] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        counters = payload.get("llm_accounting")
        if not isinstance(counters, dict):
            return None
        requests = counters.get("requests_used")
        tokens = counters.get("tokens_used")
        if any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in (requests, tokens)):
            return None
        return {"requests_used": requests, "tokens_used": tokens}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def _benchmark_summary_mismatch(
    summary: RunResourceSummary,
    live: Any,
) -> str | None:
    comparisons = {
        "accounting_source": (summary.accounting_source, live.accounting_source),
        "total_request_groups": (summary.llm_total_request_groups, live.total_request_groups),
        "dispatched_request_groups": (summary.llm_dispatched_request_groups, live.llm_requests),
        "provider_attempts": (summary.llm_provider_attempts, live.provider_attempts),
        "retries": (summary.llm_retries, live.retries),
        "pre_dispatch_denials": (summary.llm_pre_dispatch_denials, live.pre_dispatch_denials),
        "tokens": (summary.llm_tokens, live.llm_tokens),
        "terminal_status_counts": (
            summary.llm_terminal_status_counts,
            live.terminal_status_counts,
        ),
        "gap_ids": (sorted(summary.llm_gap_ids), sorted(live.gap_ids)),
        "contributing_refs": (
            sorted(str(Path(item).resolve()) for item in summary.llm_contributing_refs),
            sorted(str(Path(item).resolve()) for item in live.contributing_refs),
        ),
    }
    for field, (recorded, observed) in comparisons.items():
        if recorded != observed:
            return field
    return None


def _incomplete_result(case: BenchmarkCase, state: CaseState, reason: str, cleanup: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "case_id": case.case_id,
        "project_id": case.project_id,
        "variant": case.variant,
        "pair_id": case.pair_id,
        "required": case.required,
        "support_level": case.support_level,
        "effectiveness_eligible": case.effectiveness_eligible,
        "status": state.status,
        "baseline_eligible": False,
        "counts": None,
        "counts_unavailable_reason": reason,
        "findings": [],
        "resources": None,
        "resources_unavailable_reason": reason,
        "cleanup": cleanup or {"success": True, "reason": "not-started"},
        "failure_reason": reason,
        "reuse_fingerprint": state.reuse_fingerprint,
        "comparison_protocol_fingerprint": state.comparison_protocol_fingerprint,
        "artifact_refs": state.artifact_refs,
    }


def _read_optional(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else None
    except (OSError, json.JSONDecodeError):
        return None
