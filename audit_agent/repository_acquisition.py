from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

from .config import AuditScope, RemoteAcquisitionConfig
from .models import AuditTarget, RepositoryMetadata, stable_id, to_plain, utc_now
from .redaction import redact_text
from .repository import analyze_target


ACQUISITION_SCHEMA_VERSION = "repository-acquisition.v1"
PREPARED_TARGET_SCHEMA_VERSION = "prepared-audit-target.v1"
COMMIT_RE = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
PATH_PART_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
REMOTE_HOST_KINDS = {"github.com": "github", "gitlab.com": "gitlab"}


class AcquisitionError(RuntimeError):
    def __init__(
        self,
        reason: str,
        detail: str = "",
        *,
        acquisition: AcquisitionResult | None = None,
        summary: dict[str, Any] | None = None,
    ):
        self.reason = reason
        self.detail = redact_text(detail)[:500]
        self.acquisition = acquisition
        self.summary = dict(summary or {})
        super().__init__(reason if not self.detail else f"{reason}: {self.detail}")


@dataclass
class AcquisitionCommandOutcome:
    argv: list[str]
    returncode: int
    duration_ms: int
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class AcquisitionSafetyCheck:
    name: str
    status: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class AcquisitionCleanup:
    status: str = "pending"
    attempts: int = 0
    residual_ref: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class AcquisitionRequest:
    source: str
    job_id: str
    requested_revision: str = "HEAD"
    cache_identity: str | None = None
    schema_version: str = ACQUISITION_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class AcquisitionResult:
    source: str
    normalized_source: str
    requested_revision: str
    status: str
    job_id: str
    resolved_commit: str | None = None
    method: str = "none"
    cache_status: str = "unknown"
    network_used: bool = False
    export_path: str | None = None
    exported_files: int = 0
    exported_bytes: int = 0
    mirror_bytes: int | None = None
    failure_reason: str | None = None
    command_outcomes: list[AcquisitionCommandOutcome] = field(default_factory=list)
    safety_checks: list[AcquisitionSafetyCheck] = field(default_factory=list)
    cleanup: AcquisitionCleanup = field(default_factory=AcquisitionCleanup)
    duration_ms: int = 0
    created_at: str = field(default_factory=utc_now)
    schema_version: str = ACQUISITION_SCHEMA_VERSION
    result_id: str | None = None

    def __post_init__(self) -> None:
        self.result_id = self.result_id or stable_id(
            "ACQ", self.normalized_source, self.requested_revision, self.job_id, self.created_at
        )

    def to_dict(self) -> dict[str, Any]:
        payload = to_plain(self)
        payload["source"] = _redact_source(self.source)
        payload["normalized_source"] = _redact_source(self.normalized_source)
        if payload.get("export_path"):
            payload["export_path"] = "[WORKSPACE]"
        return payload


@dataclass
class PreparedAuditTarget:
    metadata: RepositoryMetadata
    acquisition: AcquisitionResult | None = None
    schema_version: str = PREPARED_TARGET_SCHEMA_VERSION

    @property
    def is_remote_snapshot(self) -> bool:
        return bool(self.acquisition and self.acquisition.status == "ready")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "metadata": self.metadata.to_dict(),
            "acquisition": self.acquisition.to_dict() if self.acquisition else None,
        }


@dataclass
class GitCommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


GitCommandRunner = Callable[..., GitCommandResult]


def normalize_remote_source(
    source: str,
    allowed_hosts: list[str] | set[str] | tuple[str, ...] | None = None,
) -> str:
    parsed = urlsplit(str(source).strip())
    if parsed.scheme.lower() != "https":
        raise AcquisitionError("source-policy-denied", "only canonical HTTPS repository URLs are allowed")
    if parsed.username or parsed.password:
        raise AcquisitionError("source-policy-denied", "credential-bearing URLs are forbidden")
    host = (parsed.hostname or "").lower()
    approved_values = REMOTE_HOST_KINDS if allowed_hosts is None else allowed_hosts
    approved = {item.lower() for item in approved_values}
    if host not in REMOTE_HOST_KINDS or host not in approved or parsed.port is not None:
        raise AcquisitionError("source-policy-denied", "repository host is not approved")
    if parsed.query or parsed.fragment:
        raise AcquisitionError("source-policy-denied", "query strings and fragments are forbidden")
    parts = [part for part in parsed.path.split("/") if part]
    required_parts = 2
    if len(parts) < required_parts or (host == "github.com" and len(parts) != required_parts):
        expected = "owner/repository" if host == "github.com" else "namespace/repository"
        raise AcquisitionError("source-policy-denied", f"repository path must be {expected}")
    repo = parts[-1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    parts[-1] = repo
    if not repo or any(part in {".", ".."} for part in parts):
        raise AcquisitionError("source-policy-denied", "repository path is malformed")
    if any(not PATH_PART_RE.fullmatch(part) for part in parts):
        raise AcquisitionError("source-policy-denied", "repository path contains unsupported characters")
    return urlunsplit(("https", host, "/" + "/".join(parts), "", ""))


def normalize_github_source(source: str) -> str:
    """Backward-compatible GitHub-only normalizer."""
    return normalize_remote_source(source, {"github.com"})


def remote_source_kind(source: str) -> str:
    normalized = normalize_remote_source(source)
    return REMOTE_HOST_KINDS[urlsplit(normalized).hostname or ""]


def normalize_revision(revision: str | None) -> str:
    value = (revision or "HEAD").strip()
    if value == "HEAD":
        return value
    if not COMMIT_RE.fullmatch(value):
        raise AcquisitionError("revision-policy-denied", "revision must be HEAD or a complete commit object ID")
    return value.lower()


def acquisition_cache_key(normalized_source: str) -> str:
    return hashlib.sha256(normalized_source.encode("utf-8")).hexdigest()


def _contained_child(root: Path, name: str) -> Path:
    resolved_root = root.resolve()
    candidate = (resolved_root / name).resolve()
    if candidate == resolved_root or resolved_root not in candidate.parents:
        raise AcquisitionError("path-containment-failed", "path escapes configured root")
    return candidate


class _FileLock:
    _thread_locks: dict[str, threading.Lock] = {}
    _guard = threading.Lock()

    def __init__(self, path: Path, timeout_seconds: int, cancelled: Callable[[], bool] | None = None):
        self.path = path
        self.timeout_seconds = timeout_seconds
        with self._guard:
            self._thread_lock = self._thread_locks.setdefault(str(path), threading.Lock())
        self._fd: int | None = None
        self.cancelled = cancelled or (lambda: False)

    def __enter__(self):
        deadline = time.monotonic() + self.timeout_seconds
        while not self._thread_lock.acquire(timeout=0.1):
            if self.cancelled():
                raise AcquisitionError("acquisition-cancelled")
            if time.monotonic() >= deadline:
                raise AcquisitionError("lock-timeout")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        while True:
            if self.cancelled():
                self._thread_lock.release()
                raise AcquisitionError("acquisition-cancelled")
            try:
                self._fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self._fd, str(os.getpid()).encode("ascii"))
                return self
            except FileExistsError:
                if time.monotonic() >= deadline:
                    self._thread_lock.release()
                    raise AcquisitionError("lock-timeout")
                time.sleep(0.05)

    def __exit__(self, *_args):
        if self._fd is not None:
            os.close(self._fd)
        try:
            self.path.unlink(missing_ok=True)
        finally:
            self._thread_lock.release()


class RepositoryAcquisitionService:
    def __init__(
        self,
        config: RemoteAcquisitionConfig,
        *,
        command_runner: GitCommandRunner | None = None,
    ):
        self.config = config
        self.command_runner = command_runner or run_git_command
        self._uses_default_runner = command_runner is None
        self._cancellation = threading.local()
        self.cache_root = Path(config.cache_root).expanduser().resolve()
        self.work_root = Path(config.work_root).expanduser().resolve()

    def acquire(
        self,
        request: AcquisitionRequest,
        *,
        progress_callback: Callable[[str], None] | None = None,
        cancellation_checker: Callable[[], bool] | None = None,
    ) -> AcquisitionResult:
        self._cancellation.checker = cancellation_checker or (lambda: False)
        started = time.monotonic()
        normalized = "[REDACTED]"
        revision = "HEAD"
        result: AcquisitionResult | None = None
        try:
            self._check_cancelled()
            if not self.config.enabled:
                raise AcquisitionError("remote-acquisition-disabled")
            normalized = normalize_remote_source(request.source, self.config.allowed_hosts)
            revision = normalize_revision(request.requested_revision)
            if progress_callback:
                progress_callback("acquiring")
            result = AcquisitionResult(
                source=request.source,
                normalized_source=normalized,
                requested_revision=revision,
                status="acquiring",
                job_id=request.job_id,
            )
            deadline = started + self.config.total_timeout_seconds
            if progress_callback:
                progress_callback("resolving-commit")
            commit = self._resolve_revision(normalized, revision, result, deadline)
            key = acquisition_cache_key(request.cache_identity or normalized)
            mirror = _contained_child(self.cache_root, f"{key}.git")
            lock_path = _contained_child(self.cache_root, f"{key}.lock")
            with _FileLock(lock_path, self.config.lock_timeout_seconds, self._is_cancelled):
                self._prepare_mirror(normalized, mirror, commit, result, deadline)
                resolved = self._git(
                    ["-C", str(mirror), "rev-parse", f"{commit}^{{commit}}"], result, deadline
                ).stdout.strip().lower()
                if resolved != commit.lower():
                    raise AcquisitionError("commit-mismatch")
                result.resolved_commit = resolved
                if progress_callback:
                    progress_callback("exporting")
                self._export(mirror, resolved, request.job_id, result, deadline)
            result.status = "ready"
            result.method = "git-archive"
            result.safety_checks.append(AcquisitionSafetyCheck("verified-materialization", "passed"))
            return result
        except AcquisitionError as exc:
            if result is None:
                result = AcquisitionResult(
                    source=request.source,
                    normalized_source=normalized,
                    requested_revision=revision,
                    status="failed",
                    job_id=request.job_id,
                )
            result.status = "failed"
            result.failure_reason = exc.reason
            if result.export_path:
                self.cleanup(result)
            elif result.cleanup.status == "pending":
                result.cleanup = AcquisitionCleanup(status="not-required")
            return result
        finally:
            if result is not None:
                result.duration_ms = int((time.monotonic() - started) * 1000)
            self._cancellation.checker = lambda: False

    def _resolve_revision(
        self, source: str, revision: str, result: AcquisitionResult, deadline: float
    ) -> str:
        if revision != "HEAD":
            return revision
        if not self.config.network_enabled:
            raise AcquisitionError("head-resolution-network-disabled")
        outcome = self._git(["ls-remote", "--exit-code", source, "HEAD"], result, deadline)
        first = outcome.stdout.strip().splitlines()[0].split()[0] if outcome.stdout.strip() else ""
        if not COMMIT_RE.fullmatch(first):
            raise AcquisitionError("head-resolution-invalid")
        result.network_used = True
        return first.lower()

    def _prepare_mirror(
        self, source: str, mirror: Path, commit: str, result: AcquisitionResult, deadline: float
    ) -> None:
        self.cache_root.mkdir(parents=True, exist_ok=True)
        if mirror.exists():
            origin = self._git(["-C", str(mirror), "config", "--get", "remote.origin.url"], result, deadline).stdout.strip()
            if normalize_remote_source(origin, self.config.allowed_hosts) != source:
                raise AcquisitionError("cache-origin-mismatch")
            self._git(["-C", str(mirror), "fsck", "--no-progress", "--connectivity-only"], result, deadline)
            result.cache_status = "hit"
        else:
            if not self.config.network_enabled:
                raise AcquisitionError("cache-miss-network-disabled")
            temp = Path(tempfile.mkdtemp(prefix=f".{mirror.name}-", dir=self.cache_root))
            shutil.rmtree(temp)
            try:
                self._git(
                    ["clone", "--mirror", "--filter=blob:none", "--", source, str(temp)],
                    result,
                    deadline,
                )
                os.replace(temp, mirror)
            finally:
                if temp.exists():
                    shutil.rmtree(temp, ignore_errors=True)
            result.cache_status = "created"
            result.network_used = True
        present = self._git_raw(["-C", str(mirror), "cat-file", "-e", f"{commit}^{{commit}}"], result, deadline)
        if present.returncode != 0:
            if not self.config.network_enabled:
                raise AcquisitionError("commit-missing-network-disabled")
            self._git(
                [
                    "-C", str(mirror), "fetch", "--no-tags", "--filter=blob:none",
                    "origin", commit,
                ],
                result,
                deadline,
            )
            result.cache_status = "fetched"
            result.network_used = True
            self._git(["-C", str(mirror), "cat-file", "-e", f"{commit}^{{commit}}"], result, deadline)
        mirror_bytes = _tree_size(mirror)
        result.mirror_bytes = mirror_bytes
        if mirror_bytes > self.config.max_mirror_bytes:
            raise AcquisitionError("mirror-byte-budget-exceeded")
        result.safety_checks.extend(
            [
                AcquisitionSafetyCheck("origin", "passed"),
                AcquisitionSafetyCheck("object-integrity", "passed"),
                AcquisitionSafetyCheck("mirror-budget", "passed"),
            ]
        )

    def _export(
        self, mirror: Path, commit: str, job_id: str, result: AcquisitionResult, deadline: float
    ) -> None:
        self.work_root.mkdir(parents=True, exist_ok=True)
        safe_job = re.sub(r"[^A-Za-z0-9_.-]", "-", job_id)[:80] or "job"
        destination = _contained_child(self.work_root, f"{safe_job}-{result.result_id}")
        if destination.exists():
            raise AcquisitionError("export-destination-exists")
        temp_root = Path(tempfile.mkdtemp(prefix=f".{safe_job}-", dir=self.work_root))
        archive = temp_root / "source.tar"
        extract_root = temp_root / "source"
        promoted = False
        try:
            self._git(["-C", str(mirror), "archive", "--format=tar", "-o", str(archive), commit], result, deadline)
            extract_root.mkdir()
            files, total_bytes = self._extract_archive(archive, extract_root)
            if files == 0:
                raise AcquisitionError("empty-export")
            os.replace(extract_root, destination)
            promoted = True
            _assert_tree_contained(destination)
            result.export_path = str(destination)
            result.exported_files = files
            result.exported_bytes = total_bytes
            result.safety_checks.extend(
                [
                    AcquisitionSafetyCheck("archive-containment", "passed"),
                    AcquisitionSafetyCheck("archive-types", "passed"),
                    AcquisitionSafetyCheck("export-budget", "passed"),
                ]
            )
        except Exception:
            if promoted and destination.exists():
                shutil.rmtree(destination, ignore_errors=True)
            raise
        finally:
            shutil.rmtree(temp_root, ignore_errors=True)

    def _extract_archive(self, archive: Path, destination: Path) -> tuple[int, int]:
        file_count = 0
        total_bytes = 0
        seen: set[str] = set()
        with tarfile.open(archive, "r:") as handle:
            members = handle.getmembers()
            if len(members) > self.config.max_archive_members:
                raise AcquisitionError("archive-member-budget-exceeded")
            for member in members:
                self._check_cancelled()
                pure = PurePosixPath(member.name)
                if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
                    raise AcquisitionError("archive-path-invalid")
                normalized = pure.as_posix().casefold()
                if normalized in seen:
                    raise AcquisitionError("archive-destination-collision")
                seen.add(normalized)
                if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                    raise AcquisitionError("archive-entry-type-forbidden")
                target = (destination / Path(*pure.parts)).resolve()
                root = destination.resolve()
                if target != root and root not in target.parents:
                    raise AcquisitionError("archive-path-escape")
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                file_count += 1
                total_bytes += member.size
                if file_count > self.config.max_files:
                    raise AcquisitionError("export-file-budget-exceeded")
                if total_bytes > min(self.config.max_archive_bytes, self.config.max_bytes):
                    raise AcquisitionError("export-byte-budget-exceeded")
                source = handle.extractfile(member)
                if source is None:
                    raise AcquisitionError("archive-entry-unreadable")
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as output:
                    shutil.copyfileobj(source, output)
        return file_count, total_bytes

    def _git(
        self, args: list[str], result: AcquisitionResult, deadline: float
    ) -> AcquisitionCommandOutcome:
        outcome = self._git_raw(args, result, deadline)
        if outcome.timed_out:
            raise AcquisitionError("git-timeout")
        if outcome.returncode != 0:
            raise AcquisitionError("git-command-failed", outcome.stderr or outcome.stdout)
        return outcome

    def _git_raw(
        self, args: list[str], result: AcquisitionResult, deadline: float
    ) -> AcquisitionCommandOutcome:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AcquisitionError("acquisition-timeout")
        timeout = max(1, min(self.config.command_timeout_seconds, int(remaining)))
        argv = _hardened_git_argv(args)
        started = time.monotonic()
        self._check_cancelled()
        if self._uses_default_runner:
            from .benchmark_runtime import ProcessTreeRunner

            completed = ProcessTreeRunner().run(
                argv,
                cwd=None,
                env=_minimal_git_environment(),
                timeout_seconds=timeout,
                cancelled=self._is_cancelled,
            )
            if completed.cancelled:
                raise AcquisitionError("acquisition-cancelled")
            raw = GitCommandResult(
                completed.returncode or 0,
                completed.stdout,
                completed.stderr,
                timed_out=completed.timed_out,
            )
        else:
            raw = self.command_runner(argv, None, _minimal_git_environment(), timeout)
        self._check_cancelled()
        safe_argv = [_redact_argument(item) for item in argv]
        outcome = AcquisitionCommandOutcome(
            argv=safe_argv,
            returncode=raw.returncode,
            duration_ms=int((time.monotonic() - started) * 1000),
            timed_out=raw.timed_out,
            stdout=redact_text(raw.stdout)[:20_000],
            stderr=redact_text(raw.stderr)[:20_000],
        )
        result.command_outcomes.append(outcome)
        return outcome

    def _is_cancelled(self) -> bool:
        checker = getattr(self._cancellation, "checker", None)
        return bool(checker and checker())

    def _check_cancelled(self) -> None:
        if self._is_cancelled():
            raise AcquisitionError("acquisition-cancelled")

    def cleanup(self, result: AcquisitionResult) -> AcquisitionCleanup:
        if not result.export_path:
            result.cleanup = AcquisitionCleanup(status="not-required")
            return result.cleanup
        path = Path(result.export_path)
        root = self.work_root.resolve()
        try:
            resolved = path.resolve()
            if resolved == root or root not in resolved.parents:
                raise AcquisitionError("cleanup-containment-failed")
        except OSError as exc:
            result.cleanup = AcquisitionCleanup(status="failed", reason="cleanup-path-invalid")
            return result.cleanup
        last_error = ""
        for attempt in range(1, self.config.cleanup_retries + 2):
            try:
                shutil.rmtree(resolved)
                if not resolved.exists():
                    result.cleanup = AcquisitionCleanup(status="complete", attempts=attempt)
                    return result.cleanup
            except OSError as exc:
                last_error = redact_text(str(exc))[:200]
            if self.config.cleanup_retry_delay_ms:
                time.sleep(self.config.cleanup_retry_delay_ms / 1000)
        result.cleanup = AcquisitionCleanup(
            status="failed",
            attempts=self.config.cleanup_retries + 1,
            residual_ref=stable_id("RESIDUAL", result.result_id),
            reason="cleanup-failed" + (f": {last_error}" if last_error else ""),
        )
        return result.cleanup


def prepare_audit_target(
    target: str,
    *,
    audit_scope: AuditScope,
    config: RemoteAcquisitionConfig,
    requested_revision: str | None = None,
    job_id: str | None = None,
    service: RepositoryAcquisitionService | None = None,
    progress_callback: Callable[[str], None] | None = None,
    cancellation_checker: Callable[[], bool] | None = None,
) -> PreparedAuditTarget:
    parsed = urlsplit(target)
    windows_drive_path = bool(re.match(r"^[A-Za-z]:[\\/]", target))
    scp_style_remote = bool(re.match(r"^[^/\\\s]+@[^:\s]+:", target))
    looks_remote = bool((parsed.scheme and not windows_drive_path) or parsed.netloc or scp_style_remote)
    if not looks_remote:
        if requested_revision:
            raise AcquisitionError(
                "revision-not-applicable",
                "--revision is valid only for GitHub or GitLab HTTPS sources",
            )
        return PreparedAuditTarget(metadata=analyze_target(target, audit_scope=audit_scope))
    normalized = normalize_remote_source(target, config.allowed_hosts)
    selected_service = service or RepositoryAcquisitionService(config)
    acquisition = selected_service.acquire(
        AcquisitionRequest(
            source=target,
            requested_revision=requested_revision or "HEAD",
            job_id=job_id or stable_id("PREP", normalized, utc_now()),
        ),
        progress_callback=progress_callback,
        cancellation_checker=cancellation_checker,
    )
    if acquisition.status != "ready" or not acquisition.export_path or not acquisition.resolved_commit:
        raise AcquisitionError(
            acquisition.failure_reason or "acquisition-failed",
            acquisition=acquisition,
            summary=_acquisition_summary(acquisition),
        )
    local = analyze_target(acquisition.export_path, audit_scope=audit_scope)
    if not local.file_tree:
        selected_service.cleanup(acquisition)
        raise AcquisitionError(
            "empty-remote-scope",
            acquisition=acquisition,
            summary=_acquisition_summary(acquisition),
        )
    normalized_parts = urlsplit(normalized)
    parts = [part for part in normalized_parts.path.split("/") if part]
    kind = REMOTE_HOST_KINDS[normalized_parts.hostname or ""]
    remote_target = AuditTarget(
        source=target,
        kind=kind,
        path=acquisition.export_path,
        url=normalized,
        owner="/".join(parts[:-1]),
        repo=parts[-1],
        ref=acquisition.requested_revision,
        commit=acquisition.resolved_commit,
        requested_revision=acquisition.requested_revision,
        materialization="verified-remote-snapshot",
        acquisition_ref=acquisition.result_id,
    )
    local.target = remote_target
    local.commit = acquisition.resolved_commit
    local.source_provenance = {
        "kind": kind,
        "original_source": target,
        "normalized_source": normalized,
        "requested_revision": acquisition.requested_revision,
        "resolved_commit": acquisition.resolved_commit,
    }
    local.materialization = {
        "status": "verified",
        "kind": "remote-snapshot",
        "root_path": acquisition.export_path,
        "acquisition_ref": acquisition.result_id,
        "exported_files": acquisition.exported_files,
        "exported_bytes": acquisition.exported_bytes,
    }
    return PreparedAuditTarget(metadata=local, acquisition=acquisition)


def _acquisition_summary(acquisition: AcquisitionResult) -> dict[str, Any]:
    return {
        "source_kind": remote_source_kind(acquisition.normalized_source),
        "requested_revision": acquisition.requested_revision,
        "resolved_commit": acquisition.resolved_commit,
        "acquisition_status": acquisition.status,
        "cache_status": acquisition.cache_status,
        "network_used": acquisition.network_used,
        "cleanup_status": acquisition.cleanup.status,
        "acquisition_ref": acquisition.result_id,
    }


def _hardened_git_argv(args: list[str]) -> list[str]:
    return [
        "git",
        "-c", "credential.helper=",
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", "http.followRedirects=false",
        "-c", f"core.hooksPath={os.devnull}",
        "-c", "filter.lfs.smudge=",
        "-c", "filter.lfs.required=false",
        *args,
    ]


def _minimal_git_environment() -> dict[str, str]:
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP", "HOME"}
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "",
            "GIT_LFS_SKIP_SMUDGE": "1",
        }
    )
    return env


def _redact_argument(value: str) -> str:
    try:
        parsed = urlsplit(value)
        if parsed.scheme and parsed.netloc:
            host = parsed.hostname or "[REDACTED]"
            return urlunsplit((parsed.scheme, host, parsed.path, "", ""))
    except ValueError:
        pass
    return redact_text(value)


def _redact_source(value: str) -> str:
    try:
        parsed = urlsplit(value)
        if parsed.scheme and parsed.netloc:
            host = parsed.hostname or "[REDACTED]"
            return urlunsplit((parsed.scheme, host, parsed.path, "", ""))
    except ValueError:
        return "[REDACTED]"
    return redact_text(value)


def run_git_command(
    argv: list[str], cwd: Path | None, env: dict[str, str], timeout: int
) -> GitCommandResult:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
        )
        return GitCommandResult(completed.returncode, completed.stdout, completed.stderr)
    except subprocess.TimeoutExpired as exc:
        return GitCommandResult(
            -1,
            str(exc.stdout or ""),
            str(exc.stderr or ""),
            timed_out=True,
        )
    except OSError as exc:
        return GitCommandResult(-1, "", str(exc))


def _tree_size(root: Path) -> int:
    total = 0
    for path in root.rglob("*"):
        try:
            if path.is_file() and not path.is_symlink():
                total += path.stat().st_size
        except OSError:
            continue
    return total


def _assert_tree_contained(root: Path) -> None:
    resolved_root = root.resolve()
    for path in resolved_root.rglob("*"):
        if path.is_symlink():
            raise AcquisitionError("export-link-forbidden")
        resolved = path.resolve()
        if resolved != resolved_root and resolved_root not in resolved.parents:
            raise AcquisitionError("export-path-escape")
        try:
            mode = path.stat().st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                raise AcquisitionError("export-special-entry-forbidden")
        except OSError as exc:
            raise AcquisitionError("export-inspection-failed", str(exc)) from exc
