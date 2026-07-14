from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from .benchmark_models import AcquisitionRecord, BenchmarkCase, contained_path
from .config import RemoteAcquisitionConfig
from .redaction import redact_text
from .repository_acquisition import (
    AcquisitionRequest as GenericAcquisitionRequest,
    GitCommandResult,
    RepositoryAcquisitionService,
)


DEFAULT_ALLOWED_HOSTS = {"github.com", "gitlab.com"}
GIT_ENV = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_LFS_SKIP_SMUDGE": "1",
}


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


CommandRunner = Callable[[list[str], Path | None, dict[str, str], int], CommandResult]


def normalize_source_identity(source: str, *, remote_profile: bool, allowed_hosts: set[str] | None = None) -> str:
    allowed = {item.lower() for item in (allowed_hosts or DEFAULT_ALLOWED_HOSTS)}
    parsed = urlsplit(source)
    if remote_profile:
        if parsed.scheme.lower() not in {"https", "ssh"}:
            raise ValueError("remote source protocol is not allowed")
        if parsed.username or parsed.password:
            raise ValueError("credential-bearing source URLs are forbidden")
        host = (parsed.hostname or "").lower()
        if not host or host not in allowed:
            raise ValueError("remote source host is not approved")
        if parsed.query or parsed.fragment:
            raise ValueError("remote source query and fragment are forbidden")
        path = parsed.path.rstrip("/")
        if not path or path in {".", ".."}:
            raise ValueError("remote source path is malformed")
        return urlunsplit((parsed.scheme.lower(), host, path, "", ""))
    if parsed.scheme or source.startswith("//"):
        raise ValueError("fixture source must be a local path")
    return str(Path(source).resolve())


def source_cache_key(identity: str) -> str:
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


class RepositoryAcquirer:
    def __init__(
        self,
        cache_root: str | Path,
        *,
        allow_network: bool = False,
        allowed_hosts: set[str] | None = None,
        command_runner: CommandRunner | None = None,
        timeout_seconds: int = 120,
    ):
        self.cache_root = Path(cache_root).resolve()
        self.allow_network = allow_network
        self.allowed_hosts = allowed_hosts or DEFAULT_ALLOWED_HOSTS
        self.command_runner = command_runner or run_command
        self._custom_command_runner = command_runner is not None
        self.timeout_seconds = timeout_seconds

    def acquire(self, case: BenchmarkCase, destination: str | Path, *, profile_kind: str) -> AcquisitionRecord:
        started = time.monotonic()
        remote = profile_kind != "fixture"
        commands: list[list[str]] = []
        try:
            identity = normalize_source_identity(case.source, remote_profile=remote, allowed_hosts=self.allowed_hosts)
            destination_path = contained_path(Path(destination).parent, Path(destination).name)
            if remote:
                record = self._acquire_remote(case, identity, destination_path, commands)
            else:
                record = self._acquire_local(case, identity, destination_path)
            record.commands = commands
            record.duration_ms = int((time.monotonic() - started) * 1000)
            return record
        except TimeoutError as exc:
            return self._failure(case, "acquisition-timeout", "timeout", commands, started, exc)
        except ValueError as exc:
            return self._failure(case, "acquisition-policy-denied", "denied", commands, started, exc)
        except (OSError, subprocess.SubprocessError, tarfile.TarError) as exc:
            return self._failure(case, "acquisition-failed", "failed", commands, started, exc)

    def _acquire_local(self, case: BenchmarkCase, identity: str, destination: Path) -> AcquisitionRecord:
        source = Path(identity)
        if not source.is_dir():
            raise ValueError("fixture source directory does not exist")
        self._assert_safe_tree(source)
        if destination.exists():
            raise ValueError("case export destination already exists")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, destination, symlinks=False, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        self._assert_safe_tree(destination)
        return AcquisitionRecord(
            case_id=case.case_id,
            status="ready",
            method="local-copy",
            source_identity=identity,
            expected_commit=case.commit,
            resolved_commit=case.commit,
            export_path=str(destination),
            network_allowed=False,
            cache_status="local",
            safety_checks={"contained": True, "links_safe": True, "project_execution": False},
        )

    def _acquire_remote(
        self,
        case: BenchmarkCase,
        identity: str,
        destination: Path,
        commands: list[list[str]],
    ) -> AcquisitionRecord:
        if destination.exists():
            raise ValueError("case export destination already exists")
        destination.parent.mkdir(parents=True, exist_ok=True)

        config = RemoteAcquisitionConfig(
            enabled=True,
            network_enabled=self.allow_network,
            allowed_hosts=sorted(self.allowed_hosts),
            cache_root=str(contained_path(self.cache_root, "mirrors")),
            work_root=str(destination.parent),
            command_timeout_seconds=self.timeout_seconds,
            total_timeout_seconds=max(self.timeout_seconds, self.timeout_seconds * 8),
        )

        def bridge(argv, cwd, env, timeout):
            legacy_argv = _legacy_benchmark_argv(argv)
            commands.append([redact_text(item) for item in legacy_argv])
            invoked = legacy_argv if self._custom_command_runner else argv
            raw = self.command_runner(invoked, cwd, env, timeout)
            return GitCommandResult(
                returncode=raw.returncode,
                stdout=raw.stdout,
                stderr=raw.stderr,
                timed_out=raw.timed_out,
            )

        result = RepositoryAcquisitionService(config, command_runner=bridge).acquire(
            GenericAcquisitionRequest(
                source=identity,
                job_id=f"benchmark-{case.case_id}",
                requested_revision=case.commit,
                cache_identity=identity,
            )
        )
        if result.status != "ready" or not result.export_path or not result.resolved_commit:
            if result.failure_reason in {
                "cache-miss-network-disabled",
                "commit-missing-network-disabled",
            }:
                return AcquisitionRecord(
                    case_id=case.case_id,
                    status="not-run",
                    method="cache-only",
                    source_identity=identity,
                    expected_commit=case.commit,
                    network_allowed=False,
                    cache_status=(
                        "commit-miss"
                        if result.failure_reason == "commit-missing-network-disabled"
                        else "miss"
                    ),
                    failure_reason="acquisition-cache-miss",
                    commands=commands,
                )
            failure_detail = {
                "cache-origin-mismatch": "cached mirror remote identity mismatch",
                "commit-mismatch": "resolved commit does not match exact lock",
            }.get(result.failure_reason or "", result.failure_reason or "acquisition-failed")
            raise ValueError(failure_detail)

        exported = Path(result.export_path)
        os.replace(exported, destination)
        cache_status = {
            "created": "cloned",
            "fetched": "fetched",
            "hit": "hit",
        }.get(result.cache_status, result.cache_status)
        return AcquisitionRecord(
            case_id=case.case_id,
            status="ready",
            method=result.method,
            source_identity=identity,
            expected_commit=case.commit,
            resolved_commit=result.resolved_commit,
            export_path=str(destination),
            network_allowed=self.allow_network,
            cache_status=cache_status,
            safety_checks={
                "contained": True,
                "links_safe": True,
                "hooks_disabled": True,
                "submodules_disabled": True,
                "lfs_smudge_disabled": True,
                "external_filters_disabled": True,
                "project_execution": False,
            },
        )

    def _checked(self, argv: list[str], cwd: Path | None, commands: list[list[str]]) -> CommandResult:
        result = self._run(argv, cwd, commands)
        if result.timed_out:
            raise TimeoutError("Git operation timed out")
        if result.returncode != 0:
            raise OSError(redact_text(result.stderr or result.stdout or "Git operation failed")[:2000])
        return result

    def _run(self, argv: list[str], cwd: Path | None, commands: list[list[str]]) -> CommandResult:
        safe_argv = [redact_text(item) for item in argv]
        commands.append(safe_argv)
        env = {**os.environ, **GIT_ENV, "GIT_CONFIG_GLOBAL": os.devnull}
        return self.command_runner(argv, cwd, env, self.timeout_seconds)

    @staticmethod
    def _safe_extract(archive: Path, destination: Path) -> None:
        destination = destination.resolve()
        with tarfile.open(archive, "r:") as handle:
            for member in handle.getmembers():
                target = (destination / member.name).resolve()
                if target != destination and destination not in target.parents:
                    raise ValueError("archive entry escapes destination")
                if member.issym() or member.islnk():
                    raise ValueError("archive links are forbidden")
                if not (member.isfile() or member.isdir()):
                    raise ValueError("unsupported archive entry type")
            handle.extractall(destination, filter="data")

    @staticmethod
    def _assert_safe_tree(root: Path) -> None:
        root = root.resolve()
        for path in root.rglob("*"):
            if path.is_symlink():
                resolved = path.resolve()
                if root not in resolved.parents:
                    raise ValueError("source tree link escapes root")

    @staticmethod
    def _failure(case, reason, status, commands, started, exc) -> AcquisitionRecord:
        return AcquisitionRecord(
            case_id=case.case_id,
            status=status,
            method="none",
            source_identity="[REDACTED]",
            expected_commit=case.commit,
            network_allowed=False,
            cache_status="unavailable",
            failure_reason=f"{reason}: {redact_text(str(exc))[:500]}",
            duration_ms=int((time.monotonic() - started) * 1000),
            commands=commands,
        )


def run_command(argv: list[str], cwd: Path | None, env: dict[str, str], timeout: int) -> CommandResult:
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
        return CommandResult(
            argv=argv,
            returncode=completed.returncode,
            stdout=redact_text(completed.stdout)[:20_000],
            stderr=redact_text(completed.stderr)[:20_000],
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            argv=argv,
            returncode=-1,
            stdout=redact_text(str(exc.stdout or ""))[:20_000],
            stderr=redact_text(str(exc.stderr or ""))[:20_000],
            timed_out=True,
        )


def _legacy_benchmark_argv(argv: list[str]) -> list[str]:
    """Expose the pre-refactor benchmark command shape to injected test runners."""
    if not argv:
        return []
    index = 1
    while index + 1 < len(argv) and argv[index] == "-c":
        index += 2
    legacy = [argv[0], *argv[index:]]
    if len(legacy) >= 6 and legacy[-3:] == ["config", "--get", "remote.origin.url"]:
        legacy = [*legacy[:-3], "remote", "get-url", "origin"]
    return legacy
