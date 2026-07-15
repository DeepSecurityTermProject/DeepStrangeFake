from __future__ import annotations

import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..config import AuditConfig
from ..repository_acquisition import AcquisitionError, resolve_remote_revision
from .job_store import JobStore
from .workspace_store import canonicalize_source


LANGUAGE_BY_SUFFIX = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".php": "PHP",
    ".rb": "Ruby",
    ".cs": "C#",
    ".c": "C",
    ".h": "C/C++",
    ".cc": "C++",
    ".cpp": "C++",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".swift": "Swift",
    ".vue": "Vue",
    ".svelte": "Svelte",
    ".html": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".sql": "SQL",
    ".sh": "Shell",
    ".ps1": "PowerShell",
}

IGNORED_METADATA_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
}
PREFLIGHT_POLICY_VERSION = "source-preflight.v1"


class PreflightError(RuntimeError):
    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = str(detail)[:500]
        super().__init__(reason if not detail else f"{reason}: {self.detail}")


@dataclass
class PreflightRecord:
    token: str
    source: dict[str, Any]
    source_identity: str
    source_display: str
    suggested_name: str
    revision_type: str
    requested_revision: str | None
    resolved_commit: str | None
    policy_version: str = PREFLIGHT_POLICY_VERSION
    languages: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    existing_project_id: str | None = None
    expires_at_epoch: float = 0.0
    used: bool = False

    @property
    def expires_at(self) -> str:
        return datetime.fromtimestamp(self.expires_at_epoch, tz=timezone.utc).replace(
            microsecond=0
        ).isoformat()

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "preflight_token": self.token,
            "expires_at": self.expires_at,
            "source": self.source,
            "source_identity": self.source_identity,
            "source_display": self.source_display,
            "suggested_name": self.suggested_name,
            "revision_type": self.revision_type,
            "requested_revision": self.requested_revision,
            "resolved_commit": self.resolved_commit,
            "policy_version": self.policy_version,
            "languages": self.languages,
            "metadata": self.metadata,
            "existing_project_id": self.existing_project_id,
        }


RemoteResolver = Callable[..., tuple[str, str, str]]


class PreflightService:
    def __init__(
        self,
        store: JobStore,
        config: AuditConfig,
        *,
        allowed_local_roots: list[str | Path] | None = None,
        token_ttl_seconds: int = 600,
        remote_resolver: RemoteResolver = resolve_remote_revision,
    ):
        self.store = store
        self.config = config
        self.allowed_local_roots = [
            Path(item).expanduser().resolve(strict=False)
            for item in (allowed_local_roots or [Path.cwd()])
        ]
        self.token_ttl_seconds = max(60, int(token_ttl_seconds))
        self.remote_resolver = remote_resolver
        self._records: dict[str, PreflightRecord] = {}
        self._lock = threading.RLock()

    def preflight(
        self,
        source: dict[str, Any],
        *,
        revision_type: str = "default",
        revision: str | None = None,
    ) -> PreflightRecord:
        kind = str(source.get("kind") or "").lower()
        if kind == "local":
            record = self._preflight_local(source)
        elif kind in {"github", "gitlab"}:
            record = self._preflight_remote(
                source,
                revision_type=revision_type,
                revision=revision,
            )
        else:
            raise PreflightError("unsupported-source-kind")
        with self._lock:
            self._purge_expired()
            self._records[record.token] = record
        return record

    def consume(
        self,
        token: str,
        *,
        expected_source: dict[str, Any],
        project_id: str | None = None,
    ) -> PreflightRecord:
        with self._lock:
            self._purge_expired()
            record = self._records.get(str(token))
            if record is None:
                raise PreflightError("preflight-token-invalid")
            if record.used:
                raise PreflightError("preflight-token-used")
            if record.expires_at_epoch <= time.time():
                raise PreflightError("preflight-token-expired")
            try:
                _normalized, identity, _display, _name = canonicalize_source(expected_source)
            except (ValueError, AcquisitionError) as exc:
                raise PreflightError("preflight-source-invalid", str(exc)) from exc
            if identity != record.source_identity:
                raise PreflightError("preflight-source-mismatch")
            if record.resolved_commit:
                expected_commit = str(expected_source.get("commit") or "").strip().lower()
                if expected_commit != record.resolved_commit:
                    raise PreflightError("preflight-revision-mismatch")
            if project_id:
                try:
                    project = self.store.get_project(project_id)
                except KeyError as exc:
                    raise PreflightError("project-not-found") from exc
                if project.source_identity != record.source_identity:
                    raise PreflightError("preflight-project-mismatch")
            record.used = True
            return record

    def _preflight_local(self, source: dict[str, Any]) -> PreflightRecord:
        try:
            normalized, identity, display, name = canonicalize_source(source)
        except (ValueError, AcquisitionError) as exc:
            raise PreflightError("local-source-invalid", str(exc)) from exc
        root = Path(normalized["path"])
        if not root.is_dir():
            raise PreflightError("local-source-not-directory")
        if not any(_is_contained(root, allowed) for allowed in self.allowed_local_roots):
            raise PreflightError("local-source-outside-allowed-roots")
        metadata, languages = self._inspect_local_tree(root)
        existing = self.store.get_project_by_source(normalized)
        return PreflightRecord(
            token=secrets.token_urlsafe(32),
            source=normalized,
            source_identity=identity,
            source_display=display,
            suggested_name=name,
            revision_type="local",
            requested_revision=None,
            resolved_commit=None,
            languages=languages,
            metadata=metadata,
            existing_project_id=existing.project_id if existing else None,
            expires_at_epoch=time.time() + self.token_ttl_seconds,
        )

    def _preflight_remote(
        self,
        source: dict[str, Any],
        *,
        revision_type: str,
        revision: str | None,
    ) -> PreflightRecord:
        try:
            normalized_url, requested, resolved = self.remote_resolver(
                str(source.get("url") or ""),
                revision=revision,
                revision_type=revision_type,
                config=self.config.remote_acquisition,
            )
            normalized, identity, display, name = canonicalize_source(
                {"kind": source.get("kind"), "url": normalized_url}
            )
        except AcquisitionError as exc:
            raise PreflightError(exc.reason, exc.detail) from exc
        except ValueError as exc:
            raise PreflightError(str(exc)) from exc
        normalized["commit"] = resolved
        existing = self.store.get_project_by_source(normalized)
        metadata = {
            "file_count": None,
            "total_bytes": None,
            "language_detection_status": "deferred-until-acquisition",
            "source_access": "verified",
        }
        return PreflightRecord(
            token=secrets.token_urlsafe(32),
            source=normalized,
            source_identity=identity,
            source_display=display,
            suggested_name=name,
            revision_type=revision_type,
            requested_revision=requested,
            resolved_commit=resolved,
            languages=[],
            metadata=metadata,
            existing_project_id=existing.project_id if existing else None,
            expires_at_epoch=time.time() + self.token_ttl_seconds,
        )

    def _inspect_local_tree(self, root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        max_files = self.config.audit_scope.max_files or self.config.remote_acquisition.max_files
        max_bytes = self.config.audit_scope.max_bytes or self.config.remote_acquisition.max_bytes
        file_count = 0
        total_bytes = 0
        language_counts: dict[str, int] = {}
        dependency_files: list[str] = []
        dependency_names = {
            "package.json",
            "pyproject.toml",
            "requirements.txt",
            "poetry.lock",
            "pdm.lock",
            "go.mod",
            "cargo.toml",
            "pom.xml",
            "build.gradle",
            "composer.json",
            "gemfile",
        }
        for current, directories, filenames in os.walk(root, followlinks=False):
            current_path = Path(current)
            directories[:] = [
                name
                for name in directories
                if name.lower() not in IGNORED_METADATA_DIRS
                and not (current_path / name).is_symlink()
            ]
            for filename in filenames:
                path = current_path / filename
                if path.is_symlink():
                    continue
                try:
                    size = path.stat().st_size
                except OSError:
                    continue
                file_count += 1
                total_bytes += size
                if file_count > max_files:
                    raise PreflightError("local-source-file-budget-exceeded")
                if total_bytes > max_bytes:
                    raise PreflightError("local-source-byte-budget-exceeded")
                language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
                if language:
                    language_counts[language] = language_counts.get(language, 0) + 1
                if filename.lower() in dependency_names and len(dependency_files) < 50:
                    dependency_files.append(path.relative_to(root).as_posix())
        languages = [
            {"name": name, "files": count}
            for name, count in sorted(language_counts.items(), key=lambda item: (-item[1], item[0]))
        ]
        return (
            {
                "file_count": file_count,
                "total_bytes": total_bytes,
                "dependency_files": dependency_files,
                "language_detection_status": "complete",
                "source_access": "verified",
            },
            languages,
        )

    def _purge_expired(self) -> None:
        now = time.time()
        expired = [
            token
            for token, record in self._records.items()
            if record.expires_at_epoch <= now and not record.used
        ]
        for token in expired:
            self._records.pop(token, None)


def configured_local_roots(env: dict[str, str] | None = None) -> list[Path]:
    values = os.environ if env is None else env
    raw = values.get("AUDIT_LOCAL_ALLOWED_ROOTS", "").strip()
    if not raw:
        return _filesystem_roots()
    return [Path(item).expanduser().resolve(strict=False) for item in raw.split(os.pathsep) if item]


def _filesystem_roots() -> list[Path]:
    """Return every local or mapped filesystem root visible to this process."""
    if os.name != "nt":
        return [Path(os.sep).resolve(strict=False)]

    try:
        import ctypes

        drive_mask = int(ctypes.windll.kernel32.GetLogicalDrives())
    except (AttributeError, OSError, TypeError, ValueError):
        drive_mask = 0

    roots = [
        Path(f"{chr(ord('A') + index)}:\\").resolve(strict=False)
        for index in range(26)
        if drive_mask & (1 << index)
    ]
    if roots:
        return roots
    return [Path(Path.cwd().anchor or os.sep).resolve(strict=False)]


def _is_contained(path: Path, root: Path) -> bool:
    resolved_path = path.resolve(strict=False)
    resolved_root = root.resolve(strict=False)
    return resolved_path == resolved_root or resolved_root in resolved_path.parents
