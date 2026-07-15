from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from ..models import stable_id, to_plain, utc_now
from ..redaction import redact_text
from ..repository_acquisition import normalize_remote_source, remote_source_kind
from .limits import MAX_PAGE_LIMIT, MAX_PAGE_OFFSET


SCHEMA_VERSION = 1
ACTIVE_RUN_STATUSES = {"queued", "running"}
RUN_STATUSES = {"queued", "running", "succeeded", "degraded", "cancelled", "failed"}


@dataclass
class Project:
    project_id: str
    display_name: str
    source_kind: str
    source: dict[str, Any]
    source_identity: str
    source_display: str
    status: str = "active"
    languages: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    archived_at: str | None = None
    latest_run: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


def canonicalize_source(source: dict[str, Any]) -> tuple[dict[str, Any], str, str, str]:
    kind = str(source.get("kind") or "").strip().lower()
    if kind == "local":
        raw_path = str(source.get("path") or "").strip()
        if not raw_path:
            raise ValueError("local-source-path-required")
        resolved = Path(raw_path).expanduser().resolve(strict=False)
        normalized_path = os.path.normcase(str(resolved)).replace("\\", "/")
        normalized = {"kind": "local", "path": str(resolved)}
        return normalized, f"local:{normalized_path}", str(resolved), resolved.name or str(resolved)
    if kind in {"github", "gitlab"}:
        raw_url = str(source.get("url") or "").strip()
        normalized_url = normalize_remote_source(raw_url)
        detected_kind = remote_source_kind(normalized_url)
        if detected_kind != kind:
            raise ValueError("source-kind-mismatch")
        normalized = {"kind": kind, "url": normalized_url}
        name = normalized_url.rstrip("/").rsplit("/", 1)[-1]
        return normalized, f"{kind}:{normalized_url.casefold()}", normalized_url, name
    raise ValueError("unsupported-source-kind")


class WorkspaceStore:
    """Transactional management index; detailed audit artifacts remain on disk."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        legacy_jobs_path: str | Path | None = None,
        busy_timeout_ms: int = 5_000,
    ):
        self.db_path = Path(db_path)
        self.legacy_jobs_path = Path(legacy_jobs_path) if legacy_jobs_path else None
        self.busy_timeout_ms = int(busy_timeout_ms)
        self._schema_lock = threading.RLock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()
        if self.legacy_jobs_path is not None:
            self.import_legacy_jobs(self.legacy_jobs_path)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.db_path,
            timeout=max(0.1, self.busy_timeout_ms / 1000),
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        return connection

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._schema_lock, self.connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS projects (
                    project_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    source_json TEXT NOT NULL,
                    source_identity TEXT NOT NULL UNIQUE,
                    source_display TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active', 'archived')),
                    languages_json TEXT NOT NULL DEFAULT '[]',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    archived_at TEXT
                );

                CREATE TABLE IF NOT EXISTS runs (
                    job_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE RESTRICT,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL,
                    output_dir TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    run_dir TEXT,
                    summary_json TEXT NOT NULL DEFAULT '{}',
                    error TEXT NOT NULL DEFAULT '',
                    source_json TEXT,
                    phase TEXT NOT NULL DEFAULT 'queued',
                    requested_revision TEXT,
                    resolved_commit TEXT,
                    acquisition_summary_json TEXT NOT NULL DEFAULT '{}',
                    acquisition_ref TEXT,
                    cleanup_status TEXT,
                    request_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS runs_project_created_idx
                    ON runs(project_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS runs_status_idx ON runs(status);

                CREATE TABLE IF NOT EXISTS migration_receipts (
                    source_path TEXT NOT NULL,
                    source_fingerprint TEXT NOT NULL,
                    item_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    diagnostic TEXT NOT NULL DEFAULT '',
                    imported_at TEXT NOT NULL,
                    PRIMARY KEY(source_path, source_fingerprint, item_key)
                );

                CREATE TABLE IF NOT EXISTS event_index_state (
                    run_id TEXT PRIMARY KEY REFERENCES runs(job_id) ON DELETE CASCADE,
                    journal_path TEXT NOT NULL,
                    last_event_id INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS posture_snapshots (
                    run_id TEXT PRIMARY KEY REFERENCES runs(job_id) ON DELETE CASCADE,
                    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
                    schema_version TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS finding_identities (
                    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
                    fingerprint TEXT NOT NULL,
                    fingerprint_version TEXT NOT NULL,
                    first_run_id TEXT NOT NULL REFERENCES runs(job_id) ON DELETE RESTRICT,
                    last_run_id TEXT NOT NULL REFERENCES runs(job_id) ON DELETE RESTRICT,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    PRIMARY KEY(project_id, fingerprint, fingerprint_version)
                );
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (SCHEMA_VERSION, utc_now()),
            )

    def journal_mode(self) -> str:
        with self.connection() as connection:
            row = connection.execute("PRAGMA journal_mode").fetchone()
        return str(row[0]).lower() if row else ""

    def create_or_get_project(
        self,
        source: dict[str, Any],
        *,
        display_name: str | None = None,
        languages: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[Project, bool]:
        with self.transaction(immediate=True) as connection:
            return self._create_or_get_project(
                connection,
                source,
                display_name=display_name,
                languages=languages,
                metadata=metadata,
            )

    def _create_or_get_project(
        self,
        connection: sqlite3.Connection,
        source: dict[str, Any],
        *,
        display_name: str | None = None,
        languages: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[Project, bool]:
        normalized, identity, source_display, suggested_name = canonicalize_source(source)
        existing = connection.execute(
            "SELECT * FROM projects WHERE source_identity = ?", (identity,)
        ).fetchone()
        if existing:
            return self._project_from_row(existing), False
        now = utc_now()
        project_id = stable_id("PRJ", identity, now)
        connection.execute(
            """
            INSERT INTO projects(
                project_id, display_name, source_kind, source_json, source_identity,
                source_display, status, languages_json, metadata_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)
            """,
            (
                project_id,
                (display_name or suggested_name).strip() or suggested_name,
                normalized["kind"],
                _dump(normalized),
                identity,
                source_display,
                _dump(languages or []),
                _dump(metadata or {}),
                now,
                now,
            ),
        )
        row = connection.execute(
            "SELECT * FROM projects WHERE project_id = ?", (project_id,)
        ).fetchone()
        return self._project_from_row(row), True

    def create_job_record(
        self,
        record: dict[str, Any],
        *,
        project_id: str | None = None,
        source: dict[str, Any] | None = None,
        project_display_name: str | None = None,
        project_languages: list[dict[str, Any]] | None = None,
        project_metadata: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], Project, bool]:
        with self.transaction(immediate=True) as connection:
            created_project = False
            if project_id:
                project_row = connection.execute(
                    "SELECT * FROM projects WHERE project_id = ?", (project_id,)
                ).fetchone()
                if project_row is None:
                    raise KeyError(f"Unknown project: {project_id}")
                project = self._project_from_row(project_row)
            else:
                effective_source = source or {"kind": "local", "path": record["target"]}
                project, created_project = self._create_or_get_project(
                    connection,
                    effective_source,
                    display_name=project_display_name,
                    languages=project_languages,
                    metadata=project_metadata,
                )
            payload = dict(record)
            payload["project_id"] = project.project_id
            self._insert_run(connection, payload)
            return payload, project, created_project

    def get_project(self, project_id: str) -> Project:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM projects WHERE project_id = ?", (project_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"Unknown project: {project_id}")
            project = self._project_from_row(row)
            project.latest_run = self._latest_run(connection, project_id)
            return project

    def get_project_by_source(self, source: dict[str, Any]) -> Project | None:
        _normalized, identity, _display, _name = canonicalize_source(source)
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM projects WHERE source_identity = ?", (identity,)
            ).fetchone()
            if row is None:
                return None
            project = self._project_from_row(row)
            project.latest_run = self._latest_run(connection, project.project_id)
            return project

    def list_projects(
        self,
        *,
        query: str = "",
        status: str = "active",
        security_status: str = "",
        order: str = "recent",
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Project]:
        where, values, ordering = self._project_query(
            query=query,
            status=status,
            security_status=security_status,
            order=order,
        )
        suffix = ""
        if limit is not None:
            self._validate_page(limit, offset)
            suffix = " LIMIT ? OFFSET ?"
            values.extend([limit, offset])
        elif offset:
            raise ValueError("project-offset-requires-limit")
        with self.connection() as connection:
            rows = connection.execute(
                f"SELECT * FROM projects {where} ORDER BY {ordering}{suffix}", values
            ).fetchall()
            projects: list[Project] = []
            for row in rows:
                project = self._project_from_row(row)
                project.latest_run = self._latest_run(connection, project.project_id)
                projects.append(project)
            return projects

    def list_projects_page(
        self,
        *,
        query: str = "",
        status: str = "active",
        security_status: str = "",
        order: str = "recent",
        limit: int,
        offset: int,
    ) -> tuple[list[Project], int]:
        self._validate_page(limit, offset)
        where, values, _ordering = self._project_query(
            query=query,
            status=status,
            security_status=security_status,
            order=order,
        )
        with self.connection() as connection:
            row = connection.execute(
                f"SELECT COUNT(*) AS total FROM projects {where}", values
            ).fetchone()
        projects = self.list_projects(
            query=query,
            status=status,
            security_status=security_status,
            order=order,
            limit=limit,
            offset=offset,
        )
        return projects, int(row["total"] if row is not None else 0)

    @staticmethod
    def _project_query(
        *,
        query: str,
        status: str,
        security_status: str,
        order: str,
    ) -> tuple[str, list[Any], str]:
        clauses: list[str] = []
        values: list[Any] = []
        if status in {"active", "archived"}:
            clauses.append("status = ?")
            values.append(status)
        elif status != "all":
            raise ValueError("invalid-project-status-filter")
        if query.strip():
            clauses.append("(LOWER(display_name) LIKE ? OR LOWER(source_display) LIKE ?)")
            pattern = f"%{query.strip().lower()}%"
            values.extend([pattern, pattern])
        if security_status:
            if security_status not in RUN_STATUSES:
                raise ValueError("invalid-security-status-filter")
            clauses.append(
                """
                COALESCE((
                    SELECT latest.status FROM runs AS latest
                    WHERE latest.project_id = projects.project_id
                    ORDER BY latest.created_at DESC, latest.rowid DESC LIMIT 1
                ), '') = ?
                """
            )
            values.append(security_status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        ordering = "updated_at DESC, created_at DESC" if order == "recent" else "display_name COLLATE NOCASE ASC"
        if order not in {"recent", "name"}:
            raise ValueError("invalid-project-order")
        return where, values, ordering

    def rename_project(self, project_id: str, display_name: str) -> Project:
        cleaned = display_name.strip()
        if not cleaned:
            raise ValueError("project-name-required")
        with self.transaction(immediate=True) as connection:
            result = connection.execute(
                "UPDATE projects SET display_name = ?, updated_at = ? WHERE project_id = ?",
                (cleaned, utc_now(), project_id),
            )
            if result.rowcount != 1:
                raise KeyError(f"Unknown project: {project_id}")
        return self.get_project(project_id)

    def update_project_metadata(
        self,
        project_id: str,
        *,
        languages: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Project:
        project = self.get_project(project_id)
        next_languages = project.languages if languages is None else languages
        next_metadata = dict(project.metadata)
        if metadata:
            next_metadata.update(metadata)
        with self.transaction(immediate=True) as connection:
            connection.execute(
                """
                UPDATE projects SET languages_json = ?, metadata_json = ?, updated_at = ?
                WHERE project_id = ?
                """,
                (_dump(next_languages), _dump(next_metadata), utc_now(), project_id),
            )
        return self.get_project(project_id)

    def archive_project(self, project_id: str) -> Project:
        with self.transaction(immediate=True) as connection:
            row = connection.execute(
                "SELECT project_id FROM projects WHERE project_id = ?", (project_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"Unknown project: {project_id}")
            placeholders = ",".join("?" for _ in ACTIVE_RUN_STATUSES)
            active = connection.execute(
                f"SELECT 1 FROM runs WHERE project_id = ? AND status IN ({placeholders}) LIMIT 1",
                [project_id, *sorted(ACTIVE_RUN_STATUSES)],
            ).fetchone()
            if active:
                raise ValueError("project-has-active-runs")
            now = utc_now()
            connection.execute(
                "UPDATE projects SET status = 'archived', archived_at = ?, updated_at = ? WHERE project_id = ?",
                (now, now, project_id),
            )
        return self.get_project(project_id)

    def restore_project(self, project_id: str) -> Project:
        with self.transaction(immediate=True) as connection:
            result = connection.execute(
                """
                UPDATE projects SET status = 'active', archived_at = NULL, updated_at = ?
                WHERE project_id = ?
                """,
                (utc_now(), project_id),
            )
            if result.rowcount != 1:
                raise KeyError(f"Unknown project: {project_id}")
        return self.get_project(project_id)

    def get_job_record(self, job_id: str) -> dict[str, Any]:
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM runs WHERE job_id = ?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(f"Unknown job: {job_id}")
        return self._run_from_row(row)

    def list_job_records(
        self,
        project_id: str | None = None,
        *,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        suffix = ""
        values: list[Any] = []
        if project_id:
            where = "WHERE project_id = ?"
            values.append(project_id)
        else:
            where = ""
        if limit is not None:
            self._validate_page(limit, offset)
            suffix = " LIMIT ? OFFSET ?"
            values.extend([limit, offset])
        elif offset:
            raise ValueError("run-offset-requires-limit")
        with self.connection() as connection:
            rows = connection.execute(
                f"SELECT * FROM runs {where} ORDER BY created_at ASC, rowid ASC{suffix}",
                values,
            ).fetchall()
        return [self._run_from_row(row) for row in rows]

    def count_job_records(self, project_id: str | None = None) -> int:
        with self.connection() as connection:
            if project_id:
                row = connection.execute(
                    "SELECT COUNT(*) AS total FROM runs WHERE project_id = ?", (project_id,)
                ).fetchone()
            else:
                row = connection.execute("SELECT COUNT(*) AS total FROM runs").fetchone()
        return int(row["total"] if row is not None else 0)

    @staticmethod
    def _validate_page(limit: int, offset: int) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_PAGE_LIMIT:
            raise ValueError("invalid-page-limit")
        if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= MAX_PAGE_OFFSET:
            raise ValueError("invalid-page-offset")

    def update_job_record(self, record: dict[str, Any]) -> None:
        with self.transaction(immediate=True) as connection:
            result = connection.execute(
                """
                UPDATE runs SET
                    status = ?, started_at = ?, finished_at = ?, run_dir = ?, summary_json = ?,
                    error = ?, source_json = ?, phase = ?, requested_revision = ?, resolved_commit = ?,
                    acquisition_summary_json = ?, acquisition_ref = ?, cleanup_status = ?, request_json = ?
                WHERE job_id = ?
                """,
                (
                    record["status"],
                    record.get("started_at"),
                    record.get("finished_at"),
                    record.get("run_dir"),
                    _dump(record.get("summary") or {}),
                    record.get("error") or "",
                    _dump(record.get("source")) if record.get("source") is not None else None,
                    record.get("phase") or "queued",
                    record.get("requested_revision"),
                    record.get("resolved_commit"),
                    _dump(record.get("acquisition_summary") or {}),
                    record.get("acquisition_ref"),
                    record.get("cleanup_status"),
                    _dump(record.get("request_snapshot") or {}),
                    record["job_id"],
                ),
            )
            if result.rowcount != 1:
                raise KeyError(f"Unknown job: {record['job_id']}")
            connection.execute(
                "UPDATE projects SET updated_at = ? WHERE project_id = ?",
                (utc_now(), record["project_id"]),
            )

    def get_event_index(self, run_id: str) -> dict[str, Any] | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM event_index_state WHERE run_id = ?", (run_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def set_event_index(self, run_id: str, journal_path: str, last_event_id: int) -> None:
        if last_event_id < 0:
            raise ValueError("last event ID must be non-negative")
        with self.transaction(immediate=True) as connection:
            exists = connection.execute(
                "SELECT 1 FROM runs WHERE job_id = ?", (run_id,)
            ).fetchone()
            if exists is None:
                raise KeyError(f"Unknown job: {run_id}")
            connection.execute(
                """
                INSERT INTO event_index_state(run_id, journal_path, last_event_id, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    journal_path = excluded.journal_path,
                    last_event_id = excluded.last_event_id,
                    updated_at = excluded.updated_at
                """,
                (run_id, journal_path, last_event_id, utc_now()),
            )

    def list_event_indices(self) -> list[dict[str, Any]]:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM event_index_state ORDER BY run_id"
            ).fetchall()
        return [dict(row) for row in rows]

    def get_posture_snapshot(self, run_id: str) -> dict[str, Any] | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT snapshot_json FROM posture_snapshots WHERE run_id = ?", (run_id,)
            ).fetchone()
        return _load(row["snapshot_json"], None) if row is not None else None

    def list_posture_snapshots(self, project_id: str) -> list[dict[str, Any]]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT posture_snapshots.snapshot_json
                FROM posture_snapshots
                JOIN runs ON runs.job_id = posture_snapshots.run_id
                WHERE posture_snapshots.project_id = ?
                ORDER BY runs.created_at ASC, runs.rowid ASC
                """,
                (project_id,),
            ).fetchall()
        return [
            snapshot
            for row in rows
            if isinstance(snapshot := _load(row["snapshot_json"], None), dict)
        ]

    def upsert_posture_snapshot(self, snapshot: dict[str, Any]) -> None:
        run_id = str(snapshot.get("run_id") or "")
        project_id = str(snapshot.get("project_id") or "")
        schema_version = str(snapshot.get("schema_version") or "")
        if not run_id or not project_id or not schema_version:
            raise ValueError("posture snapshot identity and schema version are required")
        with self.transaction(immediate=True) as connection:
            run = connection.execute(
                "SELECT project_id FROM runs WHERE job_id = ?", (run_id,)
            ).fetchone()
            if run is None or run["project_id"] != project_id:
                raise ValueError("posture snapshot run/project mismatch")
            connection.execute(
                """
                INSERT INTO posture_snapshots(
                    run_id, project_id, schema_version, snapshot_json, created_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    project_id = excluded.project_id,
                    schema_version = excluded.schema_version,
                    snapshot_json = excluded.snapshot_json,
                    created_at = excluded.created_at
                """,
                (
                    run_id,
                    project_id,
                    schema_version,
                    _dump(snapshot),
                    str(snapshot.get("created_at") or utc_now()),
                ),
            )

    def upsert_finding_identity(
        self,
        *,
        project_id: str,
        fingerprint: str,
        fingerprint_version: str,
        run_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if not project_id or not fingerprint or not fingerprint_version or not run_id:
            raise ValueError("finding identity fields are required")
        with self.transaction(immediate=True) as connection:
            run = connection.execute(
                "SELECT project_id FROM runs WHERE job_id = ?", (run_id,)
            ).fetchone()
            if run is None or run["project_id"] != project_id:
                raise ValueError("finding identity run/project mismatch")
            connection.execute(
                """
                INSERT INTO finding_identities(
                    project_id, fingerprint, fingerprint_version,
                    first_run_id, last_run_id, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id, fingerprint, fingerprint_version) DO UPDATE SET
                    last_run_id = excluded.last_run_id,
                    metadata_json = excluded.metadata_json
                """,
                (
                    project_id,
                    fingerprint,
                    fingerprint_version,
                    run_id,
                    run_id,
                    _dump(metadata or {}),
                ),
            )

    def list_finding_identities(self, project_id: str) -> list[dict[str, Any]]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM finding_identities
                WHERE project_id = ? ORDER BY fingerprint_version, fingerprint
                """,
                (project_id,),
            ).fetchall()
        return [
            {
                **dict(row),
                "metadata": _load(row["metadata_json"], {}),
            }
            for row in rows
        ]

    def migration_diagnostics(self) -> list[dict[str, Any]]:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM migration_receipts WHERE status != 'imported' ORDER BY imported_at"
            ).fetchall()
        return [dict(row) for row in rows]

    def import_legacy_jobs(self, path: Path) -> None:
        if not path.is_file():
            return
        raw = path.read_bytes()
        fingerprint = hashlib.sha256(raw).hexdigest()
        source_path = str(path.resolve())
        try:
            payload = json.loads(raw.decode("utf-8"))
            jobs = payload.get("jobs", []) if isinstance(payload, dict) else payload
            if not isinstance(jobs, list):
                raise ValueError("legacy jobs payload must contain a list")
        except Exception as exc:
            self._record_migration_receipt(
                source_path,
                fingerprint,
                "__file__",
                "failed",
                redact_text(str(exc)),
            )
            return
        for index, item in enumerate(jobs):
            item_key = str(item.get("job_id") if isinstance(item, dict) else f"row-{index}")
            if self._has_migration_receipt(source_path, fingerprint, item_key):
                continue
            try:
                if not isinstance(item, dict):
                    raise ValueError("legacy job row must be an object")
                self._import_legacy_row(item)
                self._record_migration_receipt(source_path, fingerprint, item_key, "imported", "")
            except Exception as exc:
                self._record_migration_receipt(
                    source_path,
                    fingerprint,
                    item_key,
                    "failed",
                    redact_text(str(exc)),
                )

    def _import_legacy_row(self, item: dict[str, Any]) -> None:
        job_id = str(item.get("job_id") or "").strip()
        if not job_id:
            raise ValueError("legacy job_id is required")
        target = str(item.get("target") or "").strip()
        source = item.get("source") if isinstance(item.get("source"), dict) else None
        unresolved = False
        try:
            effective_source = source or {"kind": "local", "path": target}
            canonicalize_source(effective_source)
        except Exception:
            unresolved = True
            effective_source = {"kind": "local", "path": str(Path.cwd() / ".legacy" / job_id)}
        record = {
            "job_id": job_id,
            "target": target or f"legacy:{job_id}",
            "status": str(item.get("status") or "failed"),
            "output_dir": str(item.get("output_dir") or "runs"),
            "created_at": str(item.get("created_at") or utc_now()),
            "started_at": item.get("started_at"),
            "finished_at": item.get("finished_at"),
            "run_dir": item.get("run_dir"),
            "summary": item.get("summary") if isinstance(item.get("summary"), dict) else {},
            "error": str(item.get("error") or ""),
            "source": source,
            "phase": str(item.get("phase") or "queued"),
            "requested_revision": item.get("requested_revision"),
            "resolved_commit": item.get("resolved_commit"),
            "acquisition_summary": item.get("acquisition_summary")
            if isinstance(item.get("acquisition_summary"), dict)
            else {},
            "acquisition_ref": item.get("acquisition_ref"),
            "cleanup_status": item.get("cleanup_status"),
            "request_snapshot": {},
        }
        with self.transaction(immediate=True) as connection:
            project, _created = self._create_or_get_project(
                connection,
                effective_source,
                display_name=f"Legacy {job_id}" if unresolved else None,
                metadata={"legacy_unresolved": unresolved},
            )
            record["project_id"] = project.project_id
            self._insert_run(connection, record, ignore_existing=True)

    def _has_migration_receipt(self, source_path: str, fingerprint: str, item_key: str) -> bool:
        with self.connection() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM migration_receipts
                WHERE source_path = ? AND source_fingerprint = ? AND item_key = ?
                """,
                (source_path, fingerprint, item_key),
            ).fetchone()
        return row is not None

    def _record_migration_receipt(
        self,
        source_path: str,
        fingerprint: str,
        item_key: str,
        status: str,
        diagnostic: str,
    ) -> None:
        with self.transaction(immediate=True) as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO migration_receipts(
                    source_path, source_fingerprint, item_key, status, diagnostic, imported_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (source_path, fingerprint, item_key, status, diagnostic[:2_000], utc_now()),
            )

    def _insert_run(
        self,
        connection: sqlite3.Connection,
        record: dict[str, Any],
        *,
        ignore_existing: bool = False,
    ) -> None:
        verb = "INSERT OR IGNORE" if ignore_existing else "INSERT"
        connection.execute(
            f"""
            {verb} INTO runs(
                job_id, project_id, target, status, output_dir, created_at, started_at,
                finished_at, run_dir, summary_json, error, source_json, phase,
                requested_revision, resolved_commit, acquisition_summary_json,
                acquisition_ref, cleanup_status, request_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["job_id"],
                record["project_id"],
                record["target"],
                record["status"],
                record["output_dir"],
                record["created_at"],
                record.get("started_at"),
                record.get("finished_at"),
                record.get("run_dir"),
                _dump(record.get("summary") or {}),
                record.get("error") or "",
                _dump(record.get("source")) if record.get("source") is not None else None,
                record.get("phase") or "queued",
                record.get("requested_revision"),
                record.get("resolved_commit"),
                _dump(record.get("acquisition_summary") or {}),
                record.get("acquisition_ref"),
                record.get("cleanup_status"),
                _dump(record.get("request_snapshot") or {}),
            ),
        )

    def _project_from_row(self, row: sqlite3.Row) -> Project:
        return Project(
            project_id=row["project_id"],
            display_name=row["display_name"],
            source_kind=row["source_kind"],
            source=_load(row["source_json"], {}),
            source_identity=row["source_identity"],
            source_display=row["source_display"],
            status=row["status"],
            languages=_load(row["languages_json"], []),
            metadata=_load(row["metadata_json"], {}),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            archived_at=row["archived_at"],
        )

    def _run_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "job_id": row["job_id"],
            "project_id": row["project_id"],
            "target": row["target"],
            "status": row["status"],
            "output_dir": row["output_dir"],
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "run_dir": row["run_dir"],
            "summary": _load(row["summary_json"], {}),
            "error": row["error"],
            "source": _load(row["source_json"], None),
            "phase": row["phase"],
            "requested_revision": row["requested_revision"],
            "resolved_commit": row["resolved_commit"],
            "acquisition_summary": _load(row["acquisition_summary_json"], {}),
            "acquisition_ref": row["acquisition_ref"],
            "cleanup_status": row["cleanup_status"],
            "request_snapshot": _load(row["request_json"], {}),
        }

    def _latest_run(self, connection: sqlite3.Connection, project_id: str) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT * FROM runs WHERE project_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (project_id,),
        ).fetchone()
        return self._run_from_row(row) if row else None


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _load(value: str | None, default: Any) -> Any:
    if value is None:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
