from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path
from typing import Iterable

from .config import MemoryRuntimeConfig
from .models import MemoryRecord, MemoryRetrieval, RepositoryMetadata
from .storage import immutable_path


class LexicalMemoryStore:
    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.records: list[MemoryRecord] = []
        self.index_path = self.root / "memory-index.json"
        if self.index_path.exists():
            self.records = [
                MemoryRecord(**payload)
                for payload in json.loads(self.index_path.read_text(encoding="utf-8")).get("records", [])
            ]

    def add(self, record: MemoryRecord) -> MemoryRecord:
        self.records = [existing for existing in self.records if existing.id != record.id]
        self.records.append(record)
        self.persist()
        return record

    def persist(self) -> Path:
        path = immutable_path(self.root / "memory-index.json") if not self.index_path.exists() else self.index_path
        path.write_text(
            json.dumps({"records": [record.to_dict() for record in self.records]}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        self.index_path = path
        return path

    def retrieve(self, query: str, limit: int = 5) -> list[MemoryRetrieval]:
        query_terms = _terms(query)
        scored: list[tuple[float, MemoryRecord]] = []
        for record in self.records:
            terms = _terms(record.content)
            overlap = query_terms.intersection(terms)
            if overlap:
                score = len(overlap) / max(len(query_terms), 1)
                scored.append((score, record))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [
            MemoryRetrieval(
                record=record,
                score=score,
                query=query,
                citation=_citation(record),
                snippet=_snippet(record.content, query_terms),
            )
            for score, record in scored[:limit]
        ]

    def stale_records(self, metadata: RepositoryMetadata) -> list[MemoryRecord]:
        root = Path(metadata.root_path or ".")
        stale: list[MemoryRecord] = []
        for record in self.records:
            if record.namespace != "repository" or not record.source_path:
                continue
            path = root / record.source_path
            if not path.exists():
                stale.append(record)
                continue
            current = path.read_text(encoding="utf-8", errors="ignore")
            lines = current.splitlines()
            start = max((record.start_line or 1) - 1, 0)
            end = record.end_line or len(lines)
            content = "\n".join(lines[start:end])
            current_record = MemoryRecord(
                namespace=record.namespace,
                target_id=record.target_id,
                content=content,
                source_path=record.source_path,
                start_line=record.start_line,
                end_line=record.end_line,
                commit=metadata.commit,
            )
            if current_record.content_hash != record.content_hash:
                stale.append(record)
        return stale


class MemoryIndexer:
    def __init__(self, store: LexicalMemoryStore, config: MemoryRuntimeConfig | None = None):
        self.store = store
        self.config = config or MemoryRuntimeConfig()

    def index_repository(self, metadata: RepositoryMetadata, chunk_size: int = 40) -> list[MemoryRecord]:
        root = Path(metadata.root_path or ".")
        records: list[MemoryRecord] = []
        target_id = metadata.target.repo or metadata.target.path or metadata.target.source
        for relative in metadata.file_tree:
            if self._excluded(relative):
                continue
            path = root / relative
            if not path.exists() or path.stat().st_size > 1_000_000:
                continue
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            for start in range(0, len(lines), chunk_size):
                chunk = "\n".join(lines[start : start + chunk_size])
                if not chunk.strip():
                    continue
                record = MemoryRecord(
                    namespace="repository",
                    target_id=target_id,
                    content=_redact(chunk, self.config.redaction_patterns),
                    source_path=relative,
                    start_line=start + 1,
                    end_line=min(start + chunk_size, len(lines)),
                    commit=metadata.commit,
                )
                self.store.add(record)
                records.append(record)
        self.persist_metadata(metadata, records)
        return records

    def persist_metadata(self, metadata: RepositoryMetadata, records: list[MemoryRecord]) -> Path:
        path = self.store.root / "memory-metadata.json"
        path.write_text(
            json.dumps(
                {"target": metadata.target.to_dict(), "record_count": len(records), "mode": self.config.mode},
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        return path

    def _excluded(self, relative: str) -> bool:
        return any(fnmatch.fnmatch(relative, pattern) or relative.startswith(pattern.rstrip("/")) for pattern in self.config.exclude_patterns)


class EmbeddingMemoryStore:
    def __init__(self, fallback: LexicalMemoryStore):
        self.fallback = fallback
        self.degraded = True

    def retrieve(self, query: str, limit: int = 5) -> list[MemoryRetrieval]:
        return self.fallback.retrieve(query, limit)


def persist_retrievals(root: Path | str, retrievals: list[MemoryRetrieval], name: str = "retrieval") -> Path:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    path = immutable_path(root / f"{name}.json")
    path.write_text(
        json.dumps({"retrievals": [item.to_dict() for item in retrievals]}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path


def _terms(text: str) -> set[str]:
    return {term.lower() for term in re.findall(r"[A-Za-z0-9_./-]+", text) if len(term) > 1}


def _citation(record: MemoryRecord) -> str:
    if record.source_path:
        return f"{record.source_path}:{record.start_line or 1}-{record.end_line or record.start_line or 1}"
    return record.artifact_ref or record.id or ""


def _snippet(content: str, query_terms: set[str]) -> str:
    for line in content.splitlines():
        if _terms(line).intersection(query_terms):
            return line.strip()[:500]
    return content.strip()[:500]


def _redact(text: str, patterns: Iterable[str]) -> str:
    redacted = text
    for pattern in patterns:
        redacted = re.sub(rf"(?i)({re.escape(pattern)}\s*=\s*)['\"][^'\"]+['\"]", r"\1[REDACTED]", redacted)
    return redacted

