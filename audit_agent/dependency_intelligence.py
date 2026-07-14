from __future__ import annotations

import json
import os
import re
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Protocol

from .intelligence import CveMcpAdapter, normalize_cve_mcp_output
from .mcp_client import MCPClient
from .models import Dependency, ToolObservation, ToolResult, VulnerabilityIntelligence
from .redaction import redact_secrets, redact_text


CACHE_SCHEMA_VERSION = "dependency-intelligence-cache.v1"
SUMMARY_SCHEMA_VERSION = "dependency-intelligence-summary.v1"
MCP_MAX_DEPENDENCIES_PER_QUERY = 1000

_OSV_ECOSYSTEMS = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "go": "Go",
    "nuget": "NuGet",
    "crates.io": "crates.io",
    "crates": "crates.io",
    "cargo": "crates.io",
    "packagist": "Packagist",
    "rubygems": "RubyGems",
}

_DEPENDENCY_SCAN_ERROR_PREFIXES = (
    "empty dependency list",
    "could not parse any packages",
    "request timed out",
    "dependency scan error",
)


def dependency_key(dependency: Dependency) -> str:
    ecosystem = dependency.ecosystem.strip().lower()
    name = dependency.name.strip().lower()
    version = (dependency.version or "unknown").strip().lower()
    return f"{ecosystem}:{name}@{version}"


def dependency_payload(dependency: Dependency) -> dict[str, Any]:
    return {
        "dependency_key": dependency_key(dependency),
        "ecosystem": dependency.ecosystem,
        "name": dependency.name,
        "version": dependency.version,
        "queried_version": dependency_query_version(dependency),
        "manifest_path": dependency.manifest_path,
        "identifiers": dependency.identifiers,
    }


def dependency_batch_key(dependency: Dependency) -> str:
    return "maven" if dependency.ecosystem.strip().lower() == "maven" else "generic"


def serialize_dependency_list(dependencies: list[Dependency]) -> str:
    if not dependencies:
        raise ValueError("dependency batch must not be empty")
    if len(dependencies) > MCP_MAX_DEPENDENCIES_PER_QUERY:
        raise ValueError("dependency batch exceeds the MCP limit of 1000")
    modes = {dependency_batch_key(item) for item in dependencies}
    if len(modes) != 1:
        raise ValueError("Maven and generic dependencies must be queried in separate batches")
    if "maven" in modes:
        return _serialize_maven_dependencies(dependencies)
    lines = []
    for dependency in dependencies:
        ecosystem = _osv_ecosystem(dependency.ecosystem)
        query_version = dependency_query_version(dependency)
        values = (dependency.name, ecosystem, query_version)
        if any("\n" in value or "\r" in value or ":" in value for value in values):
            raise ValueError(
                f"dependency cannot be represented by the MCP generic format: {dependency_key(dependency)}"
            )
        lines.append(f"{dependency.name}:{ecosystem}:{query_version}")
    return "\n".join(lines)


def _serialize_maven_dependencies(dependencies: list[Dependency]) -> str:
    project = ET.Element("project")
    dependency_nodes = ET.SubElement(project, "dependencies")
    for dependency in dependencies:
        parts = dependency.name.split(":", 1)
        if len(parts) != 2 or not all(part.strip() for part in parts):
            raise ValueError(
                f"Maven dependency must use groupId:artifactId: {dependency_key(dependency)}"
            )
        node = ET.SubElement(dependency_nodes, "dependency")
        ET.SubElement(node, "groupId").text = parts[0].strip()
        ET.SubElement(node, "artifactId").text = parts[1].strip()
        query_version = dependency_query_version(dependency)
        if query_version:
            ET.SubElement(node, "version").text = query_version
    return ET.tostring(project, encoding="unicode")


def _osv_ecosystem(ecosystem: str) -> str:
    normalized = ecosystem.strip()
    return _OSV_ECOSYSTEMS.get(normalized.lower(), normalized)


def dependency_query_version(dependency: Dependency) -> str:
    version = (dependency.version or "").strip()
    if not version:
        return ""
    ecosystem = dependency.ecosystem.strip().lower()
    if ecosystem == "npm":
        if version.lower() in {"*", "latest"} or version.startswith(("workspace:", "file:")):
            return ""
        return re.sub(r"^[\^~>=<\s]+", "", version).strip()
    if ecosystem in {"cargo", "crates", "crates.io"}:
        return re.sub(r"^[\^~>=<\s]+", "", version).strip()
    if ecosystem == "pypi":
        candidate = re.sub(r"^[><=!~\s]+", "", version).strip()
        match = re.match(r"[A-Za-z0-9_.\-*]+", candidate)
        return match.group(0) if match else ""
    return version


@dataclass
class DependencyBatchResponse:
    success: bool
    records_by_dependency: dict[str, list[VulnerabilityIntelligence]] = field(default_factory=dict)
    message: str = ""


class DependencyBatchProvider(Protocol):
    def query(self, dependencies: list[Dependency]) -> DependencyBatchResponse: ...


@dataclass
class DependencyIntelligenceRun:
    intelligence: list[VulnerabilityIntelligence]
    tool_result: ToolResult
    summary: dict[str, Any]


class DependencyIntelligenceCache:
    def __init__(self, path: Path | None, ttl_seconds: int):
        self.path = path
        self.ttl_seconds = ttl_seconds
        self.entries: dict[str, dict[str, Any]] = {}
        self.dirty = False
        if path and path.exists():
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                if payload.get("schema_version") == CACHE_SCHEMA_VERSION:
                    self.entries = dict(payload.get("entries") or {})
            except (OSError, json.JSONDecodeError, AttributeError, TypeError):
                self.entries = {}

    def get(self, key: str) -> tuple[bool, list[VulnerabilityIntelligence]]:
        entry = self.entries.get(key)
        if not entry:
            return False, []
        cached_at = float(entry.get("cached_at_epoch") or 0)
        if self.ttl_seconds and time.time() - cached_at > self.ttl_seconds:
            return False, []
        records = []
        for item in entry.get("records") or []:
            if not isinstance(item, dict):
                continue
            allowed = {field.name for field in fields(VulnerabilityIntelligence)}
            values = {name: value for name, value in item.items() if name in allowed}
            try:
                records.append(VulnerabilityIntelligence(**values))
            except TypeError:
                continue
        return True, records

    def put(self, key: str, records: list[VulnerabilityIntelligence]) -> None:
        self.entries[key] = {
            "cached_at_epoch": time.time(),
            "records": [redact_secrets(item.to_dict()) for item in records],
        }
        self.dirty = True

    def flush(self) -> None:
        if not self.path or not self.dirty:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        current = {}
        if self.path.exists():
            try:
                payload = json.loads(self.path.read_text(encoding="utf-8"))
                if payload.get("schema_version") == CACHE_SCHEMA_VERSION:
                    current = dict(payload.get("entries") or {})
            except (OSError, json.JSONDecodeError, AttributeError, TypeError):
                current = {}
        current.update(self.entries)
        payload = {
            "schema_version": CACHE_SCHEMA_VERSION,
            "updated_at_epoch": time.time(),
            "entries": current,
        }
        temporary = self.path.with_name(f".{self.path.name}.{uuid.uuid4().hex}.tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temporary, self.path)
        self.dirty = False


class DependencyIntelligenceService:
    def __init__(
        self,
        provider: DependencyBatchProvider | None,
        *,
        batch_size: int,
        query_budget: int,
        cache_path: Path | None,
        cache_ttl_seconds: int,
    ):
        self.provider = provider
        self.batch_size = max(1, int(batch_size))
        self.query_budget = max(0, int(query_budget))
        self.cache = DependencyIntelligenceCache(cache_path, cache_ttl_seconds)

    def scan(self, dependencies: list[Dependency]) -> DependencyIntelligenceRun:
        unique: dict[str, Dependency] = {}
        manifests: dict[str, list[str]] = {}
        for dependency in dependencies:
            key = dependency_key(dependency)
            unique.setdefault(key, dependency)
            manifests.setdefault(key, [])
            if dependency.manifest_path not in manifests[key]:
                manifests[key].append(dependency.manifest_path)

        items = {
            key: {
                **dependency_payload(dependency),
                "manifest_paths": manifests[key],
                "status": "pending",
                "vulnerability_count": 0,
                "vulnerability_ids": [],
            }
            for key, dependency in unique.items()
        }
        records_by_key: dict[str, list[VulnerabilityIntelligence]] = {}
        pending: list[Dependency] = []
        cache_hits = 0
        for key, dependency in unique.items():
            hit, records = self.cache.get(key)
            if hit:
                records_by_key[key] = records
                items[key]["status"] = "cached"
                cache_hits += 1
                self._record_item_vulnerabilities(items[key], records)
            else:
                pending.append(dependency)

        queries_used = 0
        degraded_count = 0
        budget_exhausted_count = 0
        disabled_count = 0
        if self.provider is None:
            for dependency in pending:
                items[dependency_key(dependency)]["status"] = "disabled"
                disabled_count += 1
        else:
            grouped: dict[str, list[Dependency]] = {}
            batch_key = getattr(self.provider, "batch_key", None)
            for dependency in pending:
                group = str(batch_key(dependency)) if callable(batch_key) else "default"
                grouped.setdefault(group, []).append(dependency)
            for grouped_dependencies in grouped.values():
                for offset in range(0, len(grouped_dependencies), self.batch_size):
                    batch = grouped_dependencies[offset : offset + self.batch_size]
                    if queries_used >= self.query_budget:
                        for dependency in batch:
                            items[dependency_key(dependency)]["status"] = "budget-exhausted"
                            budget_exhausted_count += 1
                        continue
                    queries_used += 1
                    try:
                        response = self.provider.query(batch)
                    except Exception as exc:  # pragma: no cover - provider safety boundary
                        response = DependencyBatchResponse(
                            False, message=f"provider-error: {type(exc).__name__}"
                        )
                    if not response.success:
                        for dependency in batch:
                            item = items[dependency_key(dependency)]
                            item["status"] = "degraded"
                            item["message"] = redact_text(response.message)
                            degraded_count += 1
                        continue
                    for dependency in batch:
                        key = dependency_key(dependency)
                        records = list(response.records_by_dependency.get(key, []))
                        records_by_key[key] = records
                        items[key]["status"] = "queried"
                        self._record_item_vulnerabilities(items[key], records)
                        self.cache.put(key, records)
        self.cache.flush()

        intelligence = [
            item
            for key in unique
            for item in records_by_key.get(key, [])
        ]
        observations = self._observations(unique, records_by_key)
        covered_dependency_count = sum(
            item["status"] in {"cached", "queried"} for item in items.values()
        )
        unqueried_dependency_count = len(unique) - covered_dependency_count
        complete = unqueried_dependency_count == 0
        summary = {
            "schema_version": SUMMARY_SCHEMA_VERSION,
            "input_dependency_count": len(dependencies),
            "unique_dependency_count": len(unique),
            "batch_size": self.batch_size,
            "query_budget": self.query_budget,
            "queries_used": queries_used,
            "cache_hits": cache_hits,
            "queried_dependency_count": sum(item["status"] == "queried" for item in items.values()),
            "covered_dependency_count": covered_dependency_count,
            "unqueried_dependency_count": unqueried_dependency_count,
            "budget_exhausted_count": budget_exhausted_count,
            "degraded_count": degraded_count,
            "disabled_count": disabled_count,
            "vulnerability_record_count": len(intelligence),
            "complete": complete,
            "items": list(items.values()),
        }
        success = complete
        tool_result = ToolResult(
            tool_name="dependency-intelligence",
            inputs={
                "dependency_count": len(dependencies),
                "unique_dependency_count": len(unique),
                "batch_size": self.batch_size,
                "query_budget": self.query_budget,
            },
            success=success,
            exit_status=0 if success else 1,
            observations=observations,
            message=(
                f"{len(unique)} unique dependencies; {cache_hits} cache hits; "
                f"{queries_used} queries; {len(observations)} vulnerability observations; "
                f"coverage {covered_dependency_count}/{len(unique)}"
            ),
        )
        return DependencyIntelligenceRun(intelligence, tool_result, summary)

    @staticmethod
    def _record_item_vulnerabilities(
        item: dict[str, Any], records: list[VulnerabilityIntelligence]
    ) -> None:
        identifiers = [record.cve_id for record in records if record.cve_id]
        item["vulnerability_count"] = len(records)
        item["vulnerability_ids"] = identifiers

    @staticmethod
    def _observations(
        dependencies: dict[str, Dependency],
        records_by_key: dict[str, list[VulnerabilityIntelligence]],
    ) -> list[ToolObservation]:
        observations = []
        for key, dependency in dependencies.items():
            for record in records_by_key.get(key, []):
                vulnerability_id = record.cve_id or _first_vulnerability_id(record.raw)
                if not vulnerability_id:
                    continue
                severity = _severity_from_intelligence(record)
                observations.append(
                    ToolObservation(
                        tool_name="dependency-intelligence",
                        kind="dependency-vulnerability",
                        message=(
                            f"{dependency.name}@{dependency.version or 'unknown'} is affected by "
                            f"{vulnerability_id}."
                        ),
                        path=dependency.manifest_path,
                        line=1,
                        severity=severity,
                        vulnerability_class="dependency-vulnerability",
                        evidence=(
                            f"{dependency.ecosystem}:{dependency.name}@"
                            f"{dependency.version or 'unknown'} -> {vulnerability_id}"
                        ),
                        raw={
                            "schema_version": "dependency-vulnerability-observation.v1",
                            "dependency": dependency_payload(dependency),
                            "vulnerability_id": vulnerability_id,
                            "cve_ids": [vulnerability_id] if vulnerability_id.startswith("CVE-") else [],
                            "cwe_ids": list(record.cwe_ids),
                            "cvss": record.cvss,
                            "references": list(record.references),
                            "intelligence_ref": record.id,
                            "source": record.tool_name,
                        },
                    )
                )
        return observations


class RuntimeMcpBatchProvider:
    def __init__(
        self,
        command: list[str],
        timeout_seconds: int,
        query_budget: int,
        allowed_tools: list[str],
        cwd: str | None,
        env: dict[str, str],
    ):
        self.client = MCPClient(
            command,
            timeout_seconds,
            query_budget,
            allowed_tools=allowed_tools,
            cwd=cwd,
            env=env,
        )
        self._started = False
        self._tools: dict[str, Any] | None = None

    @staticmethod
    def batch_key(dependency: Dependency) -> str:
        return dependency_batch_key(dependency)

    def __enter__(self) -> "RuntimeMcpBatchProvider":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.client.close()

    def query(self, dependencies: list[Dependency]) -> DependencyBatchResponse:
        if not self._started:
            self.client.start()
            self._started = True
        if not self.client.session.initialized:
            return DependencyBatchResponse(
                False,
                message=self.client.session.message or "MCP session is not initialized.",
            )
        if self._tools is None:
            self._tools = {tool.name: tool for tool in self.client.list_tools()}
        tool = self._tools.get("scan_dependencies")
        if tool is None:
            return DependencyBatchResponse(False, message="MCP scan_dependencies tool is unavailable.")
        try:
            arguments = dependency_scan_arguments(dependencies, tool.input_schema)
        except ValueError as exc:
            return DependencyBatchResponse(False, message=str(exc))
        result = self.client.call_tool(
            "scan_dependencies",
            arguments,
        )
        if not result.success:
            return DependencyBatchResponse(False, message=result.message)
        return normalize_dependency_batch_response(result.response, dependencies, "cve-mcp-server")


class CommandMcpBatchProvider:
    def __init__(self, adapter: CveMcpAdapter):
        self.adapter = adapter

    @staticmethod
    def batch_key(dependency: Dependency) -> str:
        return dependency_batch_key(dependency)

    def query(self, dependencies: list[Dependency]) -> DependencyBatchResponse:
        try:
            arguments = dependency_scan_arguments(dependencies)
        except ValueError as exc:
            return DependencyBatchResponse(False, message=str(exc))
        observation = self.adapter.query(
            "scan_dependencies",
            arguments,
        )
        if not observation.success:
            return DependencyBatchResponse(False, message=observation.message)
        try:
            payload = json.loads(observation.message)
        except json.JSONDecodeError:
            payload = {"text": observation.message}
        return normalize_dependency_batch_response(payload, dependencies, self.adapter.tool_name)


def dependency_scan_arguments(
    dependencies: list[Dependency],
    input_schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    properties = (input_schema or {}).get("properties") or {}
    if not properties or "dependency_list" in properties:
        return {"dependency_list": serialize_dependency_list(dependencies)}
    if "dependencies" in properties:
        return {"dependencies": [dependency_payload(item) for item in dependencies]}
    if {"ecosystem", "packages"}.issubset(properties):
        ecosystems = {_osv_ecosystem(item.ecosystem) for item in dependencies}
        if len(ecosystems) != 1:
            raise ValueError("MCP ecosystem/packages schema requires one ecosystem per batch")
        return {
            "ecosystem": next(iter(ecosystems)),
            "packages": {item.name: item.version or "" for item in dependencies},
        }
    raise ValueError("MCP scan_dependencies input schema is unsupported")


def normalize_dependency_batch_response(
    raw: Any,
    dependencies: list[Dependency],
    tool_name: str,
) -> DependencyBatchResponse:
    text = _response_text(raw)
    if text is not None:
        return _normalize_dependency_text_response(text, dependencies, tool_name)
    records_by_dependency = {dependency_key(item): [] for item in dependencies}
    candidates = _response_candidates(raw)
    unmatched_vulnerabilities = 0
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        key = _match_dependency_key(candidate, dependencies)
        vulnerabilities = _candidate_vulnerabilities(candidate)
        if key is None:
            unmatched_vulnerabilities += len(vulnerabilities)
            continue
        dependency = next(item for item in dependencies if dependency_key(item) == key)
        for vulnerability in vulnerabilities:
            normalized = dict(vulnerability)
            aliases = normalized.get("aliases") or []
            if not normalized.get("cve_id"):
                cve_alias = next(
                    (alias for alias in aliases if str(alias).upper().startswith("CVE-")),
                    None,
                )
                if cve_alias:
                    normalized["cve_id"] = cve_alias
            records_by_dependency[key].append(
                normalize_cve_mcp_output(
                    normalized,
                    query=dependency_payload(dependency),
                    tool_name=tool_name,
                )
            )
    if unmatched_vulnerabilities:
        return DependencyBatchResponse(
            False,
            message=(
                f"CVE MCP returned {unmatched_vulnerabilities} vulnerabilities without "
                "an unambiguous dependency identity."
            ),
        )
    return DependencyBatchResponse(True, records_by_dependency)


def _response_text(raw: Any) -> str | None:
    if isinstance(raw, str):
        return raw
    if isinstance(raw, dict) and isinstance(raw.get("text"), str):
        return raw["text"]
    return None


def _normalize_dependency_text_response(
    text: str,
    dependencies: list[Dependency],
    tool_name: str,
) -> DependencyBatchResponse:
    records_by_dependency = {dependency_key(item): [] for item in dependencies}
    stripped = text.strip()
    lowered = stripped.lower()
    if any(lowered.startswith(prefix) for prefix in _DEPENDENCY_SCAN_ERROR_PREFIXES):
        return DependencyBatchResponse(False, message=redact_text(stripped))

    no_vulnerabilities = re.fullmatch(
        r"No known vulnerabilities found in\s+(\d+)\s+scanned packages\.\s*"
        r"\(via OSV\.dev\)",
        stripped,
        flags=re.IGNORECASE,
    )
    if no_vulnerabilities:
        scanned_count = int(no_vulnerabilities.group(1))
        if scanned_count != len(dependencies):
            return DependencyBatchResponse(
                False,
                message=(
                    f"CVE MCP reported {scanned_count} scanned dependencies for a "
                    f"batch of {len(dependencies)}."
                ),
            )
        return DependencyBatchResponse(True, records_by_dependency)

    summary = re.search(
        r"Dependency Scan Results\s*\(\s*(\d+)\s+vulnerable\s+out\s+of\s+"
        r"(\d+)\s+packages\s*\)",
        stripped,
        flags=re.IGNORECASE,
    )
    if not summary:
        return DependencyBatchResponse(
            False,
            message="CVE MCP returned an unsupported dependency scan response.",
        )
    vulnerable_count = int(summary.group(1))
    scanned_count = int(summary.group(2))
    if scanned_count != len(dependencies):
        return DependencyBatchResponse(
            False,
            message=(
                f"CVE MCP reported {scanned_count} scanned dependencies for a "
                f"batch of {len(dependencies)}."
            ),
        )

    labels: dict[str, list[str]] = {}
    dependencies_by_key = {dependency_key(item): item for item in dependencies}
    for key, dependency in dependencies_by_key.items():
        label = _dependency_output_label(dependency).casefold()
        labels.setdefault(label, []).append(key)

    package_pattern = re.compile(
        r"^\s*(?P<label>.+?)\s{2,}.*?\s+(?P<count>\d+)\s+"
        r"vulnerabilit(?:y|ies)(?:/vulnerabilities)?\s*$",
        flags=re.IGNORECASE,
    )
    vulnerability_pattern = re.compile(
        r"^\s*\[(?P<severity>[A-Za-z]+)\]\s+"
        r"(?P<identifier>\S+)(?:\s+\((?P<cve>CVE-\d{4}-\d+)\))?"
        r":\s*(?P<summary>.*)$",
        flags=re.IGNORECASE,
    )
    current_key: str | None = None
    package_headers: set[str] = set()
    package_record_counts: dict[str, int] = {}
    for line in stripped.splitlines()[1:]:
        package_match = package_pattern.match(line)
        if package_match:
            matches = labels.get(package_match.group("label").strip().casefold(), [])
            if len(matches) != 1:
                return DependencyBatchResponse(
                    False,
                    message=(
                        "CVE MCP returned vulnerabilities without an unambiguous "
                        "dependency identity."
                    ),
                )
            current_key = matches[0]
            if current_key in package_headers:
                return DependencyBatchResponse(
                    False,
                    message="CVE MCP returned a duplicate dependency result.",
                )
            package_headers.add(current_key)
            package_record_counts[current_key] = 0
            continue
        vulnerability_match = vulnerability_pattern.match(line)
        if not vulnerability_match:
            continue
        if current_key is None:
            return DependencyBatchResponse(
                False,
                message="CVE MCP returned a vulnerability without a dependency header.",
            )
        identifier = vulnerability_match.group("identifier")
        cve_id = vulnerability_match.group("cve")
        raw = {
            "id": identifier,
            "cve_id": cve_id or identifier,
            "aliases": [cve_id] if cve_id else [],
            "severity": vulnerability_match.group("severity").upper(),
            "summary": vulnerability_match.group("summary").strip(),
            "references": [],
        }
        records_by_dependency[current_key].append(
            normalize_cve_mcp_output(
                raw,
                query=dependency_payload(dependencies_by_key[current_key]),
                tool_name=tool_name,
            )
        )
        package_record_counts[current_key] += 1

    if len(package_headers) != vulnerable_count:
        return DependencyBatchResponse(
            False,
            message=(
                f"CVE MCP declared {vulnerable_count} vulnerable dependencies but "
                f"returned {len(package_headers)} identifiable package sections."
            ),
        )
    if any(package_record_counts.get(key, 0) == 0 for key in package_headers):
        return DependencyBatchResponse(
            False,
            message="CVE MCP returned a vulnerable dependency without advisory records.",
        )
    return DependencyBatchResponse(True, records_by_dependency)


def _dependency_output_label(dependency: Dependency) -> str:
    query_version = dependency_query_version(dependency)
    version = f"@{query_version}" if query_version else ""
    return f"{_osv_ecosystem(dependency.ecosystem)}/{dependency.name}{version}"


def _response_candidates(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if not isinstance(raw, dict):
        return []
    for key in ("results", "dependencies", "packages"):
        value = raw.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    if any(key in raw for key in ("vulnerabilities", "vulns", "advisories", "cve_id")):
        return [raw]
    return []


def _match_dependency_key(candidate: dict[str, Any], dependencies: list[Dependency]) -> str | None:
    explicit = candidate.get("dependency_key") or candidate.get("key")
    known = {dependency_key(item) for item in dependencies}
    if explicit in known:
        return str(explicit)
    package = candidate.get("package") if isinstance(candidate.get("package"), dict) else candidate
    if isinstance(candidate.get("dependency"), dict):
        package = candidate["dependency"]
    name = str(package.get("name") or package.get("package") or "").lower()
    ecosystem = str(package.get("ecosystem") or "").lower()
    version = str(package.get("version") or "").lower()
    matches = []
    for dependency in dependencies:
        if name and dependency.name.lower() != name:
            continue
        if ecosystem and dependency.ecosystem.lower() != ecosystem:
            continue
        if version and (dependency.version or "").lower() != version:
            continue
        if name:
            matches.append(dependency_key(dependency))
    if len(matches) == 1:
        return matches[0]
    if len(dependencies) == 1:
        return dependency_key(dependencies[0])
    return None


def _candidate_vulnerabilities(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("vulnerabilities", "vulns", "advisories"):
        value = candidate.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            return [value]
    identifier = candidate.get("cve_id") or candidate.get("id")
    if identifier and _looks_like_vulnerability_id(str(identifier)):
        return [candidate]
    return []


def _looks_like_vulnerability_id(value: str) -> bool:
    upper = value.upper()
    return upper.startswith(("CVE-", "GHSA-", "PYSEC-", "OSV-"))


def _first_vulnerability_id(raw: dict[str, Any]) -> str | None:
    value = raw.get("cve_id") or raw.get("id")
    if value and _looks_like_vulnerability_id(str(value)):
        return str(value)
    for alias in raw.get("aliases") or []:
        if _looks_like_vulnerability_id(str(alias)):
            return str(alias)
    return None


def _severity_from_intelligence(record: VulnerabilityIntelligence) -> str:
    raw_severity = str(record.raw.get("severity") or "").strip().lower()
    if raw_severity in {"critical", "high", "medium", "low"}:
        return raw_severity
    if record.cvss is None:
        return "medium"
    if record.cvss >= 9:
        return "critical"
    if record.cvss >= 7:
        return "high"
    if record.cvss >= 4:
        return "medium"
    return "low"


def cache_path_for_policy(
    policy: str,
    configured_path: str,
    run_dir: Path,
) -> Path | None:
    if policy == "disabled":
        return None
    if policy == "per-run":
        return run_dir / "intelligence" / "dependency-cache.v1.json"
    return Path(configured_path)


def summary_without_dependencies() -> dict[str, Any]:
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "input_dependency_count": 0,
        "unique_dependency_count": 0,
        "batch_size": 0,
        "query_budget": 0,
        "queries_used": 0,
        "cache_hits": 0,
        "queried_dependency_count": 0,
        "covered_dependency_count": 0,
        "unqueried_dependency_count": 0,
        "budget_exhausted_count": 0,
        "degraded_count": 0,
        "disabled_count": 0,
        "vulnerability_record_count": 0,
        "complete": True,
        "items": [],
    }
