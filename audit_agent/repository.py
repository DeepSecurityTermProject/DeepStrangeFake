from __future__ import annotations

import json
import os
import re
import subprocess
import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from .config import DEFAULT_AUDIT_EXCLUDE_PATTERNS, AuditScope
from .models import AttackSurface, AuditTarget, Dependency, RepositoryMetadata


LANGUAGE_BY_EXTENSION = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".php": "PHP",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".hpp": "C++",
    ".rb": "Ruby",
    ".cs": "C#",
    ".kt": "Kotlin",
}

IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    ".pytest_cache",
    ".mypy_cache",
    ".cache",
    "runs",
}


@dataclass(frozen=True)
class _IgnoreRule:
    pattern: str
    negated: bool = False
    directory_only: bool = False


def parse_target(source: str) -> AuditTarget:
    parsed = urlparse(source)
    if parsed.scheme in {"http", "https", "ssh"} and parsed.netloc:
        host = parsed.netloc.lower()
        parts = [part for part in parsed.path.strip("/").split("/") if part]
        repo = parts[-1].removesuffix(".git") if parts else None
        owner = "/".join(parts[:-1]) if len(parts) > 1 else None
        kind = "github" if "github.com" in host else "gitlab" if "gitlab.com" in host else "git"
        return AuditTarget(source=source, kind=kind, url=source, owner=owner, repo=repo)

    path = Path(source).expanduser()
    return AuditTarget(source=source, kind="local", path=str(path.resolve()))


def analyze_target(
    source: str,
    allow_clone: bool = False,
    checkout_dir: str | Path | None = None,
    audit_scope: AuditScope | None = None,
) -> RepositoryMetadata:
    scope = audit_scope or AuditScope()
    target = parse_target(source)
    if target.kind != "local":
        if allow_clone:
            checkout_path, commit = checkout_remote_target(target, checkout_dir)
            target.path = str(checkout_path)
            target.commit = commit
            return _analyze_local_path(target, checkout_path, scope)
        return RepositoryMetadata(target=target)

    path = Path(target.path or source).resolve()
    return _analyze_local_path(target, path, scope)


def checkout_remote_target(
    target: AuditTarget, checkout_dir: str | Path | None = None, timeout: int = 120
) -> tuple[Path, str | None]:
    if not target.url:
        raise ValueError("Remote target URL is required for checkout.")
    root = Path(checkout_dir or ".audit-checkouts").resolve()
    root.mkdir(parents=True, exist_ok=True)
    repo_name = target.repo or "repository"
    destination = root / repo_name
    if not destination.exists():
        subprocess.run(
            ["git", "clone", "--depth", "1", target.url, str(destination)],
            check=True,
            timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    commit = _git_commit(destination)
    return destination, commit


def _analyze_local_path(target: AuditTarget, path: Path, scope: AuditScope) -> RepositoryMetadata:
    if not path.exists() or not path.is_dir():
        raise FileNotFoundError(f"Target directory does not exist: {path}")
    file_tree = list(_file_tree(path, scope))
    file_categories = {relative: source_category(relative) for relative in file_tree}
    languages = _detect_languages(path, file_tree)
    dominant_language = max(languages.items(), key=lambda item: item[1])[0] if languages else None
    dependencies = _discover_dependencies(path, file_tree)
    attack_surfaces = _discover_attack_surfaces(path, file_tree)
    commit = _git_commit(path)
    target.commit = commit
    target.path = str(path)
    return RepositoryMetadata(
        target=target,
        root_path=str(path),
        commit=commit,
        dominant_language=dominant_language,
        languages=languages,
        file_tree=file_tree,
        file_categories=file_categories,
        dependencies=dependencies,
        attack_surfaces=attack_surfaces,
    )


def _file_tree(root: Path, scope: AuditScope) -> Iterable[str]:
    gitignore_rules = _load_gitignore(root)
    emitted_files = 0
    emitted_bytes = 0
    for current, dirs, files in os.walk(root):
        dirs[:] = [dirname for dirname in dirs if dirname not in IGNORED_DIRS]
        for filename in sorted(files):
            full_path = Path(current) / filename
            relative = full_path.relative_to(root).as_posix()
            if any(part in IGNORED_DIRS for part in relative.split("/")):
                continue
            if not _included_by_scope(relative, scope, gitignore_rules):
                continue
            try:
                size = full_path.stat().st_size
            except OSError:
                continue
            if scope.max_files is not None and emitted_files >= scope.max_files:
                return
            if scope.max_bytes is not None and emitted_bytes + size > scope.max_bytes:
                return
            emitted_files += 1
            emitted_bytes += size
            yield relative


def _detect_languages(root: Path, file_tree: list[str]) -> dict[str, int]:
    languages: dict[str, int] = {}
    for relative in file_tree:
        relative_path = Path(relative)
        language = LANGUAGE_BY_EXTENSION.get(relative_path.suffix.lower())
        if relative_path.name == "package.json":
            language = "JavaScript"
        if not language:
            continue
        try:
            size = max((root / relative).stat().st_size, 1)
        except OSError:
            size = 1
        languages[language] = languages.get(language, 0) + size
    return dict(sorted(languages.items(), key=lambda item: item[1], reverse=True))


def _discover_dependencies(root: Path, file_tree: list[str]) -> list[Dependency]:
    dependencies: list[Dependency] = []
    manifest_paths = [root / relative for relative in file_tree]
    for manifest in [path for path in manifest_paths if path.name == "requirements.txt"]:
        for line in manifest.read_text(encoding="utf-8", errors="ignore").splitlines():
            parsed = _parse_requirement(line)
            if parsed:
                name, version = parsed
                dependencies.append(_dependency("pypi", name, version, manifest, root))

    for manifest in [path for path in manifest_paths if path.name == "package.json"]:
        try:
            payload = json.loads(manifest.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        for section in ("dependencies", "devDependencies"):
            for name, version in payload.get(section, {}).items():
                dependencies.append(_dependency("npm", name, str(version), manifest, root))

    for manifest in [path for path in manifest_paths if path.name == "go.mod"]:
        for line in manifest.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.strip().startswith("require "):
                parts = line.split()
                if len(parts) >= 3:
                    dependencies.append(_dependency("go", parts[1], parts[2], manifest, root))

    for manifest in [path for path in manifest_paths if path.name == "Cargo.toml"]:
        in_dependencies = False
        for line in manifest.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if stripped == "[dependencies]":
                in_dependencies = True
                continue
            if stripped.startswith("[") and stripped != "[dependencies]":
                in_dependencies = False
            if in_dependencies and "=" in stripped and not stripped.startswith("#"):
                name, version = stripped.split("=", 1)
                dependencies.append(_dependency("cargo", name.strip(), version.strip().strip('"'), manifest, root))

    return dependencies


def _parse_requirement(line: str) -> tuple[str, str | None] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith("-"):
        return None
    match = re.match(r"^([A-Za-z0-9_.-]+)\s*([<>=!~].*)?$", stripped)
    if not match:
        return None
    name = match.group(1)
    version_spec = match.group(2)
    version = version_spec.lstrip("=<>!~ ") if version_spec else None
    return name, version


def _dependency(ecosystem: str, name: str, version: str | None, manifest: Path, root: Path) -> Dependency:
    normalized_name = name.lower()
    identifiers = {
        "osv": {"ecosystem": ecosystem, "name": name, "version": version},
        "github_advisory": {"ecosystem": ecosystem, "package": name},
        "nvd_keywords": [name, version] if version else [name],
        "cve_mcp_product": normalized_name,
        "purl": f"pkg:{ecosystem}/{normalized_name}" + (f"@{version}" if version else ""),
    }
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        manifest_path=manifest.relative_to(root).as_posix(),
        identifiers=identifiers,
    )


def _discover_attack_surfaces(root: Path, file_tree: list[str]) -> list[AttackSurface]:
    surfaces: list[AttackSurface] = []
    for relative in file_tree:
        suffix = Path(relative).suffix.lower()
        if suffix not in LANGUAGE_BY_EXTENSION:
            continue
        file_path = root / relative
        text = file_path.read_text(encoding="utf-8", errors="ignore")
        for index, line in enumerate(text.splitlines(), start=1):
            lowered = line.lower()
            if re.search(r"@\w*\.route\(|@router\.(get|post|put|delete|patch)\(", line) or re.search(
                r"\b(app|router)\.(get|post|put|delete|patch)\(", line
            ):
                surfaces.append(AttackSurface("route", relative, index, index, detail=line.strip()))
            if any(token in line for token in ["os.system", "subprocess.", "Runtime.getRuntime", "child_process"]):
                surfaces.append(AttackSurface("command-execution", relative, index, index, detail=line.strip()))
            if re.search(r"(?i)\b(select|insert|update|delete)\b.+\bfrom\b|cursor\.execute|\.query\(", line):
                surfaces.append(AttackSurface("database-access", relative, index, index, detail=line.strip()))
            if ("open(" in line or "send_file" in line or "readfile" in line) and ("../" in line or "request." in line):
                surfaces.append(AttackSurface("path-traversal-sink", relative, index, index, detail=line.strip()))
            if re.search(r"(?i)(api[_-]?key|secret|password|token)\s*=\s*['\"][^'\"]{8,}", line):
                surfaces.append(AttackSurface("hardcoded-secret", relative, index, index, detail=line.strip()))
            if "auth" in lowered or "permission" in lowered or "role" in lowered:
                surfaces.append(AttackSurface("auth-logic", relative, index, index, detail=line.strip()))
    return surfaces


def _is_ignored(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    return any(part in IGNORED_DIRS for part in relative.parts)


def _load_gitignore(root: Path) -> list[_IgnoreRule]:
    path = root / ".gitignore"
    if not path.exists():
        return []
    rules: list[_IgnoreRule] = []
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        if negated:
            line = line[1:].strip()
        line = line.lstrip("/")
        directory_only = line.endswith("/")
        if directory_only:
            line = line.rstrip("/")
        if line:
            rules.append(_IgnoreRule(line, negated=negated, directory_only=directory_only))
    return rules


def _included_by_scope(relative: str, scope: AuditScope, gitignore_rules: list[_IgnoreRule]) -> bool:
    include_patterns = [pattern for pattern in scope.include_patterns if pattern]
    if include_patterns:
        explicit_excludes = [
            pattern
            for pattern in scope.exclude_patterns
            if pattern and pattern not in set(DEFAULT_AUDIT_EXCLUDE_PATTERNS)
        ]
        return _matches_any(relative, include_patterns) and not _matches_any(relative, explicit_excludes)
    if _matches_gitignore(relative, gitignore_rules):
        return False
    return not _matches_any(relative, scope.exclude_patterns)


def _matches_gitignore(relative: str, rules: list[_IgnoreRule]) -> bool:
    ignored = False
    for rule in rules:
        if _match_pattern(relative, rule.pattern, directory_only=rule.directory_only):
            ignored = not rule.negated
    return ignored


def _matches_any(relative: str, patterns: list[str]) -> bool:
    return any(_match_pattern(relative, pattern) for pattern in patterns)


def _match_pattern(relative: str, pattern: str, directory_only: bool = False) -> bool:
    normalized = pattern.replace("\\", "/").lstrip("/")
    relative = relative.replace("\\", "/")
    if not normalized:
        return False
    if normalized.endswith("/**"):
        prefix = normalized[:-3].rstrip("/")
        return relative == prefix or relative.startswith(f"{prefix}/")
    if normalized.endswith("/"):
        normalized = normalized.rstrip("/")
        directory_only = True
    if directory_only:
        return relative == normalized or relative.startswith(f"{normalized}/")
    if "/" not in normalized:
        return fnmatch.fnmatch(Path(relative).name, normalized) or normalized in relative.split("/")
    return fnmatch.fnmatch(relative, normalized)


def source_category(relative: str) -> str:
    parts = [part.lower() for part in relative.replace("\\", "/").split("/") if part]
    name = parts[-1] if parts else ""
    if any(part in {"external", "vendor", "node_modules"} for part in parts):
        return "external"
    if any(part in {"fixtures", "fixture"} for part in parts):
        return "fixture"
    if any(part in {"tests", "test"} for part in parts) or name.startswith("test_") or "_test." in name:
        return "test"
    return "product-code"


def _git_commit(path: Path) -> str | None:
    if not (path / ".git").exists():
        return None
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(path),
            check=False,
            timeout=5,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    commit = result.stdout.strip()
    return commit or None
