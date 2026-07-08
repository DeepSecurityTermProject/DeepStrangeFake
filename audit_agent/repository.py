from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

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


def analyze_target(source: str, allow_clone: bool = False, checkout_dir: str | Path | None = None) -> RepositoryMetadata:
    target = parse_target(source)
    if target.kind != "local":
        if allow_clone:
            checkout_path, commit = checkout_remote_target(target, checkout_dir)
            target.path = str(checkout_path)
            target.commit = commit
            return _analyze_local_path(target, checkout_path)
        return RepositoryMetadata(target=target)

    path = Path(target.path or source).resolve()
    return _analyze_local_path(target, path)


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


def _analyze_local_path(target: AuditTarget, path: Path) -> RepositoryMetadata:
    if not path.exists() or not path.is_dir():
        raise FileNotFoundError(f"Target directory does not exist: {path}")
    file_tree = list(_file_tree(path))
    languages = _detect_languages(path, file_tree)
    dominant_language = max(languages.items(), key=lambda item: item[1])[0] if languages else None
    dependencies = _discover_dependencies(path)
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
        dependencies=dependencies,
        attack_surfaces=attack_surfaces,
    )


def _file_tree(root: Path) -> Iterable[str]:
    for current, dirs, files in os.walk(root):
        dirs[:] = [dirname for dirname in dirs if dirname not in IGNORED_DIRS]
        for filename in sorted(files):
            full_path = Path(current) / filename
            relative = full_path.relative_to(root).as_posix()
            if any(part in IGNORED_DIRS for part in relative.split("/")):
                continue
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


def _discover_dependencies(root: Path) -> list[Dependency]:
    dependencies: list[Dependency] = []
    for manifest in root.rglob("requirements.txt"):
        if _is_ignored(manifest, root):
            continue
        for line in manifest.read_text(encoding="utf-8", errors="ignore").splitlines():
            parsed = _parse_requirement(line)
            if parsed:
                name, version = parsed
                dependencies.append(_dependency("pypi", name, version, manifest, root))

    for manifest in root.rglob("package.json"):
        if _is_ignored(manifest, root):
            continue
        try:
            payload = json.loads(manifest.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        for section in ("dependencies", "devDependencies"):
            for name, version in payload.get(section, {}).items():
                dependencies.append(_dependency("npm", name, str(version), manifest, root))

    for manifest in root.rglob("go.mod"):
        if _is_ignored(manifest, root):
            continue
        for line in manifest.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.strip().startswith("require "):
                parts = line.split()
                if len(parts) >= 3:
                    dependencies.append(_dependency("go", parts[1], parts[2], manifest, root))

    for manifest in root.rglob("Cargo.toml"):
        if _is_ignored(manifest, root):
            continue
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
