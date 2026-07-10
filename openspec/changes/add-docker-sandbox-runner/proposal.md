## Why

The current verification loop can execute PoC artifacts only through the local process runner, which provides useful reproducibility but weak isolation. Docker Desktop is now available, so the project can add a stronger sandbox execution option while preserving the existing evidence-first rule that only Judge-validated runtime evidence can produce `confirmed`.

## What Changes

- Add a configurable `SandboxRunner` abstraction so `VerificationEngine` selects `local` or `docker` from configuration instead of directly binding to `LocalSandboxRunner`.
- Add `DockerSandboxRunner` that runs existing `PoCArtifact.command_argv` inside Docker, captures exit code, timeout state, stdout/stderr, artifact refs, Docker image, runner type, and security policy parameters.
- Add sandbox configuration for runner selection, Docker binary, Docker image, Docker context/host targeting, network mode, memory limit, CPU limit, and PID limit.
- Extend CLI, backend API, and frontend scan creation controls so users can select the sandbox runner, Docker image, Docker context, and Docker host.
- Keep Docker sandbox execution safe by default: `--network none`, no privileged mode, no writable target repository mount, bounded resources, and isolated attempt directories.
- Preserve evidence semantics: Docker unavailable returns `manual-required`; Docker execution failure cannot become `confirmed`; missing structured evidence such as `sqli-result.json` cannot become `confirmed`.

## Capabilities

### New Capabilities
- `docker-sandbox-runner`: Docker-backed PoC execution, runner configuration, CLI/API/UI selection, default security policy, and failure degradation behavior.

### Modified Capabilities
- `decision-auditability-and-replay`: Replay, report, and validation artifacts must expose runner type, Docker image, and sandbox policy details for Docker-backed attempts.

## Impact

- Affected code: `audit_agent/config.py`, `audit_agent/verification.py`, CLI scan flags, backend request schemas and config builder, frontend scan form and API types, report/runtime serialization tests.
- Affected artifacts: `SandboxRunResult` environment/policy payloads, validation attempt artifacts, report JSON/Markdown, replay/runtime inspection output.
- Dependencies: no Python Docker SDK is required for the MVP; the runner uses the Docker CLI. Users must have Docker Desktop running and the selected image available locally, with `python:3.12-slim` as the default image. On Windows, users may set `sandbox.docker_context = desktop-linux` or `sandbox.docker_host = npipe:////./pipe/dockerDesktopLinuxEngine` to avoid relying on the shell's current Docker context.
- Compatibility: local sandbox remains the default runner; existing PoC generators and Judge logic continue to run unchanged unless Docker is selected.
