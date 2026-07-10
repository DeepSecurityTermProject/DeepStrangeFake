## Context

The verification subsystem already has first-class PoC artifacts, sandbox run results, verification attempts, a Judge, reports, runtime artifacts, backend APIs, and a frontend scan workflow. The current execution runner is local-process based: `VerificationEngine` constructs `LocalSandboxRunner` directly and executes `PoCArtifact.command_argv` in an isolated attempt directory with `shell=False`, timeout, stdout/stderr capture, and artifact collection.

That local runner is useful for deterministic development, but it is not a strong isolation boundary. Docker Desktop is now available and `python:3.12-slim` is expected to be present locally, so the next step is to add a Docker-backed runner without weakening the existing evidence model. Docker execution must remain an execution transport for the same PoC/Judge loop, not a shortcut to confirmation.

## Goals / Non-Goals

**Goals:**
- Introduce a `SandboxRunner` abstraction so `VerificationEngine` can select `local` or `docker` from configuration.
- Implement `DockerSandboxRunner` using the Docker CLI with `shell=False`, existing `PoCArtifact.command_argv`, per-attempt directories, stdout/stderr capture, timeout handling, and artifact collection.
- Add explicit Docker daemon targeting through `sandbox.docker_context` and `sandbox.docker_host` so Windows/Docker Desktop runs do not depend on the CLI's ambient context.
- Make Docker execution safe by default: `--network none`, no privileged mode, dropped capabilities, no target repository writable mount, resource limits, and attempt-directory-only writes.
- Record Docker runner metadata in `SandboxRunResult.environment` and security parameters in `SandboxRunResult.policy`.
- Expose runner selection through config, CLI, backend API, and frontend scan creation.
- Preserve confirmation semantics: `confirmed` still requires Judge-read execution evidence and vulnerability-specific structured artifacts when required.

**Non-Goals:**
- Do not add the Python Docker SDK or make Docker a required runtime dependency for all scans.
- Do not auto-pull Docker images during normal verification. Missing images should produce `manual-required` with an actionable message.
- Do not mount the target project as writable inside the container by default.
- Do not support `--privileged`, host networking, Docker socket mounts, or broad host filesystem mounts.
- Do not change PoC generator semantics or allow Docker return code alone to confirm a finding.

## Decisions

### Decision 1: Use a small `SandboxRunner` interface

`VerificationEngine` should depend on a runner interface with a single execution method:

```text
SandboxRunner.run(poc: PoCArtifact | dict, attempt_index: int) -> SandboxRunResult
```

`LocalSandboxRunner` keeps the current implementation. `DockerSandboxRunner` implements the same contract. A small factory selects the runner from `config.sandbox.runner`, defaulting to `local`.

Alternative considered: add Docker-specific branches inside `VerificationEngine.verify`. That would mix orchestration with execution policy and make future runners harder to add.

### Decision 2: Use the Docker CLI, not the Docker SDK

The MVP should call the configured Docker binary with `subprocess.run(argv, shell=False)`. This avoids adding a new Python dependency, respects the user's manual image-pull workflow, and is easy to exercise with fake-binary tests.

Alternative considered: add the Docker SDK. It would provide a richer API but introduces dependency installation and Windows environment complexity that is not needed for the first runner.

### Decision 3: Treat Docker unavailable as `manual-required`

Runner preflight should distinguish these cases:
- Docker binary missing.
- Docker daemon unavailable or permission denied.
- Docker image missing.
- Docker run exits with Docker-level startup failure.

These conditions should produce a persisted `SandboxRunResult` with runner `docker`, policy/environment details, stdout/stderr refs when available, and status such as `policy-denied`, `environment-unavailable`, or `image-unavailable`. The final validation should degrade to `manual-required`, not `confirmed`.

Alternative considered: fail the whole scan when Docker is unavailable. That makes the frontend/API experience brittle and violates the existing evidence-first degradation model.

### Decision 4: Container execution is attempt-directory scoped

The runner should execute inside the existing verification attempt directory. The host attempt directory is bind-mounted as `/attempt:rw`, the container working directory is `/attempt`, and generated artifacts are collected from the host attempt directory after the container exits.

The runner should normalize PoC argv for container execution:
- Host Python executable paths become `python`.
- PoC script paths under the attempt directory become `/attempt/<relative-path>`.
- Arguments that reference files under the attempt directory are rewritten to `/attempt/<relative-path>` when safe.
- Arguments outside the attempt directory are rejected unless explicitly supported by a future read-only target mount feature.

Alternative considered: mount the target repository into Docker and execute against source paths directly. That increases host exposure and makes the first implementation harder to reason about. Existing PoC generators already produce self-contained attempt artifacts, so the MVP should not need repository mounts.

### Decision 5: Docker security defaults are explicit and non-optional

The Docker command should include safe defaults:

```text
docker run --rm
  --network none
  --read-only
  --cap-drop ALL
  --security-opt no-new-privileges
  --pids-limit <configured>
  --memory <configured>
  --cpus <configured>
  --workdir /attempt
  --mount type=bind,source=<attempt_dir>,target=/attempt
  --tmpfs /tmp:rw,nosuid,nodev,size=64m
  <image>
  <container argv>
```

The implementation should reject configuration that attempts privileged mode or host networking. It should not expose `--privileged` as a user option.

Alternative considered: make all Docker flags configurable. That would be flexible but unsafe for a security-audit verifier whose default posture should be reproducible and contained.

### Decision 6: Judge semantics remain unchanged

Docker execution success cannot confirm a finding by itself. `VerificationJudge` must still read the expected signal and structured artifacts declared by `PoCArtifact.expected_signal`. For SQL injection, missing or unreadable `sqli-result.json` must prevent `confirmed` even when Docker returns exit code 0. For path traversal, the traversal signal must still come from stdout/stderr or artifacts produced by the PoC.

Alternative considered: trust Docker exit code as stronger evidence than local exit code. That would reintroduce placeholder-PoC confirmations and violate prior verification requirements.

### Decision 7: UI/API exposure stays small

The CLI should add `--sandbox-runner local|docker`, `--sandbox-docker-image`, `--sandbox-docker-context`, and `--sandbox-docker-host`. The backend request schema should add matching fields. The frontend scan page should add a runner selector near the sandbox checkbox and show Docker image/context/host inputs only when Docker is selected.

Resource limits can start as config/API fields but the UI can initially expose only runner and image to keep scan creation simple.

Alternative considered: expose every Docker security flag in the UI. That would turn the scan page into an infrastructure form and invite unsafe combinations.

### Decision 8: Docker context has precedence over Docker host

When `sandbox.docker_context` is set, every Docker CLI call should be invoked as `docker --context <context> ...`. The runner should remove `DOCKER_HOST` and `DOCKER_CONTEXT` from the subprocess environment for those calls so an ambient shell setting cannot silently override the explicit context. This is the preferred Windows Docker Desktop path for `desktop-linux`.

When `sandbox.docker_context` is not set and `sandbox.docker_host` is set, the runner should set `DOCKER_HOST` for Docker subprocesses. This supports explicit named-pipe targeting such as `npipe:////./pipe/dockerDesktopLinuxEngine`.

Both values should be accepted through config, CLI, backend API, and frontend scan creation. The persisted sandbox result should record the effective context or host so report/replay can explain which Docker daemon target was used.

Alternative considered: rely on the Docker CLI's current context. That is fragile in Codex/Windows runs because the process may read a different Docker config, connect to the wrong daemon, or report missing images that exist in another Docker Desktop context.

## Risks / Trade-offs

- [Risk] Docker Desktop may be installed but inaccessible from the current process because of named-pipe permission, daemon state, or ambient Docker CLI context. -> Mitigation: preflight Docker with the configured binary/context/host, persist the failure as `manual-required`, and include a clear blocking reason.
- [Risk] The selected image may be missing on offline machines. -> Mitigation: do not auto-pull; return `manual-required` with the exact `docker pull <image>` command.
- [Risk] Windows path binding can be fragile. -> Mitigation: pass Docker argv as a list with `shell=False`, use absolute attempt directory paths, and cover command construction with tests.
- [Risk] `--read-only` can break PoCs that need temporary files. -> Mitigation: provide a bounded `/tmp` tmpfs and make `/attempt` the only writable artifact directory.
- [Risk] Container startup failure could be mistaken for vulnerability rejection. -> Mitigation: classify runner/environment failures as `manual-required`, not `rejected` or `confirmed`.
- [Risk] Docker resource flags differ across platforms. -> Mitigation: keep defaults conservative, allow empty resource limits when unsupported, and record the effective policy in `SandboxRunResult`.

## Migration Plan

1. Add `SandboxRunner` interface/factory and route `VerificationEngine` through it while preserving `local` as the default.
2. Extend `SandboxConfig` with runner, Docker binary, Docker image, Docker context, Docker host, network mode, memory limit, CPU limit, and PID limit.
3. Implement `DockerSandboxRunner` with preflight checks, Docker argv construction, timeout/container cleanup, stdout/stderr capture, artifact collection, and persisted run result metadata.
4. Add CLI, backend schema/config builder, `/api/options`, frontend types, and scan page controls for runner, image, context, and host selection.
5. Add unit tests using fake Docker binaries for unavailable daemon, missing image, command construction, forbidden privileged policy, and no-confirmation-on-missing-structured-evidence.
6. Add opt-in live Docker tests that run only when Docker is available and the image is present.
7. Keep local runner behavior and existing PoC/Judge tests green throughout.

Rollback is straightforward: set `sandbox.runner` back to `local` or hide Docker runner selection while leaving existing validation behavior intact.

## Open Questions

- Should the API expose memory/CPU/PID limits immediately, or keep them config-file-only until the Docker runner is stable?
- Should a future change allow read-only target repository mounts for PoCs that truly need imported target modules, or should all executable PoCs remain self-contained attempt artifacts?
