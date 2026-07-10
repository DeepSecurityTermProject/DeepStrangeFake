## 1. Configuration and Runner Abstraction

- [x] 1.1 Extend `SandboxConfig` with `runner`, `docker_binary`, `docker_image`, `network`, `memory_limit`, `cpu_limit`, and `pids_limit` defaults.
- [x] 1.2 Add a `SandboxRunner` protocol or base abstraction matching `run(poc, attempt_index) -> SandboxRunResult`.
- [x] 1.3 Update `LocalSandboxRunner` to declare runner metadata in its environment summary while preserving existing behavior.
- [x] 1.4 Add a runner factory that selects `LocalSandboxRunner` or `DockerSandboxRunner` from config and produces `manual-required` behavior for unknown runners.
- [x] 1.5 Route `VerificationEngine` through the runner factory instead of directly instantiating `LocalSandboxRunner`.

## 2. Docker Sandbox Runner

- [x] 2.1 Implement Docker preflight checks for missing binary, daemon unavailable or permission denied, and missing local image.
- [x] 2.2 Implement Docker argv construction with `shell=False`, `docker run --rm`, `--network none`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, resource limits, `/attempt` bind mount, and `/tmp` tmpfs.
- [x] 2.3 Normalize PoC command argv from host Python/script paths to container-safe `/attempt` paths.
- [x] 2.4 Deny PoC arguments that require writable or executable paths outside the attempt directory.
- [x] 2.5 Execute Docker with timeout handling, stdout/stderr capture, exit code recording, duration recording, and forced container cleanup on timeout.
- [x] 2.6 Collect artifacts only from the attempt directory and persist `sandbox-result.json`.
- [x] 2.7 Record `environment.runner = docker`, Docker image, Docker binary, container status, normalized argv, and Docker policy details in `SandboxRunResult`.
- [x] 2.8 Ensure Docker unavailable, image missing, policy denial, timeout, and infrastructure failure degrade to `manual-required` and never `confirmed`.

## 3. Evidence and Judge Preservation

- [x] 3.1 Preserve existing path traversal and SQL injection PoC generator behavior under local runner.
- [x] 3.2 Ensure Docker runner feeds the same `SandboxRunResult` shape into `VerificationJudge`.
- [x] 3.3 Add regression coverage that Docker exit code 0 without vulnerability-specific structured evidence cannot produce `confirmed`.
- [x] 3.4 Add SQLi-specific regression coverage that missing or unreadable `sqli-result.json` cannot produce `confirmed`.
- [x] 3.5 Ensure Docker infrastructure failures are reported as `manual-required`, not `rejected`, unless Judge-readable contradiction evidence exists.

## 4. CLI, Backend, and Frontend Integration

- [x] 4.1 Add CLI flags `--sandbox-runner local|docker` and `--sandbox-docker-image`.
- [x] 4.2 Map CLI sandbox runner and image flags into `AuditConfig.sandbox`.
- [x] 4.3 Extend backend `ScanRunRequest` with sandbox runner and Docker image fields.
- [x] 4.4 Map backend request fields into `AuditConfig.sandbox` in the scan job config builder.
- [x] 4.5 Extend `/api/options` with available sandbox runners and the default Docker image.
- [x] 4.6 Extend frontend API types and client payloads for sandbox runner and Docker image.
- [x] 4.7 Add runner selection controls to the scan creation page and show Docker image input when Docker runner is selected.
- [x] 4.8 Update frontend tests to verify Docker runner selection is sent in scan creation payloads.

## 5. Reporting, Replay, and Runtime Visibility

- [x] 5.1 Ensure report JSON and Markdown include runner type, Docker image, exit code, timeout state, stdout/stderr previews, sandbox result refs, attempt refs, and Judge reason for Docker attempts.
- [x] 5.2 Ensure manual-required Docker failures appear in `verification_candidates` with blocking reasons and evidence refs.
- [x] 5.3 Extend replay/runtime summaries to include Docker attempt counts, statuses, runner type, image, policy-denied events, and environment failures.
- [x] 5.4 Verify Web run detail pages display Docker-backed validation evidence through existing validation fields or targeted UI additions.

## 6. Tests and Validation

- [x] 6.1 Add fake-Docker unit tests for missing binary, daemon unavailable, missing image, command construction, and policy-denied attempts.
- [x] 6.2 Add a test asserting Docker command argv contains no network, read-only root, dropped capabilities, no-new-privileges, resource limits, and no `--privileged`.
- [x] 6.3 Add a test asserting Docker runner does not mount the target repository as writable by default.
- [x] 6.4 Add closed-loop tests proving Docker unavailable returns `manual-required` with persisted `SandboxRunResult`.
- [x] 6.5 Add closed-loop tests proving Docker execution failure cannot mark a candidate `confirmed`.
- [x] 6.6 Add optional live Docker smoke tests gated by an environment variable and skipped when Docker or the image is unavailable.
- [x] 6.7 Run Python tests for verification, reports, backend config mapping, and CLI parsing.
- [x] 6.8 Run frontend tests with the existing Vite/Vitest runner configuration.
- [x] 6.9 Run OpenSpec validation/status checks for `add-docker-sandbox-runner`.

## 7. Explicit Docker Daemon Targeting

- [x] 7.1 Add `sandbox.docker_context` and `sandbox.docker_host` configuration fields.
- [x] 7.2 Ensure Docker context is passed with `docker --context <context>` for preflight, image inspect, run, and cleanup calls.
- [x] 7.3 Ensure Docker host is passed through `DOCKER_HOST` only when Docker context is not configured.
- [x] 7.4 Record the effective Docker context or Docker host in sandbox environment/policy evidence.
- [x] 7.5 Expose Docker context and host through CLI, backend API/options, frontend API types, and scan creation controls.
- [x] 7.6 Add regression tests for Docker context precedence, Docker host environment selection, CLI parsing, backend mapping, and frontend payload submission.
