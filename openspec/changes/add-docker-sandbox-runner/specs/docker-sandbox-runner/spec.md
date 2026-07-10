## ADDED Requirements

### Requirement: Sandbox runner is configurable
The system SHALL allow sandbox validation to choose between local and Docker execution through configuration while keeping local execution as the default.

#### Scenario: Local runner remains default
- **WHEN** sandbox validation runs without an explicit runner selection
- **THEN** the system SHALL use the local sandbox runner and preserve existing PoC/Judge behavior.

#### Scenario: Docker runner is selected
- **WHEN** `sandbox.runner` is `docker`
- **THEN** the system SHALL execute supported PoC artifacts through `DockerSandboxRunner` instead of directly instantiating `LocalSandboxRunner`.

#### Scenario: Unknown runner is configured
- **WHEN** `sandbox.runner` is not `local` or `docker`
- **THEN** the system SHALL reject sandbox execution for the candidate and return `manual-required` with a configuration error reason.

### Requirement: Docker sandbox configuration is supported
The system SHALL support Docker sandbox configuration for binary path, image, Docker context, Docker host, network mode, memory limit, CPU limit, and PID limit.

#### Scenario: Default Docker configuration is used
- **WHEN** Docker runner is selected without Docker-specific overrides
- **THEN** the system SHALL use `docker` as the binary, `python:3.12-slim` as the image, `none` as the network mode, and conservative resource limits.

#### Scenario: Docker image is overridden
- **WHEN** the user supplies a Docker image through config, CLI, or API
- **THEN** the system SHALL use that image for Docker PoC execution and record the image in the sandbox run result.

#### Scenario: Docker context is overridden
- **WHEN** the user supplies a Docker context through config, CLI, or API
- **THEN** the system SHALL invoke Docker CLI commands with `--context <context>` and record the context in the sandbox run result.

#### Scenario: Docker host is overridden
- **WHEN** the user supplies a Docker host and no Docker context is configured
- **THEN** the system SHALL set `DOCKER_HOST` for Docker CLI subprocesses and record the host in the sandbox run result.

#### Scenario: Docker context and host are both configured
- **WHEN** both Docker context and Docker host are configured
- **THEN** Docker context SHALL take precedence, Docker CLI commands SHALL use `--context <context>`, and Docker host environment overrides SHALL NOT be applied.

#### Scenario: Network defaults to none
- **WHEN** Docker runner builds a container command
- **THEN** the command SHALL include `--network none` unless a future explicit policy allows another safe mode.

### Requirement: Docker runner executes PoC argv in an isolated attempt directory
The system SHALL run existing `PoCArtifact.command_argv` inside a Docker container using the verification attempt directory as the only writable artifact boundary.

#### Scenario: PoC command is executed in Docker
- **WHEN** Docker runner executes a PoC artifact
- **THEN** it SHALL invoke Docker with `shell=False`, mount the attempt directory at `/attempt`, set the container workdir to `/attempt`, run the normalized PoC argv, capture stdout/stderr, exit code, timeout state, duration, and generated artifact refs.

#### Scenario: Python argv is normalized
- **WHEN** `PoCArtifact.command_argv` starts with the host Python executable and references a generated PoC script under the attempt directory
- **THEN** Docker runner SHALL execute `python` inside the container and rewrite the script path to its `/attempt` path.

#### Scenario: Argument escapes attempt directory
- **WHEN** a PoC argument requires a writable or executable path outside the attempt directory
- **THEN** Docker runner SHALL deny execution and return `manual-required` with a policy reason instead of mounting broad host paths.

### Requirement: Docker runner enforces safe container policy
The system SHALL enforce a safe Docker policy by default and SHALL NOT expose privileged execution.

#### Scenario: Docker command is built
- **WHEN** Docker runner creates the container argv
- **THEN** the Docker argv SHALL include no network, read-only root filesystem, dropped capabilities, no-new-privileges, resource limits, attempt-directory bind mount, and bounded tmpfs for temporary files.

#### Scenario: Privileged mode is requested
- **WHEN** any configuration or request attempts to enable privileged Docker execution
- **THEN** the system SHALL reject the request, SHALL NOT include `--privileged`, and SHALL mark affected validation as `manual-required`.

#### Scenario: Target repository writable mount is requested by default path
- **WHEN** Docker runner executes a generated PoC
- **THEN** it SHALL NOT mount the target project repository as writable by default.

### Requirement: Docker unavailable degrades to manual-required
The system SHALL degrade Docker environment failures to `manual-required` with persisted evidence instead of failing the whole scan or confirming a candidate.

#### Scenario: Docker binary is missing
- **WHEN** Docker runner cannot find the configured Docker binary
- **THEN** the candidate SHALL be marked `manual-required` with a blocking reason and a persisted sandbox run result.

#### Scenario: Docker daemon is unavailable
- **WHEN** Docker runner cannot connect to the Docker daemon or receives a permission error
- **THEN** the candidate SHALL be marked `manual-required` with stdout/stderr or diagnostic evidence.

#### Scenario: Docker image is missing
- **WHEN** the configured Docker image is not available locally
- **THEN** the candidate SHALL be marked `manual-required` and the reason SHALL include the image name and a manual pull instruction.

### Requirement: Docker execution failure cannot confirm findings
The system SHALL prevent Docker process or container failures from producing `confirmed`.

#### Scenario: Docker run exits with infrastructure failure
- **WHEN** Docker fails before the PoC executes successfully
- **THEN** the system SHALL NOT mark the candidate `confirmed` and SHALL record `manual-required` with Docker failure evidence.

#### Scenario: PoC exits zero without required structured evidence
- **WHEN** Docker returns exit code 0 but the vulnerability-specific structured evidence artifact is missing or unreadable
- **THEN** the Judge SHALL NOT mark the candidate `confirmed`.

#### Scenario: SQLi result artifact is missing
- **WHEN** a SQL injection PoC executed through Docker does not produce an openable `sqli-result.json`
- **THEN** the candidate SHALL NOT be marked `confirmed` even if stdout contains success-like text or the process exits with code 0.

### Requirement: CLI, backend, and frontend expose Docker runner selection
The system SHALL expose Docker runner selection through the command line, backend API, and frontend scan creation page.

#### Scenario: CLI selects Docker runner
- **WHEN** a user runs scan with `--sandbox --sandbox-runner docker --sandbox-docker-image python:3.12-slim --sandbox-docker-context desktop-linux`
- **THEN** the scan SHALL enable sandbox validation, select Docker runner, and use the supplied image and Docker context.

#### Scenario: Backend request selects Docker runner
- **WHEN** `/api/runs` receives a scan request with Docker sandbox runner fields
- **THEN** the backend SHALL map those fields into `AuditConfig.sandbox` before starting the job.

#### Scenario: Frontend selects Docker runner
- **WHEN** the user enables sandbox execution on the scan creation page
- **THEN** the UI SHALL allow selecting `local` or `docker`, and SHALL allow setting the Docker image, Docker context, and Docker host when Docker is selected.
