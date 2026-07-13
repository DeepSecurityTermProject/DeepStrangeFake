## ADDED Requirements

### Requirement: Benchmark corpora are schema-versioned and commit-locked
The system SHALL load a schema-versioned corpus in which every executable case has a stable project ID, case ID, complete commit SHA, expected language, variant, scan scope, budgets, timeout, safety policy, ground-truth reference, support level, and effectiveness-eligibility decision.

#### Scenario: Locked corpus is accepted
- **WHEN** every selected executable case satisfies the schema and names an exact commit available under its acquisition policy
- **THEN** the system SHALL persist the resolved manifest, unique-project count, case count, and canonical corpus digest before executing any case.

#### Scenario: Mutable ref is supplied for execution
- **WHEN** a selected case contains only a branch, tag, or other mutable ref
- **THEN** validation SHALL fail before scanning and SHALL instruct the operator to create a reviewed exact-commit lock.

### Requirement: Project and case cardinality are distinct
The system SHALL count upstream project identities separately from exact-revision cases.

#### Scenario: Vulnerable and fixed revisions share one project
- **WHEN** two cases use vulnerable and fixed commits of the same project
- **THEN** `case_count` SHALL increase by two and `unique_project_count` SHALL increase by one.

#### Scenario: Full-profile readiness is validated
- **WHEN** a full profile is validated for the follow-up full-corpus change
- **THEN** it SHALL contain at least 20 unique project IDs and SHALL NOT satisfy that quota with duplicate revisions, placeholders, unsupported cases, or cases ineligible for effectiveness evaluation.

### Requirement: Corpus profiles separate fixtures, pilot projects, and full readiness
The system SHALL provide fixture, pilot, and full profiles with distinct policies and promotion gates.

#### Scenario: CI fixture profile is selected
- **WHEN** normal CI runs the fixture profile
- **THEN** all targets SHALL be local, deterministic, network-free, and bounded by the documented CI budget.

#### Scenario: Pilot profile is selected
- **WHEN** a real-project pilot is requested
- **THEN** the profile SHALL contain 3-5 unique exact-commit projects with reviewed license/source, supported scan shapes, bounded scope, truth evidence, and safe local scanning policy.

#### Scenario: Full profile lacks an approved executable lock
- **WHEN** execution of the full profile is requested without exact eligible entries and reviewed `promotion_status = approved` metadata
- **THEN** execution SHALL be denied with a readiness/promotion reason.

### Requirement: Engine support is explicit
Each case SHALL declare `full-dataflow`, `pattern-only`, or `unsupported` support and whether it is eligible for effectiveness metrics.

#### Scenario: Unsupported case is present
- **WHEN** a selected case's language or scan shape is unsupported
- **THEN** it SHALL remain visible with a reason but SHALL NOT enter effectiveness denominators or effective-project quotas.

#### Scenario: Pattern-only case is proposed as effective coverage
- **WHEN** a pattern-only case lacks reviewed truth and an explicit eligibility decision
- **THEN** it SHALL NOT be counted as effectiveness-eligible.

### Requirement: Remote acquisition uses a verified, non-executing cache path
The system SHALL use source-identity-keyed bare mirrors and prefer a safe exact-commit archive/export into a contained case directory; worktrees/checkouts require the same content-safety validation.

#### Scenario: Exact commit is cached
- **WHEN** a remote case's commit exists in a valid mirror
- **THEN** acquisition SHALL export or checkout that exact commit without network access and SHALL record a cache hit and resolved commit.

#### Scenario: Cache identity or commit is invalid
- **WHEN** a cache entry has the wrong remote identity, is corrupt, escapes the cache root, or resolves to a different commit
- **THEN** acquisition SHALL fail closed and SHALL NOT scan the content.

### Requirement: Network acquisition is explicit and credential-safe
The system MUST NOT clone or fetch unless network acquisition is explicit, and MUST NOT persist embedded credentials or secret source values.

#### Scenario: Missing commit in offline mode
- **WHEN** the commit is absent and network acquisition is disabled
- **THEN** the case SHALL terminate as `not-run` or `failed` with `acquisition-cache-miss` and null finding metrics.

#### Scenario: Unsafe source URL is supplied
- **WHEN** a source uses an unapproved protocol, `file://`, local remote, or embedded credentials
- **THEN** acquisition SHALL be denied before Git invocation and persisted diagnostics SHALL be redacted.

#### Scenario: Authorized network acquisition is requested
- **WHEN** the commit is absent, network is explicit, and source policy permits the credential-free source identity
- **THEN** fixed-argv Git operations MAY fetch only the required source under timeout, bounded output, and controlled environment before commit verification.

### Requirement: Repository acquisition cannot execute project-controlled behavior
Acquisition SHALL disable hooks, submodule initialization, Git LFS smudge, repository-defined external filters, and project build/setup commands, and SHALL prevent scanners from following links outside the case source root.

#### Scenario: Project declares submodules, filters, or escaping links
- **WHEN** exported content requests a submodule/filter/LFS action or contains a link escaping the source root
- **THEN** the action SHALL NOT execute and the case SHALL be denied or sanitized according to an explicit recorded policy.

### Requirement: Acquisition results are first-class artifacts
The system SHALL persist method, redacted source identity, expected/resolved commits, export path, timing, network policy, cache status, content-safety checks, and failure reason independently from scan results.

#### Scenario: Acquisition produces no valid source tree
- **WHEN** acquisition is skipped, denied, unsafe, timed out, or failed
- **THEN** the artifact SHALL describe that outcome, SHALL NOT invoke the scan child, and SHALL NOT fabricate zero finding counts.
