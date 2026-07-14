## ADDED Requirements

### Requirement: Remote source policy is explicit and provider-bounded
The system SHALL accept remote interactive scan sources only as canonical public `https://github.com/<owner>/<repository>` or `https://gitlab.com/<namespace>/<repository>` URLs when remote acquisition is enabled by operator configuration. GitLab namespaces MAY contain nested groups. It MUST reject unsupported schemes or hosts, SSH, local/file remotes, embedded credentials, query strings, fragments, malformed repository paths, and redirects before scanning any downloaded content.

#### Scenario: Canonical public GitHub source is accepted
- **WHEN** remote acquisition is enabled and a user submits a canonical public GitHub HTTPS repository URL
- **THEN** the system normalizes the source identity without credentials and proceeds to commit resolution under the configured acquisition budgets

#### Scenario: Canonical public GitLab source is accepted
- **WHEN** remote acquisition is enabled and a user submits a canonical public GitLab HTTPS URL with one or more namespace components
- **THEN** the system preserves the GitLab source kind, normalizes the source identity, and proceeds under the same commit and resource gates as GitHub

#### Scenario: Unsafe source is denied before Git execution
- **WHEN** a source contains credentials, uses an unapproved protocol or host, resolves as a local/file remote, includes a query or fragment, or remote acquisition is disabled
- **THEN** the system denies acquisition before clone/fetch and persists only a redacted policy reason

### Requirement: Every remote scan resolves an immutable commit
The system SHALL accept remote `HEAD` or an optional complete hexadecimal commit object ID and SHALL resolve the requested revision to one exact full commit before source export. The acquisition record and repository metadata MUST retain the original source identity, requested revision, and resolved commit; branch and tag selection are not supported in this capability.

#### Scenario: Default HEAD is pinned
- **WHEN** a GitHub or GitLab URL is submitted without a commit and network acquisition is enabled
- **THEN** the system resolves remote `HEAD`, validates the returned commit object ID, and scans only the exported snapshot of that resolved commit

#### Scenario: Requested commit cannot be verified
- **WHEN** a supplied commit is malformed, absent from the verified remote, or resolves to a different object
- **THEN** acquisition fails and no audit scanner is invoked for that source

### Requirement: Mirrors are identity-keyed and fail closed
The system SHALL key persistent mirror caches by a digest of the normalized remote identity, serialize mutation of each mirror, validate every existing mirror's origin before use, and fetch only when network acquisition is enabled. Mirror creation and update MUST be atomic so interrupted or competing jobs cannot promote a partial or wrong-origin cache entry.

#### Scenario: Verified cache hit avoids network mutation
- **WHEN** the normalized mirror exists, its origin matches, and the resolved commit object is present
- **THEN** the system exports the exact commit without clone/fetch and records a verified cache hit

#### Scenario: Cache identity or commit is invalid
- **WHEN** the mirror origin differs, the cache escapes its root, the object database is corrupt, or the resolved object does not equal the requested commit
- **THEN** the system fails closed and does not export or scan that cache

### Requirement: Acquisition cannot execute project-controlled behavior
The system SHALL invoke Git with argument arrays and `shell=False`, disable interactive credentials and inherited repository/system/global configuration, disable hooks, submodule initialization, Git LFS smudge, external filters, and project setup/build commands, and restrict production remote transport to HTTPS. Acquisition MUST use mirror/fetch plus `git archive` or an equivalently non-executing exact-commit export rather than a normal working checkout.

#### Scenario: Remote project contains executable setup mechanisms
- **WHEN** a repository contains hooks, submodules, LFS pointers, filters, package scripts, or build metadata
- **THEN** acquisition exports passive source content without invoking any of those mechanisms

### Requirement: Exported source is contained and resource bounded
The system SHALL export each scan into a unique job workspace beneath a configured root and SHALL reject archive traversal, symbolic or hard links, special entries, destination collisions, and paths outside that workspace. Git command timeout, total acquisition timeout, archive member count, uncompressed bytes, mirror-size checks, and audit file/byte limits MUST be configured and enforced before the runtime scans content.

#### Scenario: Archive violates containment or budget
- **WHEN** an archive entry escapes the destination, is a link or special file, or exceeds configured member or byte limits
- **THEN** extraction and scanning stop, the partial workspace is cleaned, and the job records a bounded redacted failure

#### Scenario: Concurrent scans request the same repository
- **WHEN** two jobs acquire the same normalized repository concurrently
- **THEN** mirror mutation is serialized while each job receives a distinct immutable export workspace

### Requirement: Acquisition evidence and cleanup are authoritative
The system SHALL persist a schema-versioned acquisition record containing normalized source identity, requested revision, resolved commit, method, cache status, whether network was used, bounded command outcomes, duration, exported file/byte counts, safety checks, workspace cleanup status, and artifact refs. It MUST redact credentials and credential-derived values before persistence, retain the reusable mirror according to cache policy, and remove the per-job export after all scan and verification stages terminate.

#### Scenario: Successful acquisition and cleanup
- **WHEN** an exact commit is exported, analyzed, and the job terminates
- **THEN** the run retains immutable acquisition evidence and the per-job export is removed while the verified mirror may remain cached

#### Scenario: Cleanup cannot be verified
- **WHEN** the per-job export cannot be removed or still exists after cleanup
- **THEN** the job does not claim an unqualified success and exposes the cleanup failure with the run artifacts that remain available

### Requirement: Final reports retain remote scan proof
The final report SHALL retain the original URL, normalized URL, source kind, requested revision, exact resolved commit, non-empty scanned file list, actual findings and verification candidates, and terminal cleanup status. A report with pending or failed cleanup MUST NOT claim a completed run.

#### Scenario: Remote report is finalized after cleanup
- **WHEN** a GitHub or GitLab snapshot has been scanned and per-job cleanup terminates
- **THEN** `report.json` identifies the exact source and commit, lists the files scanners consumed, retains their scan results, and records `complete` or `failed` cleanup consistently with terminal job status

### Requirement: Interactive and benchmark acquisition share one hardened core
The system SHALL expose a target-agnostic acquisition core used by interactive scans and by a compatibility adapter for the existing benchmark acquisition API. The refactor MUST preserve benchmark source identity, exact-lock, cache-only, network, safety, command-recording, and failure semantics.

#### Scenario: Shared-core refactor preserves benchmark behavior
- **WHEN** existing benchmark acquisition and promotion tests run through the adapter
- **THEN** their normalized identities, resolved commits, cache outcomes, failure reasons, and eligibility gates remain protocol compatible
