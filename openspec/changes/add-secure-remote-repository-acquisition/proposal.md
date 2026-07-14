## Why

The CLI and Web API currently accept repository URLs syntactically, but the normal audit runtime does not materialize those repositories, so remote scans can complete with an empty file tree and no real analysis. The benchmark pipeline already demonstrates a safer mirror-and-archive acquisition model; the interactive scan workflow needs an equally explicit, bounded, and auditable path from a public GitHub or GitLab URL to a verified local source snapshot.

## What Changes

- Add an operator-gated remote repository acquisition service for public GitHub and GitLab HTTPS URLs, resolving remote `HEAD` or an optional exact commit to a full immutable commit SHA.
- Reuse one hardened Git acquisition core across interactive scans and benchmark adapters, with identity-keyed mirrors, exact-commit verification, non-executing archive export, path containment, resource budgets, redaction, and deterministic cleanup evidence.
- Add structured local/GitHub/GitLab source input to the Web API while retaining the existing `target` string as a backward-compatible local input.
- Add CLI `--revision` for exact remote commits while retaining `--commit` as a compatibility alias.
- Add Web job phases for source validation, acquisition, commit resolution, export, analysis, verification, reporting, and cleanup, and expose normalized provenance and acquisition evidence without leaking credentials or unsafe local paths.
- Add a Local/GitHub/GitLab source selector to the scan console, an optional exact commit field when HEAD resolution is available, acquisition progress/error presentation, and resolved-commit display in run details.
- Fail closed when remote acquisition is disabled, denied, timed out, unsafe, empty, mismatched, or incompletely cleaned; a zero-file remote target must never be reported as a successful scan.
- Allow a verified remote snapshot to participate in static analysis and explicitly enabled network-disabled Docker verification, while continuing to prohibit local-process execution, live-target traffic, project-controlled setup, and target-source writes.

## Capabilities

### New Capabilities
- `secure-remote-repository-acquisition`: Defines public GitHub/GitLab source normalization, explicit network policy, immutable commit resolution, safe mirror/export behavior, provenance, budgets, failure semantics, cleanup, and reusable benchmark compatibility.
- `remote-repository-scan-workflow`: Defines backward-compatible API source contracts, Web job acquisition phases, prepared-target handoff into AgentRuntime, remote-snapshot verification policy, and frontend creation/status/detail behavior.

### Modified Capabilities

None. Existing local scan, adaptive graph, decision replay, and LLM accounting requirements remain unchanged; remote acquisition evidence is additive.

## Impact

- Affects repository parsing/acquisition, `run_audit` target preparation, legacy and graph runtime initialization, target provenance models, validation policy, run artifacts, Web request/job schemas, API options, and frontend scan/run views.
- Refactors `audit_agent/benchmark_acquisition.py` behind a compatibility adapter without changing benchmark corpus acquisition semantics or protocol identity.
- Adds Git process execution only at the acquisition boundary, with `shell=False`, explicit network enablement, a fixed GitHub/GitLab HTTPS allowlist, disabled interactive credentials/hooks/submodules/LFS/project execution, and bounded disk/time/file usage.
- Adds no Git library dependency; the backend continues to require the system `git` executable for remote acquisition.
- Private repositories, SSH, arbitrary Git hosts, branch/tag selection, dependency installation, project build/setup, and live-service testing remain out of scope.
