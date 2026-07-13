## Validation Record

Date: 2026-07-13

Safety scope: local authorized synthetic fixtures only. No network request,
Docker invocation, destructive operation, or real target access was used.

### P2 scheduler and graph validation

- The effective retry limit is the minimum of the node retry policy and the
  graph-level `max_node_attempts` ceiling. A synthetic node configured for
  three attempts with a graph ceiling of one is invoked exactly once and ends
  failed without a retry transition.
- A required input ref is valid only when its source is a structural ancestor
  of the consumer through directed graph edges. Transitive upstream sources
  are allowed; an unrelated source with a compatible output type is rejected
  before any node executes.
- Task 9.3 remains pending because this correction covers the node-attempt
  ceiling only, not every ceiling listed by that aggregate acceptance task.

### Legacy and deterministic graph compatibility

The same local vulnerable fixture is executed once in `legacy` mode and once
in `deterministic-graph` mode. The acceptance compares:

- candidate, rejected, validated, confirmed, likely, manual-required, and
  validation-rejected counts;
- validation-level distribution;
- normalized target metadata, executive summary, findings, verification
  candidates, evidence chains, agent traces, handoffs, and validation results;
- presence and non-empty contents of every required legacy artifact category.

Normalization removes only run-local paths, timestamps, elapsed durations,
generated IDs, message/task correlation refs, and artifact refs. The graph
runtime section is excluded because it is the intentional additive contract.

Intentional additive differences in deterministic graph mode are limited to:

- the `graphs/` artifact category and graph revision/transition/replay refs;
- graph node metadata in runtime task state;
- `graph_mode`, `final_graph_ref`, and `execution_path` summary fields;
- the additive graph subsection in report runtime metadata.

The comparison initially exposed a real semantic difference: graph mode
discarded the legacy degraded contextual-intelligence record when MCP was
disabled. The graph handler now uses the same local degraded adapter path, so
normalized reports and evidence match without enabling network access.

### Focused checks

- `python -m unittest tests.test_graph_models tests.test_graph_scheduler tests.test_graph_policy tests.test_graph_templates tests.test_runtime_kernel -q`
  -> 42 tests passed.
- Full offline suite: `python -m unittest discover -s tests -q`
  -> 218 tests run, 7 opt-in skips, no failures.
- `openspec validate add-adaptive-agent-graph-runtime --strict` -> valid.
- `git diff --check` -> no whitespace errors; Git reported only existing
  LF-to-CRLF working-copy warnings.

This was the interim validation record for the completed P2 and compatibility
work.

### Final verification gate

- Focused graph, report, and Web Python contracts:
  `python -m unittest tests.test_graph_models tests.test_graph_templates tests.test_graph_scheduler tests.test_graph_policy tests.test_graph_artifacts tests.test_graph_replay tests.test_runtime_kernel tests.test_runtime_cli_docs tests.test_tools_agents_reporting tests.test_web_backend_service`
  -> 78 tests passed.
- Complete offline Python suite:
  `python -m unittest discover -s tests -p 'test_*.py'`
  -> 231 tests passed; 7 explicitly opt-in live tests skipped.
- Frontend `vitest` contracts -> 13 passed, 1 opt-in test skipped; TypeScript
  typecheck passed.
- No API key, network, Docker daemon, MCP service, live target, or target write
  was used. The real-model graph-decision smoke was exercised only through its
  fail-closed `skipped` contract.
- Two accepted local paths were exercised: post-recon local-context refinement
  and post-analysis repeated analysis. Their invoked node sets differ and each
  replay matches its actual path. Repeating the analysis path produced the same
  normalized revisions, execution order, mutation results, statuses, and replay
  diagnostics.
- `deterministic-graph` became the default only after legacy parity and the
  failure suite passed. `legacy` remains selectable for rollback and
  `adaptive-graph` remains explicitly configurable.

### Review correction: skipped routing, dotenv smoke, and replay

- A post-analysis `route-verification` followed by `skip-optional` now removes
  the skipped routing node's outgoing edge only when the target already has an
  alternate incoming route. The bypass path can therefore execute
  Verification, while attempts to skip an optional node that is the sole
  upstream dependency remain policy-denied.
- A scheduler-level regression runs the committed candidate graph and proves
  that the routing node is skipped, Verification succeeds, report finalization
  remains reachable, and the skipped node is never invoked.
- An `AgentRuntime` fixture acceptance executes the same adaptive path through
  the real `GraphScheduler`, persists a succeeded run, and verifies that the
  final graph and replay both contain the mutation-driven skipped state.
- Replay restores direct status changes from committed mutation graph records,
  distinguishes them from skipped states already represented by transitions,
  and marks an unexplained final skipped state incomplete instead of inventing
  a complete replay.
- `graph-decision-smoke` loads `.env` into the same process environment used by
  prerequisite checks and the provider client. An offline fake-provider smoke
  proves `provider=openai-compatible`, `model=synthetic-real-model`, and
  `api_key_env=LLM_API_KEY` without printing the synthetic secret or making a
  network request.
- Focused graph policy, scheduler, replay, CLI, and runtime kernel suite:
  54 tests passed.
- Complete offline Python suite:
  `python -m unittest discover -s tests -p 'test_*.py'` -> 237 tests passed,
  7 explicitly opt-in live tests skipped.
- Frontend `vitest`: 13 tests passed, 1 opt-in test skipped.
- `openspec validate add-adaptive-agent-graph-runtime --strict` -> valid.
- No network, Docker, MCP, destructive operation, target write, real provider,
  or real target was used.

### Live graph-decision smoke correction

- The official smoke now allows at most 8 provider requests and 50,000 tokens,
  enough to reach both graph checkpoints while retaining explicit ceilings.
- A smoke run cannot report `passed` when every checkpoint produced a
  graph-decision fallback. Output reports prompt, successful-decision, fallback,
  and fallback-reason counts separately.
- Nested Analysis candidate fields are schema validated before conversion to a
  Finding. Categorical confidence such as `"high"` and incomplete source
  locations fail closed to the deterministic Analysis result instead of
  terminating graph execution.
- A bounded live run against `fixtures/integration_smoke` using the configured
  `openai-compatible` provider completed both checkpoints without graph fallback,
  committed revisions `0 -> 1 -> 2`, and produced two successful graph decisions.
- Replay was complete with two committed mutations, no denied mutations, missing
  refs, or inconsistencies. Target integrity was unchanged, Docker/MCP remained
  disabled, and the configured API key did not appear in run artifacts.
- Complete offline Python suite after the corrections: 239 tests passed, with 7
  explicitly opt-in tests skipped.
