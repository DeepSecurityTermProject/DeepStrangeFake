# Safety Notes

The system is designed for controlled local auditing of open-source projects.
It must not be used to attack unauthorized live systems.

## Adaptive Graph Safety

Model output cannot author graph JSON, code, commands, callables, predicates, tools, or file paths. It can only select checkpoint-specific action names from a closed schema. The runtime translates these names into registered templates, evaluates mutations on a copy, validates reachability and aggregate budgets, persists required artifacts, and only then adopts a revision. Any failure leaves the previous graph active.

The scheduler is single-threaded and local. Adaptive mode does not expand target scope, permit repository writes, enable network access, start Docker, or bypass ToolBroker and VerificationEngine policy. The optional real-model graph smoke is separately gated and restricted to local synthetic fixtures.

## Validation Levels

- `static-only`: review local source and tool evidence without runtime actions.
- `poc-generate`: generate a non-destructive local proof-of-concept artifact.
- `sandbox`: execute only configured local safe commands in a temporary
  workspace.
- `manual`: emit reproduction guidance when safe automation is not available.

## No-Live-Target Rule

Sandbox validation is blocked for remote GitHub/GitLab targets unless the
repository has been checked out and analyzed as a local path. Proof-of-concept
artifacts are local evidence only and must not send traffic to third-party
deployments.

## Command Safety

Sandbox commands are opt-in through configuration. The baseline implementation
rejects commands that include obvious network URLs, destructive filesystem
tokens, shell pipelines, redirection, or chained command operators.

## CVE Intelligence

CVE MCP output may be stale, unavailable, or incomplete. The system records
timestamps, query inputs, degraded mode, and the distinction between contextual
intelligence and validation evidence. Local evidence remains mandatory for
accepted findings.

## LLM Runtime Safety

Real-provider mode reads API keys from environment variables such as
`OPENAI_API_KEY`; keys must not be written into source files, prompts, reports,
or evidence artifacts. The runtime sends only selected repository context to the
LLM provider and records rendered prompts for auditability.

LLM output is untrusted until it passes schema validation and Verification
review. A model response cannot create an accepted vulnerability unless the
finding also links to local source or dependency evidence.

When `--llm-decisions` is enabled, model output is still only a proposal. The
central decision policy rejects malformed payloads, low-confidence proposals,
memory-only or CVE-only findings, unsafe validation levels, over-budget tool
plans, and live-target actions. The deterministic pipeline remains the fallback
source of truth.

## Tool-Calling Permissions

Runtime tool calls pass through a central permission and budget layer. Analysis
can request repository, scanner, memory, and vulnerability-intelligence tools,
but sandbox validation is restricted to Verification and Validation workflows.
Denied calls are recorded as structured messages and are not executed.

## RAG Memory Safety

The memory indexer supports exclusion patterns and redaction rules for sensitive
files and secret-like values. Retrieved memory is contextual evidence only; it
must be cited and tied back to local source artifacts before it can support a
finding.

## Message Bus Auditability

The append-only message log records runtime errors, permission denials,
timeouts, budget exhaustion, degraded MCP status, and agent/tool events. Replay
is for audit reconstruction; it does not re-execute tools or proof-of-concept
artifacts.
