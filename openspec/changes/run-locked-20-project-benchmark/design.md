## Context

This is the authorized operational successor to `add-real-benchmark-evaluation-pipeline`. It consumes that change's corpus lock, safe cache acquisition, completion proof, truth, resource, comparison, and promotion contracts.

## Goals / Non-Goals

**Goals:** select, lock, execute, review, and promote the first full baseline with at least 20 unique effectiveness-eligible projects.

**Non-Goals:** do not change scanner behavior to improve results, weaken safety/budgets, count revision pairs twice, or accept partial/unscanned entries.

## Decisions

### Decision 1: Treat project selection as reviewed operational data

Each selected project needs source/license provenance, supported language/shape, bounded scope, exact commits, truth, and safety policy before cache acquisition.

### Decision 2: Require complete execution before promotion

Every required case must prove commit, coverage, runtime, report, resource summary, cleanup, truth matching, and required adjudication. Partial mode is diagnostic only.

### Decision 3: Retain the full protocol and artifacts

The promoted baseline retains corpus lock/digest, per-case artifacts, benchmark JSON/Markdown, truth/adjudication, readiness, repetitions, and comparison protocol so later engine/prompt/model changes are measurable.

## Risks / Trade-offs

- Remote history or licenses may change. Exact locks and retained review provenance fail closed.
- Unsupported projects can distort coverage. They remain visible but do not satisfy quota or denominators.
- Resource cost may be high. Execution stays sequential and per-case budgets/timeouts remain mandatory.

## Migration Plan

Start only after a reviewed pilot baseline exists. Select and lock projects, prepare cache, execute and repair operational failures, adjudicate, validate all gates, then promote the full baseline.
