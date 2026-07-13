## Why

The benchmark pipeline and fixture baseline exist, but a defensible real-project baseline requires a separately authorized operational change. It must not reuse unresolved placeholders or count vulnerable/fixed revisions as independent projects.

## What Changes

- Select at least 20 unique, legally reviewable projects whose scan shapes are supported and effectiveness-eligible.
- Resolve and review exact commit locks, including vulnerable/fixed pairs and safe negative controls.
- Prepare the cache explicitly, run the complete corpus under bounded safety/resource policy, adjudicate required findings, and publish the first full baseline.
- Reject any run with missing execution proof, partial cases, cleanup/accounting gaps, or fabricated `remote-download-skipped` zeroes.

## Capabilities

### Modified Capabilities

- `benchmark-reporting-and-ci`: execute and promote the first reviewed at-least-20-unique-project baseline.

## Impact

This operational change requires explicit network/cache/provider/Docker authorization as applicable. It does not relax the local-only CI profile or target-write/project-execution prohibitions.
