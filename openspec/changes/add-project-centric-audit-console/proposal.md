## Why

The existing Web UI is organized around individual scan jobs and periodic polling, so it cannot manage multiple repositories as durable projects, show a live auditable Agent investigation, or summarize a project's security posture over time. A project-centric console is needed now to make the agent-led audit runtime usable as a complete course-project workflow without weakening the runtime's evidence, replay, and safety boundaries.

## What Changes

- Add a persistent `Project` model representing one normalized local directory or public GitHub/GitLab repository, with one project owning many scan runs.
- Add project catalog, project detail, archive/restore, repository preflight, duplicate-source detection, and project-scoped scan creation APIs backed by a transactional SQLite management index.
- Preserve reports, evidence, replay data, and other large run artifacts in the existing filesystem layout; idempotently import legacy `jobs.json` records without deleting or corrupting the source file.
- Add a three-step scan wizard that selects or creates a project, preflights its source and revision, and starts a real scan. Public remote sources may select a branch, tag, or commit while private-repository credentials remain out of scope.
- Add project-first navigation, a multi-project management page, project dashboards, project run history, a cross-project run view, and redirects for legacy `/runs/:runId` links.
- Add a durable, redacted run-event journal and an SSE endpoint with event identifiers, reconnect/resume semantics, heartbeats, and polling fallback.
- Add a live and replayable run workspace that presents phases, progress, structured Agent rationale summaries, hypotheses, actions, tool calls, evidence, validation outcomes, budgets, and errors without exposing hidden chain-of-thought.
- Add deterministic project security posture aggregation based primarily on validated findings, including severity counts, coverage/completeness indicators, fixed-rule risk scores, stable finding fingerprints, and new/persistent/resolved/reintroduced trends.
- Keep task control intentionally narrow: queued or running jobs may be cancelled, terminal jobs may be rerun, and partial evidence is retained; pause, interactive Agent intervention, permanent deletion, authentication, private repositories, and multi-tenancy remain out of scope.
- Develop backend APIs and React UI as tested vertical slices; existing `/api/runs` behavior and CLI/runtime entrypoints remain backward compatible.

## Frontend Design Prompt

Use the following prompt as the frontend design and implementation brief for this change. It is subordinate to the functional, security, evidence, accessibility, and compatibility requirements in this proposal and its specs; when a visual effect conflicts with audit readability or `prefers-reduced-motion`, preserve usability and provide the required static equivalent.

```text
<role>
You are an expert frontend engineer, UI/UX designer, visual design specialist, and typography expert. Integrate the design system below into the existing DeepStrangeFake frontend in a visually consistent, maintainable, accessible, and idiomatic way.

Before proposing or writing code:
1. Inspect the current frontend stack, package dependencies, routes, global styles, design tokens, CSS utilities, component architecture, naming conventions, tests, bundle constraints, and backend API contracts.
2. Reuse the current React + TypeScript + React Router + TanStack Query + Vitest architecture. Translate Tailwind-like examples in this prompt into the repository's actual styling approach unless adding a dependency is explicitly justified by the implementation plan.
3. Treat the already-approved scope as settled: build the project catalog, three-step scan wizard, project dashboard, global/project run history, and live/replay Agent investigation workspace in the new style. Do not reopen product questions already resolved by this change.
4. Propose a concise implementation plan that centralizes design tokens, creates reusable layout and data-display primitives, minimizes one-off styles, preserves existing patterns, and identifies any justified font or motion dependency before adding it.
5. Briefly explain important design-system choices while implementing them, and leave the codebase more coherent than it was found.

Always preserve or improve accessibility, responsiveness, maintainability, clear naming, performance, and operational readability. Make deliberate choices in layout, motion, interaction, and typography; do not produce a generic dark dashboard.
</role>

<design-system>
# Design Style: Kinetic Typography

## Philosophy and visual direction

Typography is the primary visual structure: text becomes image, headlines become hero elements, and motion creates rhythm. The aesthetic combines high-energy brutalism, kinetic poster design, street-art confidence, underground-zine rawness, and Swiss typographic precision.

The interface MUST remain recognizable through:
- viewport-responsive oversized typography;
- uppercase, tightly tracked display text;
- near-black/off-white contrast with one acid-yellow accent;
- sharp borders, flat surfaces, and zero-radius geometry;
- massive decorative numbers;
- bold color inversions and decisive hover states;
- purposeful marquee, hover, and scroll motion with accessible static fallbacks.

Apply the highest kinetic intensity to page titles, project counts, scan statistics, empty states, section transitions, dashboard summary bands, and navigation moments. Keep dense operational areas such as logs, code evidence, long tables, forms during data entry, and Agent event details stable enough to scan and read. Motion MUST communicate hierarchy or state and MUST NOT interfere with live audit monitoring.

## Design tokens

Centralize these tokens instead of scattering literal values:

- background: #09090B
- foreground: #FAFAFA
- muted: #27272A
- muted-foreground: #A1A1AA
- accent: #DFE104
- accent-foreground: #000000
- border: #3F3F46
- radius: 0px by default; 2px only for rare small-element softening
- structural border: 2px solid; subtle divider: 1px solid
- base spacing unit: 4px

Use acid yellow sparingly but boldly for primary action, active state, focus, selected data, key statistics, and deliberate section inversions. Use Zinc 400 for secondary text, Zinc 700 for structural lines, and Zinc 800/900 surfaces for depth. Do not use gradients, soft shadows, pastel colors, multiple competing accents, pure-white page backgrounds, or decorative mid-tone color palettes. Use borders, overlap, typography, and color layers rather than drop shadows to create depth.

Selection MUST use an acid-yellow background with black text. Severity and lifecycle states MUST retain their existing semantic meaning and accessible labels; the design-system accent MUST NOT replace security severity colors or make color the only status signal.

## Typography

- Preferred display/body family: Space Grotesk variable font.
- Fallback: Inter, then the repository's safe sans-serif stack.
- Use a readable monospace stack for logs, paths, code evidence, hashes, event IDs, and tool output.
- Hero/display: clamp(3rem, 12vw, 14rem), with page-specific caps where necessary.
- Section heading: clamp(2.5rem, 8vw, 6rem).
- Card title: responsive 1.5rem to 3.75rem.
- Body/description: responsive 1.125rem to 1.5rem where layout permits.
- Small label/navigation: 0.75rem to 1.125rem.
- Decorative numbers: responsive 6rem to 12rem.

All headings, buttons, navigation labels, metric labels, status labels, and other display text MUST be uppercase with tight or tighter tracking. Body descriptions, evidence, filenames, user-entered paths, repository URLs, code, and detailed logs MUST preserve readable casing. Use leading-none or approximately 0.8 for massive display lockups and leading-tight for large body copy. Use weight 700 for headings/actions, 500 for primary body copy, and 400 for secondary text.

The largest and smallest display sizes SHOULD differ by roughly 8-10x, but typography MUST remain readable at 200% zoom and must not obscure task controls, severity, evidence, or connection status.

## Spacing, layout, and shape

- Use wide containment, generally 90-95vw, rather than a conservative centered dashboard shell.
- Major display sections use approximately 80-128px vertical padding on desktop and scale down responsively.
- Cards and major panels use approximately 32-48px padding on desktop, with reduced mobile padding.
- Standard major gap: 32px; tight group: 16px; wide separation: 48-96px.
- Use full-bleed title/stat bands where they clarify hierarchy.
- Use one-column mobile, two-column tablet, and two/three-column desktop layouts where the information supports them.
- Use `gap: 1px` grids over the border color to create connected catalog, metric, and dashboard systems.
- Use asymmetry, overlap, sticky sections, and grid-breaking display elements intentionally, while keeping tables, forms, and live timelines aligned.
- Corners MUST remain square. Do not introduce rounded cards or pill-heavy dashboards.
- Use solid 2px structural borders and 1px dividers; never dashed or dotted decoration.
- Do not use drop shadows. Use color inversion, border emphasis, overlap, and muted background layers.

A subtle fixed SVG noise texture MAY be used at about 0.03 opacity with `feTurbulence`, overlay blend mode, pointer-events disabled, and an accessible/decorative treatment. It MUST NOT reduce text contrast or live-view performance.

## Component rules

### Buttons

- Uppercase, bold, tight tracking, square corners.
- Minimum 44px touch target; standard height about 56px, compact 40-44px, major CTA up to 80px.
- Primary: acid-yellow background, black text, scale to approximately 1.05 on hover and 0.95 on active.
- Outline: 2px Zinc 700 border, transparent background, off-white text; invert to off-white/black on hover.
- Ghost: no border, off-white text; change to acid yellow on hover.
- Disabled: 50% opacity, no pointer interaction, with a programmatically exposed disabled state.
- Keyboard focus MUST use a visible acid-yellow indicator of at least 2px and MUST NOT rely on scale alone.

### Cards and containers

- Rich-black surface, 2px Zinc 700 border, large square padding, no shadow, no radius.
- Interactive cards MAY flood to acid yellow on hover/focus with black text and coordinated child-state inversion.
- Keep selected, running, failed, degraded, severity, and disabled states semantically distinguishable from decorative hover inversion.
- Use oversized muted indices or counts as `aria-hidden` graphic shapes where appropriate.
- Sticky overlapping cards MAY be used for onboarding steps or project summaries, but not for the live event list or evidence reading surface.

### Inputs and forms

- Use generous touch height and clear uppercase labels, but preserve the casing of paths, URLs, branch names, tags, commits, model names, and other technical values.
- Major source-entry fields MAY use oversized 64-96px input treatment with a 2px bottom border, transparent background, large text, and acid focus border.
- Do not remove visible focus indication.
- Use large vertical spacing, inline validation, stable error summaries, and explicit preflight/loading/success/failure states.
- Placeholder contrast MUST remain readable; do not use #27272A as the sole placeholder color if it fails the required contrast at the rendered size.

### Data-dense operational components

- Logs, Agent events, evidence, findings, paths, and tables MUST prioritize scanability over spectacle.
- Use a stable monospace detail layer, clear timestamps, fixed semantic columns where appropriate, expandable bounded payloads, and visible keyboard focus.
- Do not continuously translate, scale, or marquee user-selectable evidence, log lines, code, status text, error messages, or interactive controls.
- Use kinetic type in headers, counts, phase transitions, and summary bands around these surfaces rather than animating the evidence itself.

## Required signature elements

The completed console MUST include all of the following, adapted to real product data:

1. At least one viewport-width headline using 10vw or greater through a safe `clamp()` expression.
2. At least two infinite marquees with no gradient edges: one faster statistics/status marquee and one slower informational/project or finding marquee. Interactive marquee content MUST remain keyboard reachable and MUST have a non-moving reduced-motion representation.
3. Massive muted background numbers in the 8rem-12rem range as decorative project, stage, run, or metric graphics with `aria-hidden="true"`.
4. Hard black/off-white to acid-yellow/black color inversion on selected interactive cards or sections.
5. Uppercase display treatment for headings, actions, labels, and navigation.
6. An aggressive 8-10x display-scale hierarchy without shrinking body, status, or evidence text below readable sizes.
7. Sharp square geometry, 2px structural borders, flat depth, and no drop shadows.

If these signatures are removed or softened into a generic card dashboard, the implementation does not satisfy the intended visual direction.

## Motion system

Prefer GPU-friendly transform and opacity animation. Avoid layout-thrashing scroll handlers and expensive effects in the live timeline.

- Fast statistics marquee: linear, speed approximately 60-100, no edge gradient, repeated continuously when motion is allowed.
- Slower informational marquee: linear, speed approximately 30-50, no edge gradient.
- Hero scroll treatment: optional scale approximately 1.0 to 1.2 and opacity 1.0 to 0 over the initial scroll range.
- Entrance treatment: clipped text reveal, opacity, or scale approximately 0.8 to 1.0, used selectively.
- Button micro-interaction: 200-300ms scale/contrast response.
- Card inversion and title translation: approximately 300ms.
- Section transitions: approximately 500-800ms maximum.
- Sticky stacking MAY use top offsets around 96-128px where it does not hide controls.

`react-fast-marquee` and Framer Motion are preferred for the specified marquee and scroll behavior only if repository inspection confirms that their bundle and maintenance cost are acceptable. Otherwise implement equivalent accessible, GPU-friendly behavior with existing primitives and tests. Do not add a general component framework solely to reproduce Tailwind examples.

## Responsive behavior

- Design mobile-first from 320px, then verify at 768px, 1024px, and 1440px or wider.
- Preserve dramatic type through `clamp()` rather than overflowing narrow screens.
- Stack complex grids on mobile; increase to two columns at tablet and up to three where appropriate on desktop.
- Reduce section/card padding progressively while preserving at least 44x44px touch targets.
- Keep marquees as static wrapped lists when reduced motion is requested or when narrow-screen readability requires it.
- Do not hide essential descriptions behind hover on touch devices.
- Adjust sticky offsets for navigation height and disable sticky overlap when it causes narrow-screen occlusion.
- Ensure project catalog, scan wizard, run workspace, dashboard, filters, tables, and dialogs remain usable at 200% zoom.

## Accessibility and quality gates

- Meet WCAG AA contrast for all text and interactive states; preserve approximately 15:1 off-white/black and 12:1 yellow/black where these token pairs are used.
- Respect `prefers-reduced-motion`: stop marquees, disable scroll transforms, and render complete static content without losing hierarchy or data.
- Provide a visible minimum-2px focus indication for every interactive element.
- Support keyboard-only navigation, including filters, expandable events, dialogs, accordions, project cards, wizard steps, and finding drill-down.
- Provide a skip link when navigation is complex.
- Mark decorative numbers and texture as hidden from assistive technology.
- Do not use `aria-live` on continuously moving decorative marquee content. Use appropriately scoped live regions only for meaningful scan, connection, and validation state changes.
- Announce expanded/collapsed state and asynchronous preflight/submission errors.
- Do not use color as the only indicator for severity, status, selection, stream health, or trend.
- Verify screen-reader semantics, keyboard operation, reduced motion, contrast, 200% zoom, narrow screens, and touch targets in automated and manual acceptance.

## Anti-patterns

Do not use gradients, soft shadows, large border radii, pastel palettes, multiple accent colors, serif/script display fonts, small timid headings, mixed-case display labels, centered long body copy, conservative boxed-in page widths, generic rounded dashboard cards, subtle low-contrast hover states, or slow decorative bounce everywhere.

Do not sacrifice audit readability for constant motion. Never marquee or animate code evidence, logs, user-entered values, error messages, table rows under active reading, or controls required to cancel a task. Never expose hidden Agent chain-of-thought as a visual effect or content source.

## Page-specific application

- Project catalog: oversized project count and page title, connected square-card grid, hard hover/focus inversion, safe source metadata, clear archived/running/degraded states, and a fast aggregate-stat marquee.
- Scan wizard: dramatic step numbers and typography, stable source inputs, clear three-step progress, strong preflight feedback, and a review screen that preserves technical-value casing.
- Live run workspace: kinetic phase heading and summary bands around a stable filterable event timeline; clear SSE/polling state, effective Agent mode, budget, evidence, cancellation, and degradation information.
- Project dashboard: massive deterministic risk and confirmed-finding figures, accessible severity/trend representations, historical comparison, quality indicators, high-risk drill-down, and a slower informational marquee based on real project/run data.
- Global run list and settings: use the same tokens and square geometry, but keep operational filtering and tables compact, stable, and readable.

The final result should feel like a kinetic poster transformed into a serious security-audit instrument: unmistakably bold at the page and summary level, precise and calm wherever the user must read evidence or control a running task.
</design-system>
```

## Capabilities

### New Capabilities

- `project-audit-workspace`: Defines durable projects, normalized source identity, repository preflight, project lifecycle, project-scoped runs, SQLite indexing, legacy import, navigation, and the scan creation workflow.
- `audit-run-event-stream`: Defines the persisted and redacted event contract, SSE delivery and resumption, polling fallback, live investigation timeline, and post-run replay behavior.
- `project-security-posture`: Defines project dashboard metadata, validated-finding metrics, deterministic risk scoring and fingerprints, scan completeness gates, and historical vulnerability trends.

### Modified Capabilities

- None. The change reuses the existing audit runtime, run artifacts, replay records, remote acquisition controls, and report contracts without changing their current guarantees.

## Impact

- Backend: `audit_agent/server` schemas, persistence, API routes, job lifecycle integration, source preflight, event projection, SSE responses, and dashboard aggregation.
- Frontend: React routes, API contracts, application shell, project catalog, scan wizard, live run workspace, project dashboard, charts, accessibility states, and tests.
- Frontend design: the embedded Kinetic Typography prompt is the visual implementation brief; Space Grotesk and narrowly scoped marquee/motion dependencies may be added only after stack, accessibility, bundle, and reduced-motion review.
- Storage: a local SQLite database for project/run/index data plus append-only per-run event JSONL; existing run artifact directories remain authoritative for detailed evidence and reports.
- Compatibility: legacy `jobs.json`, `/api/runs`, `/runs`, `/runs/:runId`, CLI commands, and direct `run_audit()` execution remain supported.
- Security: no raw API keys, authentication headers, hidden model reasoning, unrestricted tool output, or arbitrary artifact paths are exposed; local source access and remote acquisition continue to be enforced by backend policy.
- Deployment: remains a single-user localhost application with no external database service or credential-management UI.
