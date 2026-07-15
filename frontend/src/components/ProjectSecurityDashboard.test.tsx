import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import type { PostureSnapshot, ProjectSecurityDashboard as Dashboard } from "../api/types";
import { ProjectSecurityDashboard } from "./ProjectSecurityDashboard";

const run = {
  job_id: "JOB-2",
  project_id: "PRJ-1",
  status: "succeeded",
  phase: "complete",
  created_at: "2026-07-15T01:00:00Z",
  started_at: "2026-07-15T01:00:01Z",
  finished_at: "2026-07-15T01:00:10Z",
  resolved_commit: "abc123"
};

const finding = {
  finding_id: "F-CMD",
  title: "Command injection in job runner",
  vulnerability_class: "command-injection",
  severity: "critical",
  confidence: 1,
  location: { path: "src/jobs.py", start_line: 42, end_line: 42, symbol: "execute_job" },
  verification_status: "confirmed",
  evidence_state: "complete",
  evidence_refs: ["EC-F-CMD", "EVI-1"],
  artifact_refs: [{ path: "evidence/F-CMD.json", url: "/api/runs/JOB-2/artifacts/evidence/F-CMD.json" }],
  run_id: "JOB-2",
  fingerprint: "FP-CMD",
  fingerprint_version: "finding-fingerprint.v1",
  trend_status: "new",
  run_url: "/projects/PRJ-1/runs/JOB-2?finding=F-CMD"
};

const snapshot: PostureSnapshot = {
  schema_version: "project-security-posture.v1",
  run_id: "JOB-2",
  project_id: "PRJ-1",
  created_at: "2026-07-15T01:00:10Z",
  versions: {
    completeness: "posture-completeness.v1",
    risk_formula: "validated-severity-confidence.v1",
    fingerprint: "finding-fingerprint.v1",
    trend: "finding-trend.v1"
  },
  availability: { status: "available", reasons: [] },
  run,
  repository: { resolved_commit: "abc123", languages: { Python: 100 }, dependency_count: 2 },
  coverage: { available: true, scanned_files: 25, scanned_bytes: 1200, language: "Python", scope: {} },
  findings: {
    contract_available: true,
    validated: [finding],
    states: {
      candidate: [finding, finding, finding],
      pending: [],
      manual: [finding],
      rejected: [finding, finding],
      inconclusive: []
    },
    validation_counts: { validated: 1, candidate: 3, pending: 0, manual: 1, rejected: 2, inconclusive: 0 },
    evidence_gate_failures: 0
  },
  severity_counts: { critical: 1, high: 0, medium: 0, low: 0, informational: 0 },
  risk: {
    available: true,
    authoritative: true,
    score: 25,
    uncapped_total: 25,
    cap: 100,
    formula: "min(100, round_half_up(sum(severity_weight * clamped_confidence)))",
    formula_version: "validated-severity-confidence.v1",
    severity_weights: { critical: 25, high: 15, medium: 7, low: 2, informational: 0 },
    confidence_fallback_rule: "validated-missing-or-invalid-confidence=1.0",
    fallback_count: 0,
    clamped_count: 0,
    components: [{ finding_id: "F-CMD", contribution: 25 }]
  },
  completeness: {
    schema_version: "posture-completeness.v1",
    complete: true,
    status: "complete",
    checks: { coverage_evidence: true, validation_complete: true },
    reasons: []
  },
  quality: {
    requested_mode: "agent-led",
    effective_mode: "agent-led",
    fallback_reason: null,
    degraded_reasons: [],
    budget: { used: { requests: 3, tokens: 400 } },
    accounting_status: "complete",
    accounting_gaps: [],
    evidence_complete: true,
    validation_complete: true
  },
  trend: {
    comparison_status: "comparable",
    comparable: true,
    basis_run_id: "JOB-1",
    counts: { new: 1, persistent: 0, resolved: 1, reintroduced: 0, unconfirmed: 0 },
    limitations: []
  }
};

function dashboard(overrides: Partial<Dashboard> = {}): Dashboard {
  return {
    schema_version: "project-security-dashboard.v1",
    state: "complete",
    project: {
      project_id: "PRJ-1",
      display_name: "Course service",
      source_kind: "local",
      source: { kind: "local", path: "D:/course/service" },
      source_identity: "local:d:/course/service",
      source_display: "D:/course/service",
      status: "active",
      languages: [{ name: "Python", files: 25 }],
      metadata: { file_count: 25 },
      created_at: "2026-07-14T00:00:00Z",
      updated_at: "2026-07-15T01:00:00Z",
      latest_run: run
    },
    latest_run: run,
    latest_run_posture: snapshot,
    latest_complete_posture: snapshot,
    posture: snapshot,
    posture_is_historical: false,
    active_runs: [],
    recent_runs: [],
    trend_series: [
      {
        run_id: "JOB-1",
        created_at: "2026-07-14T01:00:00Z",
        complete: true,
        risk_score: 15,
        confirmed_count: 1,
        severity_counts: { high: 1 },
        trend_counts: { new: 1, persistent: 0, resolved: 0, reintroduced: 0, unconfirmed: 0 },
        comparison_status: "baseline"
      },
      {
        run_id: "JOB-2",
        created_at: "2026-07-15T01:00:00Z",
        complete: true,
        risk_score: 25,
        confirmed_count: 1,
        severity_counts: { critical: 1 },
        trend_counts: snapshot.trend.counts,
        comparison_status: "comparable"
      }
    ],
    high_risk_findings: [finding],
    limitations: [],
    ...overrides
  };
}

function renderDashboard(value: Dashboard) {
  return render(<MemoryRouter><ProjectSecurityDashboard dashboard={value} /></MemoryRouter>);
}

describe("ProjectSecurityDashboard", () => {
  it("explains deterministic risk and keeps candidate states separate from confirmed findings", async () => {
    renderDashboard(dashboard());
    expect(screen.getByLabelText("Risk score 25 out of 100")).toBeInTheDocument();
    expect(screen.getByText("Static / likely candidates").parentElement).toHaveTextContent("3");
    expect(screen.getByText("Confirmed findings").parentElement).toHaveTextContent("01");
    expect(screen.getByText(/deliberately excluded from confirmed totals/i)).toBeInTheDocument();

    await userEvent.click(screen.getByText("Formula and components"));
    expect(screen.getByText("validated-severity-confidence.v1")).toBeInTheDocument();
    expect(screen.getByText(/critical 25, high 15/i)).toBeInTheDocument();
    expect(screen.getByText(/missing-or-invalid-confidence=1.0/i)).toBeInTheDocument();
  });

  it("provides a numeric trend table and evidence-linked high-risk navigation", () => {
    renderDashboard(dashboard());
    const table = screen.getByRole("table", { name: "Numeric security posture trend by run" });
    expect(table).toHaveTextContent("JOB-1");
    expect(table.textContent).toMatch(/resolved/i);
    expect(table.textContent).toMatch(/reintroduced/i);
    expect(table.textContent).toMatch(/unconfirmed/i);
    expect(screen.getByRole("link", { name: /open run and finding/i })).toHaveAttribute(
      "href",
      "/projects/PRJ-1/runs/JOB-2?finding=F-CMD"
    );
    expect(screen.getByText(/src\/jobs.py:42/)).toBeInTheDocument();
    expect(screen.getByText(/2 evidence reference/)).toBeInTheDocument();
  });

  it("labels stale and missing posture without displaying zero risk", () => {
    const failedRun = { ...run, job_id: "JOB-3", status: "failed", finished_at: "2026-07-15T02:00:00Z" };
    const { rerender } = renderDashboard(dashboard({
      state: "stale-historical-posture",
      latest_run: failedRun,
      latest_run_posture: null,
      posture_is_historical: true,
      limitations: ["report-unavailable"]
    }));
    expect(screen.getByText("Latest run is incomplete")).toBeInTheDocument();
    expect(screen.getByText(/displayed posture is historical/i)).toBeInTheDocument();
    expect(screen.getByText("Historical — not latest run")).toBeInTheDocument();

    rerender(<MemoryRouter><ProjectSecurityDashboard dashboard={dashboard({
      state: "running-only",
      latest_run: { ...run, status: "running", finished_at: null },
      latest_run_posture: null,
      latest_complete_posture: null,
      posture: null,
      active_runs: [{ ...run, status: "running", finished_at: null }],
      trend_series: [],
      high_risk_findings: [],
      limitations: ["no-terminal-posture"]
    })} /></MemoryRouter>);
    expect(screen.getByText("Audit in progress")).toBeInTheDocument();
    expect(screen.getByLabelText("Risk score unavailable")).toHaveTextContent("N/A");
    expect(screen.queryByLabelText("Risk score 0 out of 100")).not.toBeInTheDocument();
    expect(screen.getAllByText(/no complete posture exists yet/i).length).toBeGreaterThan(0);
  });
});
