import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { RunDetailTabs } from "./RunDetailTabs";

const job = {
  job_id: "JOB-1",
  target: "fixtures/integration_smoke",
  status: "succeeded",
  created_at: "2026-07-08T00:00:00Z",
  output_dir: "runs",
  run_dir: "runs/run-1",
  summary: {
    candidate_count: 1,
    rejected_count: 0,
    validated_count: 1,
    runtime_state_ref: "runs/run-1/runtime_state/state.json"
  },
  error: ""
};

describe("RunDetailTabs", () => {
  it("shows summary, findings, runtime tasks, replay, and markdown report tabs", async () => {
    render(
      <RunDetailTabs
        job={job}
        runtimeState={{
          graph_mode: "adaptive-graph",
          tasks: [{ id: "TSK-1", role: "analysis", kind: "agent", status: "succeeded", graph_node_id: "analysis", graph_revision: 1, attempt: 1, artifact_refs: ["a"], message_refs: ["m"] }]
        }}
        replaySummary={{
          message_count: 3,
          decision_lifecycle: { accepted_gates: 1 },
          runtime_lifecycle: { tool_calls: 1 }
        }}
        reportJson={{
          runtime: {
            graph: {
              mode: "adaptive-graph",
              revision: 1,
              mutation_counts: { committed: 1, denied: 0 },
              checkpoint_total: 1,
              fallback_reason: ""
            }
          },
          findings: [
            {
              id: "F-1",
              title: "Potential SQL injection",
              vulnerability_class: "sql-injection",
              severity: "high",
              confidence: 0.72,
              location: { path: "app.py", start_line: 15 },
              evidence: ["select * from users"],
              remediation: "Use parameterized queries."
            }
          ]
        }}
        markdownReport="# Agentic Security Audit Report"
      />
    );

    expect(screen.getByText(/validated/i)).toBeInTheDocument();
    expect(screen.getByText("adaptive-graph")).toBeInTheDocument();
    expect(screen.getByText(/1 committed/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: /findings/i }));
    expect(screen.getByText(/potential sql injection/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: /runtime tasks/i }));
    expect(screen.getAllByText("analysis").length).toBeGreaterThan(0);
    await userEvent.click(screen.getByRole("tab", { name: /replay/i }));
    expect(screen.getByText(/message count/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: /markdown report/i }));
    expect(screen.getByText(/agentic security audit report/i)).toBeInTheDocument();
  });

  it("shows unavailable states when artifacts are missing", async () => {
    render(<RunDetailTabs job={job} />);

    await userEvent.click(screen.getByRole("tab", { name: /runtime tasks/i }));
    expect(screen.getByText(/runtime state is not available/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: /markdown report/i }));
    expect(screen.getByText(/markdown report is not available/i)).toBeInTheDocument();
  });

  it("shows verification status distribution and candidate evidence", async () => {
    render(
      <RunDetailTabs
        job={{
          ...job,
          summary: {
            ...job.summary,
            confirmed_count: 1,
            likely_count: 1,
            rejected_count: 1,
            manual_required_count: 1
          }
        }}
        reportJson={{
          executive_summary: {
            confirmed_count: 1,
            likely_count: 1,
            rejected_count: 1,
            manual_required_count: 1
          },
          findings: [],
          verification_candidates: [
            {
              id: "F-path",
              title: "Potential path traversal",
              vulnerability_class: "path-traversal",
              severity: "high",
              confidence: 0.86,
              verification_status: "confirmed",
              verification_reason: "Traversal signal observed from sandbox output.",
              location: { path: "app.py", start_line: 18 },
              validation: {
                level: "sandbox",
                exit_code: 0,
                environment: { runner: "docker", docker_image: "python:3.12-slim" },
                judge_reason: "Traversal signal observed from stdout.",
                poc_refs: ["runs/run-1/verification/F-path/poc.json"],
                sandbox_result_refs: ["runs/run-1/verification/F-path/result.json"],
                stdout_preview: "PATH_TRAVERSAL_CONFIRMED",
                stderr_preview: ""
              },
              repair_summary: {
                attempt_count: 1,
                classifications: [{ attempt_index: 1, failure_class: "harness-error" }],
                semantic_integrity_status: "allowed",
                safety_status: "allowed",
                final_status: "confirmed",
                integrity: { unchanged: true },
                final_stop_reason: "terminal-outcome"
              }
            },
            {
              id: "F-sql",
              title: "Potential SQL injection",
              vulnerability_class: "sql-injection",
              severity: "high",
              confidence: 0.72,
              verification_status: "manual-required",
              verification_reason: "Unsupported vulnerability class for MVP PoC execution.",
              location: { path: "app.py", start_line: 8 }
            }
          ]
        }}
      />
    );

    expect(screen.getByText("Confirmed")).toBeInTheDocument();
    expect(screen.getByText("Manual required")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: /findings/i }));
    expect(screen.getByText(/potential path traversal/i)).toBeInTheDocument();
    expect(screen.getAllByText(/confirmed/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/^docker$/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/python:3.12-slim/i)).toBeInTheDocument();
    expect(screen.getByText(/PATH_TRAVERSAL_CONFIRMED/i)).toBeInTheDocument();
    expect(screen.getByText(/harness-error@1/i)).toBeInTheDocument();
    expect(screen.getByText(/^unchanged$/i)).toBeInTheDocument();
    expect(screen.getByText(/terminal-outcome/i)).toBeInTheDocument();
    expect(screen.getByText(/unsupported vulnerability class/i)).toBeInTheDocument();
  });
});
