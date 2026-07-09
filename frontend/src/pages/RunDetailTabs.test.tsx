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
          tasks: [{ id: "TSK-1", role: "analysis", kind: "agent", status: "succeeded", artifact_refs: ["a"], message_refs: ["m"] }]
        }}
        replaySummary={{
          message_count: 3,
          decision_lifecycle: { accepted_gates: 1 },
          runtime_lifecycle: { tool_calls: 1 }
        }}
        reportJson={{
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
    await userEvent.click(screen.getByRole("tab", { name: /findings/i }));
    expect(screen.getByText(/potential sql injection/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: /runtime tasks/i }));
    expect(screen.getByText("analysis")).toBeInTheDocument();
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
});
