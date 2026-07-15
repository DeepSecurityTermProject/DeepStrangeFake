import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "../api/client";
import type { ApiOptions, Project, SourcePreflightResponse } from "../api/types";
import { ScanWizardPage } from "./ScanWizardPage";

vi.mock("../api/client", () => ({
  apiClient: {
    getOptions: vi.fn(),
    listProjects: vi.fn(),
    getProject: vi.fn(),
    getRerunConfiguration: vi.fn(),
    preflightSource: vi.fn(),
    createRun: vi.fn(),
    createProjectRun: vi.fn()
  }
}));

const options: ApiOptions = {
  provider_modes: ["mock", "openai-compatible"],
  graph_modes: ["agent-led", "legacy"],
  default_graph_mode: "agent-led",
  memory_modes: ["lexical", "off"],
  mcp_modes: ["off", "on"],
  validation_levels: ["static-only", "sandbox"],
  llm_decision_roles: ["analysis", "verification"],
  sandbox_runners: ["local", "docker"],
  default_docker_image: "python:3.12-slim",
  default_docker_context: "",
  default_docker_host: "",
  default_exclude_patterns: ["tests/**"],
  remote_acquisition: { enabled: true, network_enabled: true, allowed_hosts: ["github.com", "gitlab.com"], supports_head: true, limits: {} }
};

const project: Project = {
  project_id: "PRJ-1",
  display_name: "Existing Course Repo",
  source_kind: "local",
  source: { kind: "local", path: "D:/course/repo" },
  source_identity: "local:d:/course/repo",
  source_display: "D:/course/repo",
  status: "active",
  languages: [{ name: "Python", files: 2 }],
  metadata: { file_count: 2 },
  created_at: "2026-07-14T00:00:00Z",
  updated_at: "2026-07-14T00:00:00Z"
};

const preview: SourcePreflightResponse = {
  preflight_token: "opaque-preflight-token",
  expires_at: "2026-07-14T01:00:00Z",
  source: { kind: "local", path: "D:/course/repo" },
  source_identity: "local:d:/course/repo",
  source_display: "D:/course/repo",
  suggested_name: "repo",
  revision_type: "local",
  policy_version: "source-preflight.v1",
  languages: [{ name: "Python", files: 2 }],
  metadata: { file_count: 2, total_bytes: 100 },
  existing_project_id: "PRJ-1"
};

function renderWizard(path = "/scans/new") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/scans/new" element={<ScanWizardPage />} />
          <Route path="/projects/:projectId/scans/new" element={<ScanWizardPage />} />
          <Route path="/projects/:projectId/runs/:jobId" element={<div>Run workspace reached</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("ScanWizardPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.getOptions).mockResolvedValue(options);
    vi.mocked(apiClient.listProjects).mockResolvedValue({ projects: [project], total: 1 });
    vi.mocked(apiClient.getProject).mockResolvedValue(project);
    vi.mocked(apiClient.getRerunConfiguration).mockResolvedValue({
      source_run_id: "JOB-OLD",
      project_id: "PRJ-1",
      configuration: {
        source: project.source,
        graph_mode: "legacy",
        runtime: false,
        llm_provider: "mock",
        memory_mode: "off",
        mcp_mode: "on",
        validation_level: "sandbox",
        include_patterns: ["src/**"],
        exclude_patterns: ["tests/**"]
      }
    });
    vi.mocked(apiClient.preflightSource).mockResolvedValue(preview);
    vi.mocked(apiClient.createProjectRun).mockResolvedValue({ job_id: "JOB-1", project_id: "PRJ-1", status: "queued", status_url: "/api/runs/JOB-1", run_url: "/projects/PRJ-1/runs/JOB-1" });
  });

  it("walks all three steps, reports duplicate ownership, and reaches the project run", async () => {
    renderWizard();
    expect(await screen.findByRole("heading", { name: "New scan" })).toBeInTheDocument();
    expect(screen.getByRole("list", { name: /scan creation progress/i })).toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText(/server-local absolute path/i));
    await userEvent.type(screen.getByLabelText(/server-local absolute path/i), "D:/course/repo");
    await userEvent.click(screen.getByRole("button", { name: /run preflight/i }));

    expect(await screen.findByText(/already belongs to a project/i)).toBeInTheDocument();
    expect(screen.getByText("Python")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /configure scan/i }));
    expect(await screen.findByRole("heading", { name: /review execution/i })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /launch audit/i }));

    await waitFor(() => expect(apiClient.createProjectRun).toHaveBeenCalledWith("PRJ-1", expect.objectContaining({ preflight_token: "opaque-preflight-token", graph_mode: "agent-led" })));
    expect(await screen.findByText("Run workspace reached")).toBeInTheDocument();
  });

  it("supports GitHub revision selection and exposes recoverable preflight errors", async () => {
    vi.mocked(apiClient.preflightSource).mockRejectedValueOnce(new Error("revision-not-found"));
    renderWizard();
    await screen.findByRole("heading", { name: "New scan" });
    await userEvent.click(screen.getByRole("button", { name: "github" }));
    await userEvent.type(screen.getByLabelText(/public github https url/i), "https://github.com/acme/repo");
    await userEvent.selectOptions(screen.getByLabelText(/revision type/i), "branch");
    await userEvent.type(screen.getByLabelText(/^branch$/i), "main");
    await userEvent.click(screen.getByRole("button", { name: /run preflight/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent("revision-not-found");
    expect(vi.mocked(apiClient.preflightSource).mock.calls[0][0]).toEqual({ source: { kind: "github", url: "https://github.com/acme/repo" }, revision_type: "branch", revision: "main" });
  });

  it("keeps submission errors on the review step for retry", async () => {
    vi.mocked(apiClient.createProjectRun).mockRejectedValueOnce(new Error("runner-submit-failed"));
    renderWizard("/projects/PRJ-1/scans/new");
    await screen.findByRole("heading", { name: "New scan" });
    await userEvent.click(screen.getByRole("button", { name: /run preflight/i }));
    await userEvent.click(await screen.findByRole("button", { name: /configure scan/i }));
    await userEvent.click(screen.getByRole("button", { name: /launch audit/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent("runner-submit-failed");
    expect(screen.getByRole("button", { name: /launch audit/i })).toBeEnabled();
  });

  it("loads a terminal run configuration into an explicit rerun review flow", async () => {
    renderWizard("/projects/PRJ-1/scans/new?rerun=JOB-OLD");
    expect(await screen.findByRole("heading", { name: /rerun review/i })).toBeInTheDocument();
    expect(screen.getByText(/configuration copied from JOB-OLD/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /run preflight/i }));
    await userEvent.click(await screen.findByRole("button", { name: /configure scan/i }));
    expect(screen.getByLabelText(/graph mode/i)).toHaveValue("legacy");
    expect(screen.getByLabelText(/memory/i)).toHaveValue("off");
    expect(screen.getByLabelText(/mcp/i)).toHaveValue("on");
    expect(screen.getByLabelText(/include patterns/i)).toHaveValue("src/**");
    expect(screen.getByLabelText(/exclude patterns/i)).toHaveValue("tests/**");
  });
});
