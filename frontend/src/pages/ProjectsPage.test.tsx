import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "../api/client";
import type { Project } from "../api/types";
import { ProjectsPage } from "./ProjectsPage";

vi.mock("../api/client", () => ({
  apiClient: {
    listProjects: vi.fn(),
    archiveProject: vi.fn(),
    restoreProject: vi.fn(),
    updateProject: vi.fn()
  }
}));

const project: Project = {
  project_id: "PRJ-1",
  display_name: "Course Service",
  source_kind: "local",
  source: { kind: "local", path: "D:/course/service" },
  source_identity: "local:d:/course/service",
  source_display: "D:/course/service",
  status: "active",
  languages: [{ name: "Python", files: 3 }],
  metadata: { file_count: 3 },
  created_at: "2026-07-14T00:00:00Z",
  updated_at: "2026-07-14T00:00:00Z",
  latest_run: {
    job_id: "JOB-1",
    project_id: "PRJ-1",
    target: "D:/course/service",
    status: "succeeded",
    created_at: "2026-07-14T00:00:00Z",
    output_dir: "runs",
    summary: { validated_count: 2 },
    error: "",
    phase: "complete"
  }
};

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}><MemoryRouter><ProjectsPage /></MemoryRouter></QueryClientProvider>);
}

describe("ProjectsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.listProjects).mockResolvedValue({ projects: [project], total: 1 });
    vi.mocked(apiClient.updateProject).mockResolvedValue({ ...project, display_name: "Renamed Service" });
    vi.mocked(apiClient.archiveProject).mockResolvedValue({ ...project, status: "archived" });
  });

  it("renders safe project state, filters, project links, and inline rename", async () => {
    renderPage();
    expect(await screen.findByRole("heading", { name: "Projects" })).toBeInTheDocument();
    expect(screen.getByText("D:/course/service")).toBeInTheDocument();
    expect(screen.getAllByText("Succeeded")).toHaveLength(2);
    expect(screen.getByRole("link", { name: /open project/i })).toHaveAttribute("href", "/projects/PRJ-1");

    await userEvent.click(screen.getByRole("button", { name: /rename course service/i }));
    const nameInput = screen.getByRole("textbox", { name: /project name/i });
    await userEvent.clear(nameInput);
    await userEvent.type(nameInput, "Renamed Service");
    await userEvent.click(screen.getByRole("button", { name: /save course service name/i }));
    await waitFor(() => expect(apiClient.updateProject).toHaveBeenCalledWith("PRJ-1", "Renamed Service"));

    await userEvent.type(screen.getByPlaceholderText(/search project/i), "service");
    await waitFor(() => expect(apiClient.listProjects).toHaveBeenLastCalledWith(expect.objectContaining({ query: "service" })));
  });

  it("disables archive while the latest run is active", async () => {
    vi.mocked(apiClient.listProjects).mockResolvedValue({ projects: [{ ...project, latest_run: { ...project.latest_run!, status: "running" } }], total: 1 });
    renderPage();
    expect(await screen.findByRole("button", { name: /archive/i })).toBeDisabled();
  });
});
