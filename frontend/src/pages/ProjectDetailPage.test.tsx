import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "../api/client";
import type { Project } from "../api/types";
import { ProjectDetailPage } from "./ProjectDetailPage";

vi.mock("../api/client", () => ({
  apiClient: {
    getProject: vi.fn(),
    listProjectRuns: vi.fn(),
    getProjectDashboard: vi.fn()
  }
}));

const project: Project = {
  project_id: "PRJ-1",
  display_name: "Course service",
  source_kind: "local",
  source: { kind: "local", path: "D:/course/service" },
  source_identity: "local:d:/course/service",
  source_display: "D:/course/service",
  status: "active",
  languages: [{ name: "Python", files: 3 }],
  metadata: { file_count: 3 },
  created_at: "2026-07-15T00:00:00Z",
  updated_at: "2026-07-15T00:00:00Z"
};

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/projects/PRJ-1"]}>
        <Routes><Route path="/projects/:projectId" element={<ProjectDetailPage />} /></Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("ProjectDetailPage dashboard failure", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.getProject).mockResolvedValue(project);
    vi.mocked(apiClient.listProjectRuns).mockResolvedValue({ jobs: [] });
  });

  it("renders an explicit recoverable API failure state", async () => {
    vi.mocked(apiClient.getProjectDashboard).mockRejectedValue(new Error("posture-projection-failed"));
    renderPage();
    expect(await screen.findByText(/security dashboard unavailable: error: posture-projection-failed/i)).toBeInTheDocument();
  });
});
