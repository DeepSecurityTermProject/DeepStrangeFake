import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "../api/client";
import { LegacyRunRedirect } from "./LegacyRunRedirect";

vi.mock("../api/client", () => ({ apiClient: { getRun: vi.fn() } }));

describe("LegacyRunRedirect", () => {
  beforeEach(() => {
    vi.mocked(apiClient.getRun).mockResolvedValue({ job_id: "JOB-1", project_id: "PRJ-1", target: "repo", status: "succeeded", created_at: "2026-07-14T00:00:00Z", output_dir: "runs", summary: {}, error: "" });
  });

  it("resolves the owning project before redirecting", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><MemoryRouter initialEntries={["/runs/JOB-1"]}><Routes><Route path="/runs/:jobId" element={<LegacyRunRedirect />} /><Route path="/projects/:projectId/runs/:jobId" element={<div>Scoped run</div>} /></Routes></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByText("Scoped run")).toBeInTheDocument();
  });
});
