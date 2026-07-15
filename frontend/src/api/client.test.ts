import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "./client";

describe("apiClient", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("creates scan jobs through the backend API", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ job_id: "JOB-1", status: "queued", status_url: "/api/runs/JOB-1" }), {
        status: 202,
        headers: { "Content-Type": "application/json" }
      })
    );

    const result = await apiClient.createRun({
      target: "fixtures/integration_smoke",
      runtime: true,
      llm_provider: "mock",
      llm_decisions: true,
      memory_mode: "lexical",
      mcp_mode: "off",
      validation_level: "static-only"
    });

    expect(result.job_id).toBe("JOB-1");
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/runs",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" }
      })
    );
  });

  it("fetches runtime artifacts through fixed endpoints", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({ status: "succeeded" }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ runtime_lifecycle: { tasks: {} } }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ findings: [] }), { status: 200 }))
      .mockResolvedValueOnce(new Response("# Report", { status: 200 }));

    await expect(apiClient.getRuntimeState("JOB-1")).resolves.toEqual({ status: "succeeded" });
    await expect(apiClient.getReplaySummary("JOB-1")).resolves.toEqual({ runtime_lifecycle: { tasks: {} } });
    await expect(apiClient.getReportJson("JOB-1")).resolves.toEqual({ findings: [] });
    await expect(apiClient.getMarkdownReport("JOB-1")).resolves.toBe("# Report");
  });

  it("requests cancellation through the fixed run endpoint", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ job_id: "JOB-1", status: "cancelled" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );
    await expect(apiClient.cancelRun("JOB-1")).resolves.toMatchObject({ status: "cancelled" });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/runs/JOB-1/cancel",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("loads project-scoped event snapshots and safe rerun configuration", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({ schema_version: "audit-event.v1", run_id: "JOB-1", events: [], last_event_id: 0, history_status: "live" }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ source_run_id: "JOB-1", project_id: "PRJ-1", configuration: { graph_mode: "agent-led" } }), { status: 200 }));

    await expect(apiClient.getRunEventSnapshot("PRJ-1", "JOB-1")).resolves.toMatchObject({ run_id: "JOB-1" });
    await expect(apiClient.getRerunConfiguration("JOB-1")).resolves.toMatchObject({ project_id: "PRJ-1" });
    expect(fetchMock.mock.calls[0][0]).toBe("/api/projects/PRJ-1/runs/JOB-1/events/snapshot");
    expect(fetchMock.mock.calls[1][0]).toBe("/api/runs/JOB-1/rerun-config");
  });

  it("preflights sources and submits project-scoped runs without credential fields", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({ preflight_token: "opaque", source: { kind: "github", url: "https://github.com/acme/repo", commit: "a".repeat(40) } }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ job_id: "JOB-2", project_id: "PRJ-1", status: "queued", status_url: "/api/runs/JOB-2", run_url: "/projects/PRJ-1/runs/JOB-2" }), { status: 202 }));

    const preview = await apiClient.preflightSource({
      source: { kind: "github", url: "https://github.com/acme/repo" },
      revision_type: "branch",
      revision: "main"
    });
    await expect(apiClient.createProjectRun("PRJ-1", {
      source: preview.source,
      preflight_token: preview.preflight_token
    })).resolves.toMatchObject({ project_id: "PRJ-1", job_id: "JOB-2" });

    expect(fetchMock.mock.calls[0][0]).toBe("/api/sources/preflight");
    expect(fetchMock.mock.calls[1][0]).toBe("/api/projects/PRJ-1/runs");
    expect(JSON.stringify(fetchMock.mock.calls)).not.toMatch(/password|api_key|credential/i);
  });

  it("encodes project catalog filters", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ projects: [], total: 0 }), { status: 200 }));

    await apiClient.listProjects({ query: "course repo", status: "archived", security_status: "degraded", order: "name" });

    expect(fetchMock).toHaveBeenCalledWith("/api/projects?query=course+repo&status=archived&security_status=degraded&order=name", undefined);
  });

  it("throws a readable error for failed responses", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ detail: { error: "job-not-found" } }), { status: 404 })
    );

    await expect(apiClient.getRun("JOB-missing")).rejects.toThrow("job-not-found");
  });
});
