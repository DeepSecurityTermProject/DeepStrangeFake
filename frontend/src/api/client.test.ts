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

  it("throws a readable error for failed responses", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ detail: { error: "job-not-found" } }), { status: 404 })
    );

    await expect(apiClient.getRun("JOB-missing")).rejects.toThrow("job-not-found");
  });
});
