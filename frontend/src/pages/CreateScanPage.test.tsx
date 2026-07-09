import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CreateScanPage } from "./CreateScanPage";
import { apiClient } from "../api/client";

vi.mock("../api/client", () => ({
  apiClient: {
    createRun: vi.fn(),
    getOptions: vi.fn()
  }
}));

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } }
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <CreateScanPage />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("CreateScanPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.getOptions).mockResolvedValue({
      provider_modes: ["mock", "openai-compatible"],
      memory_modes: ["lexical", "embedding", "off"],
      mcp_modes: ["on", "degraded", "off"],
      validation_levels: ["static-only", "poc-generate", "sandbox", "manual"],
      llm_decision_roles: ["orchestrator", "recon", "analysis", "verification"]
    });
    vi.mocked(apiClient.createRun).mockResolvedValue({
      job_id: "JOB-1",
      status: "queued",
      status_url: "/api/runs/JOB-1"
    });
  });

  it("prevents empty target submissions", async () => {
    renderPage();

    await userEvent.clear(screen.getByLabelText(/target/i));
    await userEvent.click(screen.getByRole("button", { name: /create scan/i }));

    expect(await screen.findByText(/target is required/i)).toBeInTheDocument();
    expect(apiClient.createRun).not.toHaveBeenCalled();
  });

  it("submits scan options without secret fields", async () => {
    renderPage();

    await userEvent.clear(screen.getByLabelText(/target/i));
    await userEvent.type(screen.getByLabelText(/target/i), "fixtures/integration_smoke");
    await userEvent.click(screen.getByLabelText(/runtime/i));
    await userEvent.click(screen.getByLabelText(/llm decisions/i));
    await userEvent.selectOptions(screen.getByLabelText(/memory/i), "lexical");
    await userEvent.selectOptions(screen.getByLabelText(/mcp/i), "off");
    await userEvent.selectOptions(screen.getByLabelText(/validation/i), "static-only");
    await userEvent.click(screen.getByRole("button", { name: /create scan/i }));

    await waitFor(() => expect(apiClient.createRun).toHaveBeenCalled());
    const calls = vi.mocked(apiClient.createRun).mock.calls;
    const payload = calls[calls.length - 1][0];
    expect(payload).toMatchObject({
      target: "fixtures/integration_smoke",
      runtime: true,
      llm_provider: "mock",
      llm_decisions: true,
      memory_mode: "lexical",
      mcp_mode: "off",
      validation_level: "static-only"
    });
    expect(JSON.stringify(payload).toLowerCase()).not.toContain("api_key");
  });

  it("omits model in real provider mode when the user leaves it blank", async () => {
    renderPage();

    await userEvent.click(await screen.findByRole("button", { name: /real/i }));
    await userEvent.click(screen.getByRole("button", { name: /create scan/i }));

    await waitFor(() => expect(apiClient.createRun).toHaveBeenCalledTimes(1));
    const payload = vi.mocked(apiClient.createRun).mock.calls[0][0];
    expect(payload.llm_provider).toBe("openai-compatible");
    expect(payload).not.toHaveProperty("model");
  });
});
