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
      graph_modes: ["legacy", "deterministic-graph", "adaptive-graph"],
      default_graph_mode: "agent-led",
      memory_modes: ["lexical", "embedding", "off"],
      mcp_modes: ["on", "degraded", "off"],
      validation_levels: ["static-only", "poc-generate", "sandbox", "manual"],
      llm_decision_roles: ["orchestrator", "recon", "analysis", "verification"],
      sandbox_runners: ["local", "docker"],
      default_docker_image: "python:3.12-slim",
      default_docker_context: "",
      default_docker_host: "",
      default_exclude_patterns: ["tests/**", "fixtures/**", "external/**", "openspec/**", ".codex/**"]
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
    await userEvent.click(screen.getByLabelText(/sandbox execution/i));
    await userEvent.clear(screen.getByLabelText(/include patterns/i));
    await userEvent.type(screen.getByLabelText(/include patterns/i), "src/**\napp.py");
    await userEvent.clear(screen.getByLabelText(/exclude patterns/i));
    await userEvent.type(screen.getByLabelText(/exclude patterns/i), "tests/**\nfixtures/**");
    await userEvent.click(screen.getByRole("button", { name: /create scan/i }));

    await waitFor(() => expect(apiClient.createRun).toHaveBeenCalled());
    const calls = vi.mocked(apiClient.createRun).mock.calls;
    const payload = calls[calls.length - 1][0];
    expect(payload).toMatchObject({
      target: "fixtures/integration_smoke",
      runtime: true,
      graph_mode: "agent-led",
      llm_provider: "mock",
      llm_decisions: true,
      memory_mode: "lexical",
      mcp_mode: "off",
      validation_level: "static-only",
      sandbox_enabled: true,
      sandbox_runner: "local",
      include_patterns: ["src/**", "app.py"],
      exclude_patterns: ["tests/**", "fixtures/**"]
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

  it("submits docker sandbox runner and image when selected", async () => {
    renderPage();

    await userEvent.selectOptions(screen.getByLabelText(/validation/i), "sandbox");
    await userEvent.selectOptions(await screen.findByLabelText(/sandbox runner/i), "docker");
    await userEvent.clear(screen.getByLabelText(/docker image/i));
    await userEvent.type(screen.getByLabelText(/docker image/i), "python:3.12-slim");
    await userEvent.type(screen.getByLabelText(/docker context/i), "desktop-linux");
    await userEvent.type(screen.getByLabelText(/docker host/i), "npipe:////./pipe/dockerDesktopLinuxEngine");
    await userEvent.click(screen.getByRole("button", { name: /create scan/i }));

    await waitFor(() => expect(apiClient.createRun).toHaveBeenCalled());
    const payload = vi.mocked(apiClient.createRun).mock.calls.at(-1)?.[0];
    expect(payload).toMatchObject({
      validation_level: "sandbox",
      sandbox_enabled: true,
      sandbox_runner: "docker",
      sandbox_docker_image: "python:3.12-slim",
      sandbox_docker_context: "desktop-linux",
      sandbox_docker_host: "npipe:////./pipe/dockerDesktopLinuxEngine"
    });
  });

  it("enables bounded LLM PoC repair only with runtime sandbox Docker settings", async () => {
    renderPage();

    await userEvent.click(screen.getByLabelText(/llm poc repair/i));
    expect(screen.getByLabelText(/runtime/i)).toBeChecked();
    expect(screen.getByLabelText(/validation/i)).toHaveValue("sandbox");
    expect(screen.getByLabelText(/sandbox runner/i)).toHaveValue("docker");
    await userEvent.selectOptions(screen.getByLabelText(/maximum repair attempts/i), "2");
    await userEvent.click(screen.getByRole("button", { name: /create scan/i }));

    await waitFor(() => expect(apiClient.createRun).toHaveBeenCalled());
    const payload = vi.mocked(apiClient.createRun).mock.calls.at(-1)?.[0];
    expect(payload).toMatchObject({
      runtime: true,
      validation_level: "sandbox",
      sandbox_enabled: true,
      sandbox_runner: "docker",
      llm_poc_repair: true,
      max_repair_attempts: 2
    });
  });

  it("submits a bounded structured GitHub source", async () => {
    vi.mocked(apiClient.getOptions).mockResolvedValue({
      provider_modes: ["mock", "openai-compatible"],
      graph_modes: ["legacy", "deterministic-graph", "adaptive-graph"],
      default_graph_mode: "agent-led",
      memory_modes: ["lexical", "embedding", "off"],
      mcp_modes: ["on", "degraded", "off"],
      validation_levels: ["static-only", "poc-generate", "sandbox", "manual"],
      llm_decision_roles: ["orchestrator", "recon", "analysis", "verification"],
      sandbox_runners: ["local", "docker"],
      default_docker_image: "python:3.12-slim",
      default_docker_context: "",
      default_docker_host: "",
      default_exclude_patterns: [],
      remote_acquisition: {
        enabled: true,
        network_enabled: false,
        allowed_hosts: ["github.com", "gitlab.com"],
        supports_head: false,
        limits: {}
      }
    });
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "GitHub" }));
    await userEvent.type(screen.getByLabelText(/github repository url/i), "https://github.com/example/repo");
    await userEvent.type(screen.getByLabelText(/exact commit/i), "a".repeat(40));
    await userEvent.click(screen.getByRole("button", { name: /create scan/i }));
    await waitFor(() => expect(apiClient.createRun).toHaveBeenCalled());
    expect(vi.mocked(apiClient.createRun).mock.calls.at(-1)?.[0]).toMatchObject({
      source: { kind: "github", url: "https://github.com/example/repo", commit: "a".repeat(40) }
    });
  });

  it("submits a GitLab nested namespace with an exact commit", async () => {
    vi.mocked(apiClient.getOptions).mockResolvedValue({
      provider_modes: ["mock", "openai-compatible"],
      graph_modes: ["legacy", "deterministic-graph", "adaptive-graph"],
      default_graph_mode: "agent-led",
      memory_modes: ["lexical", "embedding", "off"],
      mcp_modes: ["on", "degraded", "off"],
      validation_levels: ["static-only", "poc-generate", "sandbox", "manual"],
      llm_decision_roles: ["orchestrator", "recon", "analysis", "verification"],
      sandbox_runners: ["local", "docker"],
      default_docker_image: "python:3.12-slim",
      default_docker_context: "",
      default_docker_host: "",
      default_exclude_patterns: [],
      remote_acquisition: {
        enabled: true,
        network_enabled: false,
        allowed_hosts: ["github.com", "gitlab.com"],
        supports_head: false,
        limits: {}
      }
    });
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "GitLab" }));
    await userEvent.type(
      screen.getByLabelText(/gitlab repository url/i),
      "https://gitlab.com/example/security/repo.git"
    );
    await userEvent.type(screen.getByLabelText(/exact commit/i), "b".repeat(40));
    await userEvent.click(screen.getByRole("button", { name: /create scan/i }));
    await waitFor(() => expect(apiClient.createRun).toHaveBeenCalled());
    expect(vi.mocked(apiClient.createRun).mock.calls.at(-1)?.[0]).toMatchObject({
      source: {
        kind: "gitlab",
        url: "https://gitlab.com/example/security/repo.git",
        commit: "b".repeat(40)
      }
    });
  });

  it("requires an exact commit when backend HEAD resolution is disabled", async () => {
    vi.mocked(apiClient.getOptions).mockResolvedValue({
      provider_modes: ["mock", "openai-compatible"],
      graph_modes: ["legacy", "deterministic-graph", "adaptive-graph"],
      default_graph_mode: "agent-led",
      memory_modes: ["lexical", "embedding", "off"],
      mcp_modes: ["on", "degraded", "off"],
      validation_levels: ["static-only", "poc-generate", "sandbox", "manual"],
      llm_decision_roles: ["orchestrator", "recon", "analysis", "verification"],
      sandbox_runners: ["local", "docker"],
      default_docker_image: "python:3.12-slim",
      default_docker_context: "",
      default_docker_host: "",
      default_exclude_patterns: [],
      remote_acquisition: {
        enabled: true,
        network_enabled: false,
        allowed_hosts: ["github.com", "gitlab.com"],
        supports_head: false,
        limits: {}
      }
    });
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "GitHub" }));
    await userEvent.type(
      screen.getByLabelText(/github repository url/i),
      "https://github.com/example/repo"
    );
    await userEvent.click(screen.getByRole("button", { name: /create scan/i }));
    expect(await screen.findByText(/exact commit is required/i)).toBeInTheDocument();
    expect(apiClient.createRun).not.toHaveBeenCalled();
  });
});
