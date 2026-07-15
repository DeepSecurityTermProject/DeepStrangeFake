import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { App } from "./App";

const apiBase = process.env.VITE_E2E_API_URL?.replace(/\/$/, "");
const describeSmoke = apiBase ? describe : describe.skip;

describeSmoke("App local smoke", () => {
  let originalFetch: typeof fetch;

  beforeAll(() => {
    originalFetch = globalThis.fetch;
    vi.stubGlobal("fetch", (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.startsWith("/api")) {
        return originalFetch(`${apiBase}${url}`, init);
      }
      return originalFetch(input, init);
    });
  });

  afterAll(() => {
    vi.unstubAllGlobals();
  });

  it("creates a mock scan from the UI and loads completed run artifacts", async () => {
    render(
      <MemoryRouter initialEntries={["/create"]}>
        <App />
      </MemoryRouter>
    );

    await userEvent.type(await screen.findByLabelText(/server-local absolute path/i), "fixtures/integration_smoke");
    await userEvent.click(screen.getByRole("button", { name: /run preflight/i }));
    await userEvent.click(await screen.findByRole("button", { name: /configure scan/i }));
    await userEvent.click(screen.getByRole("button", { name: /launch audit/i }));

    await waitFor(
      () => expect(screen.getByRole("heading", { name: /report and replay/i })).toBeInTheDocument(),
      { timeout: 30000 }
    );
    expect(screen.getByText(/validated/i)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("tab", { name: /runtime tasks/i }));
    expect(screen.getAllByText(/orchestrator|recon|analysis|verification/i).length).toBeGreaterThan(0);

    await userEvent.click(screen.getByRole("tab", { name: /replay/i }));
    expect(screen.getByText(/message count/i)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("tab", { name: /markdown report/i }));
    expect(screen.getByText(/agentic security audit report/i)).toBeInTheDocument();
  }, 40000);
});
