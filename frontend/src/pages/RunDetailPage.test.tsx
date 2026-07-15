import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "../api/client";
import type { AuditEvent, JobStatusResponse } from "../api/types";
import { useAuditEventStream } from "../events/useAuditEventStream";
import { RunDetailPage } from "./RunDetailPage";

vi.mock("../events/useAuditEventStream", () => ({ useAuditEventStream: vi.fn() }));

const mockedStream = vi.mocked(useAuditEventStream);

function event(eventId: number, overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    schema_version: "audit-event.v1",
    run_id: "JOB-1",
    event_id: eventId,
    timestamp: `2026-07-15T00:00:0${eventId}Z`,
    category: "action",
    phase: "analyzing",
    actor: "analysis",
    title: `Event ${eventId}`,
    summary: {},
    severity: "info",
    status: "recorded",
    artifact_refs: [],
    ...overrides
  };
}

const activeJob: JobStatusResponse = {
  job_id: "JOB-1",
  project_id: "PRJ-1",
  target: "D:\\safe\\repository",
  status: "running",
  created_at: "2026-07-15T00:00:00Z",
  started_at: "2026-07-15T00:00:01Z",
  output_dir: "runs",
  summary: { requested_mode: "agent-led", effective_mode: "agent-led" },
  error: "",
  phase: "analyzing"
};

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const ui = () => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/projects/PRJ-1/runs/JOB-1"]}>
        <Routes><Route path="/projects/:projectId/runs/:jobId" element={<RunDetailPage />} /></Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
  const view = render(ui());
  return { ...view, rerenderPage: () => view.rerender(ui()) };
}

describe("RunDetailPage live workspace", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(apiClient, "getRun").mockResolvedValue(activeJob);
    vi.spyOn(apiClient, "cancelRun").mockResolvedValue({ ...activeJob, status: "cancelled", phase: "cancelled" });
    vi.spyOn(apiClient, "getRuntimeState").mockResolvedValue({ tasks: [] });
    vi.spyOn(apiClient, "getReplaySummary").mockResolvedValue({ message_count: 0 });
    vi.spyOn(apiClient, "getReportJson").mockResolvedValue({ findings: [] });
    vi.spyOn(apiClient, "getMarkdownReport").mockResolvedValue("# report");
  });

  it("renders ordered public events, filters them, labels effective mode, and confirms cancellation", async () => {
    const hypothesis = event(1, { category: "hypothesis", actor: "analysis", title: "Candidate SQL flow", summary: { hypothesis_id: "HYP-1", rationale_summary: "Tainted input may reach a query sink", api_key: "[REDACTED]" } });
    const tool = event(2, { category: "tool", actor: "verification", title: "Tool dataflow-scan completed", summary: { tool: "dataflow-scan", observations: 2 } });
    mockedStream.mockReturnValue({
      runId: "JOB-1", events: [hypothesis, tool], lastEventId: 2, connection: "polling-fallback", failures: 3,
      historyStatus: "live", historyReason: "", heartbeatAt: "2026-07-15T00:00:03Z"
    });
    const confirm = vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValueOnce(true);
    renderPage();
    expect(await screen.findByRole("heading", { name: "JOB-1" })).toBeInTheDocument();
    expect(screen.getByText("agent-led")).toBeInTheDocument();
    expect(screen.getByText(/polling every two seconds/i)).toBeInTheDocument();
    expect(screen.getByText("[REDACTED]")).toBeInTheDocument();
    const first = screen.getByRole("heading", { name: "Candidate SQL flow" });
    const second = screen.getByRole("heading", { name: "Tool dataflow-scan completed" });
    expect(first.compareDocumentPosition(second) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

    await userEvent.selectOptions(screen.getByLabelText("Category filter"), "hypothesis");
    expect(screen.getByRole("heading", { name: "Candidate SQL flow" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Tool dataflow-scan completed" })).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /cancel audit/i }));
    expect(apiClient.cancelRun).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: /cancel audit/i }));
    await waitFor(() => expect(apiClient.cancelRun).toHaveBeenCalledWith("JOB-1"));
    expect(confirm).toHaveBeenCalledTimes(2);
  });

  it("shows legacy unavailable history and opens terminal rerun review without implicit cancellation", async () => {
    vi.spyOn(apiClient, "getRun").mockResolvedValue({ ...activeJob, status: "succeeded", phase: "complete", finished_at: "2026-07-15T00:02:00Z" });
    mockedStream.mockReturnValue({
      runId: "JOB-1", events: [], lastEventId: 0, connection: "unavailable", failures: 0,
      historyStatus: "unavailable", historyReason: "legacy-run-without-public-journal", terminalStatus: "succeeded"
    });
    const view = renderPage();
    expect(await screen.findByText(/legacy-run-without-public-journal/i)).toBeInTheDocument();
    const rerun = screen.getByRole("link", { name: /review and rerun/i });
    expect(rerun).toHaveAttribute("href", "/projects/PRJ-1/scans/new?rerun=JOB-1");
    view.unmount();
    expect(apiClient.cancelRun).not.toHaveBeenCalled();
  });

  it("keeps the timeline in a bounded viewport and scrolls to each new event", async () => {
    const scrollTo = vi.fn();
    const originalScrollTo = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "scrollTo");
    Object.defineProperty(HTMLElement.prototype, "scrollTo", { configurable: true, value: scrollTo });
    const first = event(1);
    mockedStream.mockReturnValue({
      runId: "JOB-1", events: [first], lastEventId: 1, connection: "live", failures: 0,
      historyStatus: "live", historyReason: ""
    });
    const view = renderPage();
    const viewport = await screen.findByTestId("investigation-timeline");
    Object.defineProperty(viewport, "scrollHeight", { configurable: true, value: 640 });
    scrollTo.mockClear();

    mockedStream.mockReturnValue({
      runId: "JOB-1", events: [first, event(2)], lastEventId: 2, connection: "live", failures: 0,
      historyStatus: "live", historyReason: ""
    });
    view.rerenderPage();

    await waitFor(() => expect(scrollTo).toHaveBeenCalledWith({ top: 640, behavior: "smooth" }));
    expect(viewport).toHaveClass("timeline-viewport");
    if (originalScrollTo) Object.defineProperty(HTMLElement.prototype, "scrollTo", originalScrollTo);
    else delete (HTMLElement.prototype as Partial<HTMLElement>).scrollTo;
  });

  it("updates elapsed time every second while the run is active", async () => {
    let tick: (() => void) | undefined;
    const now = vi.spyOn(Date, "now").mockReturnValue(new Date("2026-07-15T00:00:11Z").valueOf());
    vi.spyOn(window, "setInterval").mockImplementation(((handler: TimerHandler, delay?: number) => {
      if (delay === 1_000 && typeof handler === "function") tick = () => handler();
      return 1;
    }) as typeof window.setInterval);
    mockedStream.mockReturnValue({
      runId: "JOB-1", events: [], lastEventId: 0, connection: "live", failures: 0,
      historyStatus: "live", historyReason: ""
    });
    renderPage();
    expect(await screen.findByText("10s")).toBeInTheDocument();

    now.mockReturnValue(new Date("2026-07-15T00:00:12Z").valueOf());
    act(() => tick?.());

    expect(screen.getByText("11s")).toBeInTheDocument();
  });
});
