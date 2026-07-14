import type {
  ApiOptions,
  AuditReport,
  CreateRunResponse,
  JobListResponse,
  JobStatusResponse,
  ReplaySummary,
  RuntimeState,
  ScanRunRequest
} from "./types";

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  if (!response.ok) {
    throw new Error(await readError(response));
  }
  return (await response.json()) as T;
}

async function requestText(url: string): Promise<string> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(await readError(response));
  }
  return response.text();
}

async function readError(response: Response): Promise<string> {
  try {
    const payload = await response.json();
    if (payload?.detail?.error) {
      return String(payload.detail.error);
    }
    if (payload?.error) {
      return String(payload.error);
    }
  } catch {
    return `${response.status} ${response.statusText}`;
  }
  return `${response.status} ${response.statusText}`;
}

export const apiClient = {
  getHealth: () => requestJson<Record<string, unknown>>("/api/health"),
  getOptions: () => requestJson<ApiOptions>("/api/options"),
  createRun: (payload: ScanRunRequest) =>
    requestJson<CreateRunResponse>("/api/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }),
  listRuns: () => requestJson<JobListResponse>("/api/runs"),
  getRun: (jobId: string) => requestJson<JobStatusResponse>(`/api/runs/${encodeURIComponent(jobId)}`),
  cancelRun: (jobId: string) =>
    requestJson<JobStatusResponse>(`/api/runs/${encodeURIComponent(jobId)}/cancel`, { method: "POST" }),
  getRuntimeState: (jobId: string) =>
    requestJson<RuntimeState>(`/api/runs/${encodeURIComponent(jobId)}/runtime-state`),
  getReplaySummary: (jobId: string) =>
    requestJson<ReplaySummary>(`/api/runs/${encodeURIComponent(jobId)}/replay-summary`),
  getReportJson: (jobId: string) =>
    requestJson<AuditReport>(`/api/runs/${encodeURIComponent(jobId)}/reports/report.json`),
  getMarkdownReport: (jobId: string) =>
    requestText(`/api/runs/${encodeURIComponent(jobId)}/reports/report.md`)
};
