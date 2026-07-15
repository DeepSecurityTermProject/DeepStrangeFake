import type {
  ApiOptions,
  AuditEventSnapshot,
  AuditReport,
  CreateRunResponse,
  JobListResponse,
  JobStatusResponse,
  Project,
  ProjectFilters,
  ProjectListResponse,
  ProjectSecurityDashboard,
  ReplaySummary,
  RerunConfiguration,
  RuntimeState,
  ScanRunRequest,
  SourcePreflightRequest,
  SourcePreflightResponse,
  SourceSpec
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
  preflightSource: (payload: SourcePreflightRequest) =>
    requestJson<SourcePreflightResponse>("/api/sources/preflight", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }),
  listProjects: (filters: ProjectFilters = {}) => {
    const params = new URLSearchParams();
    if (filters.query) params.set("query", filters.query);
    if (filters.status) params.set("status", filters.status);
    if (filters.security_status) params.set("security_status", filters.security_status);
    if (filters.order) params.set("order", filters.order);
    const query = params.toString();
    return requestJson<ProjectListResponse>(`/api/projects${query ? `?${query}` : ""}`);
  },
  getProject: (projectId: string) =>
    requestJson<Project>(`/api/projects/${encodeURIComponent(projectId)}`),
  getProjectDashboard: (projectId: string) =>
    requestJson<ProjectSecurityDashboard>(`/api/projects/${encodeURIComponent(projectId)}/dashboard`),
  createProject: (payload: { preflight_token: string; source: SourceSpec; display_name?: string }) =>
    requestJson<Project>("/api/projects", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }),
  updateProject: (projectId: string, displayName: string) =>
    requestJson<Project>(`/api/projects/${encodeURIComponent(projectId)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ display_name: displayName })
    }),
  archiveProject: (projectId: string) =>
    requestJson<Project>(`/api/projects/${encodeURIComponent(projectId)}/archive`, { method: "POST" }),
  restoreProject: (projectId: string) =>
    requestJson<Project>(`/api/projects/${encodeURIComponent(projectId)}/restore`, { method: "POST" }),
  listProjectRuns: (projectId: string) =>
    requestJson<JobListResponse>(`/api/projects/${encodeURIComponent(projectId)}/runs`),
  createProjectRun: (projectId: string, payload: ScanRunRequest) =>
    requestJson<CreateRunResponse>(`/api/projects/${encodeURIComponent(projectId)}/runs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }),
  listRuns: () => requestJson<JobListResponse>("/api/runs"),
  getRun: (jobId: string) => requestJson<JobStatusResponse>(`/api/runs/${encodeURIComponent(jobId)}`),
  getRunEventSnapshot: (projectId: string, jobId: string) =>
    requestJson<AuditEventSnapshot>(
      `/api/projects/${encodeURIComponent(projectId)}/runs/${encodeURIComponent(jobId)}/events/snapshot`
    ),
  getRerunConfiguration: (jobId: string) =>
    requestJson<RerunConfiguration>(`/api/runs/${encodeURIComponent(jobId)}/rerun-config`),
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
