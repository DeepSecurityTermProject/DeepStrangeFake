export type JobStatus = "queued" | "running" | "succeeded" | "failed";
export type MemoryMode = "lexical" | "embedding" | "off";
export type McpMode = "on" | "degraded" | "off";
export type ValidationLevel = "static-only" | "poc-generate" | "sandbox" | "manual";

export interface ScanRunRequest {
  target: string;
  runtime?: boolean;
  llm_provider?: string;
  model?: string;
  llm_decisions?: boolean;
  llm_decision_roles?: string[];
  memory_mode?: MemoryMode;
  mcp_mode?: McpMode;
  validation_level?: ValidationLevel;
  output?: string;
}

export interface CreateRunResponse {
  job_id: string;
  status: JobStatus | string;
  status_url: string;
}

export interface JobStatusResponse {
  job_id: string;
  target: string;
  status: JobStatus | string;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  output_dir: string;
  run_dir?: string | null;
  summary: Record<string, unknown>;
  error: string;
}

export interface JobListResponse {
  jobs: JobStatusResponse[];
}

export interface ApiOptions {
  provider_modes: string[];
  memory_modes: MemoryMode[];
  mcp_modes: McpMode[];
  validation_levels: ValidationLevel[];
  llm_decision_roles: string[];
}

export interface RuntimeTask {
  id?: string;
  role: string;
  kind: string;
  status: string;
  fallback_reason?: string;
  artifact_refs?: string[];
  message_refs?: string[];
}

export interface RuntimeState {
  status?: string;
  tasks?: RuntimeTask[];
  [key: string]: unknown;
}

export interface ReplaySummary {
  message_count?: number;
  decision_lifecycle?: Record<string, unknown>;
  runtime_lifecycle?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface ReportFinding {
  id?: string;
  title?: string;
  vulnerability_class?: string;
  severity?: string;
  confidence?: number;
  location?: { path?: string; start_line?: number; end_line?: number };
  evidence?: string[];
  remediation?: string;
  [key: string]: unknown;
}

export interface AuditReport {
  executive_summary?: Record<string, unknown>;
  findings?: ReportFinding[];
  [key: string]: unknown;
}
