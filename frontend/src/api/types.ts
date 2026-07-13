export type JobStatus = "queued" | "running" | "succeeded" | "failed";
export type MemoryMode = "lexical" | "embedding" | "off";
export type McpMode = "on" | "degraded" | "off";
export type ValidationLevel = "static-only" | "poc-generate" | "sandbox" | "manual";
export type SandboxRunner = "local" | "docker";

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
  sandbox_enabled?: boolean;
  sandbox_runner?: SandboxRunner;
  sandbox_docker_image?: string;
  sandbox_docker_context?: string;
  sandbox_docker_host?: string;
  llm_poc_repair?: boolean;
  max_repair_attempts?: number;
  include_patterns?: string[];
  exclude_patterns?: string[];
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
  sandbox_runners: SandboxRunner[];
  default_docker_image: string;
  default_docker_context: string;
  default_docker_host: string;
  llm_poc_repair_default?: boolean;
  max_repair_attempts_default?: number;
  max_repair_attempts_range?: [number, number] | number[];
  poc_repair_effective_source?: string;
  poc_repair_requires_docker?: boolean;
  default_exclude_patterns: string[];
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
  repair_lifecycle?: Record<string, unknown>;
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
  verification_status?: string;
  verification_reason?: string;
  validation?: Record<string, unknown>;
  repair_summary?: {
    attempt_count?: number;
    classifications?: Array<Record<string, unknown>>;
    semantic_integrity_status?: string;
    safety_status?: string;
    provisional_status?: string;
    final_status?: string;
    integrity?: Record<string, unknown>;
    final_stop_reason?: string;
  };
  [key: string]: unknown;
}

export interface AuditReport {
  executive_summary?: Record<string, unknown>;
  findings?: ReportFinding[];
  verification_candidates?: ReportFinding[];
  [key: string]: unknown;
}
