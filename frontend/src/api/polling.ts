import type { JobStatusResponse } from "./types";

export function runStatusRefetchInterval(job?: Pick<JobStatusResponse, "status"> | null): 2000 | false {
  if (!job || job.status === "queued" || job.status === "running") {
    return 2000;
  }
  return false;
}

export function isTerminalStatus(status?: string): boolean {
  return status === "succeeded" || status === "degraded" || status === "cancelled" || status === "failed";
}
