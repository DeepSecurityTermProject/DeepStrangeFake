import type { JobStatus } from "../api/types";

const LABELS: Record<JobStatus, string> = {
  queued: "Queued",
  running: "Running",
  succeeded: "Succeeded",
  degraded: "Degraded",
  cancelled: "Cancelled",
  failed: "Failed"
};

export function StatusBadge({ status }: { status: string }) {
  const normalized = status as JobStatus;
  return <span className={`status-badge status-${status}`}>{LABELS[normalized] ?? status}</span>;
}
