import type { JobStatus } from "../api/types";

const LABELS: Record<JobStatus, string> = {
  queued: "Queued",
  running: "Running",
  succeeded: "Succeeded",
  failed: "Failed"
};

export function StatusBadge({ status }: { status: string }) {
  const normalized = status as JobStatus;
  return <span className={`status-badge status-${status}`}>{LABELS[normalized] ?? status}</span>;
}
