import { useQuery } from "@tanstack/react-query";
import { RefreshCw } from "lucide-react";
import { Link } from "react-router-dom";
import { apiClient } from "../api/client";
import { ErrorState, LoadingState } from "../components/DataState";
import { EmptyState } from "../components/EmptyState";
import { StatusBadge } from "../components/StatusBadge";

export function RunListPage() {
  const runsQuery = useQuery({
    queryKey: ["runs"],
    queryFn: apiClient.listRuns,
    refetchInterval: 5000
  });

  if (runsQuery.isLoading) {
    return <LoadingState title="Loading runs" />;
  }
  if (runsQuery.isError) {
    return <ErrorState title={String(runsQuery.error)} />;
  }

  const jobs = runsQuery.data?.jobs ?? [];

  return (
    <section className="page-panel">
      <div className="page-heading">
        <div>
          <h1>Runs</h1>
          <p>Queued, running, and completed audits</p>
        </div>
        <button className="icon-action" type="button" onClick={() => runsQuery.refetch()} aria-label="Refresh runs">
          <RefreshCw size={18} aria-hidden="true" />
        </button>
      </div>
      {jobs.length === 0 ? (
        <EmptyState title="No scan runs yet" />
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Status</th>
                <th>Phase</th>
                <th>Target</th>
                <th>Resolved commit</th>
                <th>Run directory</th>
                <th>Validated</th>
                <th>Created</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={job.job_id}>
                  <td>
                    <StatusBadge status={job.status} />
                  </td>
                  <td>{job.phase || "n/a"}</td>
                  <td className="source-value">{job.target}</td>
                  <td className="source-value">{job.resolved_commit || "n/a"}</td>
                  <td>{job.run_dir || job.output_dir}</td>
                  <td>{String(job.summary?.validated_count ?? 0)}</td>
                  <td>{formatTime(job.created_at)}</td>
                  <td>
                    <Link className="inline-link" to={job.project_id ? `/projects/${job.project_id}/runs/${job.job_id}` : `/runs/${job.job_id}`}>Open</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function formatTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}
