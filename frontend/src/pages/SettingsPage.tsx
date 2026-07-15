import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../api/client";
import { ErrorState, LoadingState } from "../components/DataState";

export function SettingsPage() {
  const optionsQuery = useQuery({ queryKey: ["options"], queryFn: apiClient.getOptions });
  if (optionsQuery.isLoading) return <LoadingState title="Loading runtime policy" />;
  if (optionsQuery.isError || !optionsQuery.data) return <ErrorState title={String(optionsQuery.error ?? "Settings unavailable")} />;

  const options = optionsQuery.data;
  return (
    <section className="page-panel settings-page">
      <header className="kinetic-hero compact-hero">
        <div>
          <span className="eyebrow">Runtime policy / read only</span>
          <h1>Settings</h1>
          <p>Effective capabilities exposed by the trusted backend.</p>
        </div>
        <span className="hero-count" aria-hidden="true">04</span>
      </header>
      <div className="project-summary-grid">
        <Setting label="Default graph" value={options.default_graph_mode} />
        <Setting label="Providers" value={options.provider_modes.join(", ")} />
        <Setting label="Validation" value={options.validation_levels.join(", ")} />
        <Setting label="Remote acquisition" value={options.remote_acquisition?.enabled ? "Enabled" : "Disabled"} />
      </div>
      <div className="notice-strip">Configuration changes remain server-controlled in Phase One.</div>
    </section>
  );
}

function Setting({ label, value }: { label: string; value: string }) {
  return <div className="summary-metric"><span>{label}</span><strong>{value}</strong></div>;
}
