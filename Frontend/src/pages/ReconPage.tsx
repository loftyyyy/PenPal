import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { formatBytes, formatDate, formatDuration, labelize } from "../lib/format";
import { keys } from "../lib/keys";
import { useAssessment } from "../components/AssessmentLayout";
import {
  Badge,
  Card,
  EmptyState,
  ErrorNotice,
  Loading,
  PageHeader,
  Stat,
  StatusBadge,
} from "../components/ui";

export function ReconPage() {
  const assessment = useAssessment();
  const query = useQuery({
    queryKey: keys.recon(assessment.id),
    queryFn: () => api.recon.get(assessment.id),
  });

  return (
    <div className="stack-lg">
      <PageHeader
        title="Recon"
        description="Parsed results from completed reconnaissance scans."
      />
      {query.isLoading ? <Loading /> : null}
      {query.isError ? (
        <ErrorNotice error={query.error} onRetry={() => void query.refetch()} />
      ) : null}
      {query.data ? (
        <>
          <div className="stat-grid">
            <Stat label="Scans" value={query.data.totals.scans} />
            <Stat label="Hosts" value={query.data.totals.hosts} />
            <Stat label="Hosts up" value={query.data.totals.hosts_up} />
            <Stat label="Open ports" value={query.data.totals.open_ports} />
          </div>
          <p className="muted tiny">
            Generated {formatDate(query.data.generated_at)}
          </p>

          <Card title="Hosts and services">
            {query.data.hosts.length === 0 ? (
              <EmptyState
                title="No host data yet"
                description="Run an Nmap scan against an in-scope host."
              />
            ) : (
              <div className="stack">
                {query.data.hosts.map((host) => (
                  <div key={host.address} className="host-block">
                    <div className="row-between">
                      <strong className="mono">{host.address}</strong>
                      <span className="row-actions">
                        <Badge tone={host.status === "up" ? "success" : "neutral"}>
                          {host.status}
                        </Badge>
                        <span className="muted tiny">{host.address_type}</span>
                      </span>
                    </div>
                    {host.hostnames.length ? (
                      <p className="tiny muted mono">{host.hostnames.join(", ")}</p>
                    ) : null}
                    {host.os_matches.length ? (
                      <p className="tiny muted">
                        OS: {host.os_matches.join("; ")}
                      </p>
                    ) : null}
                    {host.ports.length ? (
                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr>
                              <th>Port</th>
                              <th>State</th>
                              <th>Service</th>
                              <th>Product / version</th>
                              <th>Extra</th>
                            </tr>
                          </thead>
                          <tbody>
                            {host.ports.map((port) => (
                              <tr
                                key={`${port.port}-${port.protocol}`}
                                id={`port-${host.address}-${port.port}`}
                              >
                                <td className="mono">
                                  {port.port}/{port.protocol}
                                </td>
                                <td>{port.state}</td>
                                <td>{port.service?.name ?? "—"}</td>
                                <td>
                                  {[port.service?.product, port.service?.version]
                                    .filter(Boolean)
                                    .join(" ") || "—"}
                                </td>
                                <td className="muted">
                                  {port.service?.extrainfo ?? port.reason ?? "—"}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <p className="muted tiny">No open ports parsed.</p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </Card>

          <div className="two-col">
            <Card title="DNS records">
              {query.data.dns.length === 0 ? (
                <EmptyState title="No DNS scans" />
              ) : (
                <div className="stack">
                  {query.data.dns.map((entry) => (
                    <div key={entry.scan_id}>
                      <strong className="mono">{entry.target}</strong>
                      <dl className="description-list compact">
                        {Object.entries(entry.records).map(([type, values]) => (
                          <div key={type}>
                            <dt>{type}</dt>
                            <dd className="mono">{values.join(", ")}</dd>
                          </div>
                        ))}
                      </dl>
                    </div>
                  ))}
                </div>
              )}
            </Card>

            <Card title="Whois">
              {query.data.whois.length === 0 ? (
                <EmptyState title="No whois scans" />
              ) : (
                <div className="stack">
                  {query.data.whois.map((entry) => (
                    <div key={entry.scan_id}>
                      <strong className="mono">{entry.target}</strong>
                      {entry.skipped ? (
                        <p className="muted tiny">
                          Skipped: {entry.note ?? "private target"}
                        </p>
                      ) : (
                        <dl className="description-list compact">
                          {Object.entries(entry.fields).map(([field, fieldValue]) => (
                            <div key={field}>
                              <dt>{labelize(field)}</dt>
                              <dd>{fieldValue}</dd>
                            </div>
                          ))}
                        </dl>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </Card>
          </div>

          <div className="two-col">
            <Card title="Technologies">
              {query.data.technologies.length === 0 ? (
                <EmptyState title="No technology fingerprints" />
              ) : (
                <div className="stack">
                  {query.data.technologies.map((entry) => (
                    <div key={entry.scan_id}>
                      <strong className="mono">{entry.target}</strong>
                      <p className="muted tiny">
                        Status {entry.status_code ?? "—"}
                      </p>
                      <dl className="description-list compact">
                        {Object.entries(entry.technologies).map(
                          ([name, plugins]) => (
                            <div key={name}>
                              <dt>{name}</dt>
                              <dd>{plugins.join(", ") || "—"}</dd>
                            </div>
                          ),
                        )}
                      </dl>
                    </div>
                  ))}
                </div>
              )}
            </Card>

            <Card title="HTTP responses">
              {query.data.http.length === 0 ? (
                <EmptyState title="No HTTP checks" />
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Type</th>
                        <th>Headers</th>
                        <th>Body</th>
                      </tr>
                    </thead>
                    <tbody>
                      {query.data.http.map((entry) => (
                        <tr key={entry.scan_id}>
                          <td className="mono break-all">{entry.target}</td>
                          <td>{entry.status_code ?? "—"}</td>
                          <td>{entry.content_type ?? "—"}</td>
                          <td>{entry.header_count}</td>
                          <td>{formatBytes(entry.body_bytes)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          </div>

          <Card title="Scans included">
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Target</th>
                    <th>Profile</th>
                    <th>Status</th>
                    <th>Duration</th>
                    <th>Tool version</th>
                  </tr>
                </thead>
                <tbody>
                  {query.data.scans.map((scan) => (
                    <tr key={scan.id}>
                      <td className="mono">#{scan.id}</td>
                      <td className="mono break-all">{scan.target}</td>
                      <td>{scan.profile}</td>
                      <td>
                        <StatusBadge status={scan.status} />
                        {scan.parse_error ? (
                          <div className="cell-sub text-warning">
                            Parse: {scan.parse_error}
                          </div>
                        ) : null}
                      </td>
                      <td>{formatDuration(scan.duration_seconds)}</td>
                      <td>{scan.tool_version ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      ) : null}
    </div>
  );
}
