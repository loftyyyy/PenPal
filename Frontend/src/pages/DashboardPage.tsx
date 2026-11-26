import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { formatDate, formatDuration, labelize } from "../lib/format";
import { keys } from "../lib/keys";
import { SEVERITY_ORDER } from "../lib/severity";
import type { SeverityCounts } from "../lib/types";
import { useAssessment } from "../components/AssessmentLayout";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorNotice,
  Loading,
  ProgressBar,
  SeverityBadge,
  Stat,
  StatusBadge,
} from "../components/ui";

export function DashboardPage() {
  const assessment = useAssessment();
  const query = useQuery({
    queryKey: keys.dashboard(assessment.id),
    queryFn: () => api.dashboard.get(assessment.id),
  });

  if (query.isLoading) return <Loading label="Loading dashboard…" />;
  if (query.isError) {
    return (
      <ErrorNotice error={query.error} onRetry={() => void query.refetch()} />
    );
  }
  if (!query.data) return null;
  const data = query.data;

  return (
    <div className="stack-lg">
      <div className="toolbar">
        <p className="muted">
          Generated {formatDate(data.generated_at)}
          {data.last_updated_at ? ` · last activity ${formatDate(data.last_updated_at)}` : ""}
        </p>
        <Button variant="secondary" onClick={() => void query.refetch()}>
          Refresh
        </Button>
      </div>

      <div className="stat-grid">
        <Stat label="Total findings" value={data.total_findings} />
        <Stat label="Confirmed" value={data.status_counts.confirmed} />
        <Stat label="Pending" value={data.status_counts.pending} />
        <Stat
          label="AI coverage"
          value={`${data.ai_coverage.coverage_percent}%`}
          hint={`${data.ai_coverage.analyzed} of ${data.ai_coverage.total} findings`}
        />
      </div>

      <div className="two-col">
        <Card title="Confirmed severity">
          <SeverityBars counts={data.severity_confirmed} />
          <p className="muted tiny">
            Only confirmed findings, using server-computed final severity.
          </p>
        </Card>
        <Card title="Unverified severity">
          <SeverityBars counts={data.severity_unverified.total} />
          <p className="muted tiny">
            Pending or needs-retest findings, AI-suggested when available, otherwise
            tool severity.
          </p>
        </Card>
      </div>

      <div className="two-col">
        <Card title="Verification status">
          <div className="status-counts">
            {(
              Object.entries(data.status_counts) as Array<
                [keyof typeof data.status_counts, number]
              >
            ).map(([status, count]) => (
              <div key={status} className="status-count">
                <span>{labelize(status)}</span>
                <strong>{count}</strong>
              </div>
            ))}
          </div>
        </Card>
        <Card title="AI summary">
          {data.ai_summary ? (
            <>
              <div className="row-between">
                <Badge tone="success">Approved</Badge>
                <span className="muted tiny">
                  {data.ai_summary.provider} · {data.ai_summary.model}
                </span>
              </div>
              <p className="summary-preview">{data.ai_summary.text}</p>
              <Link to="../ai" className="text-link">
                Open summary workspace →
              </Link>
            </>
          ) : (
            <EmptyState
              title="No approved summary"
              description="Generate and approve a summary to show it here and in the report."
              action={
                <Link to="../ai" className="btn btn-secondary">
                  Go to AI & summary
                </Link>
              }
            />
          )}
        </Card>
      </div>

      <Card title="Top confirmed findings">
        {data.top_confirmed_findings.length === 0 ? (
          <EmptyState
            title="No confirmed findings"
            description="Verify findings to build the confirmed risk picture."
          />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Finding</th>
                  <th>Severity</th>
                  <th>Category</th>
                  <th>Endpoint</th>
                </tr>
              </thead>
              <tbody>
                {data.top_confirmed_findings.map((finding) => (
                  <tr key={finding.id}>
                    <td>
                      <Link to={`../findings/${finding.id}`} className="strong-link">
                        {finding.title}
                      </Link>
                    </td>
                    <td>
                      <SeverityBadge
                        severity={
                          (finding.final_severity as
                            | "critical"
                            | "high"
                            | "medium"
                            | "low"
                            | "info"
                            | null) ?? null
                        }
                      />
                    </td>
                    <td>{labelize(finding.category)}</td>
                    <td className="mono">{finding.affected_url ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="two-col">
        <Card title="Scan history">
          {data.scan_history.length === 0 ? (
            <EmptyState title="No scans yet" />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Tool</th>
                    <th>Profile</th>
                    <th>Status</th>
                    <th>Duration</th>
                  </tr>
                </thead>
                <tbody>
                  {data.scan_history.map((scan) => (
                    <tr key={scan.id}>
                      <td>{scan.tool}</td>
                      <td>{scan.profile}</td>
                      <td>
                        <StatusBadge status={scan.status} />
                      </td>
                      <td>{formatDuration(scan.duration_seconds)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card title="Category counts">
          {Object.keys(data.category_counts.confirmed).length === 0 &&
          Object.keys(data.category_counts.unverified).length === 0 ? (
            <EmptyState title="No categorized findings" />
          ) : (
            <div className="category-counts">
              {Array.from(
                new Set([
                  ...Object.keys(data.category_counts.confirmed),
                  ...Object.keys(data.category_counts.unverified),
                ]),
              ).map((category) => (
                <div key={category} className="category-row">
                  <span>{labelize(category)}</span>
                  <span>
                    <Badge tone="success">
                      {data.category_counts.confirmed[category] ?? 0}
                    </Badge>{" "}
                    <Badge tone="neutral">
                      {data.category_counts.unverified[category] ?? 0}
                    </Badge>
                  </span>
                </div>
              ))}
              <p className="muted tiny">Confirmed · unverified</p>
            </div>
          )}
        </Card>
      </div>

      <p className="muted tiny">{data.severity_basis}</p>
    </div>
  );
}

function SeverityBars({ counts }: { counts: SeverityCounts }) {
  const total = SEVERITY_ORDER.reduce((sum, severity) => sum + counts[severity], 0);
  if (total === 0) {
    return <p className="muted">No findings in this bucket.</p>;
  }
  return (
    <div className="severity-bars">
      {SEVERITY_ORDER.map((severity) => (
        <div key={severity} className="severity-bar-row">
          <span className="severity-bar-label">{labelize(severity)}</span>
          <ProgressBar
            value={(counts[severity] / total) * 100}
            tone={severity}
          />
          <span className="severity-bar-count">{counts[severity]}</span>
        </div>
      ))}
    </div>
  );
}
