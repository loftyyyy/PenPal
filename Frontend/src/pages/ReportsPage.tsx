import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, formatApiError, saveBlob } from "../lib/api";
import { formatDate } from "../lib/format";
import { keys } from "../lib/keys";
import type { ReportFormat } from "../lib/types";
import { useAssessment } from "../components/AssessmentLayout";
import {
  Button,
  Card,
  EmptyState,
  ErrorNotice,
  Loading,
  Notice,
  PageHeader,
  Pagination,
  StatusBadge,
} from "../components/ui";
import { useToast } from "../state/toast";
import { InfoTip } from "../components/InfoTip";

export function ReportsPage() {
  const assessment = useAssessment();
  const queryClient = useQueryClient();
  const toast = useToast();
  const [format, setFormat] = useState<ReportFormat>("html");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);

  const params = { page, page_size: pageSize };
  const list = useQuery({
    queryKey: keys.reports(assessment.id, params),
    queryFn: () => api.reports.list(assessment.id, params),
  });

  const create = useMutation({
    mutationFn: () => api.reports.create(assessment.id, format),
    onSuccess: (report) => {
      toast.push(
        report.status === "ready"
          ? `Report #${report.id} is ready.`
          : `Report #${report.id} failed.`,
        report.status === "ready" ? "success" : "error",
      );
      void queryClient.invalidateQueries({ queryKey: ["reports", assessment.id] });
    },
  });

  const download = useMutation({
    mutationFn: (reportId: number) => api.reports.download(reportId),
    onSuccess: ({ blob, filename }) =>
      void saveBlob(blob, filename, "penpal-report"),
    onError: (error) => toast.push(formatApiError(error), "error"),
  });

  return (
    <div className="stack-lg">
      <PageHeader
        title="Reports"
        description="Reports use confirmed findings and the approved summary. PDF may fall back to HTML if rendering fails."
      />

      <Card
        title="Generate report"
        help="Builds the report from confirmed findings and the approved summary. PDF may fall back to HTML when rendering fails."
      >
        <div className="inline-form">
          <label className="inline-field">
            <span>
              Format
              <InfoTip label="Report format">
                HTML opens in a browser; PDF is best for submission. If PDF
                rendering fails, PenPal returns a ready HTML report instead.
              </InfoTip>
            </span>
            <select
              value={format}
              onChange={(event) => setFormat(event.target.value as ReportFormat)}
            >
              <option value="html">HTML</option>
              <option value="pdf">PDF</option>
            </select>
          </label>
          <Button onClick={() => create.mutate()} disabled={create.isPending}>
            {create.isPending ? "Generating…" : "Generate"}
          </Button>
        </div>
        {create.isError ? <ErrorNotice error={create.error} /> : null}
        {create.data ? (
          <Notice
            tone={
              create.data.status === "ready"
                ? "success"
                : create.data.status === "failed"
                  ? "error"
                  : "info"
            }
          >
            Report #{create.data.id} · {create.data.status} · {create.data.format}
            {create.data.error ? ` — ${create.data.error}` : ""}
            {create.data.summary_counts.pdf_fallback ? (
              <div className="tiny">
                PDF rendering failed; an HTML report was produced instead.
              </div>
            ) : null}
          </Notice>
        ) : null}
        <p className="muted tiny">
          Generation is synchronous. The report includes confirmed findings and the
          approved summary only.
        </p>
      </Card>

      <Card title="Report history">
        {list.isLoading ? <Loading /> : null}
        {list.isError ? (
          <ErrorNotice error={list.error} onRetry={() => void list.refetch()} />
        ) : null}
        {list.data && list.data.items.length === 0 ? (
          <EmptyState
            title="No reports yet"
            description="Verify findings and approve a summary first."
          />
        ) : null}
        {list.data && list.data.items.length > 0 ? (
          <>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Format</th>
                    <th>Status</th>
                    <th>Findings</th>
                    <th>Created</th>
                    <th>SHA-256</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {list.data.items.map((report) => (
                    <tr key={report.id}>
                      <td className="mono">#{report.id}</td>
                      <td>{report.format}</td>
                      <td>
                        <StatusBadge status={report.status} />
                        {report.error ? (
                          <div className="cell-sub text-warning">{report.error}</div>
                        ) : null}
                      </td>
                      <td>{countLabel(report.summary_counts)}</td>
                      <td>{formatDate(report.created_at)}</td>
                      <td className="mono tiny break-all">
                        {report.sha256 ?? "—"}
                      </td>
                      <td className="cell-actions">
                        <Button
                          variant="secondary"
                          disabled={!report.has_file || download.isPending}
                          onClick={() => download.mutate(report.id)}
                        >
                          Download
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination
              page={list.data.page}
              pageSize={list.data.page_size}
              total={list.data.total}
              onPage={setPage}
              onPageSize={(size) => {
                setPageSize(size);
                setPage(1);
              }}
            />
          </>
        ) : null}
      </Card>
    </div>
  );
}

function countLabel(counts: Record<string, unknown>): string {
  const value = counts.total_findings ?? counts.findings ?? counts.confirmed;
  return typeof value === "number" ? String(value) : "—";
}
