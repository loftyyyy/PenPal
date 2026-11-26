import { useEffect, useRef, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { formatDate, labelize } from "../lib/format";
import { keys } from "../lib/keys";
import {
  SEVERITIES,
  type BulkAnalyzeRequest,
  type Severity,
} from "../lib/types";
import { useAssessment } from "../components/AssessmentLayout";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorNotice,
  Field,
  Loading,
  Notice,
  PageHeader,
  ProgressBar,
  SeverityBadge,
  StatusBadge,
} from "../components/ui";
import { useToast } from "../state/toast";

export function AiPage() {
  const assessment = useAssessment();
  const queryClient = useQueryClient();
  const toast = useToast();
  const observedJob = useRef<number | null>(null);
  const queuedJob = useRef<number | null>(null);

  const statusQuery = useQuery({
    queryKey: keys.aiStatus(assessment.id),
    queryFn: () => api.ai.status(assessment.id),
    refetchInterval: (query) => {
      const job = query.state.data?.job;
      return job?.status === "queued" || job?.status === "running" ? 2000 : false;
    },
  });

  const job = statusQuery.data?.job ?? null;
  const jobActive = job?.status === "queued" || job?.status === "running";

  useEffect(() => {
    if (!job) return;
    if (jobActive) {
      observedJob.current = job.id;
      return;
    }
    if (observedJob.current !== job.id && queuedJob.current !== job.id) return;
    observedJob.current = null;
    queuedJob.current = null;
    toast.push(
      `Bulk analysis ${job.status}: ${job.processed} processed, ${job.failed} failed.`,
      job.status === "completed" ? "success" : "error",
    );
    void queryClient.invalidateQueries({ queryKey: ["findings", assessment.id] });
    void queryClient.invalidateQueries({ queryKey: keys.dashboard(assessment.id) });
  }, [job, jobActive, assessment.id, queryClient, toast]);

  const [minSeverity, setMinSeverity] = useState<Severity | "">("");
  const [onlyUnanalyzed, setOnlyUnanalyzed] = useState(true);
  const [force, setForce] = useState(false);

  const bulk = useMutation({
    mutationFn: (body: BulkAnalyzeRequest) => api.ai.bulk(assessment.id, body),
    onSuccess: (result) => {
      queuedJob.current = result.job_id;
      toast.push(`Bulk analysis queued for ${result.total} findings.`, "success");
      void queryClient.invalidateQueries({ queryKey: keys.aiStatus(assessment.id) });
    },
  });

  function runBulk(event: FormEvent) {
    event.preventDefault();
    bulk.mutate({
      min_severity: minSeverity || null,
      only_unanalyzed: onlyUnanalyzed,
      force,
    });
  }

  const summaryQuery = useQuery({
    queryKey: keys.summary(assessment.id),
    queryFn: () => api.summary.get(assessment.id),
  });

  const latest = summaryQuery.data?.latest ?? null;
  const [summaryText, setSummaryText] = useState("");
  const [forceSummary, setForceSummary] = useState(false);

  useEffect(() => {
    if (latest) setSummaryText(latest.text);
  }, [latest?.id, latest?.updated_at]);

  const generate = useMutation({
    mutationFn: (forceValue: boolean) => api.summary.generate(assessment.id, forceValue),
    onSuccess: () => {
      toast.push("Summary draft generated.", "success");
      void queryClient.invalidateQueries({ queryKey: keys.summary(assessment.id) });
      void queryClient.invalidateQueries({ queryKey: keys.dashboard(assessment.id) });
    },
  });

  const edit = useMutation({
    mutationFn: () => api.summary.edit(latest!.id, summaryText.trim()),
    onSuccess: () => {
      toast.push("Summary saved. An approved summary becomes a draft again.", "success");
      void queryClient.invalidateQueries({ queryKey: keys.summary(assessment.id) });
      void queryClient.invalidateQueries({ queryKey: keys.dashboard(assessment.id) });
    },
  });

  const approve = useMutation({
    mutationFn: () => api.summary.approve(latest!.id),
    onSuccess: () => {
      toast.push("Summary approved. Reports will use it.", "success");
      void queryClient.invalidateQueries({ queryKey: keys.summary(assessment.id) });
      void queryClient.invalidateQueries({ queryKey: keys.dashboard(assessment.id) });
    },
  });

  return (
    <div className="stack-lg">
      <PageHeader
        title="AI & summary"
        description="AI analyses are advisory and audited. Summaries use confirmed findings only and must be approved before a report uses them."
      />

      <div className="two-col">
        <Card title="AI coverage">
          {statusQuery.isLoading ? <Loading /> : null}
          {statusQuery.isError ? (
            <ErrorNotice
              error={statusQuery.error}
              onRetry={() => void statusQuery.refetch()}
            />
          ) : null}
          {statusQuery.data ? (
            <div className="stack">
              <div className="stat-grid compact">
                <MiniStat
                  label="Findings"
                  value={statusQuery.data.total_findings}
                />
                <MiniStat
                  label="Interpreted"
                  value={statusQuery.data.findings_with_interpretation}
                />
                <MiniStat
                  label="Remediation"
                  value={statusQuery.data.findings_with_remediation}
                />
                <MiniStat label="Pending" value={statusQuery.data.pending_findings} />
              </div>
              <p className="muted tiny">
                Last analyzed {formatDate(statusQuery.data.last_analyzed_at)}
              </p>
              {job ? (
                <div className="job-block">
                  <div className="row-between">
                    <strong>Bulk job #{job.id}</strong>
                    <StatusBadge status={job.status} />
                  </div>
                  <ProgressBar
                    value={job.total ? (job.processed / job.total) * 100 : 0}
                  />
                  <p className="muted tiny">
                    {job.processed} of {job.total} processed · {job.failed} failed
                  </p>
                  {job.error ? <Notice tone="error">{job.error}</Notice> : null}
                </div>
              ) : null}
            </div>
          ) : null}
        </Card>

        <Card
          title="Run bulk analysis"
          help="Runs interpretation and remediation for matching findings. AI output is advisory and audited. One job runs per assessment."
        >
          <form onSubmit={runBulk} className="stack">
            <Field
              label="Minimum severity"
              hint="Leave empty to include all."
              help="Skip low-priority findings. Example: medium analyzes medium, high and critical only."
            >
              <select
                value={minSeverity}
                onChange={(event) =>
                  setMinSeverity(event.target.value as Severity | "")
                }
              >
                <option value="">All severities</option>
                {SEVERITIES.map((severity) => (
                  <option key={severity} value={severity}>
                    {labelize(severity)}
                  </option>
                ))}
              </select>
            </Field>
            <label className="check-row">
              <input
                type="checkbox"
                aria-label="Only unanalyzed findings"
                checked={onlyUnanalyzed}
                onChange={(event) => setOnlyUnanalyzed(event.target.checked)}
              />
              Only findings without a successful interpretation
            </label>
            <label className="check-row">
              <input
                type="checkbox"
                aria-label="Force regeneration"
                checked={force}
                onChange={(event) => setForce(event.target.checked)}
              />
              Force regeneration (bypass cache)
            </label>
            <Button type="submit" disabled={bulk.isPending || jobActive}>
              {jobActive
                ? "Job running…"
                : bulk.isPending
                  ? "Queueing…"
                  : "Queue bulk analysis"}
            </Button>
            {bulk.isError ? <ErrorNotice error={bulk.error} /> : null}
            <p className="muted tiny">
              One bulk job per assessment. Job progress is in memory; a backend
              restart loses progress but completed analyses remain stored.
            </p>
          </form>
        </Card>
      </div>

      <Card
        title="Assessment summary"
        help="Summaries use confirmed findings only. AI drafts stay advisory until you edit and approve them; reports use the approved text."
        actions={
          <div className="row-actions">
            <label className="check-row compact">
              <input
                type="checkbox"
                aria-label="Force summary regeneration"
                checked={forceSummary}
                onChange={(event) => setForceSummary(event.target.checked)}
              />
              Force
            </label>
            <Button
              onClick={() => generate.mutate(forceSummary)}
              disabled={generate.isPending}
            >
              {generate.isPending ? "Generating…" : "Generate draft"}
            </Button>
          </div>
        }
      >
        {summaryQuery.isLoading ? <Loading /> : null}
        {summaryQuery.isError ? (
          <ErrorNotice
            error={summaryQuery.error}
            onRetry={() => void summaryQuery.refetch()}
          />
        ) : null}
        {generate.isError ? <ErrorNotice error={generate.error} /> : null}
        {summaryQuery.data && !latest ? (
          <EmptyState
            title="No summary yet"
            description="Generate a draft from confirmed findings, then review and approve it."
          />
        ) : null}
        {latest ? (
          <div className="stack">
            <div className="row-between">
              <span className="row-actions">
                <StatusBadge status={latest.status} />
                <SeverityBadge severity={latest.overall_risk} />
                <span className="muted tiny">
                  {latest.provider} · {latest.model}
                </span>
              </span>
              <span className="muted tiny">
                Updated {formatDate(latest.updated_at)}
                {latest.approved_at
                  ? ` · approved ${formatDate(latest.approved_at)}`
                  : ""}
              </span>
            </div>
            <Field
              label="Summary text"
              hint="Editing an approved summary resets it to draft."
              help="Assessor-owned executive summary. Keep it concise and factual; approval makes it the report narrative."
            >
              <textarea
                rows={12}
                maxLength={6000}
                value={summaryText}
                onChange={(event) => setSummaryText(event.target.value)}
              />
            </Field>
            <div className="row-actions">
              <Button
                variant="secondary"
                onClick={() => edit.mutate()}
                disabled={
                  edit.isPending ||
                  !summaryText.trim() ||
                  summaryText === latest.text
                }
              >
                {edit.isPending ? "Saving…" : "Save edits"}
              </Button>
              {latest.status !== "approved" ? (
                <Button
                  onClick={() => approve.mutate()}
                  disabled={approve.isPending || summaryText !== latest.text}
                >
                  {approve.isPending ? "Approving…" : "Approve summary"}
                </Button>
              ) : (
                <Badge tone="success">Approved summary in use</Badge>
              )}
            </div>
            {summaryText !== latest.text ? (
              <Notice tone="info">
                Save edits before approving; approval applies to the stored text.
              </Notice>
            ) : null}
            {edit.isError ? <ErrorNotice error={edit.error} /> : null}
            {approve.isError ? <ErrorNotice error={approve.error} /> : null}

            {latest.output ? (
              <details>
                <summary>Structured AI output</summary>
                <pre className="code-block">
                  {JSON.stringify(latest.output, null, 2)}
                </pre>
              </details>
            ) : null}

            {summaryQuery.data && summaryQuery.data.history.length > 1 ? (
              <details>
                <summary>
                  History ({summaryQuery.data.history.length} summaries)
                </summary>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Status</th>
                        <th>Risk</th>
                        <th>Created</th>
                      </tr>
                    </thead>
                    <tbody>
                      {summaryQuery.data.history.map((summary) => (
                        <tr key={summary.id}>
                          <td className="mono">#{summary.id}</td>
                          <td>
                            <StatusBadge status={summary.status} />
                          </td>
                          <td>
                            <SeverityBadge severity={summary.overall_risk} />
                          </td>
                          <td>{formatDate(summary.created_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </details>
            ) : null}
          </div>
        ) : null}
      </Card>
    </div>
  );
}

function MiniStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="mini-stat">
      <span className="muted tiny">{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
