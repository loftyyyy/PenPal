import { useEffect, useMemo, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, formatApiError, saveBlob } from "../lib/api";
import { formatDate, labelize } from "../lib/format";
import { keys } from "../lib/keys";
import { score, severityFromScore } from "../lib/severity";
import type {
  AIAnalysisOut,
  FindingVerify,
  Severity,
  VerificationDecision,
} from "../lib/types";
import { useAssessment } from "../components/AssessmentLayout";
import {
  Badge,
  Button,
  Card,
  DescriptionList,
  EmptyState,
  ErrorNotice,
  Field,
  Loading,
  Notice,
  PageHeader,
  SeverityBadge,
  VerificationBadge,
} from "../components/ui";
import { useToast } from "../state/toast";

const DECISIONS: VerificationDecision[] = [
  "confirmed",
  "false_positive",
  "needs_retest",
];

export function FindingDetailPage() {
  const assessment = useAssessment();
  const { findingId } = useParams();
  const id = Number(findingId);
  const queryClient = useQueryClient();
  const toast = useToast();

  const findingQuery = useQuery({
    queryKey: keys.finding(id),
    queryFn: () => api.findings.get(id),
    enabled: Number.isInteger(id) && id > 0,
  });

  const evidenceQuery = useQuery({
    queryKey: keys.evidence(id),
    queryFn: () => api.findings.evidence.list(id),
    enabled: Number.isInteger(id) && id > 0,
  });

  const analysesQuery = useQuery({
    queryKey: keys.analyses(id),
    queryFn: () => api.ai.analyses(id),
    enabled: Number.isInteger(id) && id > 0,
  });

  const matrixQuery = useQuery({
    queryKey: keys.severityMatrix(),
    queryFn: () => api.meta.severityMatrix(),
    staleTime: Infinity,
  });

  const finding = findingQuery.data;

  const [decision, setDecision] = useState<VerificationDecision>(
    (finding?.verification_status === "pending"
      ? "confirmed"
      : finding?.verification_status) ?? "confirmed",
  );
  const [likelihood, setLikelihood] = useState<number | "">(
    finding?.likelihood ?? "",
  );
  const [impact, setImpact] = useState<number | "">(finding?.impact ?? "");
  const [remediation, setRemediation] = useState(
    finding?.final_remediation ?? "",
  );
  const [reason, setReason] = useState(finding?.rejection_reason ?? "");

  useEffect(() => {
    if (!finding) return;
    setDecision(
      finding.verification_status === "pending"
        ? "confirmed"
        : finding.verification_status,
    );
    setLikelihood(finding.likelihood ?? "");
    setImpact(finding.impact ?? "");
    setRemediation(finding.final_remediation ?? "");
    setReason(finding.rejection_reason ?? "");
  }, [finding?.id]);

  const verify = useMutation({
    mutationFn: (body: FindingVerify) => api.findings.verify(id, body),
    onSuccess: () => {
      toast.push("Verification saved.", "success");
      void queryClient.invalidateQueries({ queryKey: keys.finding(id) });
      void queryClient.invalidateQueries({ queryKey: ["findings", assessment.id] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard", assessment.id] });
      void queryClient.invalidateQueries({ queryKey: keys.audit(assessment.id) });
    },
  });

  const analyze = useMutation({
    mutationFn: (force: boolean) => api.ai.analyze(id, force),
    onSuccess: () => {
      toast.push("AI analysis completed.", "success");
      void queryClient.invalidateQueries({ queryKey: keys.finding(id) });
      void queryClient.invalidateQueries({ queryKey: keys.analyses(id) });
      void queryClient.invalidateQueries({ queryKey: ["dashboard", assessment.id] });
      void queryClient.invalidateQueries({ queryKey: ["ai-status", assessment.id] });
    },
  });

  const [forceAnalyze, setForceAnalyze] = useState(false);

  const previewSeverity: Severity | null =
    matrixQuery.data && likelihood !== "" && impact !== ""
      ? severityFromScore(score(Number(likelihood), Number(impact)), matrixQuery.data)
      : null;

  const remediationRequired =
    decision === "confirmed" && !finding?.final_remediation;

  function canSubmit(): boolean {
    if (decision === "confirmed") {
      return likelihood !== "" && impact !== "";
    }
    if (decision === "false_positive") return reason.trim().length >= 10;
    if (likelihood === "" && impact === "") return true;
    return likelihood !== "" && impact !== "";
  }

  function submitVerification(event: FormEvent) {
    event.preventDefault();
    const body: FindingVerify = {
      decision,
      likelihood: decision === "false_positive" || likelihood === "" ? null : Number(likelihood),
      impact: decision === "false_positive" || impact === "" ? null : Number(impact),
      final_remediation:
        decision === "confirmed" ? remediation.trim() || null : null,
      reason: decision === "confirmed" ? null : reason.trim() || null,
    };
    verify.mutate(body);
  }

  const [evidenceMode, setEvidenceMode] = useState<"note" | "file">("note");
  const [evidenceNote, setEvidenceNote] = useState("");
  const [evidenceFile, setEvidenceFile] = useState<File | null>(null);

  const upload = useMutation({
    mutationFn: () =>
      api.findings.evidence.upload(id, {
        ...(evidenceMode === "note" ? { note: evidenceNote } : {}),
        ...(evidenceMode === "file" && evidenceFile
          ? { file: evidenceFile }
          : {}),
      }),
    onSuccess: () => {
      toast.push("Evidence uploaded.", "success");
      setEvidenceNote("");
      setEvidenceFile(null);
      void queryClient.invalidateQueries({ queryKey: keys.evidence(id) });
    },
  });

  const downloadEvidence = useMutation({
    mutationFn: (url: string) => api.findings.evidence.download(url),
    onSuccess: ({ blob, filename }) =>
      void saveBlob(blob, filename, "evidence"),
    onError: (error) => toast.push(formatApiError(error), "error"),
  });

  const latestAnalyses = useMemo(
    () => (analysesQuery.data ? [...analysesQuery.data].reverse() : []),
    [analysesQuery.data],
  );

  if (findingQuery.isLoading) return <Loading label="Loading finding…" />;
  if (findingQuery.isError) {
    return (
      <ErrorNotice
        error={findingQuery.error}
        onRetry={() => void findingQuery.refetch()}
      />
    );
  }
  if (!finding) return null;

  return (
    <div className="stack-lg">
      <PageHeader
        title={finding.title}
        description={
          <span className="row-actions">
            <VerificationBadge status={finding.verification_status} />
            <SeverityBadge severity={finding.final_severity} />
            <span className="muted">Source {labelize(finding.source)}</span>
          </span>
        }
        actions={
          <Link to="../findings" className="btn btn-secondary">
            Back to findings
          </Link>
        }
      />

      {finding.assessment_id !== assessment.id ? (
        <Notice tone="warning">
          This finding belongs to assessment #{finding.assessment_id}, not the one
          in the URL.
        </Notice>
      ) : null}

      <div className="two-col two-col-wide">
        <Card title="Details">
          <DescriptionList
            items={[
              { label: "Category", value: labelize(finding.category) },
              { label: "OWASP", value: finding.owasp_category ?? "—" },
              { label: "CWE", value: finding.cwe ?? "—" },
              {
                label: "Affected URL",
                value: (
                  <span className="mono break-all">
                    {finding.affected_url ?? "—"}
                  </span>
                ),
              },
              { label: "HTTP method", value: finding.http_method ?? "—" },
              { label: "Parameter", value: finding.parameter ?? "—" },
              { label: "Tool confidence", value: finding.tool_confidence ?? "—" },
              { label: "Scan", value: finding.scan_id ? `#${finding.scan_id}` : "Manual" },
              { label: "First seen", value: formatDate(finding.first_seen_at) },
              { label: "Last seen", value: formatDate(finding.last_seen_at) },
              { label: "Seen count", value: finding.seen_count },
              {
                label: "Evidence SHA",
                value: finding.scan_id ? "See scan raw output" : "—",
              },
            ]}
          />
          {finding.description ? (
            <>
              <h3>Description</h3>
              <p className="pre-wrap">{finding.description}</p>
            </>
          ) : null}
          {finding.rejection_reason ? (
            <Notice tone="warning">
              Verification note: {finding.rejection_reason}
            </Notice>
          ) : null}
        </Card>

        <Card title="Severity and verification">
          <div className="severity-triple">
            <div>
              <span className="muted tiny">Tool</span>
              <SeverityBadge severity={finding.tool_severity} />
            </div>
            <div>
              <span className="muted tiny">AI-suggested</span>
              <SeverityBadge severity={finding.ai_suggested_severity} />
            </div>
            <div>
              <span className="muted tiny">Final</span>
              <SeverityBadge severity={finding.final_severity} />
            </div>
          </div>
          {finding.likelihood && finding.impact ? (
            <p className="muted tiny">
              Current score: likelihood {finding.likelihood} × impact{" "}
              {finding.impact} = {finding.likelihood * finding.impact}
            </p>
          ) : null}

          <form onSubmit={submitVerification} className="stack">
            <Field
              label="Decision"
              hint="Final severity is always computed by the server."
            >
              <select
                value={decision}
                onChange={(event) => {
                  const next = event.target.value as VerificationDecision;
                  setDecision(next);
                  if (next === "false_positive") {
                    setLikelihood("");
                    setImpact("");
                    setRemediation("");
                  }
                }}
              >
                {DECISIONS.map((option) => (
                  <option key={option} value={option}>
                    {labelize(option)}
                  </option>
                ))}
              </select>
            </Field>

            <div className="form-grid">
              <Field
                label="Likelihood"
                hint="1 rare – 5 almost certain"
              >
                <select
                  value={likelihood}
                  disabled={decision === "false_positive"}
                  onChange={(event) =>
                    setLikelihood(event.target.value ? Number(event.target.value) : "")
                  }
                >
                  <option value="">Not set</option>
                  {[1, 2, 3, 4, 5].map((value) => (
                    <option key={value} value={value}>
                      {value} — {matrixQuery.data?.likelihood.labels[String(value)] ?? ""}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Impact" hint="1 negligible – 5 severe">
                <select
                  value={impact}
                  disabled={decision === "false_positive"}
                  onChange={(event) =>
                    setImpact(event.target.value ? Number(event.target.value) : "")
                  }
                >
                  <option value="">Not set</option>
                  {[1, 2, 3, 4, 5].map((value) => (
                    <option key={value} value={value}>
                      {value} — {matrixQuery.data?.impact.labels[String(value)] ?? ""}
                    </option>
                  ))}
                </select>
              </Field>
            </div>

            {likelihood !== "" && impact !== "" ? (
              <div className="score-preview">
                <span>
                  Score {score(Number(likelihood), Number(impact))} →{" "}
                  <SeverityBadge severity={previewSeverity} />
                </span>
                <span className="muted tiny">
                  Server will compute the final value.
                </span>
              </div>
            ) : null}

            {decision === "confirmed" ? (
              <Field
                label="Final remediation"
                hint={
                  remediationRequired
                    ? "Required unless a successful AI remediation already exists."
                    : "Leave empty to keep the latest AI remediation."
                }
              >
                <textarea
                  rows={4}
                  maxLength={20000}
                  value={remediation}
                  onChange={(event) => setRemediation(event.target.value)}
                />
              </Field>
            ) : null}

            {decision !== "confirmed" ? (
              <Field
                label={decision === "false_positive" ? "Reason (required)" : "Note"}
                hint={
                  decision === "false_positive"
                    ? "At least 10 characters."
                    : "Optional context for the next assessor."
                }
              >
                <textarea
                  rows={3}
                  maxLength={5000}
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                />
              </Field>
            ) : null}

            <Button type="submit" disabled={verify.isPending || !canSubmit()}>
              {verify.isPending ? "Saving…" : "Save verification"}
            </Button>
            {verify.isError ? <ErrorNotice error={verify.error} /> : null}
          </form>
        </Card>
      </div>

      <Card
        title="AI analysis"
        actions={
          <div className="row-actions">
            <label className="check-row compact">
              <input
                type="checkbox"
                aria-label="Force AI analysis"
                checked={forceAnalyze}
                onChange={(event) => setForceAnalyze(event.target.checked)}
              />
              Force
            </label>
            <Button
              onClick={() => analyze.mutate(forceAnalyze)}
              disabled={analyze.isPending}
            >
              {analyze.isPending ? "Analyzing…" : "Analyze finding"}
            </Button>
          </div>
        }
      >
        <p className="muted tiny">
          AI output is advisory. It never sets final severity or confirms a finding.
        </p>
        {analyze.isError ? <ErrorNotice error={analyze.error} /> : null}
        {analysesQuery.isLoading ? <Loading label="Loading analyses…" /> : null}
        {analysesQuery.isError ? (
          <ErrorNotice
            error={analysesQuery.error}
            onRetry={() => void analysesQuery.refetch()}
          />
        ) : null}
        {analysesQuery.data && analysesQuery.data.length === 0 ? (
          <EmptyState
            title="No analyses yet"
            description="Run AI interpretation and remediation for this finding."
          />
        ) : null}
        <div className="stack">
          {latestAnalyses.map((analysis) => (
            <AnalysisCard key={analysis.id} analysis={analysis} />
          ))}
        </div>
      </Card>

      <Card
        title="Evidence"
        actions={
          <span className="muted tiny">
            Files: PNG, JPEG, TXT, PDF · max 5 MB
          </span>
        }
      >
        {evidenceQuery.isLoading ? <Loading /> : null}
        {evidenceQuery.isError ? (
          <ErrorNotice
            error={evidenceQuery.error}
            onRetry={() => void evidenceQuery.refetch()}
          />
        ) : null}
        {evidenceQuery.data && evidenceQuery.data.length === 0 ? (
          <EmptyState
            title="No evidence attached"
            description="Add a note or upload a screenshot, text or PDF."
          />
        ) : null}
        <div className="stack">
          {evidenceQuery.data?.map((evidence) => (
            <div key={evidence.id} className="evidence-item">
              <div className="row-between">
                <span className="row-actions">
                  <Badge tone="info">{labelize(evidence.type)}</Badge>
                  <span className="muted tiny">
                    {formatDate(evidence.created_at)}
                  </span>
                </span>
                {evidence.has_file && evidence.download_url ? (
                  <Button
                    variant="secondary"
                    disabled={downloadEvidence.isPending}
                    onClick={() =>
                      downloadEvidence.mutate(evidence.download_url!)
                    }
                  >
                    Download
                  </Button>
                ) : null}
              </div>
              {evidence.content ? (
                <pre className="code-block">{evidence.content}</pre>
              ) : null}
              {evidence.filename ? (
                <p className="mono tiny">{evidence.filename}</p>
              ) : null}
              {evidence.sha256 ? (
                <p className="muted tiny break-all mono">
                  SHA-256 {evidence.sha256}
                </p>
              ) : null}
            </div>
          ))}
        </div>

        <form
          className="stack evidence-form"
          onSubmit={(event) => {
            event.preventDefault();
            upload.mutate();
          }}
        >
          <fieldset className="segmented">
            <legend>New evidence</legend>
            <label>
              <input
                type="radio"
                name="evidence-mode"
                aria-label="Evidence note"
                checked={evidenceMode === "note"}
                onChange={() => setEvidenceMode("note")}
              />
              Note
            </label>
            <label>
              <input
                type="radio"
                name="evidence-mode"
                aria-label="Evidence file"
                checked={evidenceMode === "file"}
                onChange={() => setEvidenceMode("file")}
              />
              File
            </label>
          </fieldset>
          {evidenceMode === "note" ? (
            <Field label="Note text">
              <textarea
                rows={3}
                value={evidenceNote}
                onChange={(event) => setEvidenceNote(event.target.value)}
              />
            </Field>
          ) : (
            <Field label="File">
              <input
                type="file"
                accept=".png,.jpg,.jpeg,.txt,.pdf,image/png,image/jpeg,text/plain,application/pdf"
                onChange={(event) =>
                  setEvidenceFile(event.target.files?.[0] ?? null)
                }
              />
            </Field>
          )}
          <Button
            type="submit"
            variant="secondary"
            disabled={
              upload.isPending ||
              (evidenceMode === "note"
                ? !evidenceNote.trim()
                : !evidenceFile)
            }
          >
            {upload.isPending ? "Uploading…" : "Add evidence"}
          </Button>
          {upload.isError ? <ErrorNotice error={upload.error} /> : null}
        </form>
      </Card>

      <Card title="Raw finding data">
        <details>
          <summary>Show raw JSON</summary>
          <pre className="code-block">{JSON.stringify(finding.raw, null, 2)}</pre>
        </details>
      </Card>
    </div>
  );
}

function AnalysisCard({ analysis }: { analysis: AIAnalysisOut }) {
  return (
    <article className="analysis-card">
      <div className="row-between">
        <span className="row-actions">
          <Badge tone={analysis.status === "success" ? "success" : "error"}>
            {labelize(analysis.function)}
          </Badge>
          <span className="muted tiny">
            {analysis.provider} · {analysis.model} · prompt{" "}
            {analysis.prompt_version}
          </span>
        </span>
        <span className="muted tiny">
          {analysis.latency_ms ? `${analysis.latency_ms} ms` : ""}{" "}
          {formatDate(analysis.created_at)}
        </span>
      </div>
      {analysis.error ? (
        <Notice tone="error">{analysis.error}</Notice>
      ) : null}
      {analysis.output ? <ObjectView value={analysis.output} /> : null}
      {analysis.attempts?.length ? (
        <details>
          <summary>Attempts</summary>
          <ul className="plain-list tiny">
            {analysis.attempts.map((attempt, index) => (
              <li key={`${attempt.provider}-${index}`}>
                {attempt.provider}
                {attempt.model ? ` / ${attempt.model}` : ""}: {attempt.outcome},{" "}
                {attempt.latency_ms} ms
                {attempt.error_class ? ` (${attempt.error_class})` : ""}
              </li>
            ))}
          </ul>
        </details>
      ) : null}
      <details>
        <summary>Sanitized input</summary>
        <pre className="code-block">{analysis.sanitized_input}</pre>
      </details>
    </article>
  );
}

function ObjectView({ value, depth = 0 }: { value: unknown; depth?: number }) {
  if (value === null || value === undefined) return <span className="muted">—</span>;
  if (typeof value === "string") {
    return <p className="pre-wrap">{value}</p>;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return <p>{String(value)}</p>;
  }
  if (Array.isArray(value)) {
    return (
      <ul className="plain-list">
        {value.map((item, index) => (
          <li key={index}>
            <ObjectView value={item} depth={depth + 1} />
          </li>
        ))}
      </ul>
    );
  }
  if (typeof value === "object") {
    if (depth > 3) {
      return <pre className="code-block">{JSON.stringify(value, null, 2)}</pre>;
    }
    return (
      <dl className="description-list compact">
        {Object.entries(value as Record<string, unknown>).map(([key, item]) => (
          <div key={key}>
            <dt>{labelize(key)}</dt>
            <dd>
              <ObjectView value={item} depth={depth + 1} />
            </dd>
          </div>
        ))}
      </dl>
    );
  }
  return null;
}
