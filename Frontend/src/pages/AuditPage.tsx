import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, saveBlob } from "../lib/api";
import { dateInputToIso, formatDate, labelize } from "../lib/format";
import { keys } from "../lib/keys";
import type { AuditFilters, AuditOutcome } from "../lib/types";
import { useAssessment } from "../components/AssessmentLayout";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorNotice,
  Field,
  Loading,
  PageHeader,
  Pagination,
} from "../components/ui";
import { useToast } from "../state/toast";

const AUDIT_ACTIONS = [
  "auth.login_success",
  "auth.login_failed",
  "assessment.created",
  "assessment.authorization_confirmed",
  "scope.checked",
  "scope.item_added",
  "scan.requested",
  "scan.started",
  "scan.completed",
  "scan.failed",
  "scan.cancelled",
  "scan.scope_denied",
  "finding.created",
  "finding.verified",
  "evidence.added",
  "ai.analyzed",
  "ai.bulk_requested",
  "summary.generated",
  "summary.edited",
  "summary.approved",
  "http_check.request",
  "http_checks.config_updated",
  "test_account.created",
  "test_account.deleted",
  "report.generated",
];

interface FilterForm {
  action: string;
  entity_type: string;
  user_id: string;
  outcome: "" | AuditOutcome;
  from: string;
  to: string;
}

const EMPTY_FILTERS: FilterForm = {
  action: "",
  entity_type: "",
  user_id: "",
  outcome: "",
  from: "",
  to: "",
};

export function AuditPage() {
  const assessment = useAssessment();
  const toast = useToast();
  const [form, setForm] = useState<FilterForm>(EMPTY_FILTERS);
  const [filters, setFilters] = useState<AuditFilters>({});
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);

  const queryFilters: AuditFilters = {
    ...filters,
    page,
    page_size: pageSize,
  };

  const query = useQuery({
    queryKey: keys.audit(assessment.id, queryFilters),
    queryFn: () => api.audit.list(assessment.id, queryFilters),
  });

  function applyFilters() {
    setFilters({
      ...(form.action ? { action: form.action } : {}),
      ...(form.entity_type ? { entity_type: form.entity_type.trim() } : {}),
      ...(form.user_id ? { user_id: Number(form.user_id) } : {}),
      ...(form.outcome ? { outcome: form.outcome } : {}),
      ...(form.from ? { from: dateInputToIso(form.from) } : {}),
      ...(form.to ? { to: dateInputToIso(form.to) } : {}),
    });
    setPage(1);
  }

  const exportAudit = useMutation({
    mutationFn: (format: "csv" | "json") =>
      api.audit.export(assessment.id, filters, format),
    onSuccess: ({ blob, filename }, format) =>
      void saveBlob(
        blob,
        filename,
        `audit-log-${assessment.id}.${format}`,
      ),
    onError: (error) =>
      toast.push(
        error instanceof Error ? error.message : "Export failed",
        "error",
      ),
  });

  return (
    <div className="stack-lg">
      <PageHeader
        title="Audit log"
        description="Append-only record of assessment actions, including scope allow/deny decisions."
        actions={
          <div className="row-actions">
            <Button
              variant="secondary"
              onClick={() => exportAudit.mutate("csv")}
              disabled={exportAudit.isPending}
            >
              Export CSV
            </Button>
            <Button
              variant="secondary"
              onClick={() => exportAudit.mutate("json")}
              disabled={exportAudit.isPending}
            >
              Export JSON
            </Button>
          </div>
        }
      />

      <Card>
        <form
          className="filter-grid"
          onSubmit={(event) => {
            event.preventDefault();
            applyFilters();
          }}
        >
          <label className="inline-field">
            <span>Action</span>
            <select
              value={form.action}
              onChange={(event) =>
                setForm({ ...form, action: event.target.value })
              }
            >
              <option value="">All actions</option>
              {AUDIT_ACTIONS.map((action) => (
                <option key={action} value={action}>
                  {action}
                </option>
              ))}
            </select>
          </label>
          <label className="inline-field">
            <span>Entity type</span>
            <input
              value={form.entity_type}
              maxLength={50}
              onChange={(event) =>
                setForm({ ...form, entity_type: event.target.value })
              }
              placeholder="finding"
            />
          </label>
          <label className="inline-field">
            <span>User ID</span>
            <input
              type="number"
              min={1}
              value={form.user_id}
              onChange={(event) =>
                setForm({ ...form, user_id: event.target.value })
              }
            />
          </label>
          <label className="inline-field">
            <span>Outcome</span>
            <select
              value={form.outcome}
              onChange={(event) =>
                setForm({
                  ...form,
                  outcome: event.target.value as FilterForm["outcome"],
                })
              }
            >
              <option value="">All outcomes</option>
              <option value="allowed">Allowed</option>
              <option value="denied">Denied</option>
            </select>
          </label>
          <Field label="From">
            <input
              type="datetime-local"
              value={form.from}
              onChange={(event) => setForm({ ...form, from: event.target.value })}
            />
          </Field>
          <Field label="To">
            <input
              type="datetime-local"
              value={form.to}
              onChange={(event) => setForm({ ...form, to: event.target.value })}
            />
          </Field>
          <div className="row-actions filter-actions">
            <Button type="submit">Apply filters</Button>
            <Button
              variant="ghost"
              onClick={() => {
                setForm(EMPTY_FILTERS);
                setFilters({});
                setPage(1);
              }}
            >
              Clear
            </Button>
          </div>
        </form>
      </Card>

      {query.isLoading ? <Loading /> : null}
      {query.isError ? (
        <ErrorNotice error={query.error} onRetry={() => void query.refetch()} />
      ) : null}
      {query.data && query.data.items.length === 0 ? (
        <EmptyState title="No audit entries match these filters" />
      ) : null}
      {query.data && query.data.items.length > 0 ? (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Action</th>
                  <th>User</th>
                  <th>Entity</th>
                  <th>Outcome</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {query.data.items.map((entry) => {
                  const allowed =
                    typeof entry.details.allowed === "boolean"
                      ? entry.details.allowed
                      : null;
                  return (
                    <tr key={entry.id}>
                      <td className="nowrap">{formatDate(entry.created_at)}</td>
                      <td className="mono">{entry.action}</td>
                      <td>{entry.user_id ?? "—"}</td>
                      <td>
                        {entry.entity_type ?? "—"}
                        {entry.entity_id ? (
                          <span className="muted"> #{entry.entity_id}</span>
                        ) : null}
                      </td>
                      <td>
                        {allowed === null ? (
                          <span className="muted">—</span>
                        ) : allowed ? (
                          <Badge tone="success">Allowed</Badge>
                        ) : (
                          <Badge tone="error">Denied</Badge>
                        )}
                      </td>
                      <td>
                        {Object.keys(entry.details).length ? (
                          <details>
                            <summary>View</summary>
                            <pre className="code-block compact">
                              {JSON.stringify(entry.details, null, 2)}
                            </pre>
                          </details>
                        ) : (
                          "—"
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <Pagination
            page={query.data.page}
            pageSize={query.data.page_size}
            total={query.data.total}
            onPage={setPage}
            onPageSize={(size) => {
              setPageSize(size);
              setPage(1);
            }}
          />
        </>
      ) : null}

      <p className="muted tiny">
        Exports use the applied filters, not unsaved form values.
        {filters.outcome ? ` Outcome: ${labelize(filters.outcome)}.` : ""}
      </p>
      {exportAudit.isError ? <ErrorNotice error={exportAudit.error} /> : null}
    </div>
  );
}
