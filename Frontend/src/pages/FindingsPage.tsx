import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../lib/api";
import { formatDate, labelize } from "../lib/format";
import { keys } from "../lib/keys";
import { effectiveSeverity, SEVERITY_ORDER } from "../lib/severity";
import {
  FINDING_CATEGORIES,
  FINDING_SOURCES,
  VERIFICATION_STATUSES,
  type FindingCategory,
  type FindingFilters,
  type FindingSortField,
  type FindingSource,
  type Severity,
  type SortOrder,
  type VerificationStatus,
} from "../lib/types";
import { useAssessment } from "../components/AssessmentLayout";
import {
  Button,
  Card,
  EmptyState,
  ErrorNotice,
  Loading,
  PageHeader,
  Pagination,
  SeverityBadge,
  VerificationBadge,
} from "../components/ui";

export function FindingsPage() {
  const assessment = useAssessment();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const filters: FindingFilters = {
    page: Math.max(1, Number(searchParams.get("page") ?? "1")),
    page_size: Number(searchParams.get("page_size") ?? "20"),
    sort: (searchParams.get("sort") as FindingSortField | null) ?? "last_seen_at",
    order: (searchParams.get("order") as SortOrder | null) ?? "desc",
    ...(searchParams.get("q") ? { q: searchParams.get("q")! } : {}),
    ...(searchParams.get("severity")
      ? { severity: searchParams.get("severity") as Severity }
      : {}),
    ...(searchParams.get("status")
      ? { status: searchParams.get("status") as VerificationStatus }
      : {}),
    ...(searchParams.get("category")
      ? { category: searchParams.get("category") as FindingCategory }
      : {}),
    ...(searchParams.get("source")
      ? { source: searchParams.get("source") as FindingSource }
      : {}),
  };

  const query = useQuery({
    queryKey: keys.findings(assessment.id, filters),
    queryFn: () => api.findings.list(assessment.id, filters),
  });

  function update(next: Record<string, string | undefined>) {
    const merged = new URLSearchParams(searchParams);
    for (const [key, value] of Object.entries(next)) {
      if (value === undefined || value === "") merged.delete(key);
      else merged.set(key, value);
    }
    setSearchParams(merged, { replace: true });
  }

  const search = searchParams.get("q") ?? "";

  return (
    <div className="stack-lg">
      <PageHeader
        title="Findings"
        description="Severity is the effective value: final for confirmed findings, otherwise AI-suggested, otherwise tool severity."
        actions={
          <Button onClick={() => navigate("new")}>Add manual finding</Button>
        }
      />

      <Card>
        <div className="filter-grid">
          <label className="inline-field span-2">
            <span>Search</span>
            <input
              key={search}
              type="search"
              defaultValue={search}
              placeholder="Title, description, URL or parameter"
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  update({
                    q: (event.target as HTMLInputElement).value.trim(),
                    page: undefined,
                  });
                }
              }}
              aria-label="Search findings"
            />
          </label>
          <FilterSelect
            label="Severity"
            value={filters.severity ?? ""}
            options={SEVERITY_ORDER}
            onChange={(value) => update({ severity: value, page: undefined })}
          />
          <FilterSelect
            label="Status"
            value={filters.status ?? ""}
            options={VERIFICATION_STATUSES}
            onChange={(value) => update({ status: value, page: undefined })}
          />
          <FilterSelect
            label="Category"
            value={filters.category ?? ""}
            options={FINDING_CATEGORIES}
            onChange={(value) => update({ category: value, page: undefined })}
          />
          <FilterSelect
            label="Source"
            value={filters.source ?? ""}
            options={FINDING_SOURCES}
            onChange={(value) => update({ source: value, page: undefined })}
          />
          <label className="inline-field">
            <span>Sort</span>
            <select
              value={`${filters.sort}:${filters.order}`}
              onChange={(event) => {
                const [sort, order] = event.target.value.split(":");
                update({ sort, order, page: undefined });
              }}
            >
              <option value="last_seen_at:desc">Last seen ↓</option>
              <option value="created_at:desc">Created ↓</option>
              <option value="severity:desc">Severity ↓</option>
              <option value="severity:asc">Severity ↑</option>
              <option value="title:asc">Title A–Z</option>
              <option value="title:desc">Title Z–A</option>
            </select>
          </label>
          <Button
            variant="ghost"
            onClick={() => {
              setSearchParams(new URLSearchParams(), { replace: true });
            }}
          >
            Clear filters
          </Button>
        </div>
      </Card>

      {query.isLoading ? <Loading /> : null}
      {query.isError ? (
        <ErrorNotice error={query.error} onRetry={() => void query.refetch()} />
      ) : null}
      {query.data && query.data.items.length === 0 ? (
        <EmptyState
          title="No findings match"
          description="Run a scan, or add a manual finding for anything the tools missed."
          action={
            <Button onClick={() => navigate("new")}>Add manual finding</Button>
          }
        />
      ) : null}
      {query.data && query.data.items.length > 0 ? (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Finding</th>
                  <th>Category</th>
                  <th>Source</th>
                  <th>Status</th>
                  <th>Endpoint</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {query.data.items.map((finding) => {
                  const severity = effectiveSeverity(finding);
                  const basis = finding.final_severity
                    ? "Final"
                    : finding.ai_suggested_severity
                      ? "AI"
                      : "Tool";
                  return (
                    <tr key={finding.id}>
                      <td>
                        <SeverityBadge severity={severity} />
                        <div className="cell-sub muted">{basis}</div>
                      </td>
                      <td>
                        <Link
                          to={`${finding.id}`}
                          className="strong-link"
                          state={{ from: "findings" }}
                        >
                          {finding.title}
                        </Link>
                        {finding.parameter ? (
                          <div className="cell-sub muted">
                            Parameter {finding.parameter}
                          </div>
                        ) : null}
                      </td>
                      <td>{labelize(finding.category)}</td>
                      <td>{labelize(finding.source)}</td>
                      <td>
                        <VerificationBadge status={finding.verification_status} />
                      </td>
                      <td className="mono break-all">
                        {finding.affected_url ?? "—"}
                      </td>
                      <td>{formatDate(finding.last_seen_at)}</td>
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
            onPage={(page) => update({ page: String(page) })}
            onPageSize={(size) =>
              update({ page_size: String(size), page: undefined })
            }
          />
        </>
      ) : null}
    </div>
  );
}

function FilterSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: readonly string[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="inline-field">
      <span>{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        <option value="">All</option>
        {options.map((option) => (
          <option key={option} value={option}>
            {labelize(option)}
          </option>
        ))}
      </select>
    </label>
  );
}
