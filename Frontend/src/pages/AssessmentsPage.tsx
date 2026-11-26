import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../lib/api";
import { formatDate } from "../lib/format";
import { keys } from "../lib/keys";
import { ASSESSMENT_STATUSES } from "../lib/types";
import {
  Button,
  EmptyState,
  ErrorNotice,
  Loading,
  PageHeader,
  Pagination,
  StatusBadge,
} from "../components/ui";

export function AssessmentsPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const q = searchParams.get("q") ?? "";
  const status = searchParams.get("status") ?? "";
  const page = Math.max(1, Number(searchParams.get("page") ?? "1"));
  const pageSize = Number(searchParams.get("page_size") ?? "20");

  const [search, setSearch] = useState(q);

  useEffect(() => {
    setSearch(q);
  }, [q]);

  const params = {
    page,
    page_size: pageSize,
    ...(q ? { q } : {}),
    ...(status ? { status } : {}),
  };

  const query = useQuery({
    queryKey: keys.assessments(params),
    queryFn: () => api.assessments.list(params),
  });

  function updateParams(next: Record<string, string | undefined>) {
    const merged = new URLSearchParams(searchParams);
    for (const [key, value] of Object.entries(next)) {
      if (value === undefined || value === "") merged.delete(key);
      else merged.set(key, value);
    }
    setSearchParams(merged, { replace: true });
  }

  return (
    <div className="page">
      <PageHeader
        title="Assessments"
        description="Authorized targets, their scope and results."
        actions={
          <Button onClick={() => navigate("/assessments/new")}>
            New assessment
          </Button>
        }
      />

      <div className="toolbar">
        <form
          className="toolbar-search"
          onSubmit={(event) => {
            event.preventDefault();
            updateParams({ q: search.trim(), page: undefined });
          }}
        >
          <input
            type="search"
            placeholder="Search name or target"
            aria-label="Search assessments"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
          <Button type="submit" variant="secondary">
            Search
          </Button>
        </form>
        <label className="inline-field">
          <span>Status</span>
          <select
            value={status}
            onChange={(event) =>
              updateParams({ status: event.target.value, page: undefined })
            }
          >
            <option value="">All</option>
            {ASSESSMENT_STATUSES.map((option) => (
              <option key={option} value={option}>
                {option.replaceAll("_", " ")}
              </option>
            ))}
          </select>
        </label>
      </div>

      {query.isLoading ? <Loading /> : null}
      {query.isError ? (
        <ErrorNotice error={query.error} onRetry={() => void query.refetch()} />
      ) : null}
      {query.data && query.data.items.length === 0 ? (
        <EmptyState
          title="No assessments yet"
          description="Create one, add scope items and confirm authorization before scanning."
          action={
            <Button onClick={() => navigate("/assessments/new")}>
              New assessment
            </Button>
          }
        />
      ) : null}
      {query.data && query.data.items.length > 0 ? (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Authorization</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {query.data.items.map((assessment) => (
                  <tr key={assessment.id}>
                    <td>
                      <Link
                        to={`/assessments/${assessment.id}/dashboard`}
                        className="strong-link"
                      >
                        {assessment.name}
                      </Link>
                      {assessment.description ? (
                        <div className="cell-sub muted">
                          {assessment.description}
                        </div>
                      ) : null}
                    </td>
                    <td>
                      {assessment.target_name}
                      {assessment.target_base_url ? (
                        <div className="cell-sub muted">
                          {assessment.target_base_url}
                        </div>
                      ) : null}
                    </td>
                    <td>
                      <StatusBadge status={assessment.status} />
                    </td>
                    <td>
                      {assessment.authorization_confirmed ? (
                        <span className="text-success">Confirmed</span>
                      ) : (
                        <span className="text-warning">Not confirmed</span>
                      )}
                    </td>
                    <td>{formatDate(assessment.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination
            page={query.data.page}
            pageSize={query.data.page_size}
            total={query.data.total}
            onPage={(next) => updateParams({ page: String(next) })}
            onPageSize={(size) =>
              updateParams({ page_size: String(size), page: undefined })
            }
          />
        </>
      ) : null}
    </div>
  );
}
