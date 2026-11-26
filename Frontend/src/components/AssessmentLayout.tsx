import { useQuery } from "@tanstack/react-query";
import { Link, NavLink, Outlet, useOutletContext, useParams } from "react-router-dom";
import { api } from "../lib/api";
import { formatDate } from "../lib/format";
import { keys } from "../lib/keys";
import type { AssessmentOut } from "../lib/types";
import { ErrorNotice, Loading, Notice, StatusBadge } from "./ui";

const TABS = [
  { to: "dashboard", label: "Dashboard" },
  { to: "scope", label: "Scope" },
  { to: "scans", label: "Scans" },
  { to: "recon", label: "Recon" },
  { to: "findings", label: "Findings" },
  { to: "http-checks", label: "HTTP checks" },
  { to: "ai", label: "AI & summary" },
  { to: "reports", label: "Reports" },
  { to: "audit", label: "Audit" },
  { to: "settings", label: "Settings" },
];

export function AssessmentLayout() {
  const { assessmentId } = useParams();
  const id = Number(assessmentId);
  const valid = Number.isInteger(id) && id > 0;

  const query = useQuery({
    queryKey: keys.assessment(valid ? id : 0),
    queryFn: () => api.assessments.get(id),
    enabled: valid,
  });

  if (!valid) return <ErrorNotice error={new Error("Invalid assessment id")} />;
  if (query.isLoading) return <Loading label="Loading assessment…" />;
  if (query.isError) {
    return (
      <ErrorNotice error={query.error} onRetry={() => void query.refetch()} />
    );
  }
  if (!query.data) return <ErrorNotice error={new Error("Assessment not found")} />;

  const assessment = query.data;

  return (
    <div className="assessment-layout">
      <div className="assessment-heading">
        <Link to="/assessments" className="back-link">
          ← All assessments
        </Link>
        <div className="assessment-title-row">
          <div>
            <h1>{assessment.name}</h1>
            <p className="page-description">
              {assessment.target_name}
              {assessment.target_base_url ? ` · ${assessment.target_base_url}` : ""}
            </p>
          </div>
          <StatusBadge status={assessment.status} />
        </div>
        <p className="muted assessment-meta">
          Owner {assessment.owner_name} · created {formatDate(assessment.created_at)}
        </p>
      </div>

      {!assessment.authorization_confirmed ? (
        <Notice tone="warning">
          Authorization is not confirmed. Scans are blocked until you confirm it in{" "}
          <Link to="settings">Settings</Link>.
        </Notice>
      ) : null}
      {assessment.status === "archived" ? (
        <Notice tone="info">
          This assessment is archived. Scans and scope edits are blocked.
        </Notice>
      ) : null}

      <nav className="assessment-tabs" aria-label="Assessment sections">
        {TABS.map((tab) => (
          <NavLink key={tab.to} to={tab.to} className="assessment-tab">
            {tab.label}
          </NavLink>
        ))}
      </nav>

      <Outlet context={{ assessment } satisfies AssessmentOutletContext} />
    </div>
  );
}

export interface AssessmentOutletContext {
  assessment: AssessmentOut;
}

export function useAssessment(): AssessmentOut {
  return useOutletContext<AssessmentOutletContext>().assessment;
}
