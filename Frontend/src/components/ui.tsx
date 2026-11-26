import {
  cloneElement,
  isValidElement,
  useId,
  type ButtonHTMLAttributes,
  type ReactElement,
  type ReactNode,
} from "react";
import type { Severity, VerificationStatus } from "../lib/types";
import { labelize } from "../lib/format";
import { formatApiError } from "../lib/api";

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <h1>{title}</h1>
        {description ? <p className="page-description">{description}</p> : null}
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </header>
  );
}

export function Button({
  variant = "primary",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "ghost" | "danger";
}) {
  return (
    <button
      type="button"
      className={`btn btn-${variant} ${className}`.trim()}
      {...props}
    />
  );
}

export function Card({
  title,
  actions,
  children,
  className = "",
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`card ${className}`.trim()}>
      {title || actions ? (
        <div className="card-header">
          {title ? <h2>{title}</h2> : <span />}
          {actions ? <div className="card-actions">{actions}</div> : null}
        </div>
      ) : null}
      {children}
    </section>
  );
}

export function Field({
  label,
  hint,
  error,
  children,
  className = "",
}: {
  label: string;
  hint?: ReactNode;
  error?: string | null;
  children: ReactNode;
  className?: string;
}) {
  const generatedId = useId();
  const childProps =
    isValidElement(children)
      ? (children as ReactElement<{ id?: string }>).props
      : null;
  const childId = childProps?.id ?? generatedId;
  const control =
    isValidElement(children) && childProps && !childProps.id
      ? cloneElement(children as ReactElement<{ id?: string }>, {
          id: childId,
        })
      : children;

  return (
    <div className={`field ${className}`.trim()}>
      <label className="field-label" htmlFor={childId}>
        {label}
      </label>
      {control}
      {hint ? <span className="field-hint">{hint}</span> : null}
      {error ? (
        <span className="field-error" role="alert">
          {error}
        </span>
      ) : null}
    </div>
  );
}

export type BadgeTone =
  | "neutral"
  | "info"
  | "success"
  | "warning"
  | "error"
  | "critical"
  | "high"
  | "medium"
  | "low";

export function Badge({
  tone = "neutral",
  children,
}: {
  tone?: BadgeTone;
  children: ReactNode;
}) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

export function SeverityBadge({ severity }: { severity: Severity | null }) {
  if (!severity) return <span className="muted">—</span>;
  return <Badge tone={severity}>{labelize(severity)}</Badge>;
}

export function VerificationBadge({ status }: { status: VerificationStatus }) {
  const tone: BadgeTone =
    status === "confirmed"
      ? "success"
      : status === "false_positive"
        ? "error"
        : status === "needs_retest"
          ? "warning"
          : "neutral";
  return <Badge tone={tone}>{labelize(status)}</Badge>;
}

export function StatusBadge({ status }: { status: string }) {
  const tone: BadgeTone =
    status === "completed" || status === "ready" || status === "approved"
      ? "success"
      : status === "failed" || status === "cancelled"
        ? "error"
        : status === "running" || status === "in_progress"
          ? "info"
          : status === "queued" || status === "pending"
            ? "warning"
            : "neutral";
  return <Badge tone={tone}>{labelize(status)}</Badge>;
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="state state-loading" role="status">
      <span className="spinner" aria-hidden="true" />
      {label}
    </div>
  );
}

export function ErrorNotice({
  error,
  onRetry,
}: {
  error: unknown;
  onRetry?: () => void;
}) {
  return (
    <div className="notice notice-error" role="alert">
      <span>{formatApiError(error)}</span>
      {onRetry ? (
        <Button variant="secondary" onClick={onRetry}>
          Retry
        </Button>
      ) : null}
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="state state-empty">
      <h3>{title}</h3>
      {description ? <p>{description}</p> : null}
      {action}
    </div>
  );
}

export function Notice({
  tone = "info",
  children,
}: {
  tone?: "info" | "warning" | "error" | "success";
  children: ReactNode;
}) {
  return <div className={`notice notice-${tone}`}>{children}</div>;
}

export function Pagination({
  page,
  pageSize,
  total,
  onPage,
  onPageSize,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPage: (page: number) => void;
  onPageSize?: (size: number) => void;
}) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <nav className="pagination" aria-label="Pagination">
      <span className="muted">
        {total} item{total === 1 ? "" : "s"} · page {page} of {totalPages}
      </span>
      <div className="pagination-controls">
        {onPageSize ? (
          <label className="inline-field">
            <span>Per page</span>
            <select
              value={pageSize}
              onChange={(event) => onPageSize(Number(event.target.value))}
            >
              {[10, 20, 50, 100].map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </label>
        ) : null}
        <Button
          variant="secondary"
          disabled={page <= 1}
          onClick={() => onPage(page - 1)}
        >
          Previous
        </Button>
        <Button
          variant="secondary"
          disabled={page >= totalPages}
          onClick={() => onPage(page + 1)}
        >
          Next
        </Button>
      </div>
    </nav>
  );
}

export function Stat({
  label,
  value,
  hint,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
}) {
  return (
    <div className="stat">
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
      {hint ? <span className="stat-hint">{hint}</span> : null}
    </div>
  );
}

export function ProgressBar({
  value,
  tone,
}: {
  value: number;
  tone?: string;
}) {
  const clamped = Math.max(0, Math.min(100, value));
  return (
    <div
      className={`progress ${tone ? `progress-${tone}` : ""}`.trim()}
      role="progressbar"
      aria-valuenow={clamped}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <span style={{ width: `${clamped}%` }} />
    </div>
  );
}

export function DescriptionList({
  items,
}: {
  items: Array<{ label: string; value: ReactNode }>;
}) {
  return (
    <dl className="description-list">
      {items.map((item) => (
        <div key={item.label}>
          <dt>{item.label}</dt>
          <dd>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}
