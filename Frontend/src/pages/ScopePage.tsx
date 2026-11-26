import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { formatDate, labelize } from "../lib/format";
import { keys } from "../lib/keys";
import {
  SCAN_TOOLS,
  type ScopeCheckResponse,
  type ScopeKind,
  type ScanTool,
} from "../lib/types";
import { useAssessment } from "../components/AssessmentLayout";
import { InfoTip } from "../components/InfoTip";
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
} from "../components/ui";
import { useToast } from "../state/toast";

const SCOPE_KINDS: ScopeKind[] = ["host", "ip", "cidr", "url_prefix", "port"];

export function ScopePage() {
  const assessment = useAssessment();
  const queryClient = useQueryClient();
  const toast = useToast();
  const archived = assessment.status === "archived";

  const [kind, setKind] = useState<ScopeKind>("host");
  const [value, setValue] = useState("");
  const [inScope, setInScope] = useState(true);
  const [note, setNote] = useState("");

  const [checkTarget, setCheckTarget] = useState(
    assessment.target_base_url ?? assessment.target_name,
  );
  const [checkTool, setCheckTool] = useState<ScanTool>("http_checks");
  const [checkPorts, setCheckPorts] = useState("");
  const [checkResult, setCheckResult] = useState<ScopeCheckResponse | null>(null);

  const list = useQuery({
    queryKey: keys.scope(assessment.id),
    queryFn: () => api.scope.list(assessment.id),
  });

  const create = useMutation({
    mutationFn: () =>
      api.scope.create(assessment.id, {
        kind,
        value: value.trim(),
        in_scope: inScope,
        note: note.trim() || null,
      }),
    onSuccess: () => {
      setValue("");
      setNote("");
      toast.push("Scope item added.", "success");
      void queryClient.invalidateQueries({ queryKey: keys.scope(assessment.id) });
      void queryClient.invalidateQueries({ queryKey: keys.audit(assessment.id) });
    },
  });

  const remove = useMutation({
    mutationFn: (itemId: number) => api.scope.remove(assessment.id, itemId),
    onSuccess: () => {
      toast.push("Scope item removed.", "success");
      void queryClient.invalidateQueries({ queryKey: keys.scope(assessment.id) });
    },
  });

  const check = useMutation({
    mutationFn: () =>
      api.scope.check(assessment.id, {
        target: checkTarget.trim(),
        tool: checkTool,
        ports: parsePorts(checkPorts),
      }),
    onSuccess: (result) => setCheckResult(result),
  });

  function addItem(event: FormEvent) {
    event.preventDefault();
    if (!value.trim()) return;
    create.mutate();
  }

  return (
    <div className="stack-lg">
      <PageHeader
        title="Scope"
        description="Allowlist every host, IP, CIDR, URL prefix or port. Out-of-scope rules win."
      />

      {!assessment.authorization_confirmed ? (
        <Card title="Authorization required">
          <p>
            Scans stay blocked until the signed authorization is recorded. Choose
            the authorization file in Settings; it is confirmed automatically.
          </p>
          <Link to="../settings" className="btn btn-primary">
            Add authorization file
          </Link>
        </Card>
      ) : null}

      <div className="two-col two-col-wide">
        <Card
          title="Add scope item"
          help="Every scan target must match an in-scope rule. Out-of-scope rules always win. Start with the target host and its URL prefix."
        >
          {archived ? (
            <Notice tone="warning">
              Archived assessments cannot change scope. Unarchive in Settings first.
            </Notice>
          ) : (
            <form onSubmit={addItem} className="stack">
              <div className="form-grid">
                <Field
                  label="Kind"
                  help="How the value is interpreted: host, IP, CIDR range, URL prefix or port. Example: host for a DNS name."
                >
                  <select
                    value={kind}
                    onChange={(event) => setKind(event.target.value as ScopeKind)}
                  >
                    {SCOPE_KINDS.map((option) => (
                      <option key={option} value={option}>
                        {labelize(option)}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field
                  label="Value"
                  help="The exact host, IP, CIDR, URL prefix or port to allow. Example: target or http://target:3000/."
                >
                  <input
                    required
                    maxLength={2048}
                    value={value}
                    onChange={(event) => setValue(event.target.value)}
                    placeholder={
                      kind === "cidr"
                        ? "10.0.0.0/24"
                        : kind === "port"
                          ? "443"
                          : kind === "url_prefix"
                            ? "http://target:3000/"
                            : "target"
                    }
                  />
                </Field>
              </div>
              <Field
                label="Note"
                help="Why this rule exists or who approved it. Example: Authorized staging host from the letter."
              >
                <input
                  maxLength={500}
                  value={note}
                  onChange={(event) => setNote(event.target.value)}
                />
              </Field>
              <label className="check-row">
                <input
                  type="checkbox"
                  aria-label="In scope"
                  checked={inScope}
                  onChange={(event) => setInScope(event.target.checked)}
                />
                <span>In scope (uncheck to add an explicit exclusion)</span>
                <InfoTip label="Scope direction">
                  In-scope rules allow a target. Out-of-scope rules always win.
                  Example: uncheck to exclude a shared host.
                </InfoTip>
              </label>
              <Button type="submit" disabled={create.isPending}>
                {create.isPending ? "Adding…" : "Add item"}
              </Button>
              {create.isError ? <ErrorNotice error={create.error} /> : null}
            </form>
          )}
        </Card>

        <Card
          title="Dry-run scope check"
          help="Test a target against the current rules before running a scan. This is audited and changes nothing."
        >
          <form
            className="stack"
            onSubmit={(event) => {
              event.preventDefault();
              check.mutate();
            }}
          >
            <Field
              label="Target"
              help="The exact target you plan to scan. Example: http://target:3000/."
            >
              <input
                required
                maxLength={2048}
                value={checkTarget}
                onChange={(event) => setCheckTarget(event.target.value)}
              />
            </Field>
            <div className="form-grid">
              <Field
                label="Tool"
                help="Scope rules can differ by tool. Choose the tool you will actually run. Example: http_checks."
              >
                <select
                  value={checkTool}
                  onChange={(event) =>
                    setCheckTool(event.target.value as ScanTool)
                  }
                >
                  {SCAN_TOOLS.map((tool) => (
                    <option key={tool} value={tool}>
                      {tool}
                    </option>
                  ))}
                </select>
              </Field>
              <Field
                label="Ports"
                hint="Optional, comma-separated"
                help="Check specific ports as part of the scope decision. Example: 80, 443."
              >
                <input
                  value={checkPorts}
                  onChange={(event) => setCheckPorts(event.target.value)}
                  placeholder="80, 443"
                />
              </Field>
            </div>
            <Button type="submit" variant="secondary" disabled={check.isPending}>
              {check.isPending ? "Checking…" : "Check target"}
            </Button>
          </form>
          {check.isError ? <ErrorNotice error={check.error} /> : null}
          {checkResult ? (
            <div className="check-result">
              <p>
                {checkResult.allowed ? (
                  <Badge tone="success">Allowed</Badge>
                ) : (
                  <Badge tone="error">Blocked</Badge>
                )}
              </p>
              <CheckList title="Reasons" items={checkResult.reasons} />
              <CheckList
                title="Resolved IPs"
                items={checkResult.resolved_ips}
                mono
              />
              <CheckList title="Matched rules" items={checkResult.matched_rules} />
              <CheckList
                title="ZAP context include"
                items={checkResult.zap_context_include}
                mono
              />
              <CheckList
                title="ZAP context exclude"
                items={checkResult.zap_context_exclude}
                mono
              />
            </div>
          ) : null}
        </Card>
      </div>

      <Card title="Scope rules">
        {list.isLoading ? <Loading /> : null}
        {list.isError ? (
          <ErrorNotice error={list.error} onRetry={() => void list.refetch()} />
        ) : null}
        {list.data && list.data.length === 0 ? (
          <EmptyState
            title="No scope items"
            description="Add at least the target host and URL prefix before scanning."
          />
        ) : null}
        {list.data && list.data.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Kind</th>
                  <th>Value</th>
                  <th>Direction</th>
                  <th>Note</th>
                  <th>Added</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {list.data.map((item) => (
                  <tr key={item.id}>
                    <td>{labelize(item.kind)}</td>
                    <td className="mono">{item.value}</td>
                    <td>
                      {item.in_scope ? (
                        <Badge tone="success">In scope</Badge>
                      ) : (
                        <Badge tone="error">Out of scope</Badge>
                      )}
                    </td>
                    <td>{item.note ?? "—"}</td>
                    <td>{formatDate(item.created_at)}</td>
                    <td className="cell-actions">
                      <Button
                        variant="danger"
                        disabled={archived || remove.isPending}
                        onClick={() => {
                          if (
                            window.confirm(
                              `Remove scope item "${item.value}"?`,
                            )
                          ) {
                            remove.mutate(item.id);
                          }
                        }}
                      >
                        Remove
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
        {remove.isError ? <ErrorNotice error={remove.error} /> : null}
      </Card>
    </div>
  );
}

function parsePorts(text: string): number[] {
  return text
    .split(",")
    .map((part) => Number(part.trim()))
    .filter((value) => Number.isInteger(value) && value > 0 && value <= 65535);
}

function CheckList({
  title,
  items,
  mono = false,
}: {
  title: string;
  items: string[];
  mono?: boolean;
}) {
  if (items.length === 0) return null;
  return (
    <div>
      <strong className="tiny">{title}</strong>
      <ul className={`plain-list ${mono ? "mono" : ""}`}>
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  );
}
