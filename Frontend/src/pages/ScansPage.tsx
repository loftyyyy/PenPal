import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, formatApiError, saveBlob } from "../lib/api";
import { formatDate, formatDuration } from "../lib/format";
import { keys } from "../lib/keys";
import {
  SCAN_PROFILES,
  SCAN_TOOLS,
  SCAN_STATUSES,
  type ScanOut,
  type ScanTool,
} from "../lib/types";
import { useAssessment } from "../components/AssessmentLayout";
import {
  Button,
  Card,
  EmptyState,
  ErrorNotice,
  Field,
  Loading,
  Notice,
  PageHeader,
  Pagination,
  ProgressBar,
  StatusBadge,
} from "../components/ui";
import { useToast } from "../state/toast";

function isActive(scan: ScanOut | undefined): boolean {
  return scan?.status === "queued" || scan?.status === "running";
}

export function ScansPage() {
  const assessment = useAssessment();
  const queryClient = useQueryClient();
  const toast = useToast();
  const archived = assessment.status === "archived";

  const [tool, setTool] = useState<ScanTool>("nmap");
  const [profile, setProfile] = useState(SCAN_PROFILES.nmap[0] ?? "quick");
  const [target, setTarget] = useState(
    assessment.target_base_url ?? assessment.target_name,
  );
  const [ports, setPorts] = useState("");
  const [lockout, setLockout] = useState(false);

  const [filterStatus, setFilterStatus] = useState("");
  const [filterTool, setFilterTool] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [activeScanId, setActiveScanId] = useState<number | null>(null);

  const listParams = {
    page,
    page_size: pageSize,
    ...(filterStatus ? { status: filterStatus } : {}),
    ...(filterTool ? { tool: filterTool } : {}),
  };

  const list = useQuery({
    queryKey: keys.scans(assessment.id, listParams),
    queryFn: () => api.scans.list(assessment.id, listParams),
  });

  const detail = useQuery({
    queryKey: keys.scan(activeScanId ?? 0),
    queryFn: () => api.scans.get(activeScanId!),
    enabled: activeScanId !== null,
    refetchInterval: (query) =>
      isActive(query.state.data) ? 1500 : false,
  });

  useEffect(() => {
    if (activeScanId === null || !detail.data) return;
    if (detail.data.status === "queued" || detail.data.status === "running") return;
    void queryClient.invalidateQueries({ queryKey: ["scans", assessment.id] });
    void queryClient.invalidateQueries({ queryKey: ["recon", assessment.id] });
    void queryClient.invalidateQueries({ queryKey: ["dashboard", assessment.id] });
    void queryClient.invalidateQueries({ queryKey: ["findings", assessment.id] });
    setActiveScanId(null);
    toast.push(`Scan ${detail.data.status}.`, detail.data.status === "completed" ? "success" : "error");
  }, [activeScanId, detail.data, assessment.id, queryClient, toast]);

  function changeTool(next: ScanTool) {
    setTool(next);
    setProfile(SCAN_PROFILES[next][0] ?? "default");
    setLockout(false);
  }

  const create = useMutation({
    mutationFn: () =>
      api.scans.create(assessment.id, {
        tool,
        profile,
        target: target.trim(),
        ports: parsePorts(ports),
        confirm_lockout_test:
          tool === "http_checks" && profile === "auth_limited" ? lockout : false,
      }),
    onSuccess: (result) => {
      toast.push(`Scan ${result.scan_id} queued.`, "success");
      setActiveScanId(result.scan_id);
      void queryClient.invalidateQueries({ queryKey: ["scans", assessment.id] });
    },
  });

  const cancel = useMutation({
    mutationFn: (scanId: number) => api.scans.cancel(scanId),
    onSuccess: () => {
      toast.push("Scan cancelled.", "success");
      void queryClient.invalidateQueries({ queryKey: ["scans", assessment.id] });
    },
  });

  const raw = useMutation({
    mutationFn: (scan: ScanOut) => api.scans.raw(scan.id),
    onSuccess: ({ blob, filename }) =>
      void saveBlob(blob, filename, "scan-raw.txt"),
    onError: (error) => toast.push(formatApiError(error), "error"),
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    create.mutate();
  }

  const current = detail.data;

  return (
    <div className="stack-lg">
      <PageHeader
        title="Scans"
        description="Run one scope-guarded tool at a time, then poll until it finishes."
      />

      <div className="two-col two-col-wide">
        <Card title="Request a scan">
          {archived ? (
            <Notice tone="warning">Archived assessments cannot run scans.</Notice>
          ) : (
            <form onSubmit={submit} className="stack">
              <div className="form-grid">
                <Field
                  label="Tool"
                  help="Pick what to run: Nmap for ports, dig/whois for DNS and ownership, WhatWeb/curl/http_checks for web behavior, ZAP for web scanning. Example: nmap."
                >
                  <select
                    value={tool}
                    onChange={(event) =>
                      changeTool(event.target.value as ScanTool)
                    }
                  >
                    {SCAN_TOOLS.map((option) => (
                      <option key={option} value={option}>
                        {option}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field
                  label="Profile"
                  help="Intensity preset for the chosen tool. Quick is fast and low noise; standard/full_tcp broaden coverage. Example: quick."
                >
                  <select
                    value={profile}
                    onChange={(event) => setProfile(event.target.value)}
                  >
                    {SCAN_PROFILES[tool].map((option) => (
                      <option key={option} value={option}>
                        {option}
                      </option>
                    ))}
                  </select>
                </Field>
              </div>
              <Field
                label="Target"
                help="Use a host or IP for Nmap, dig and whois. Use an absolute http(s) URL for ZAP, WhatWeb, curl and HTTP checks. Example: http://target:3000/."
                hint={
                  tool === "nmap" || tool === "dig" || tool === "whois"
                    ? "Host or IP. Nmap accepts host plus explicit port."
                    : "Absolute http(s) URL."
                }
              >
                <input
                  required
                  maxLength={2048}
                  value={target}
                  onChange={(event) => setTarget(event.target.value)}
                />
              </Field>
              {tool === "nmap" ? (
                <Field
                  label="Ports"
                  hint="Optional, comma-separated; empty uses the profile default."
                  help="Limit Nmap to specific ports. Example: 22, 80, 443. Leave empty to use the profile's default set."
                >
                  <input
                    value={ports}
                    onChange={(event) => setPorts(event.target.value)}
                    placeholder="22, 80, 443"
                  />
                </Field>
              ) : null}
              {tool === "http_checks" && profile === "auth_limited" ? (
                <label className="check-row">
                  <input
                    type="checkbox"
                    aria-label="Confirm the short lockout test"
                    checked={lockout}
                    onChange={(event) => setLockout(event.target.checked)}
                  />
                  I confirm the short lockout test against configured test accounts.
                </label>
              ) : null}
              <p className="muted tiny">
                Only one queued or running scan is allowed per assessment. A second
                request returns a conflict until the active scan finishes.
              </p>
              <Button type="submit" disabled={create.isPending}>
                {create.isPending ? "Queueing…" : "Queue scan"}
              </Button>
              {create.isError ? <ErrorNotice error={create.error} /> : null}
            </form>
          )}
        </Card>

        <Card title="Active scan">
          {!activeScanId ? (
            <EmptyState
              title="No active scan"
              description="Queued and running scans appear here with live progress."
            />
          ) : detail.isError ? (
            <ErrorNotice
              error={detail.error}
              onRetry={() => void detail.refetch()}
            />
          ) : !current ? (
            <Loading label="Loading scan…" />
          ) : (
            <div className="stack">
              <div className="row-between">
                <strong>
                  #{current.id} · {current.tool} / {current.profile}
                </strong>
                <StatusBadge status={current.status} />
              </div>
              <p className="mono tiny break-all">{current.target}</p>
              <ProgressBar value={current.progress} />
              <p className="muted tiny">
                {current.progress}% · started {formatDate(current.started_at)}
              </p>
              {current.error ? (
                <Notice tone="error">{current.error}</Notice>
              ) : null}
              <div className="row-actions">
                <Button
                  variant="secondary"
                  onClick={() => setActiveScanId(null)}
                >
                  Stop following
                </Button>
                {isActive(current) ? (
                  <Button
                    variant="danger"
                    disabled={cancel.isPending}
                    onClick={() => cancel.mutate(current.id)}
                  >
                    Cancel scan
                  </Button>
                ) : null}
              </div>
            </div>
          )}
          {cancel.isError ? <ErrorNotice error={cancel.error} /> : null}
        </Card>
      </div>

      <Card
        title="Scan history"
        actions={
          <div className="row-actions">
            <select
              aria-label="Filter by status"
              value={filterStatus}
              onChange={(event) => {
                setFilterStatus(event.target.value);
                setPage(1);
              }}
            >
              <option value="">All statuses</option>
              {SCAN_STATUSES.map((status) => (
                <option key={status} value={status}>
                  {status}
                </option>
              ))}
            </select>
            <select
              aria-label="Filter by tool"
              value={filterTool}
              onChange={(event) => {
                setFilterTool(event.target.value);
                setPage(1);
              }}
            >
              <option value="">All tools</option>
              {SCAN_TOOLS.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </div>
        }
      >
        {list.isLoading ? <Loading /> : null}
        {list.isError ? (
          <ErrorNotice error={list.error} onRetry={() => void list.refetch()} />
        ) : null}
        {list.data && list.data.items.length === 0 ? (
          <EmptyState title="No scans match these filters" />
        ) : null}
        {list.data && list.data.items.length > 0 ? (
          <>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Tool / profile</th>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Progress</th>
                    <th>Duration</th>
                    <th>Started</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {list.data.items.map((scan) => (
                    <tr key={scan.id}>
                      <td className="mono">#{scan.id}</td>
                      <td>
                        {scan.tool}
                        <div className="cell-sub muted">{scan.profile}</div>
                      </td>
                      <td className="mono break-all">{scan.target}</td>
                      <td>
                        <StatusBadge status={scan.status} />
                        {scan.error ? (
                          <div className="cell-sub text-error">{scan.error}</div>
                        ) : null}
                      </td>
                      <td>
                        <ProgressBar value={scan.progress} />
                      </td>
                      <td>{formatDuration(scan.duration_seconds)}</td>
                      <td>{formatDate(scan.started_at)}</td>
                      <td className="cell-actions">
                        {isActive(scan) ? (
                          <>
                            <Button
                              variant="secondary"
                              onClick={() => setActiveScanId(scan.id)}
                            >
                              Follow
                            </Button>
                            <Button
                              variant="danger"
                              onClick={() => cancel.mutate(scan.id)}
                            >
                              Cancel
                            </Button>
                          </>
                        ) : null}
                        {scan.has_raw_output ? (
                          <Button
                            variant="ghost"
                            disabled={raw.isPending}
                            onClick={() => raw.mutate(scan)}
                          >
                            Raw
                          </Button>
                        ) : null}
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

function parsePorts(text: string): number[] {
  return text
    .split(",")
    .map((part) => Number(part.trim()))
    .filter((value) => Number.isInteger(value) && value > 0 && value <= 65535);
}
