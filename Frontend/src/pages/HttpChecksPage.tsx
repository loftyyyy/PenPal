import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { ApiError, api } from "../lib/api";
import { formatDate } from "../lib/format";
import { keys } from "../lib/keys";
import type {
  AccessRule,
  HttpCheckConfigIn,
  HttpCheckLimits,
  LoginSpec,
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
} from "../components/ui";
import { useToast } from "../state/toast";

const DEFAULT_LIMITS: HttpCheckLimits = {
  max_requests: 200,
  max_rps: 2,
  max_login_attempts: 5,
  min_login_interval_seconds: 1,
  max_redirects: 3,
};

const DEFAULT_LOGIN: LoginSpec = {
  url: "/login",
  method: "POST",
  content_type: "form",
  username_field: "username",
  password_field: "password",
  success_status: 200,
  success_redirect: null,
  success_regex: null,
  csrf_regex: null,
};

function newRule(): AccessRule {
  return {
    path: "/admin",
    method: "GET",
    allowed_roles: ["admin"],
    id_template: false,
    sample_ids: [],
  };
}

function splitList(text: string): string[] {
  return text
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function CsvInput({
  id,
  value,
  onChange,
  maxItems,
  placeholder,
  ariaLabel,
}: {
  id?: string;
  value: string[];
  onChange: (value: string[]) => void;
  maxItems?: number;
  placeholder?: string;
  ariaLabel?: string;
}) {
  const normalized = value.join("\u0000");
  const [text, setText] = useState(value.join(", "));
  const [focused, setFocused] = useState(false);

  useEffect(() => {
    if (!focused) setText(value.join(", "));
  }, [normalized, focused]);

  return (
    <input
      id={id}
      value={text}
      aria-label={ariaLabel}
      placeholder={placeholder}
      onFocus={() => setFocused(true)}
      onBlur={() => {
        setFocused(false);
        setText(splitList(text).join(", "));
      }}
      onChange={(event) => {
        const next = event.target.value;
        setText(next);
        const parsed = splitList(next);
        onChange(maxItems ? parsed.slice(0, maxItems) : parsed);
      }}
    />
  );
}

export function HttpChecksPage() {
  const assessment = useAssessment();
  const queryClient = useQueryClient();
  const toast = useToast();
  const archived = assessment.status === "archived";

  const configQuery = useQuery({
    queryKey: keys.httpConfig(assessment.id),
    queryFn: () => api.httpChecks.getConfig(assessment.id),
    retry: false,
  });

  const configMissing =
    configQuery.error instanceof ApiError && configQuery.error.status === 404;

  const [loginEnabled, setLoginEnabled] = useState(false);
  const [login, setLogin] = useState<LoginSpec>(DEFAULT_LOGIN);
  const [accessRules, setAccessRules] = useState<AccessRule[]>([]);
  const [roles, setRoles] = useState<string[]>(["staff", "admin"]);
  const [limits, setLimits] = useState<HttpCheckLimits>(DEFAULT_LIMITS);

  useEffect(() => {
    const config = configQuery.data;
    if (!config) return;
    setLoginEnabled(config.login !== null);
    setLogin(config.login ?? DEFAULT_LOGIN);
    setAccessRules(config.access_rules);
    setRoles(config.roles);
    setLimits(config.limits);
  }, [configQuery.data]);

  const saveConfig = useMutation({
    mutationFn: (body: HttpCheckConfigIn) =>
      api.httpChecks.putConfig(assessment.id, body),
    onSuccess: () => {
      toast.push("HTTP check configuration saved.", "success");
      void queryClient.invalidateQueries({
        queryKey: keys.httpConfig(assessment.id),
      });
      void queryClient.invalidateQueries({ queryKey: keys.audit(assessment.id) });
    },
  });

  function save(event: FormEvent) {
    event.preventDefault();
    saveConfig.mutate({
      login: loginEnabled ? login : null,
      access_rules: accessRules.map((rule) => ({
        ...rule,
        path: rule.path.trim(),
        allowed_roles: rule.allowed_roles.filter(Boolean),
        sample_ids: rule.sample_ids.filter(Boolean),
      })),
      roles,
      limits,
    });
  }

  const accountsQuery = useQuery({
    queryKey: keys.testAccounts(assessment.id),
    queryFn: () => api.httpChecks.listAccounts(assessment.id),
  });

  const [account, setAccount] = useState({
    role: "staff",
    username: "",
    password: "",
  });

  const addAccount = useMutation({
    mutationFn: () =>
      api.httpChecks.createAccount(assessment.id, {
        role: account.role.trim(),
        username: account.username.trim(),
        password: account.password,
      }),
    onSuccess: () => {
      setAccount({ role: account.role, username: "", password: "" });
      toast.push("Test account added. Password is write-only.", "success");
      void queryClient.invalidateQueries({
        queryKey: keys.testAccounts(assessment.id),
      });
    },
  });

  const deleteAccount = useMutation({
    mutationFn: (accountId: number) =>
      api.httpChecks.deleteAccount(assessment.id, accountId),
    onSuccess: () => {
      toast.push("Test account deleted.", "success");
      void queryClient.invalidateQueries({
        queryKey: keys.testAccounts(assessment.id),
      });
    },
  });

  function updateRule(index: number, patch: Partial<AccessRule>) {
    setAccessRules((current) =>
      current.map((rule, i) => (i === index ? { ...rule, ...patch } : rule)),
    );
  }

  return (
    <div className="stack-lg">
      <PageHeader
        title="HTTP checks"
        description="Configure login, roles and access rules for the in-process http_checks tool. Requests stay behind the scope guard."
        actions={
          <Link to="../scans" className="btn btn-secondary">
            Run via Scans
          </Link>
        }
      />

      {configQuery.isLoading ? <Loading label="Loading configuration…" /> : null}
      {configQuery.isError && !configMissing ? (
        <ErrorNotice
          error={configQuery.error}
          onRetry={() => void configQuery.refetch()}
        />
      ) : null}
      {configMissing ? (
        <Notice tone="info">
          No configuration yet. Saving creates it; until then, http_checks scans
          use defaults and fail if they need login details.
        </Notice>
      ) : null}

      <form onSubmit={save} className="stack-lg">
        <Card title="Login specification">
          <label className="check-row">
            <input
              type="checkbox"
              aria-label="Configure a login request"
              checked={loginEnabled}
              onChange={(event) => setLoginEnabled(event.target.checked)}
              disabled={archived}
            />
            Configure a login request for session and access-control checks
          </label>

          {loginEnabled ? (
            <div className="form-grid">
              <Field label="Login URL" hint="Relative to the target base URL, or absolute in scope.">
                <input
                  required
                  maxLength={2048}
                  value={login.url}
                  onChange={(event) =>
                    setLogin({ ...login, url: event.target.value })
                  }
                />
              </Field>
              <Field label="Content type">
                <select
                  value={login.content_type}
                  onChange={(event) =>
                    setLogin({
                      ...login,
                      content_type: event.target.value as LoginSpec["content_type"],
                    })
                  }
                >
                  <option value="form">Form</option>
                  <option value="json">JSON</option>
                </select>
              </Field>
              <Field label="Username field">
                <input
                  required
                  maxLength={100}
                  value={login.username_field}
                  onChange={(event) =>
                    setLogin({ ...login, username_field: event.target.value })
                  }
                />
              </Field>
              <Field label="Password field">
                <input
                  required
                  maxLength={100}
                  value={login.password_field}
                  onChange={(event) =>
                    setLogin({ ...login, password_field: event.target.value })
                  }
                />
              </Field>
              <Field label="Success status" hint="100–599, or empty">
                <input
                  type="number"
                  min={100}
                  max={599}
                  value={login.success_status ?? ""}
                  onChange={(event) =>
                    setLogin({
                      ...login,
                      success_status: event.target.value
                        ? Number(event.target.value)
                        : null,
                    })
                  }
                />
              </Field>
              <Field label="Success redirect" hint="Optional">
                <input
                  maxLength={2048}
                  value={login.success_redirect ?? ""}
                  onChange={(event) =>
                    setLogin({
                      ...login,
                      success_redirect: event.target.value || null,
                    })
                  }
                />
              </Field>
              <Field label="Success regex" hint="Optional">
                <input
                  maxLength={500}
                  value={login.success_regex ?? ""}
                  onChange={(event) =>
                    setLogin({
                      ...login,
                      success_regex: event.target.value || null,
                    })
                  }
                />
              </Field>
              <Field label="CSRF regex" hint="Optional">
                <input
                  maxLength={500}
                  value={login.csrf_regex ?? ""}
                  onChange={(event) =>
                    setLogin({
                      ...login,
                      csrf_regex: event.target.value || null,
                    })
                  }
                />
              </Field>
            </div>
          ) : null}
        </Card>

        <Card title="Access rules">
          <div className="stack">
            {accessRules.length === 0 ? (
              <EmptyState
                title="No access rules"
                description="Add paths whose access differs by role, for example /admin."
              />
            ) : null}
            {accessRules.map((rule, index) => (
              <div key={index} className="rule-row">
                <div className="form-grid">
                  <Field label="Path">
                    <input
                      required
                      maxLength={2048}
                      value={rule.path}
                      onChange={(event) =>
                        updateRule(index, { path: event.target.value })
                      }
                    />
                  </Field>
                  <Field label="Method">
                    <select
                      value={rule.method}
                      onChange={(event) =>
                        updateRule(index, {
                          method: event.target.value as AccessRule["method"],
                        })
                      }
                    >
                      <option value="GET">GET</option>
                      <option value="HEAD">HEAD</option>
                      <option value="OPTIONS">OPTIONS</option>
                    </select>
                  </Field>
                  <Field label="Allowed roles" hint="Comma-separated">
                    <CsvInput
                      value={rule.allowed_roles}
                      ariaLabel="Allowed roles"
                      onChange={(allowed_roles) =>
                        updateRule(index, { allowed_roles })
                      }
                    />
                  </Field>
                  <Field label="Sample IDs" hint="Comma-separated, max 5">
                    <CsvInput
                      value={rule.sample_ids}
                      maxItems={5}
                      ariaLabel="Sample IDs"
                      onChange={(sample_ids) =>
                        updateRule(index, { sample_ids })
                      }
                    />
                  </Field>
                </div>
                <div className="row-between">
                  <label className="check-row compact">
                    <input
                      type="checkbox"
                      aria-label="Path contains an ID template"
                      checked={rule.id_template}
                      onChange={(event) =>
                        updateRule(index, { id_template: event.target.checked })
                      }
                    />
                    Path contains an ID template
                  </label>
                  <Button
                    variant="danger"
                    onClick={() =>
                      setAccessRules((current) =>
                        current.filter((_, i) => i !== index),
                      )
                    }
                  >
                    Remove rule
                  </Button>
                </div>
              </div>
            ))}
            <Button
              variant="secondary"
              onClick={() => setAccessRules((current) => [...current, newRule()])}
            >
              Add access rule
            </Button>
          </div>
        </Card>

        <Card title="Roles and limits">
          <div className="form-grid">
            <Field label="Roles" hint="Comma-separated, max 10">
              <CsvInput
                value={roles}
                maxItems={10}
                ariaLabel="Roles"
                onChange={setRoles}
              />
            </Field>
            <Field label="Max requests" hint="1–500">
              <input
                type="number"
                min={1}
                max={500}
                value={limits.max_requests}
                onChange={(event) =>
                  setLimits({ ...limits, max_requests: Number(event.target.value) })
                }
              />
            </Field>
            <Field label="Max requests/second" hint=">0–10">
              <input
                type="number"
                min={0.1}
                max={10}
                step={0.1}
                value={limits.max_rps}
                onChange={(event) =>
                  setLimits({ ...limits, max_rps: Number(event.target.value) })
                }
              />
            </Field>
            <Field label="Max login attempts" hint="1–10">
              <input
                type="number"
                min={1}
                max={10}
                value={limits.max_login_attempts}
                onChange={(event) =>
                  setLimits({
                    ...limits,
                    max_login_attempts: Number(event.target.value),
                  })
                }
              />
            </Field>
            <Field label="Min login interval" hint="0–10 seconds">
              <input
                type="number"
                min={0}
                max={10}
                step={0.1}
                value={limits.min_login_interval_seconds}
                onChange={(event) =>
                  setLimits({
                    ...limits,
                    min_login_interval_seconds: Number(event.target.value),
                  })
                }
              />
            </Field>
            <Field label="Max redirects" hint="0–3">
              <input
                type="number"
                min={0}
                max={3}
                value={limits.max_redirects}
                onChange={(event) =>
                  setLimits({ ...limits, max_redirects: Number(event.target.value) })
                }
              />
            </Field>
          </div>
        </Card>

        {saveConfig.isError ? <ErrorNotice error={saveConfig.error} /> : null}

        <div className="form-actions">
          <Button type="submit" disabled={archived || saveConfig.isPending}>
            {saveConfig.isPending ? "Saving…" : "Save configuration"}
          </Button>
        </div>
      </form>

      <Card title="Test accounts">
        <p className="muted tiny">
          Passwords are write-only and never returned. Use test accounts only.
        </p>
        {accountsQuery.isLoading ? <Loading /> : null}
        {accountsQuery.isError ? (
          <ErrorNotice
            error={accountsQuery.error}
            onRetry={() => void accountsQuery.refetch()}
          />
        ) : null}
        {accountsQuery.data && accountsQuery.data.length === 0 ? (
          <EmptyState title="No test accounts" />
        ) : null}
        {accountsQuery.data && accountsQuery.data.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Role</th>
                  <th>Username</th>
                  <th>Created</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {accountsQuery.data.map((item) => (
                  <tr key={item.id}>
                    <td>{item.role}</td>
                    <td className="mono">{item.username}</td>
                    <td>{formatDate(item.created_at)}</td>
                    <td className="cell-actions">
                      <Button
                        variant="danger"
                        disabled={archived || deleteAccount.isPending}
                        onClick={() => deleteAccount.mutate(item.id)}
                      >
                        Delete
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}

        <form
          className="inline-form"
          onSubmit={(event) => {
            event.preventDefault();
            addAccount.mutate();
          }}
        >
          <input
            required
            maxLength={50}
            aria-label="Account role"
            placeholder="Role (staff)"
            value={account.role}
            onChange={(event) =>
              setAccount({ ...account, role: event.target.value })
            }
          />
          <input
            required
            maxLength={200}
            aria-label="Account username"
            placeholder="Username"
            value={account.username}
            onChange={(event) =>
              setAccount({ ...account, username: event.target.value })
            }
          />
          <input
            required
            maxLength={200}
            type="password"
            aria-label="Account password"
            placeholder="Password"
            value={account.password}
            onChange={(event) =>
              setAccount({ ...account, password: event.target.value })
            }
          />
          <Button type="submit" disabled={archived || addAccount.isPending}>
            {addAccount.isPending ? "Adding…" : "Add test account"}
          </Button>
        </form>
        {addAccount.isError ? <ErrorNotice error={addAccount.error} /> : null}
        {deleteAccount.isError ? (
          <ErrorNotice error={deleteAccount.error} />
        ) : null}
      </Card>
    </div>
  );
}
