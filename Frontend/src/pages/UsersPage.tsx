import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { formatDate, labelize } from "../lib/format";
import { keys } from "../lib/keys";
import type { Role, UserOut, UserUpdate } from "../lib/types";
import { useAuth } from "../state/auth";
import { useToast } from "../state/toast";
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
  Pagination,
} from "../components/ui";

export function UsersPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const toast = useToast();

  const [q, setQ] = useState("");
  const [role, setRole] = useState("");
  const [active, setActive] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);

  const params = {
    page,
    page_size: pageSize,
    ...(q ? { q } : {}),
    ...(role ? { role } : {}),
    ...(active ? { is_active: active === "active" } : {}),
  };

  const list = useQuery({
    queryKey: keys.users(params),
    queryFn: () => api.users.list(params),
    enabled: user?.role === "admin",
  });

  const health = useQuery({
    queryKey: ["health"],
    queryFn: () => api.health.status(),
    enabled: user?.role === "admin",
    refetchInterval: 60_000,
  });

  const dependencies = useQuery({
    queryKey: ["health-dependencies"],
    queryFn: () => api.health.dependencies(),
    enabled: user?.role === "admin",
    refetchInterval: 60_000,
  });

  const [createForm, setCreateForm] = useState({
    email: "",
    full_name: "",
    password: "",
    role: "assessor" as Role,
  });

  const create = useMutation({
    mutationFn: () =>
      api.users.create({
        email: createForm.email.trim(),
        full_name: createForm.full_name.trim(),
        password: createForm.password,
        role: createForm.role,
      }),
    onSuccess: () => {
      setCreateForm({ email: "", full_name: "", password: "", role: "assessor" });
      toast.push("User created.", "success");
      void queryClient.invalidateQueries({ queryKey: ["users"] });
    },
  });

  const [editing, setEditing] = useState<UserOut | null>(null);
  const [editForm, setEditForm] = useState({
    full_name: "",
    role: "assessor" as Role,
    is_active: true,
    password: "",
  });

  function startEdit(userToEdit: UserOut) {
    setEditing(userToEdit);
    setEditForm({
      full_name: userToEdit.full_name,
      role: userToEdit.role,
      is_active: userToEdit.is_active,
      password: "",
    });
  }

  const update = useMutation({
    mutationFn: ({ id, body }: { id: number; body: UserUpdate }) =>
      api.users.update(id, body),
    onSuccess: () => {
      toast.push("User updated.", "success");
      setEditing(null);
      void queryClient.invalidateQueries({ queryKey: ["users"] });
    },
  });

  if (user?.role !== "admin") {
    return (
      <div className="page">
        <PageHeader title="Users" />
        <Notice tone="warning">
          User management is restricted to administrators.
        </Notice>
      </div>
    );
  }

  return (
    <div className="page">
      <PageHeader
        title="Users"
        description="Admin and assessor accounts. Never remove the last active admin."
      />

      <div className="two-col two-col-wide">
        <Card title="Directory">
          <div className="filter-grid">
            <label className="inline-field span-2">
              <span>Search</span>
              <input
                type="search"
                value={q}
                onChange={(event) => {
                  setQ(event.target.value);
                  setPage(1);
                }}
                placeholder="Email or name"
              />
            </label>
            <label className="inline-field">
              <span>Role</span>
              <select
                value={role}
                onChange={(event) => {
                  setRole(event.target.value);
                  setPage(1);
                }}
              >
                <option value="">All</option>
                <option value="admin">Admin</option>
                <option value="assessor">Assessor</option>
              </select>
            </label>
            <label className="inline-field">
              <span>Active</span>
              <select
                value={active}
                onChange={(event) => {
                  setActive(event.target.value);
                  setPage(1);
                }}
              >
                <option value="">All</option>
                <option value="active">Active</option>
                <option value="inactive">Inactive</option>
              </select>
            </label>
          </div>

          {list.isLoading ? <Loading /> : null}
          {list.isError ? (
            <ErrorNotice error={list.error} onRetry={() => void list.refetch()} />
          ) : null}
          {list.data && list.data.items.length === 0 ? (
            <EmptyState title="No users match" />
          ) : null}
          {list.data && list.data.items.length > 0 ? (
            <>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Email</th>
                      <th>Role</th>
                      <th>Active</th>
                      <th>Created</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {list.data.items.map((item) => (
                      <tr key={item.id}>
                        <td>
                          {item.full_name}
                          {item.id === user.id ? (
                            <span className="muted tiny"> (you)</span>
                          ) : null}
                        </td>
                        <td className="mono">{item.email}</td>
                        <td>
                          <Badge tone={item.role === "admin" ? "info" : "neutral"}>
                            {labelize(item.role)}
                          </Badge>
                        </td>
                        <td>
                          {item.is_active ? (
                            <Badge tone="success">Active</Badge>
                          ) : (
                            <Badge tone="error">Inactive</Badge>
                          )}
                        </td>
                        <td>{formatDate(item.created_at)}</td>
                        <td className="cell-actions">
                          <Button
                            variant="secondary"
                            onClick={() => startEdit(item)}
                          >
                            Edit
                          </Button>
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

        <div className="stack">
          <Card
            title="System status"
            actions={
              health.data ? (
                <Badge tone={health.data.status === "ok" ? "success" : "warning"}>
                  {health.data.status}
                </Badge>
              ) : null
            }
          >
            {health.isError || dependencies.isError ? (
              <p className="muted tiny">
                Health endpoints are unavailable; assessment work is not blocked by
                this panel.
              </p>
            ) : null}
            {health.data ? (
              <p className="muted tiny">
                {health.data.service} v{health.data.version}
              </p>
            ) : null}
            {dependencies.data ? (
              <div className="stack">
                {dependencies.data.dependencies.map((dependency) => (
                  <div key={dependency.name} className="row-between">
                    <span className="mono tiny">{dependency.name}</span>
                    <span className="row-actions">
                      <span className="muted tiny">{dependency.detail}</span>
                      <Badge tone={dependency.ok ? "success" : "error"}>
                        {dependency.ok ? "OK" : "Bad"}
                      </Badge>
                    </span>
                  </div>
                ))}
              </div>
            ) : null}
            <p className="muted tiny">
              Tools and AI availability only; scans still enforce scope and
              authorization.
            </p>
          </Card>

          <Card title="Create user">
            <form
              className="stack"
              onSubmit={(event) => {
                event.preventDefault();
                create.mutate();
              }}
            >
              <Field label="Full name">
                <input
                  required
                  maxLength={200}
                  value={createForm.full_name}
                  onChange={(event) =>
                    setCreateForm({ ...createForm, full_name: event.target.value })
                  }
                />
              </Field>
              <Field label="Email">
                <input
                  type="email"
                  required
                  value={createForm.email}
                  onChange={(event) =>
                    setCreateForm({ ...createForm, email: event.target.value })
                  }
                />
              </Field>
              <Field
                label="Temporary password"
                hint="12–200 characters."
                help="Give the user this password out of band and ask them to change it. Example: a long unique passphrase."
              >
                <input
                  type="password"
                  required
                  minLength={12}
                  maxLength={200}
                  autoComplete="new-password"
                  value={createForm.password}
                  onChange={(event) =>
                    setCreateForm({ ...createForm, password: event.target.value })
                  }
                />
              </Field>
              <Field
                label="Role"
                help="Assessors do assessment work. Admins also manage users. Example: assessor."
              >
                <select
                  value={createForm.role}
                  onChange={(event) =>
                    setCreateForm({
                      ...createForm,
                      role: event.target.value as Role,
                    })
                  }
                >
                  <option value="assessor">Assessor</option>
                  <option value="admin">Admin</option>
                </select>
              </Field>
              <Button type="submit" disabled={create.isPending}>
                {create.isPending ? "Creating…" : "Create user"}
              </Button>
              {create.isError ? <ErrorNotice error={create.error} /> : null}
            </form>
          </Card>

          {editing ? (
            <Card
              title={`Edit ${editing.email}`}
              actions={
                <Button variant="ghost" onClick={() => setEditing(null)}>
                  Close
                </Button>
              }
            >
              <form
                className="stack"
                onSubmit={(event) => {
                  event.preventDefault();
                  const body: UserUpdate = {
                    full_name: editForm.full_name.trim(),
                    role: editForm.role,
                    is_active: editForm.is_active,
                  };
                  if (editForm.password) body.password = editForm.password;
                  update.mutate({ id: editing.id, body });
                }}
              >
                <Field label="Full name">
                  <input
                    required
                    maxLength={200}
                    value={editForm.full_name}
                    onChange={(event) =>
                      setEditForm({ ...editForm, full_name: event.target.value })
                    }
                  />
                </Field>
                <Field label="Role">
                  <select
                    value={editForm.role}
                    onChange={(event) =>
                      setEditForm({
                        ...editForm,
                        role: event.target.value as Role,
                      })
                    }
                  >
                    <option value="assessor">Assessor</option>
                    <option value="admin">Admin</option>
                  </select>
                </Field>
                <label className="check-row">
                  <input
                    type="checkbox"
                    aria-label="Account active"
                    checked={editForm.is_active}
                    onChange={(event) =>
                      setEditForm({ ...editForm, is_active: event.target.checked })
                    }
                  />
                  Active
                </label>
                <Field
                  label="New password"
                  hint="Leave empty to keep the current password. 12–200 characters."
                >
                  <input
                    type="password"
                    minLength={12}
                    maxLength={200}
                    autoComplete="new-password"
                    value={editForm.password}
                    onChange={(event) =>
                      setEditForm({ ...editForm, password: event.target.value })
                    }
                  />
                </Field>
                <div className="row-actions">
                  <Button type="submit" disabled={update.isPending}>
                    {update.isPending ? "Saving…" : "Save user"}
                  </Button>
                  <Button
                    variant="secondary"
                    onClick={() => setEditing(null)}
                  >
                    Cancel
                  </Button>
                </div>
                {update.isError ? <ErrorNotice error={update.error} /> : null}
              </form>
            </Card>
          ) : null}
        </div>
      </div>
    </div>
  );
}
