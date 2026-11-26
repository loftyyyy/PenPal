import { useState, type FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import type { AssessmentCreate, FindingCategory } from "../lib/types";
import { CategoryPicker } from "../components/CategoryPicker";
import {
  Button,
  Card,
  ErrorNotice,
  Field,
  PageHeader,
} from "../components/ui";
import { useToast } from "../state/toast";

export function AssessmentNewPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const toast = useToast();
  const [categories, setCategories] = useState<FindingCategory[]>([
    "authentication",
    "access_control",
    "injection",
    "session_management",
    "security_configuration",
  ]);
  const [form, setForm] = useState({
    name: "",
    description: "",
    target_name: "",
    target_base_url: "",
    target_description: "",
    owner_name: "",
    authorization_reference: "",
    hosting_environment: "",
  });

  function set<K extends keyof typeof form>(key: K, value: string) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  const mutation = useMutation({
    mutationFn: (body: AssessmentCreate) => api.assessments.create(body),
    onSuccess: (assessment) => {
      void queryClient.invalidateQueries({ queryKey: ["assessments"] });
      toast.push("Assessment created. Add scope, then confirm authorization.", "success");
      navigate(`/assessments/${assessment.id}/scope`);
    },
  });

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    mutation.mutate({
      name: form.name.trim(),
      description: form.description.trim() || null,
      target_name: form.target_name.trim(),
      target_base_url: form.target_base_url.trim() || null,
      target_description: form.target_description.trim() || null,
      owner_name: form.owner_name.trim(),
      authorization_reference: form.authorization_reference.trim(),
      hosting_environment: form.hosting_environment.trim() || null,
      selected_categories: categories,
    });
  }

  return (
    <div className="page page-narrow">
      <PageHeader
        title="New assessment"
        description="Register the authorized target. Scans stay blocked until authorization is confirmed."
      />
      <form onSubmit={handleSubmit} className="stack-lg">
        <Card title="Assessment">
          <div className="form-grid">
            <Field label="Name" className="span-2">
              <input
                required
                maxLength={200}
                value={form.name}
                onChange={(event) => set("name", event.target.value)}
                placeholder="LSRS assessment"
              />
            </Field>
            <Field label="Description" className="span-2">
              <textarea
                rows={3}
                maxLength={5000}
                value={form.description}
                onChange={(event) => set("description", event.target.value)}
                placeholder="Scope, goals and constraints"
              />
            </Field>
          </div>
        </Card>

        <Card title="Target">
          <div className="form-grid">
            <Field label="Target name">
              <input
                required
                maxLength={200}
                value={form.target_name}
                onChange={(event) => set("target_name", event.target.value)}
                placeholder="Love & Styles Rental System"
              />
            </Field>
            <Field
              label="Base URL"
              hint="Absolute http(s) URL. Add the host to scope separately."
            >
              <input
                type="url"
                maxLength={2048}
                value={form.target_base_url}
                onChange={(event) => set("target_base_url", event.target.value)}
                placeholder="http://target:3000"
              />
            </Field>
            <Field label="Hosting environment">
              <input
                maxLength={200}
                value={form.hosting_environment}
                onChange={(event) =>
                  set("hosting_environment", event.target.value)
                }
                placeholder="Docker Compose internal network"
              />
            </Field>
            <Field label="Target description">
              <textarea
                rows={2}
                maxLength={5000}
                value={form.target_description}
                onChange={(event) =>
                  set("target_description", event.target.value)
                }
              />
            </Field>
          </div>
        </Card>

        <Card title="Authorization">
          <div className="form-grid">
            <Field label="Owner / authorizing person">
              <input
                required
                maxLength={200}
                value={form.owner_name}
                onChange={(event) => set("owner_name", event.target.value)}
              />
            </Field>
            <Field
              label="Authorization reference"
              hint="File name or reference to the signed authorization."
            >
              <input
                required
                maxLength={5000}
                value={form.authorization_reference}
                onChange={(event) =>
                  set("authorization_reference", event.target.value)
                }
                placeholder="signed-authorization-letter.pdf"
              />
            </Field>
          </div>
        </Card>

        <Card title="Categories">
          <CategoryPicker value={categories} onChange={setCategories} />
        </Card>

        {mutation.isError ? <ErrorNotice error={mutation.error} /> : null}

        <div className="form-actions">
          <Button variant="secondary" onClick={() => navigate("/assessments")}>
            Cancel
          </Button>
          <Button type="submit" disabled={mutation.isPending}>
            {mutation.isPending ? "Creating…" : "Create assessment"}
          </Button>
        </div>
      </form>
    </div>
  );
}
