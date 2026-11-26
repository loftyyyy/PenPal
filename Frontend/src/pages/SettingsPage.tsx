import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { formatDate } from "../lib/format";
import { keys } from "../lib/keys";
import {
  ASSESSMENT_STATUSES,
  type AssessmentStatus,
  type AssessmentUpdate,
  type FindingCategory,
} from "../lib/types";
import { useAssessment } from "../components/AssessmentLayout";
import { CategoryPicker } from "../components/CategoryPicker";
import {
  Button,
  Card,
  DescriptionList,
  ErrorNotice,
  Field,
  Notice,
  PageHeader,
} from "../components/ui";
import { useToast } from "../state/toast";

const EDITABLE_STATUSES = ASSESSMENT_STATUSES.filter(
  (status) => status !== "archived",
);

export function SettingsPage() {
  const assessment = useAssessment();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const toast = useToast();
  const archived = assessment.status === "archived";

  const [form, setForm] = useState({
    name: assessment.name,
    description: assessment.description ?? "",
    target_name: assessment.target_name,
    target_base_url: assessment.target_base_url ?? "",
    target_description: assessment.target_description ?? "",
    owner_name: assessment.owner_name,
    authorization_reference: assessment.authorization_reference,
    hosting_environment: assessment.hosting_environment ?? "",
    status: assessment.status as AssessmentStatus,
  });
  const [categories, setCategories] = useState<FindingCategory[]>(
    assessment.selected_categories,
  );

  useEffect(() => {
    setForm({
      name: assessment.name,
      description: assessment.description ?? "",
      target_name: assessment.target_name,
      target_base_url: assessment.target_base_url ?? "",
      target_description: assessment.target_description ?? "",
      owner_name: assessment.owner_name,
      authorization_reference: assessment.authorization_reference,
      hosting_environment: assessment.hosting_environment ?? "",
      status: assessment.status,
    });
    setCategories(assessment.selected_categories);
  }, [assessment.id, assessment.updated_at, assessment]);

  function set<K extends keyof typeof form>(key: K, value: string) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  const save = useMutation({
    mutationFn: (body: AssessmentUpdate) =>
      api.assessments.update(assessment.id, body),
    onSuccess: () => {
      toast.push("Assessment updated.", "success");
      void queryClient.invalidateQueries({
        queryKey: keys.assessment(assessment.id),
      });
      void queryClient.invalidateQueries({ queryKey: ["assessments"] });
    },
  });

  const archive = useMutation({
    mutationFn: () => api.assessments.archive(assessment.id),
    onSuccess: () => {
      toast.push("Assessment archived. Scans and scope edits are blocked.", "success");
      void queryClient.invalidateQueries({
        queryKey: keys.assessment(assessment.id),
      });
      void queryClient.invalidateQueries({ queryKey: ["assessments"] });
    },
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    save.mutate({
      name: form.name.trim(),
      description: form.description.trim() || null,
      target_name: form.target_name.trim(),
      target_base_url: form.target_base_url.trim() || null,
      target_description: form.target_description.trim() || null,
      owner_name: form.owner_name.trim(),
      authorization_reference: form.authorization_reference.trim(),
      hosting_environment: form.hosting_environment.trim() || null,
      selected_categories: categories,
      status: form.status,
    });
  }

  return (
    <div className="stack-lg">
      <PageHeader
        title="Settings"
        description="Assessment metadata, authorization record and lifecycle status."
      />

      <Card title="Authorization record">
        <DescriptionList
          items={[
            {
              label: "Status",
              value: assessment.authorization_confirmed ? (
                <span className="text-success">Confirmed</span>
              ) : (
                <span className="text-warning">Not confirmed</span>
              ),
            },
            {
              label: "Confirmed at",
              value: formatDate(assessment.authorization_confirmed_at),
            },
            {
              label: "Confirmed by user",
              value: assessment.authorization_confirmed_by ?? "—",
            },
            { label: "Reference", value: assessment.authorization_reference },
          ]}
        />
        {!assessment.authorization_confirmed ? (
          <Notice tone="warning">
            Confirm authorization on the Scope page before scans can run.
          </Notice>
        ) : null}
      </Card>

      <form onSubmit={submit} className="stack-lg">
        <Card title="Metadata">
          <div className="form-grid">
            <Field label="Name" className="span-2">
              <input
                required
                maxLength={200}
                value={form.name}
                onChange={(event) => set("name", event.target.value)}
              />
            </Field>
            <Field label="Description" className="span-2">
              <textarea
                rows={3}
                maxLength={5000}
                value={form.description}
                onChange={(event) => set("description", event.target.value)}
              />
            </Field>
            <Field label="Target name">
              <input
                required
                maxLength={200}
                value={form.target_name}
                onChange={(event) => set("target_name", event.target.value)}
              />
            </Field>
            <Field label="Base URL">
              <input
                type="url"
                maxLength={2048}
                value={form.target_base_url}
                onChange={(event) => set("target_base_url", event.target.value)}
              />
            </Field>
            <Field label="Target description" className="span-2">
              <textarea
                rows={2}
                maxLength={5000}
                value={form.target_description}
                onChange={(event) =>
                  set("target_description", event.target.value)
                }
              />
            </Field>
            <Field label="Owner">
              <input
                required
                maxLength={200}
                value={form.owner_name}
                onChange={(event) => set("owner_name", event.target.value)}
              />
            </Field>
            <Field label="Hosting environment">
              <input
                maxLength={200}
                value={form.hosting_environment}
                onChange={(event) =>
                  set("hosting_environment", event.target.value)
                }
              />
            </Field>
            <Field label="Authorization reference" className="span-2">
              <input
                required
                maxLength={5000}
                value={form.authorization_reference}
                onChange={(event) =>
                  set("authorization_reference", event.target.value)
                }
              />
            </Field>
            <Field label="Status" hint="Archiving is done with the button below.">
              <select
                value={form.status === "archived" ? "completed" : form.status}
                onChange={(event) => set("status", event.target.value)}
                disabled={archived}
              >
                {EDITABLE_STATUSES.map((status) => (
                  <option key={status} value={status}>
                    {status.replaceAll("_", " ")}
                  </option>
                ))}
              </select>
            </Field>
          </div>
        </Card>

        <Card title="Categories">
          <CategoryPicker value={categories} onChange={setCategories} />
        </Card>

        {save.isError ? <ErrorNotice error={save.error} /> : null}

        <div className="form-actions">
          <Button type="submit" disabled={save.isPending || archived}>
            {save.isPending ? "Saving…" : "Save changes"}
          </Button>
        </div>
      </form>

      <Card title="Danger zone">
        {archived ? (
          <p className="muted">
            This assessment is archived. Its data remains available read-only.
          </p>
        ) : (
          <>
            <p>
              Archiving blocks further scans and scope edits. Results, findings and
              reports stay available.
            </p>
            <Button
              variant="danger"
              disabled={archive.isPending}
              onClick={() => {
                if (
                  window.confirm(
                    "Archive this assessment? Scans and scope edits will be blocked.",
                  )
                ) {
                  archive.mutate();
                }
              }}
            >
              {archive.isPending ? "Archiving…" : "Archive assessment"}
            </Button>
            {archive.isError ? <ErrorNotice error={archive.error} /> : null}
          </>
        )}
        <button
          type="button"
          className="text-link button-link"
          onClick={() => navigate("/assessments")}
        >
          Back to all assessments
        </button>
      </Card>
    </div>
  );
}
