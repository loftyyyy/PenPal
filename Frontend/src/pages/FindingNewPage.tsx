import { useState, type FormEvent } from "react";
import { useMutation } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import {
  FINDING_CATEGORIES,
  SEVERITIES,
  type FindingCategory,
  type ManualFindingCreate,
  type Severity,
} from "../lib/types";
import { useAssessment } from "../components/AssessmentLayout";
import {
  Button,
  Card,
  ErrorNotice,
  Field,
  PageHeader,
} from "../components/ui";
import { labelize } from "../lib/format";

export function FindingNewPage() {
  const assessment = useAssessment();
  const navigate = useNavigate();
  const [form, setForm] = useState({
    title: "",
    description: "",
    category: "uncategorized" as FindingCategory,
    severity: "medium" as Severity,
    affected_url: "",
    http_method: "",
    parameter: "",
    cwe: "",
    owasp_category: "",
  });

  function set<K extends keyof typeof form>(key: K, value: string) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  const mutation = useMutation({
    mutationFn: (body: ManualFindingCreate) =>
      api.findings.create(assessment.id, body),
    onSuccess: (finding) => navigate(`../findings/${finding.id}`, { replace: true }),
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    mutation.mutate({
      title: form.title.trim(),
      description: form.description.trim() || null,
      category: form.category,
      severity: form.severity,
      affected_url: form.affected_url.trim() || null,
      http_method: form.http_method.trim() || null,
      parameter: form.parameter.trim() || null,
      cwe: form.cwe.trim() || null,
      owasp_category: form.owasp_category.trim() || null,
    });
  }

  return (
    <div className="page page-narrow">
      <PageHeader
        title="Manual finding"
        description="Record something the tools did not detect. It still needs assessor verification."
      />
      <form onSubmit={submit} className="stack-lg">
        <Card title="Finding">
          <div className="form-grid">
            <Field label="Title" className="span-2">
              <input
                required
                maxLength={500}
                value={form.title}
                onChange={(event) => set("title", event.target.value)}
              />
            </Field>
            <Field label="Description" className="span-2">
              <textarea
                rows={5}
                maxLength={10000}
                value={form.description}
                onChange={(event) => set("description", event.target.value)}
              />
            </Field>
            <Field label="Category">
              <select
                value={form.category}
                onChange={(event) => set("category", event.target.value)}
              >
                {FINDING_CATEGORIES.map((category) => (
                  <option key={category} value={category}>
                    {labelize(category)}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Tool severity" hint="Advisory until confirmed.">
              <select
                value={form.severity}
                onChange={(event) => set("severity", event.target.value)}
              >
                {SEVERITIES.map((severity) => (
                  <option key={severity} value={severity}>
                    {labelize(severity)}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Affected URL" className="span-2">
              <input
                maxLength={2048}
                value={form.affected_url}
                onChange={(event) => set("affected_url", event.target.value)}
                placeholder="/account/edit?id=2"
              />
            </Field>
            <Field label="HTTP method">
              <input
                maxLength={20}
                value={form.http_method}
                onChange={(event) => set("http_method", event.target.value)}
                placeholder="GET"
              />
            </Field>
            <Field label="Parameter">
              <input
                maxLength={200}
                value={form.parameter}
                onChange={(event) => set("parameter", event.target.value)}
              />
            </Field>
            <Field label="CWE">
              <input
                maxLength={50}
                value={form.cwe}
                onChange={(event) => set("cwe", event.target.value)}
                placeholder="CWE-639"
              />
            </Field>
            <Field label="OWASP category">
              <input
                maxLength={100}
                value={form.owasp_category}
                onChange={(event) => set("owasp_category", event.target.value)}
                placeholder="A01:2021 Broken Access Control"
              />
            </Field>
          </div>
        </Card>

        {mutation.isError ? <ErrorNotice error={mutation.error} /> : null}

        <div className="form-actions">
          <Button variant="secondary" onClick={() => navigate("../findings")}>
            Cancel
          </Button>
          <Button type="submit" disabled={mutation.isPending}>
            {mutation.isPending ? "Saving…" : "Create finding"}
          </Button>
        </div>
      </form>
    </div>
  );
}
