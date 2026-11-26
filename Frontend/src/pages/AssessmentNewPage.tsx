import { useState, type FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import type { AssessmentCreate, FindingCategory } from "../lib/types";
import { CategoryPicker } from "../components/CategoryPicker";
import { FileDrop } from "../components/FileDrop";
import { InfoTip } from "../components/InfoTip";
import {
  Badge,
  Button,
  Card,
  ErrorNotice,
  Field,
  Notice,
  PageHeader,
} from "../components/ui";
import { useToast } from "../state/toast";

const DEFAULT_CATEGORIES: FindingCategory[] = [
  "authentication",
  "access_control",
  "injection",
  "session_management",
  "security_configuration",
];

export function AssessmentNewPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const toast = useToast();
  const [categories, setCategories] = useState<FindingCategory[]>(
    DEFAULT_CATEGORIES,
  );
  const [authorizationFile, setAuthorizationFile] = useState<File | null>(null);
  const [form, setForm] = useState({
    name: "",
    description: "",
    target_name: "",
    target_base_url: "",
    target_description: "",
    owner_name: "",
    hosting_environment: "",
  });

  function set<K extends keyof typeof form>(key: K, value: string) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  const mutation = useMutation({
    mutationFn: async (body: AssessmentCreate) => {
      const assessment = await api.assessments.create(body);
      try {
        await api.assessments.confirmAuthorization(
          assessment.id,
          `Authorization file recorded: ${body.authorization_reference}`,
        );
        return { assessment, confirmed: true };
      } catch {
        return { assessment, confirmed: false };
      }
    },
    onSuccess: ({ assessment, confirmed }) => {
      void queryClient.invalidateQueries({ queryKey: ["assessments"] });
      if (!confirmed) {
        toast.push(
          "Assessment created, but automatic authorization confirmation failed. Choose the file again in Settings.",
          "error",
        );
        navigate(`/assessments/${assessment.id}/settings`);
        return;
      }
      toast.push(
        "Assessment created and authorization recorded. Add scope next.",
        "success",
      );
      navigate(`/assessments/${assessment.id}/scope`);
    },
  });

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!authorizationFile) return;
    mutation.mutate({
      name: form.name.trim(),
      description: form.description.trim() || null,
      target_name: form.target_name.trim(),
      target_base_url: form.target_base_url.trim() || null,
      target_description: form.target_description.trim() || null,
      owner_name: form.owner_name.trim(),
      authorization_reference: authorizationFile.name,
      hosting_environment: form.hosting_environment.trim() || null,
      selected_categories: categories,
    });
  }

  return (
    <div className="page page-narrow">
      <PageHeader
        title="New assessment"
        description="Three short steps: describe the target, record authorization, choose focus areas. Scope comes next."
      />

      <ol className="wizard-progress" aria-label="Setup steps">
        <li className="is-current">
          <span>1</span> Target
        </li>
        <li>
          <span>2</span> Authorization
        </li>
        <li>
          <span>3</span> Focus
        </li>
        <li className="is-upcoming">
          <span>4</span> Scope
        </li>
      </ol>

      <form onSubmit={handleSubmit} className="stack-lg">
        <Card className="wizard-step">
          <StepHeader
            step="01"
            title="Describe the target"
            description="Start with the essentials. Descriptions and hosting notes are optional."
          />
          <div className="form-grid">
            <Field
              label="Assessment name"
              help="A short internal label for this engagement, for example the system name plus a date. It appears in the report."
            >
              <input
                required
                maxLength={200}
                value={form.name}
                onChange={(event) => set("name", event.target.value)}
                placeholder="LSRS assessment — November"
              />
            </Field>
            <Field
              label="Target name"
              help="The system being assessed, as the owner calls it. Example: Love & Styles Rental System."
            >
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
              className="span-2"
              help="The starting point for web checks. Use an absolute http(s) URL without a username or password. Example: http://target:3000. You still allowlist the host in Scope."
              hint="Optional, but needed for URL-based tools such as ZAP and HTTP checks."
            >
              <input
                type="url"
                maxLength={2048}
                value={form.target_base_url}
                onChange={(event) => set("target_base_url", event.target.value)}
                placeholder="http://target:3000"
              />
            </Field>
          </div>

          <details className="advanced-details">
            <summary>Optional context</summary>
            <div className="form-grid">
              <Field
                label="Assessment description"
                className="span-2"
                help="What this assessment covers and any constraints. Example: Local staging copy, synthetic data only."
              >
                <textarea
                  rows={2}
                  maxLength={5000}
                  value={form.description}
                  onChange={(event) => set("description", event.target.value)}
                  placeholder="Scope, goals and constraints"
                />
              </Field>
              <Field
                label="Target description"
                className="span-2"
                help="A short note about the application and its data. Example: Gown rental system with staff and admin roles."
              >
                <textarea
                  rows={2}
                  maxLength={5000}
                  value={form.target_description}
                  onChange={(event) =>
                    set("target_description", event.target.value)
                  }
                  placeholder="What the application does"
                />
              </Field>
              <Field
                label="Hosting environment"
                className="span-2"
                help="Where the target runs. Example: Docker Compose internal network, or local test machine."
              >
                <input
                  maxLength={200}
                  value={form.hosting_environment}
                  onChange={(event) =>
                    set("hosting_environment", event.target.value)
                  }
                  placeholder="Docker Compose internal network"
                />
              </Field>
            </div>
          </details>
        </Card>

        <Card className="wizard-step">
          <StepHeader
            step="02"
            title="Record authorization"
            description="Choose the signed authorization file. Authorization is accepted automatically; no second confirmation click."
            help="The backend stores the reference name and confirms authorization in one chain, so scans can run immediately after you add scope."
          />
          <div className="form-grid">
            <Field
              label="Owner / authorizing person"
              help="The person or group that approved testing. Example: LSRS owners."
            >
              <input
                required
                maxLength={200}
                value={form.owner_name}
                onChange={(event) => set("owner_name", event.target.value)}
                placeholder="LSRS owners"
              />
            </Field>
            <Field
              label="Authorization file"
              help="Choose the signed letter or approval document (PDF or image). PenPal records its file name as the reference and marks authorization confirmed. The file is not uploaded."
            >
              <FileDrop
                file={authorizationFile}
                onChange={setAuthorizationFile}
                label="Choose the signed authorization file"
              />
            </Field>
          </div>
          <div className="auto-accept-row">
            <Badge tone={authorizationFile ? "success" : "neutral"}>
              {authorizationFile ? "Ready" : "Required"}
            </Badge>
            <span className="muted tiny">
              {authorizationFile
                ? "Creating the assessment records the file name and confirms authorization automatically."
                : "Select a file to enable automatic authorization."}
            </span>
          </div>
        </Card>

        <Card className="wizard-step">
          <StepHeader
            step="03"
            title="Choose focus areas"
            description="Pick the security categories this assessment should cover. Defaults match the PenPal methodology."
          />
          <CategoryPicker value={categories} onChange={setCategories} />
        </Card>

        <Notice tone="info">
          After creation you will add scope rules, then run recon and scans. The
          assessment dashboard shows the next step at every stage.
        </Notice>

        {mutation.isError ? <ErrorNotice error={mutation.error} /> : null}

        <div className="form-actions">
          <Button variant="secondary" onClick={() => navigate("/assessments")}>
            Cancel
          </Button>
          <Button
            type="submit"
            disabled={mutation.isPending || !authorizationFile}
          >
            {mutation.isPending
              ? "Creating and confirming…"
              : "Create assessment and continue"}
          </Button>
        </div>
      </form>
    </div>
  );
}

function StepHeader({
  step,
  title,
  description,
  help,
}: {
  step: string;
  title: string;
  description: string;
  help?: string;
}) {
  return (
    <div className="step-header">
      <span className="step-badge" aria-hidden="true">
        {step}
      </span>
      <div>
        <span className="step-title-row">
          <h2>{title}</h2>
          {help ? <InfoTip label={title}>{help}</InfoTip> : null}
        </span>
        <p>{description}</p>
      </div>
    </div>
  );
}
