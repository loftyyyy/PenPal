import { useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { API_BASE, formatApiError } from "../lib/api";
import { useAuth } from "../state/auth";
import { Button, Field, Notice } from "../components/ui";

export function LoginPage() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const from =
    typeof location.state === "object" &&
    location.state !== null &&
    "from" in location.state &&
    typeof location.state.from === "string"
      ? location.state.from
      : "/assessments";

  if (user) return <Navigate to={from} replace />;

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login({ email: email.trim(), password });
      navigate(from, { replace: true });
    } catch (err) {
      setError(formatApiError(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="login-page">
      <section className="login-intro">
        <div className="brand brand-large">
          <span className="brand-mark" aria-hidden="true">
            P
          </span>
          <span>
            <strong>PenPal</strong>
            <small>Security assessment</small>
          </span>
        </div>
        <h1>Authorized testing, clearly documented.</h1>
        <p>
          Scope-guarded reconnaissance, scanning and evidence in one place. AI is
          advisory; assessors confirm every finding and own the final severity.
        </p>
        <ul>
          <li>Scope guard on every tool run</li>
          <li>Findings verified by a human</li>
          <li>Audit trail and downloadable reports</li>
        </ul>
      </section>

      <section className="login-panel">
        <h2>Sign in</h2>
        <p className="muted">Use your PenPal assessor or admin account.</p>
        <form onSubmit={handleSubmit} className="stack">
          <Field label="Email">
            <input
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          </Field>
          <Field label="Password">
            <input
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </Field>
          {error ? <Notice tone="error">{error}</Notice> : null}
          <Button type="submit" disabled={submitting}>
            {submitting ? "Signing in…" : "Sign in"}
          </Button>
        </form>
        <p className="muted tiny">API: {API_BASE}</p>
      </section>
    </div>
  );
}
