import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

const STORAGE_KEY = "penpal.onboarding.dismissed";

export function OnboardingBanner({ storage = localStorage }: { storage?: Storage }) {
  const [dismissed, setDismissed] = useState(
    () => storage.getItem(STORAGE_KEY) === "1",
  );

  useEffect(() => {
    setDismissed(storage.getItem(STORAGE_KEY) === "1");
  }, [storage]);

  if (dismissed) return null;

  function dismiss() {
    storage.setItem(STORAGE_KEY, "1");
    setDismissed(true);
  }

  return (
    <section className="onboarding" aria-labelledby="onboarding-title">
      <div className="onboarding-head">
        <span className="eyebrow">Start here</span>
        <h2 id="onboarding-title">Your first assessment, step by step</h2>
        <p>
          PenPal keeps testing authorized and reviewable. Follow this path once;
          later assessments reuse the same flow.
        </p>
      </div>
      <ol className="onboarding-steps">
        <li>
          <span className="step-number">1</span>
          <div>
            <strong>Describe the target</strong>
            <span>Name the system, owner and authorized URL.</span>
          </div>
        </li>
        <li>
          <span className="step-number">2</span>
          <div>
            <strong>Record authorization and scope</strong>
            <span>
              Choose the signed file; authorization is accepted automatically.
              Then allowlist hosts and URLs.
            </span>
          </div>
        </li>
        <li>
          <span className="step-number">3</span>
          <div>
            <strong>Scan, review, report</strong>
            <span>
              Run recon and scans, verify findings, approve the summary and export
              the report.
            </span>
          </div>
        </li>
      </ol>
      <div className="onboarding-actions">
        <Link to="/assessments/new" className="btn btn-primary">
          Start an assessment
        </Link>
        <button type="button" className="btn btn-ghost" onClick={dismiss}>
          Dismiss guide
        </button>
      </div>
    </section>
  );
}
