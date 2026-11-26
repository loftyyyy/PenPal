import { Link } from "react-router-dom";

export interface GuidedStep {
  title: string;
  description: string;
  done: boolean;
  to: string;
  action: string;
}

export function GuidedChecklist({ steps }: { steps: GuidedStep[] }) {
  const currentIndex = steps.findIndex((step) => !step.done);

  return (
    <section className="guided-card" aria-labelledby="guided-title">
      <div className="guided-head">
        <div>
          <span className="eyebrow">Next steps</span>
          <h2 id="guided-title">Assessment workflow</h2>
        </div>
        <span className="muted tiny">
          {steps.filter((step) => step.done).length} of {steps.length} complete
        </span>
      </div>
      <ol className="guided-steps">
        {steps.map((step, index) => {
          const current = index === currentIndex;
          return (
            <li
              key={step.title}
              className={`guided-step ${step.done ? "is-done" : ""} ${
                current ? "is-current" : ""
              }`}
            >
              <span className="guided-marker" aria-hidden="true">
                {step.done ? "✓" : index + 1}
              </span>
              <div className="guided-copy">
                <strong>{step.title}</strong>
                <span>{step.description}</span>
              </div>
              {step.done ? (
                <span className="guided-state">Done</span>
              ) : (
                <Link to={step.to} className="btn btn-secondary btn-small">
                  {step.action}
                </Link>
              )}
            </li>
          );
        })}
      </ol>
    </section>
  );
}
