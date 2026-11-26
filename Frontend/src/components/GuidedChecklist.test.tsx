import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { GuidedChecklist } from "./GuidedChecklist";

describe("GuidedChecklist", () => {
  it("marks completed steps and points at the next action", () => {
    render(
      <MemoryRouter initialEntries={["/assessments/4/dashboard"]}>
        <GuidedChecklist
          steps={[
            {
              title: "Record authorization",
              description: "Choose the signed file.",
              done: true,
              to: "../settings",
              action: "Add authorization",
            },
            {
              title: "Add scope",
              description: "Allowlist the target.",
              done: false,
              to: "../scope",
              action: "Add scope",
            },
            {
              title: "Run a scan",
              description: "Start with Nmap.",
              done: false,
              to: "../scans",
              action: "Run a scan",
            },
          ]}
        />
      </MemoryRouter>,
    );

    expect(screen.getByText("1 of 3 complete")).toBeInTheDocument();
    expect(screen.getByText("Done")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Add scope" })).toBeInTheDocument();
  });
});
