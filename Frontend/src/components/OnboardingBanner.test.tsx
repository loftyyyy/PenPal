import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { OnboardingBanner } from "./OnboardingBanner";

function renderBanner() {
  return render(
    <MemoryRouter>
      <OnboardingBanner />
    </MemoryRouter>,
  );
}

describe("OnboardingBanner", () => {
  it("explains the three-step setup workflow and dismissal persists", async () => {
    const user = userEvent.setup();
    renderBanner();

    expect(screen.getByText("Your first assessment, step by step")).toBeInTheDocument();
    expect(screen.getByText("Describe the target")).toBeInTheDocument();
    expect(screen.getByText("Record authorization and scope")).toBeInTheDocument();
    expect(screen.getByText("Scan, review, report")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Dismiss guide" }));
    expect(
      screen.queryByText("Your first assessment, step by step"),
    ).not.toBeInTheDocument();
    expect(localStorage.getItem("penpal.onboarding.dismissed")).toBe("1");
  });

  it("stays dismissed on the next render", () => {
    localStorage.setItem("penpal.onboarding.dismissed", "1");
    renderBanner();
    expect(
      screen.queryByText("Your first assessment, step by step"),
    ).not.toBeInTheDocument();
  });
});
