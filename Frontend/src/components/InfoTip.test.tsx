import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { InfoTip } from "./InfoTip";

describe("InfoTip", () => {
  it("shows help on focus and hides it on Escape", async () => {
    const user = userEvent.setup();
    render(<InfoTip label="Base URL">Use an absolute URL.</InfoTip>);

    const panel = screen.getByRole("tooltip");
    expect(panel).not.toHaveClass("is-open");

    await user.tab();
    expect(screen.getByRole("button", { name: "Help: Base URL" })).toHaveFocus();
    expect(panel).toHaveClass("is-open");
    expect(screen.getByText("Use an absolute URL.")).toBeInTheDocument();

    await user.keyboard("{Escape}");
    expect(panel).not.toHaveClass("is-open");
  });

  it("opens on click for touch users", async () => {
    const user = userEvent.setup();
    render(<InfoTip label="Scope">Allowlist one host.</InfoTip>);

    await user.click(screen.getByRole("button", { name: "Help: Scope" }));
    expect(screen.getByRole("tooltip")).toHaveClass("is-open");
  });
});
