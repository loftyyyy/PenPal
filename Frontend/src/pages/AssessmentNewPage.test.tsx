import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { AssessmentOut } from "../lib/types";
import { ToastProvider } from "../state/toast";
import { AssessmentNewPage } from "./AssessmentNewPage";

vi.mock("../lib/api", () => ({
  api: {
    assessments: {
      create: vi.fn(),
      confirmAuthorization: vi.fn(),
    },
  },
  formatApiError: (error: unknown) =>
    error instanceof Error ? error.message : String(error),
}));

import { api } from "../lib/api";

const createdAssessment = { id: 42 } as AssessmentOut;

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter initialEntries={["/assessments/new"]}>
          <Routes>
            <Route path="/assessments/new" element={<AssessmentNewPage />} />
            <Route
              path="/assessments/:assessmentId/scope"
              element={<div>Scope step reached</div>}
            />
            <Route
              path="/assessments/:assessmentId/settings"
              element={<div>Settings step reached</div>}
            />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

describe("AssessmentNewPage guided authorization flow", () => {
  it("records the selected authorization file and confirms automatically", async () => {
    vi.mocked(api.assessments.create).mockResolvedValue(createdAssessment);
    vi.mocked(api.assessments.confirmAuthorization).mockResolvedValue(
      createdAssessment,
    );
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("Assessment name"), "LSRS assessment");
    await user.type(
      screen.getByLabelText("Target name"),
      "Love & Styles Rental System",
    );
    await user.type(screen.getByLabelText("Owner / authorizing person"), "LSRS");

    const file = new File(["signed"], "signed-letter.pdf", {
      type: "application/pdf",
    });
    const fileInput = document.querySelector<HTMLInputElement>(
      'input[type="file"]',
    );
    expect(fileInput).not.toBeNull();
    await user.upload(fileInput!, file);

    expect(screen.getByText("signed-letter.pdf")).toBeInTheDocument();
    await user.click(
      screen.getByRole("button", { name: "Create assessment and continue" }),
    );

    await waitFor(() => {
      expect(api.assessments.create).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "LSRS assessment",
          target_name: "Love & Styles Rental System",
          owner_name: "LSRS",
          authorization_reference: "signed-letter.pdf",
        }),
      );
    });
    expect(api.assessments.confirmAuthorization).toHaveBeenCalledWith(
      42,
      expect.stringContaining("signed-letter.pdf"),
    );
    expect(await screen.findByText("Scope step reached")).toBeInTheDocument();
  });

  it("keeps the submit disabled until an authorization file is chosen", () => {
    renderPage();
    expect(
      screen.getByRole("button", { name: "Create assessment and continue" }),
    ).toBeDisabled();
  });
});
