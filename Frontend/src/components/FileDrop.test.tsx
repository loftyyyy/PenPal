import { useState } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { FileDrop } from "./FileDrop";

function Harness() {
  const [file, setFile] = useState<File | null>(null);
  return (
    <FileDrop
      file={file}
      onChange={setFile}
      label="Choose the signed authorization file"
    />
  );
}

describe("FileDrop", () => {
  it("shows the selected file name and size, then removes it", async () => {
    const user = userEvent.setup();
    render(<Harness />);

    const file = new File(["hello"], "authorization.pdf", {
      type: "application/pdf",
    });
    await user.upload(screen.getByLabelText(/authorization file/i), file);

    expect(screen.getByText("authorization.pdf")).toBeInTheDocument();
    expect(screen.getByText(/5 B/)).toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: "Remove selected file" }),
    );
    expect(screen.queryByText("authorization.pdf")).not.toBeInTheDocument();
    expect(
      screen.getByText("Choose the signed authorization file"),
    ).toBeInTheDocument();
  });

  it("shows an existing recorded reference", () => {
    render(
      <FileDrop file={null} existingName="signed-letter.pdf" onChange={() => {}} />,
    );
    expect(screen.getByText("signed-letter.pdf")).toBeInTheDocument();
    expect(screen.getByText("Replace")).toBeInTheDocument();
  });
});
