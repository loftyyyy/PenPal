import { useId, useRef, useState } from "react";
import { formatBytes } from "../lib/format";

export function FileDrop({
  id,
  file,
  existingName,
  onChange,
  accept = ".pdf,.png,.jpg,.jpeg",
  label = "Authorization file",
  helpText = "Drop a PDF or image here, or choose a file.",
}: {
  id?: string;
  file: File | null;
  existingName?: string | null;
  onChange: (file: File | null) => void;
  accept?: string;
  label?: string;
  helpText?: string;
}) {
  const generatedId = useId();
  const inputId = id ?? generatedId;
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const shownName = file?.name ?? existingName ?? null;

  function choose(next: File | null) {
    onChange(next);
    if (inputRef.current) inputRef.current.value = "";
  }

  return (
    <div className="file-drop-wrap">
      <label
        htmlFor={inputId}
        className={`file-drop ${dragging ? "is-dragging" : ""}`}
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          const dropped = event.dataTransfer.files[0];
          if (dropped) choose(dropped);
        }}
      >
        <input
          ref={inputRef}
          id={inputId}
          type="file"
          accept={accept}
          className="file-drop-input"
          onChange={(event) => choose(event.target.files?.[0] ?? null)}
        />
        <span className="file-drop-icon" aria-hidden="true">
          +
        </span>
        <span className="file-drop-copy">
          <strong>{shownName ?? label}</strong>
          <small>
            {file
              ? `${formatBytes(file.size)} · ready to record`
              : existingName
                ? "Recorded reference · choose a file to replace it"
                : helpText}
          </small>
        </span>
        <span className="file-drop-action">
          {shownName ? "Replace" : "Choose file"}
        </span>
      </label>

      {file ? (
        <button
          type="button"
          className="btn btn-ghost btn-small"
          onClick={() => choose(null)}
        >
          Remove selected file
        </button>
      ) : null}
      <p className="field-hint">
        Only the file name is recorded as the authorization reference. The file
        itself stays on your device.
      </p>
    </div>
  );
}
