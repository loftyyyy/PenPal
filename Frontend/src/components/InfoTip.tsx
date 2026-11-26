import { useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";

export function InfoTip({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLSpanElement>(null);

  function closeOnEscape(event: KeyboardEvent) {
    if (event.key === "Escape") {
      setOpen(false);
      wrapRef.current?.querySelector<HTMLButtonElement>("button")?.blur();
    }
  }

  return (
    <span
      className="info-tip-wrap"
      ref={wrapRef}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onKeyDown={closeOnEscape}
    >
      <button
        type="button"
        className="info-tip"
        aria-label={`Help: ${label}`}
        aria-describedby={open ? id : undefined}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        onClick={() => setOpen(true)}
      >
        i
      </button>
      <span
        id={id}
        role="tooltip"
        className={`info-tip-panel ${open ? "is-open" : ""}`}
      >
        {children}
      </span>
    </span>
  );
}
