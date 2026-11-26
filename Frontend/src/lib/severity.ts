import type {
  FindingOut,
  Severity,
  SeverityMatrixOut,
} from "./types";

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

/** Listing uses the same precedence as the backend's effective severity. */
export function effectiveSeverity(finding: FindingOut): Severity | null {
  return (
    finding.final_severity ??
    finding.ai_suggested_severity ??
    finding.tool_severity
  );
}

export function severityFromScore(
  score: number,
  matrix: Pick<SeverityMatrixOut, "thresholds">,
): Severity | null {
  const match = matrix.thresholds.find(
    (threshold) => score >= threshold.min_score && score <= threshold.max_score,
  );
  return match?.severity ?? null;
}

export function score(likelihood: number, impact: number): number {
  return likelihood * impact;
}
