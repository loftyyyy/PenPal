import { describe, expect, it } from "vitest";
import { effectiveSeverity, score, severityFromScore } from "./severity";
import type { FindingOut, SeverityMatrixOut } from "./types";

const matrix: Pick<SeverityMatrixOut, "thresholds"> = {
  thresholds: [
    { min_score: 1, max_score: 2, severity: "info" },
    { min_score: 3, max_score: 5, severity: "low" },
    { min_score: 6, max_score: 11, severity: "medium" },
    { min_score: 12, max_score: 19, severity: "high" },
    { min_score: 20, max_score: 25, severity: "critical" },
  ],
};

function finding(partial: Partial<FindingOut>): FindingOut {
  return {
    id: 1,
    assessment_id: 1,
    scan_id: null,
    source: "manual",
    title: "Example",
    description: null,
    category: "uncategorized",
    owasp_category: null,
    cwe: null,
    affected_url: null,
    http_method: null,
    parameter: null,
    tool_severity: null,
    ai_suggested_severity: null,
    final_severity: null,
    likelihood: null,
    impact: null,
    tool_confidence: null,
    verification_status: "pending",
    rejection_reason: null,
    verified_by: null,
    verified_at: null,
    final_remediation: null,
    first_seen_at: "2026-11-25T00:00:00Z",
    last_seen_at: "2026-11-25T00:00:00Z",
    seen_count: 1,
    created_at: "2026-11-25T00:00:00Z",
    updated_at: "2026-11-25T00:00:00Z",
    ...partial,
  };
}

describe("effectiveSeverity", () => {
  it("prefers final, then AI, then tool severity", () => {
    expect(
      effectiveSeverity(
        finding({
          tool_severity: "low",
          ai_suggested_severity: "high",
          final_severity: "critical",
        }),
      ),
    ).toBe("critical");
    expect(
      effectiveSeverity(
        finding({ tool_severity: "low", ai_suggested_severity: "high" }),
      ),
    ).toBe("high");
    expect(effectiveSeverity(finding({ tool_severity: "low" }))).toBe("low");
    expect(effectiveSeverity(finding({}))).toBeNull();
  });
});

describe("severity matrix", () => {
  it("multiplies likelihood by impact", () => {
    expect(score(4, 5)).toBe(20);
    expect(score(1, 1)).toBe(1);
  });

  it("maps inclusive score bands to severities", () => {
    expect(severityFromScore(0, matrix)).toBeNull();
    expect(severityFromScore(2, matrix)).toBe("info");
    expect(severityFromScore(5, matrix)).toBe("low");
    expect(severityFromScore(6, matrix)).toBe("medium");
    expect(severityFromScore(11, matrix)).toBe("medium");
    expect(severityFromScore(12, matrix)).toBe("high");
    expect(severityFromScore(19, matrix)).toBe("high");
    expect(severityFromScore(20, matrix)).toBe("critical");
    expect(severityFromScore(25, matrix)).toBe("critical");
    expect(severityFromScore(26, matrix)).toBeNull();
  });
});
