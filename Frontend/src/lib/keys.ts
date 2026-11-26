export const keys = {
  assessments: (params?: object) => ["assessments", params ?? {}] as const,
  assessment: (id: number) => ["assessment", id] as const,
  scope: (id: number) => ["scope", id] as const,
  scans: (id: number, params?: object) => ["scans", id, params ?? {}] as const,
  scan: (scanId: number) => ["scan", scanId] as const,
  recon: (id: number) => ["recon", id] as const,
  findings: (id: number, filters?: object) =>
    ["findings", id, filters ?? {}] as const,
  finding: (findingId: number) => ["finding", findingId] as const,
  evidence: (findingId: number) => ["evidence", findingId] as const,
  analyses: (findingId: number) => ["analyses", findingId] as const,
  httpConfig: (id: number) => ["http-config", id] as const,
  testAccounts: (id: number) => ["test-accounts", id] as const,
  aiStatus: (id: number) => ["ai-status", id] as const,
  summary: (id: number) => ["summary", id] as const,
  dashboard: (id: number) => ["dashboard", id] as const,
  reports: (id: number, params?: object) =>
    ["reports", id, params ?? {}] as const,
  audit: (id: number, filters?: object) => ["audit", id, filters ?? {}] as const,
  users: (params?: object) => ["users", params ?? {}] as const,
  severityMatrix: () => ["severity-matrix"] as const,
};
