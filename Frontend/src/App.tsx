import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { AssessmentLayout } from "./components/AssessmentLayout";
import { RequireAuth } from "./components/RequireAuth";
import { AiPage } from "./pages/AiPage";
import { AssessmentNewPage } from "./pages/AssessmentNewPage";
import { AssessmentsPage } from "./pages/AssessmentsPage";
import { AuditPage } from "./pages/AuditPage";
import { DashboardPage } from "./pages/DashboardPage";
import { FindingDetailPage } from "./pages/FindingDetailPage";
import { FindingNewPage } from "./pages/FindingNewPage";
import { FindingsPage } from "./pages/FindingsPage";
import { HttpChecksPage } from "./pages/HttpChecksPage";
import { LoginPage } from "./pages/LoginPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { ReconPage } from "./pages/ReconPage";
import { ReportsPage } from "./pages/ReportsPage";
import { ScansPage } from "./pages/ScansPage";
import { ScopePage } from "./pages/ScopePage";
import { SettingsPage } from "./pages/SettingsPage";
import { UsersPage } from "./pages/UsersPage";

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />

      <Route element={<RequireAuth />}>
        <Route element={<AppShell />}>
          <Route index element={<Navigate to="/assessments" replace />} />
          <Route path="/assessments" element={<AssessmentsPage />} />
          <Route path="/assessments/new" element={<AssessmentNewPage />} />
          <Route path="/users" element={<UsersPage />} />

          <Route
            path="/assessments/:assessmentId"
            element={<AssessmentLayout />}
          >
            <Route index element={<Navigate to="dashboard" replace />} />
            <Route path="dashboard" element={<DashboardPage />} />
            <Route path="scope" element={<ScopePage />} />
            <Route path="scans" element={<ScansPage />} />
            <Route path="recon" element={<ReconPage />} />
            <Route path="findings" element={<FindingsPage />} />
            <Route path="findings/new" element={<FindingNewPage />} />
            <Route path="findings/:findingId" element={<FindingDetailPage />} />
            <Route path="http-checks" element={<HttpChecksPage />} />
            <Route path="ai" element={<AiPage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="audit" element={<AuditPage />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>

          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Route>
    </Routes>
  );
}
