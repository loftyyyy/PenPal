import { Route, Routes } from 'react-router-dom'
import { AdminRoute, ProtectedRoute } from './components/common/ProtectedRoute'
import AppLayout from './components/layout/AppLayout'
import Login from './pages/Login'
import NotFound from './pages/NotFound'
import Dashboard from './pages/Dashboard'
import Assessments from './pages/Assessments'
import AssessmentDetail from './pages/AssessmentDetail'
import Findings from './pages/Findings'
import FindingDetail from './pages/FindingDetail'
import ManualFinding from './pages/ManualFinding'
import Reports from './pages/Reports'
import Users from './pages/Users'

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />

      <Route element={<ProtectedRoute />}>
        <Route element={<AppLayout />}>
          <Route index element={<Dashboard />} />

          <Route path="assessments" element={<Assessments />} />
          <Route path="assessments/:id" element={<AssessmentDetail />} />

          <Route path="findings" element={<Findings />} />
          <Route path="findings/new" element={<ManualFinding />} />
          <Route path="findings/:id" element={<FindingDetail />} />

          <Route path="reports" element={<Reports />} />

          <Route element={<AdminRoute />}>
            <Route path="users" element={<Users />} />
          </Route>

          <Route path="*" element={<NotFound />} />
        </Route>
      </Route>
    </Routes>
  )
}
