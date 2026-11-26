import { Route, Routes } from 'react-router-dom'
import { AdminRoute, ProtectedRoute } from './components/common/ProtectedRoute'
import AppLayout from './components/layout/AppLayout'
import Login from './pages/Login'
import NotFound from './pages/NotFound'
import PagePlaceholder from './pages/PagePlaceholder'

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />

      <Route element={<ProtectedRoute />}>
        <Route element={<AppLayout />}>
          <Route index element={<PagePlaceholder title="Dashboard" phase="Phase 3" />} />
          <Route path="assessments" element={<PagePlaceholder title="Assessments" phase="Phase 2" />} />
          <Route path="assessments/:id" element={<PagePlaceholder title="Assessment details" phase="Phase 2" />} />
          <Route path="findings" element={<PagePlaceholder title="Findings" phase="Phase 4" />} />
          <Route path="reports" element={<PagePlaceholder title="Reports" phase="Phase 5" />} />

          <Route element={<AdminRoute />}>
            <Route path="users" element={<PagePlaceholder title="User management" phase="Phase 6" />} />
          </Route>

          <Route path="*" element={<NotFound />} />
        </Route>
      </Route>
    </Routes>
  )
}
