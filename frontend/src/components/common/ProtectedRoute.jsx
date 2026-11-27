import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { ShieldOff } from 'lucide-react'
import { useAuth } from '../../context/AuthContext'
import Spinner from './Spinner'

// Wraps every page that needs a logged-in user.
export function ProtectedRoute() {
  const { status } = useAuth()
  const location = useLocation()

  if (status === 'loading') return <Spinner label="Restoring your session" className="h-full" />
  if (status === 'unauthenticated') {
    return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />
  }
  return <Outlet />
}

// Admin-only pages. This hides the UI; the backend still enforces access.
export function AdminRoute() {
  const { isAdmin } = useAuth()
  if (!isAdmin) {
    return (
      <div className="ui-page ui-panel mx-auto mt-16 max-w-md text-center">
        <ShieldOff className="mx-auto mb-3 h-8 w-8 text-muted" aria-hidden="true" />
        <h2 className="text-lg font-semibold">Admin access required</h2>
        <p className="mt-2 text-sm text-muted">
          Your account is an assessor account. Ask an administrator if you need user management.
        </p>
      </div>
    )
  }
  return <Outlet />
}
