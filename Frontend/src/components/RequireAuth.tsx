import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../state/auth";
import { Loading } from "./ui";

export function RequireAuth() {
  const { user, initializing } = useAuth();
  const location = useLocation();

  if (initializing) {
    return (
      <div className="auth-loading">
        <Loading label="Restoring session…" />
      </div>
    );
  }
  if (!user) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return <Outlet />;
}
