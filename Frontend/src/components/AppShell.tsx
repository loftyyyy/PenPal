import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../state/auth";
import { useTheme, type ThemePreference } from "../state/theme";

export function AppShell() {
  const { user, logout } = useAuth();
  const { preference, setPreference } = useTheme();
  const navigate = useNavigate();

  function handleLogout() {
    logout();
    navigate("/login", { replace: true });
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <aside className="sidebar">
        <NavLink to="/assessments" className="brand" aria-label="PenPal home">
          <span className="brand-mark" aria-hidden="true">
            P
          </span>
          <span>
            <strong>PenPal</strong>
            <small>Security assessment</small>
          </span>
        </NavLink>

        <nav className="sidebar-nav" aria-label="Main">
          <NavLink to="/assessments" className="sidebar-link">
            Assessments
          </NavLink>
          {user?.role === "admin" ? (
            <NavLink to="/users" className="sidebar-link">
              Users
            </NavLink>
          ) : null}
        </nav>

        <div className="sidebar-footer">
          <label className="theme-select">
            <span>Theme</span>
            <select
              aria-label="Theme"
              value={preference}
              onChange={(event) =>
                setPreference(event.target.value as ThemePreference)
              }
            >
              <option value="system">System</option>
              <option value="light">Light</option>
              <option value="dark">Dark</option>
            </select>
          </label>
          <div className="user-block">
            <div>
              <strong>{user?.full_name}</strong>
              <small>
                {user?.email} · {user?.role}
              </small>
            </div>
            <button type="button" className="btn btn-ghost" onClick={handleLogout}>
              Sign out
            </button>
          </div>
        </div>
      </aside>

      <main id="main" className="main" tabIndex={-1}>
        <Outlet />
      </main>
    </div>
  );
}
