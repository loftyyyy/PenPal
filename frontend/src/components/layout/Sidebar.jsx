import { NavLink } from 'react-router-dom'
import { ClipboardCheck, FileText, LayoutDashboard, PanelLeftClose, PanelLeftOpen, ShieldAlert, Users as UsersIcon, X } from 'lucide-react'
import { useAuth } from '../../context/AuthContext'

const NAV = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/assessments', label: 'Assessments', icon: ClipboardCheck },
  { to: '/findings', label: 'Findings', icon: ShieldAlert },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/users', label: 'User management', icon: UsersIcon, adminOnly: true },
]

function NavItem({ item, collapsed, onNavigate }) {
  const Icon = item.icon
  return (
    <NavLink
      to={item.to}
      end={item.end}
      onClick={onNavigate}
      title={collapsed ? item.label : undefined}
      className={({ isActive }) =>
        `flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
          isActive ? 'bg-raised text-fg shadow-[inset_2px_0_0_var(--color-accent)]' : 'text-muted hover:bg-raised/60 hover:text-fg'
        } ${collapsed ? 'justify-center' : ''}`
      }
    >
      <Icon className="h-[18px] w-[18px] shrink-0" aria-hidden="true" />
      {!collapsed && <span className="truncate">{item.label}</span>}
    </NavLink>
  )
}

export default function Sidebar({ collapsed, onToggleCollapse, mobileOpen, onCloseMobile }) {
  const { isAdmin } = useAuth()
  const items = NAV.filter((n) => !n.adminOnly || isAdmin)

  const content = (isMobile) => {
    const narrow = collapsed && !isMobile
    return (
      <div className="flex h-full flex-col">
        <div className={`flex h-14 items-center border-b border-line px-4 ${narrow ? 'justify-center' : 'justify-between'}`}>
          <div className="flex items-center gap-2">
            <span className="grid h-7 w-7 place-items-center rounded bg-accent font-mono text-sm font-medium text-canvas">P</span>
            {!narrow && <span className="text-base font-semibold tracking-tight">PenPal</span>}
          </div>
          {isMobile && (
            <button onClick={onCloseMobile} className="rounded p-1 text-muted hover:text-fg" aria-label="Close menu">
              <X className="h-5 w-5" />
            </button>
          )}
        </div>

        <nav className="flex-1 space-y-1 p-3" aria-label="Main">
          {items.map((item) => (
            <NavItem key={item.to} item={item} collapsed={narrow} onNavigate={isMobile ? onCloseMobile : undefined} />
          ))}
        </nav>

        {!isMobile && (
          <div className="border-t border-line p-3">
            <button
              onClick={onToggleCollapse}
              className={`flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-muted hover:bg-raised/60 hover:text-fg ${narrow ? 'justify-center' : ''}`}
              aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            >
              {collapsed ? <PanelLeftOpen className="h-[18px] w-[18px]" /> : <PanelLeftClose className="h-[18px] w-[18px]" />}
              {!narrow && <span>Collapse</span>}
            </button>
          </div>
        )}
      </div>
    )
  }

  return (
    <>
      <aside className={`hidden shrink-0 border-r border-line bg-surface transition-[width] duration-150 md:block ${collapsed ? 'w-16' : 'w-60'}`}>
        {content(false)}
      </aside>

      {mobileOpen && (
        <div className="fixed inset-0 z-40 md:hidden">
          <div className="absolute inset-0 bg-black/60" onClick={onCloseMobile} aria-hidden="true" />
          <aside className="absolute inset-y-0 left-0 w-64 border-r border-line bg-surface">{content(true)}</aside>
        </div>
      )}
    </>
  )
}
