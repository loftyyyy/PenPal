import { useEffect, useRef, useState } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import {
  ChevronUp,
  ClipboardCheck,
  FileText,
  LayoutDashboard,
  LogOut,
  Settings,
  ShieldAlert,
  User,
  Users as UsersIcon,
  X,
} from 'lucide-react'
import { useAuth } from '../../context/AuthContext'

// ─── constants ────────────────────────────────────────────────────────────────
const SIDEBAR_WIDTH = '220px'

const NAV = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/assessments', label: 'Assessments', icon: ClipboardCheck },
  { to: '/findings', label: 'Findings', icon: ShieldAlert },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/users', label: 'User management', icon: UsersIcon, adminOnly: true },
]

// ─── nav item ─────────────────────────────────────────────────────────────────
function NavItem({ item, onNavigate }) {
  const Icon = item.icon
  return (
    <NavLink
      to={item.to}
      end={item.end}
      onClick={onNavigate}
      style={({ isActive }) =>
        isActive
          ? { background: 'var(--color-nav-active)', border: '1px solid var(--color-nav-active-border)', borderRadius: 'var(--radius-none)' }
          : { border: '1px solid transparent', borderRadius: 'var(--radius-none)' }
      }
      className="flex h-8 w-full items-center gap-2 px-[9px] text-body font-medium transition-colors hover:bg-surface-hover"
    >
      {({ isActive }) => (
        <>
          <Icon
            style={{ width: '15px', height: '15px', flexShrink: 0 }}
            className={isActive ? 'text-primary' : 'text-text-muted'}
            aria-hidden="true"
          />
          <span
            style={{ whiteSpace: 'nowrap', flex: 1, minWidth: 0 }}
            className={isActive ? 'text-text-primary' : 'text-text-secondary'}
          >
            {item.label}
          </span>
          {item.adminOnly && (
            <span
              style={{
                flexShrink: 0,
                border: '1px solid var(--color-border)',
                borderRadius: 'var(--radius-xs)',
                fontSize: 'var(--text-caption)',
                padding: '1px 5px',
                color: 'var(--color-text-muted)',
                lineHeight: '14px',
              }}
            >
              Admin
            </span>
          )}
        </>
      )}
    </NavLink>
  )
}

// ─── profile dropdown ─────────────────────────────────────────────────────────
function ProfileDropdown({ user, onSignOut }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  // Close on outside click
  useEffect(() => {
    if (!open) return
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  // Close on Escape
  useEffect(() => {
    if (!open) return
    const handler = (e) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [open])

  // Derive initials for avatar
  const initials = (user?.full_name || user?.email || '?')
    .split(' ')
    .map((w) => w[0])
    .slice(0, 2)
    .join('')
    .toUpperCase()

  const name = user?.full_name || 'Assessor'
  const role = user?.role || 'assessor'
  const roleLabel = role.charAt(0).toUpperCase() + role.slice(1)

  // Menu items — Profile / Settings are placeholders (pages don't exist yet)
  const menuItems = [
    {
      icon: User,
      label: 'Profile',
      action: () => { setOpen(false); alert('Profile page coming soon.') },
      danger: false,
    },
    {
      icon: Settings,
      label: 'Settings',
      action: () => { setOpen(false); alert('Settings page coming soon.') },
      danger: false,
    },
    {
      icon: LogOut,
      label: 'Log out',
      action: () => { setOpen(false); onSignOut() },
      danger: true,
    },
  ]

  return (
    <div
      ref={ref}
      style={{
        borderTop: '1px solid var(--color-border)',
        padding: '10px',
        flexShrink: 0,
        position: 'relative', // anchor for the upward dropdown
      }}
    >
      {/* ── upward dropdown panel ── */}
      {open && (
        <div
          role="menu"
          aria-label="Account menu"
          style={{
            position: 'absolute',
            bottom: 'calc(100% + 4px)', // opens above the trigger
            left: '10px',
            right: '10px',
            background: '#0D1829',
            border: '1px solid var(--color-border-strong)',
            borderRadius: 'var(--radius-sm)',
            overflow: 'hidden',
            zIndex: 50,
            boxShadow: '0 -4px 24px rgba(0,0,0,0.5)',
          }}
        >
          {/* user info header inside the dropdown */}
          <div
            style={{
              padding: '10px 12px',
              borderBottom: '1px solid var(--color-border)',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
            }}
          >
            <div style={avatarStyle}>
              <span style={initialsStyle}>{initials}</span>
            </div>
            <div style={{ minWidth: 0 }}>
              <p style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', lineHeight: 1.3, margin: 0 }}>
                {name}
              </p>
              <p style={{ fontSize: '9.5px', color: 'var(--color-text-muted)', textTransform: 'capitalize', lineHeight: 1.4, margin: 0, marginTop: '1px' }}>
                {roleLabel}
              </p>
            </div>
          </div>

          {/* menu items */}
          <div style={{ padding: '4px' }}>
            {menuItems.map(({ icon: Icon, label, action, danger }) => (
              <button
                key={label}
                role="menuitem"
                onClick={action}
                style={{
                  width: '100%',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '9px',
                  padding: '7px 10px',
                  background: 'transparent',
                  border: 'none',
                  borderRadius: 'var(--radius-xs)',
                  cursor: 'pointer',
                  fontSize: '11px',
                  fontFamily: 'var(--font-sans)',
                  fontWeight: 500,
                  color: danger ? '#F87171' : 'var(--color-text-secondary)',
                  textAlign: 'left',
                  transition: 'background 120ms ease, color 120ms ease',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = danger ? 'rgba(244,63,94,0.1)' : 'var(--color-surface-hover)'
                  e.currentTarget.style.color = danger ? '#F43F5E' : 'var(--color-text-primary)'
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = 'transparent'
                  e.currentTarget.style.color = danger ? '#F87171' : 'var(--color-text-secondary)'
                }}
              >
                <Icon
                  aria-hidden="true"
                  style={{
                    width: '14px',
                    height: '14px',
                    flexShrink: 0,
                    color: 'inherit',
                  }}
                />
                {label}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* ── collapsed trigger ── */}
      <button
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Account menu"
        style={{
          width: '100%',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '8px 10px',
          background: open ? 'var(--color-nav-active)' : 'var(--color-surface)',
          border: `1px solid ${open ? 'var(--color-nav-active-border)' : 'var(--color-border)'}`,
          borderRadius: 'var(--radius-sm)',
          cursor: 'pointer',
          transition: 'background 120ms ease, border-color 120ms ease',
        }}
        onMouseEnter={(e) => {
          if (!open) {
            e.currentTarget.style.background = 'var(--color-surface-hover)'
            e.currentTarget.style.borderColor = 'var(--color-border-strong)'
          }
        }}
        onMouseLeave={(e) => {
          if (!open) {
            e.currentTarget.style.background = 'var(--color-surface)'
            e.currentTarget.style.borderColor = 'var(--color-border)'
          }
        }}
      >
        {/* avatar */}
        <div style={avatarStyle}>
          <span style={initialsStyle}>{initials}</span>
        </div>

        {/* name + role */}
        <div style={{ flex: 1, minWidth: 0, textAlign: 'left' }}>
          <p style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', lineHeight: 1.3, margin: 0 }}>
            {name}
          </p>
          <p style={{ fontSize: '9.5px', color: 'var(--color-text-muted)', textTransform: 'capitalize', lineHeight: 1.4, margin: 0, marginTop: '1px' }}>
            {roleLabel}
          </p>
        </div>

        {/* chevron — rotates when open */}
        <ChevronUp
          aria-hidden="true"
          style={{
            width: '13px',
            height: '13px',
            flexShrink: 0,
            color: 'var(--color-text-muted)',
            transform: open ? 'rotate(180deg)' : 'rotate(0deg)',
            transition: 'transform 150ms ease',
          }}
        />
      </button>
    </div>
  )
}

// shared avatar styles kept outside render to avoid object churn
const avatarStyle = {
  width: '28px',
  height: '28px',
  borderRadius: '50%',
  background: '#1E3A5F',
  border: '1px solid var(--color-border-strong)',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  flexShrink: 0,
}

const initialsStyle = {
  fontSize: '10px',
  fontWeight: 700,
  color: '#7DD3FC',
  letterSpacing: '0.03em',
  lineHeight: 1,
  userSelect: 'none',
}

// ─── sidebar ──────────────────────────────────────────────────────────────────
export default function Sidebar({ mobileOpen, onCloseMobile }) {
  const { user, isAdmin, logout } = useAuth()
  const navigate = useNavigate()
  const items = NAV.filter((n) => !n.adminOnly || isAdmin)

  const handleSignOut = () => {
    logout()
    navigate('/login', { replace: true })
  }

  const content = (isMobile) => (
    <div className="flex h-full flex-col" style={{ background: 'var(--color-sidebar)' }}>

      {/* ── logo header ── */}
      <div
        style={{
          height: '51px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 14px',
          borderBottom: '1px solid var(--color-border)',
          flexShrink: 0,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <img
            src="/logo.png"
            alt=""
            width="32"
            height="32"
            style={{ objectFit: 'contain', flexShrink: 0 }}
          />
          <span style={{ fontSize: 'var(--text-section-title)', fontWeight: 600, color: 'var(--color-text-primary)', letterSpacing: '-0.01em' }}>
            penpal
          </span>
        </div>
        {isMobile && (
          <button onClick={onCloseMobile} className="ui-button" data-variant="ghost" aria-label="Close menu">
            <X style={{ width: '16px', height: '16px' }} />
          </button>
        )}
      </div>

      {/* ── navigation ── */}
      <nav style={{ flex: 1, padding: '8px 0', overflowY: 'auto' }} aria-label="Main">
        <div style={{ margin: '0 10px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
          {items.map((item) => (
            <NavItem
              key={item.to}
              item={item}
              onNavigate={isMobile ? onCloseMobile : undefined}
            />
          ))}
        </div>
      </nav>

      {/* ── profile dropdown ── */}
      <ProfileDropdown user={user} onSignOut={handleSignOut} />

    </div>
  )

  return (
    <>
      {/* ── desktop sidebar ── */}
      <aside
        className="hidden md:block"
        style={{
          width: SIDEBAR_WIDTH,
          flexShrink: 0,
          borderRight: '1px solid var(--color-border)',
          background: 'var(--color-sidebar)',
          height: '100%',
        }}
      >
        {content(false)}
      </aside>

      {/* ── mobile drawer ── */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 md:hidden">
          <div
            className="absolute inset-0 bg-black/60"
            onClick={onCloseMobile}
            aria-hidden="true"
          />
          <aside
            className="absolute inset-y-0 left-0"
            style={{
              width: SIDEBAR_WIDTH,
              borderRight: '1px solid var(--color-border)',
              background: 'var(--color-sidebar)',
            }}
          >
            {content(true)}
          </aside>
        </div>
      )}
    </>
  )
}
