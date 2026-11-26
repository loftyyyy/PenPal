import { useEffect, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { ChevronDown, LogOut, Menu } from 'lucide-react'
import { useAuth } from '../../context/AuthContext'

const TITLES = [
  { match: (p) => p === '/', title: 'Dashboard' },
  { match: (p) => p === '/assessments', title: 'Assessments' },
  { match: (p) => p.startsWith('/assessments/'), title: 'Assessment details' },
  { match: (p) => p.startsWith('/findings'), title: 'Findings' },
  { match: (p) => p.startsWith('/reports'), title: 'Reports' },
  { match: (p) => p.startsWith('/users'), title: 'User management' },
]

export default function TopBar({ onOpenMobile }) {
  const { user, logout } = useAuth()
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const menuRef = useRef(null)

  const title = TITLES.find((t) => t.match(pathname))?.title ?? 'PenPal'
  const initials = (user?.full_name || user?.email || '?')
    .split(' ').map((s) => s[0]).slice(0, 2).join('').toUpperCase()

  useEffect(() => {
    const onClick = (e) => { if (menuRef.current && !menuRef.current.contains(e.target)) setOpen(false) }
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onClick)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onClick)
      document.removeEventListener('keydown', onKey)
    }
  }, [])

  const handleLogout = () => {
    logout()
    navigate('/login', { replace: true })
  }

  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b border-line bg-surface px-4">
      <div className="flex items-center gap-3">
        <button onClick={onOpenMobile} className="rounded p-1.5 text-muted hover:text-fg md:hidden" aria-label="Open menu">
          <Menu className="h-5 w-5" />
        </button>
        <h1 className="text-base font-semibold">{title}</h1>
      </div>

      <div className="relative" ref={menuRef}>
        <button
          onClick={() => setOpen((v) => !v)}
          aria-haspopup="menu"
          aria-expanded={open}
          className="flex items-center gap-3 rounded-md px-2 py-1.5 hover:bg-raised"
        >
          <span className="grid h-8 w-8 place-items-center rounded-full bg-raised text-xs font-semibold ring-1 ring-line">{initials}</span>
          <span className="hidden text-left sm:block">
            <span className="block text-sm font-medium leading-tight">{user?.full_name}</span>
            <span className="block text-xs capitalize leading-tight text-muted">{user?.role}</span>
          </span>
          <ChevronDown className="h-4 w-4 text-muted" aria-hidden="true" />
        </button>

        {open && (
          <div role="menu" className="absolute right-0 z-30 mt-2 w-64 rounded-lg border border-line bg-raised p-2 shadow-xl">
            <div className="border-b border-line px-3 py-2">
              <p className="truncate text-sm font-medium">{user?.full_name}</p>
              <p className="truncate text-xs text-muted">{user?.email}</p>
              <p className="mt-1 inline-block rounded bg-surface px-1.5 py-0.5 text-xs capitalize text-muted ring-1 ring-line">{user?.role}</p>
            </div>
            <button role="menuitem" onClick={handleLogout} className="mt-1 flex w-full items-center gap-2 rounded px-3 py-2 text-sm hover:bg-surface">
              <LogOut className="h-4 w-4" aria-hidden="true" /> Log out
            </button>
          </div>
        )}
      </div>
    </header>
  )
}
