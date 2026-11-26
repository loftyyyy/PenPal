import { useLocation } from 'react-router-dom'
import { Menu } from 'lucide-react'

// Breadcrumb-style titles per route
const CRUMBS = [
  { match: (p) => p === '/', crumbs: [] },
  { match: (p) => p === '/assessments', crumbs: ['Assessments'] },
  { match: (p) => /^\/assessments\/[^/]+$/.test(p), crumbs: ['Assessment'] },
  { match: (p) => p.startsWith('/findings/'), crumbs: ['Findings'] },
  { match: (p) => p.startsWith('/findings'), crumbs: ['Findings'] },
  { match: (p) => p.startsWith('/reports'), crumbs: ['Reports'] },
  { match: (p) => p.startsWith('/users'), crumbs: ['Users'] },
]

export default function TopBar({ onOpenMobile, breadcrumb, action }) {
  const { pathname } = useLocation()
  const found = CRUMBS.find((c) => c.match(pathname))
  const crumbs = breadcrumb ?? found?.crumbs ?? []

  return (
    <header className="flex h-[52px] shrink-0 items-center justify-between border-b border-border bg-sidebar px-5">
      <div className="flex items-center gap-3">
        <button
          onClick={onOpenMobile}
          className="ui-button md:hidden"
          data-variant="ghost"
          aria-label="Open menu"
        >
          <Menu className="h-3.5 w-3.5" />
        </button>

        {crumbs.length > 0 && (
          <nav aria-label="Breadcrumb" className="text-[10px] text-text-muted">
            {crumbs.map((c, i) => (
              <span key={i}>
                {i > 0 && <span className="mx-1 text-text-muted/40">/</span>}
                <span className={i === crumbs.length - 1 ? 'text-primary' : ''}>{c}</span>
              </span>
            ))}
          </nav>
        )}
      </div>

      {action && <div>{action}</div>}
    </header>
  )
}
