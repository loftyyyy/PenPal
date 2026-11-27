import { useState } from 'react'
import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'

export default function AppLayout() {
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <div className="flex h-full" style={{ background: 'var(--color-background)' }}>
      <Sidebar
        mobileOpen={mobileOpen}
        onCloseMobile={() => setMobileOpen(false)}
      />
      <main
        className="relative min-w-0 flex-1 overflow-y-auto"
        style={{ background: 'var(--background-gradient)' }}
      >
        {/* Mobile hamburger */}
        <div
          className="flex items-center px-4 py-2 md:hidden"
          style={{ borderBottom: '1px solid var(--color-border)' }}
        >
          <button
            onClick={() => setMobileOpen(true)}
            className="ui-button"
            data-variant="ghost"
            aria-label="Open menu"
          >
            <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
        </div>
        <div className="p-5">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
