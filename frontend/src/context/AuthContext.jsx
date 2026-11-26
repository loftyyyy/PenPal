import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { authService } from '../services/authService'
import { tokenStore, UNAUTHORIZED_EVENT } from '../services/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [status, setStatus] = useState('loading') // loading | authenticated | unauthenticated
  const [sessionExpired, setSessionExpired] = useState(false)
  const timer = useRef(null)

  const endSession = useCallback((expired = false) => {
    clearTimeout(timer.current)
    authService.logout()
    setUser(null)
    setStatus('unauthenticated')
    setSessionExpired(expired)
  }, [])

  // Auto-logout when the token's lifetime runs out.
  const scheduleExpiry = useCallback(() => {
    clearTimeout(timer.current)
    const expiresAt = tokenStore.getExpiry()
    if (!expiresAt) return
    const ms = Math.max(expiresAt - Date.now(), 0)
    timer.current = setTimeout(() => endSession(true), ms)
  }, [endSession])

  // Restore the session on page load.
  useEffect(() => {
    let cancelled = false
    async function restore() {
      const expiresAt = tokenStore.getExpiry()
      if (!tokenStore.get() || (expiresAt && expiresAt <= Date.now())) {
        tokenStore.clear()
        if (!cancelled) setStatus('unauthenticated')
        return
      }
      try {
        const me = await authService.me()
        if (cancelled) return
        setUser(me)
        setStatus('authenticated')
        scheduleExpiry()
      } catch {
        if (!cancelled) endSession(false)
      }
    }
    restore()
    return () => { cancelled = true }
  }, [endSession, scheduleExpiry])

  // Any 401 from the API ends the session.
  useEffect(() => {
    const onUnauthorized = () => endSession(true)
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
  }, [endSession])

  const login = useCallback(async (email, password) => {
    const loggedIn = await authService.login(email, password)
    setUser(loggedIn)
    setStatus('authenticated')
    setSessionExpired(false)
    scheduleExpiry()
    return loggedIn
  }, [scheduleExpiry])

  const logout = useCallback(() => endSession(false), [endSession])

  const value = useMemo(
    () => ({ user, status, sessionExpired, isAdmin: user?.role === 'admin', login, logout }),
    [user, status, sessionExpired, login, logout],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}
