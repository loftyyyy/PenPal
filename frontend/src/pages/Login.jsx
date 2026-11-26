import { useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { AlertCircle, Loader2 } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import { getErrorMessage } from '../utils/errors'

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/ // same pattern the backend uses

export default function Login() {
  const { login, status, sessionExpired } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = location.state?.from || '/'

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [fieldErrors, setFieldErrors] = useState({})
  const [formError, setFormError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  if (status === 'authenticated') return <Navigate to={from} replace />

  const validate = () => {
    const errs = {}
    if (!email.trim()) errs.email = 'Enter your email address.'
    else if (!EMAIL_RE.test(email.trim())) errs.email = 'Enter a valid email address.'
    if (!password) errs.password = 'Enter your password.'
    setFieldErrors(errs)
    return Object.keys(errs).length === 0
  }

  const onSubmit = async (e) => {
    e.preventDefault()
    setFormError('')
    if (!validate()) return
    setSubmitting(true)
    try {
      await login(email.trim(), password)
      navigate(from, { replace: true })
    } catch (err) {
      setPassword('')
      setFormError(
        err.response?.status === 401
          ? 'Email or password is incorrect.'
          : getErrorMessage(err),
      )
    } finally {
      setSubmitting(false)
    }
  }

  const inputClass = (hasError) =>
    `mt-1.5 w-full rounded-md border bg-canvas px-3 py-2.5 text-sm placeholder:text-muted/60 ${
      hasError ? 'border-sev-critical' : 'border-line focus:border-accent'
    }`

  return (
    <div className="grid min-h-full lg:grid-cols-[1.1fr_1fr]">
      <aside className="hidden flex-col justify-between border-r border-line bg-surface p-12 lg:flex">
        <div className="flex items-center gap-2">
          <span className="grid h-8 w-8 place-items-center rounded bg-accent font-mono text-base font-medium text-canvas">P</span>
          <span className="text-lg font-semibold tracking-tight">PenPal</span>
        </div>
        <div className="max-w-md">
          <h2 className="text-3xl font-semibold leading-tight">Scan, analyze, then decide.</h2>
          <p className="mt-4 text-base leading-relaxed text-muted">
            PenPal gathers findings from Nmap and ZAP and adds AI explanations. Only findings
            an assessor confirms appear in the report.
          </p>
        </div>
        <p className="text-sm text-muted">Authorized assessments only.</p>
      </aside>

      <main className="flex items-center justify-center p-6">
        <form onSubmit={onSubmit} noValidate className="w-full max-w-sm">
          <h1 className="text-2xl font-semibold">Log in</h1>
          <p className="mt-1 text-sm text-muted">Use the account an administrator created for you.</p>

          {sessionExpired && !formError && (
            <div role="alert" className="mt-5 flex gap-2 rounded-md border border-sev-medium/40 bg-sev-medium/10 p-3 text-sm">
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-sev-medium" aria-hidden="true" />
              Your session ended. Log in again to continue.
            </div>
          )}
          {formError && (
            <div role="alert" className="mt-5 flex gap-2 rounded-md border border-sev-critical/40 bg-sev-critical/10 p-3 text-sm">
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-sev-critical" aria-hidden="true" />
              {formError}
            </div>
          )}

          <div className="mt-6">
            <label htmlFor="email" className="text-sm font-medium">Email</label>
            <input
              id="email" type="email" autoComplete="username" autoFocus
              value={email} onChange={(e) => setEmail(e.target.value)}
              aria-invalid={!!fieldErrors.email} aria-describedby={fieldErrors.email ? 'email-err' : undefined}
              className={inputClass(fieldErrors.email)} placeholder="you@example.com"
            />
            {fieldErrors.email && <p id="email-err" className="mt-1 text-xs text-sev-critical">{fieldErrors.email}</p>}
          </div>

          <div className="mt-4">
            <label htmlFor="password" className="text-sm font-medium">Password</label>
            <input
              id="password" type="password" autoComplete="current-password"
              value={password} onChange={(e) => setPassword(e.target.value)}
              aria-invalid={!!fieldErrors.password} aria-describedby={fieldErrors.password ? 'pw-err' : undefined}
              className={inputClass(fieldErrors.password)}
            />
            {fieldErrors.password && <p id="pw-err" className="mt-1 text-xs text-sev-critical">{fieldErrors.password}</p>}
          </div>

          <button
            type="submit" disabled={submitting}
            className="mt-6 flex w-full items-center justify-center gap-2 rounded-md bg-accent px-4 py-2.5 text-sm font-semibold text-canvas hover:bg-accent-strong disabled:opacity-60"
          >
            {submitting && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
            {submitting ? 'Logging in' : 'Log in'}
          </button>
        </form>
      </main>
    </div>
  )
}
