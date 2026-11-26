import { useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import { getErrorMessage } from '../utils/errors'

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/

/* ─────────────────────────────────────────────
   Decorative SVG curves – upper-right + lower-left
   Matching the reference: thin cyan strokes, no fill,
   positioned behind the form content.
───────────────────────────────────────────── */
function CurveUpperRight() {
  return (
    <svg
      aria-hidden="true"
      style={{
        position: 'absolute',
        top: 0,
        right: 0,
        width: '340px',
        height: '320px',
        pointerEvents: 'none',
        zIndex: 0,
      }}
      viewBox="0 0 340 320"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      {/* outer arc – sweeps from upper-right corner toward mid-right */}
      <path
        d="M340 0 C280 40, 240 100, 300 180 S380 260, 340 320"
        stroke="#38BDF8"
        strokeWidth="1.5"
        strokeOpacity="0.45"
        fill="none"
      />
      {/* inner arc – tighter, slightly lower opacity */}
      <path
        d="M340 30 C290 65, 258 118, 310 196 S382 272, 340 320"
        stroke="#38BDF8"
        strokeWidth="1"
        strokeOpacity="0.25"
        fill="none"
      />
    </svg>
  )
}

function CurveLowerLeft() {
  return (
    <svg
      aria-hidden="true"
      style={{
        position: 'absolute',
        bottom: 0,
        left: 0,
        width: '340px',
        height: '320px',
        pointerEvents: 'none',
        zIndex: 0,
      }}
      viewBox="0 0 340 320"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      {/* mirror of upper-right */}
      <path
        d="M0 320 C60 280, 100 220, 40 140 S-40 60, 0 0"
        stroke="#38BDF8"
        strokeWidth="1.5"
        strokeOpacity="0.45"
        fill="none"
      />
      <path
        d="M0 290 C50 255, 82 202, 30 124 S-42 48, 0 0"
        stroke="#38BDF8"
        strokeWidth="1"
        strokeOpacity="0.25"
        fill="none"
      />
    </svg>
  )
}

/* ─────────────────────────────────────────────
   Main login page
───────────────────────────────────────────── */
export default function Login() {
  const { login, status, sessionExpired } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = location.state?.from || '/'

  const [email, setEmail]           = useState('')
  const [password, setPassword]     = useState('')
  const [fieldErrors, setFieldErrors] = useState({})
  const [formError, setFormError]   = useState('')
  const [submitting, setSubmitting] = useState(false)

  if (status === 'authenticated') return <Navigate to={from} replace />

  const validate = () => {
    const errs = {}
    if (!email.trim())                   errs.email    = 'Enter your email address.'
    else if (!EMAIL_RE.test(email.trim())) errs.email  = 'Enter a valid email address.'
    if (!password)                        errs.password = 'Enter your password.'
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

  /* ── shared input style (rectangular, dark) ── */
  const inputStyle = (hasError) => ({
    width: '251px',
    height: '37px',
    background: 'rgba(8, 15, 32, 0.85)',
    border: `1px solid ${hasError ? '#F43F5E' : 'rgba(105, 130, 180, 0.22)'}`,
    borderRadius: '0px',
    color: '#E2E8F0',
    fontSize: '10px',
    padding: '0 14px',
    outline: 'none',
    boxSizing: 'border-box',
    display: 'block',
  })

  return (
    /* ── full-viewport wrapper with layered gradient background ── */
    <div
      style={{
        minHeight: '100%',
        width: '100%',
        position: 'relative',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        overflow: 'hidden',
        /* Reference: deep electric blue upper-right, rich dark blue lower-left,
           near-black in the center/bottom */
        background: `
          radial-gradient(ellipse 55% 55% at 100% 0%,   #1142b8 0%, transparent 60%),
          radial-gradient(ellipse 50% 50% at 0%   100%, #0e3799 0%, transparent 55%),
          radial-gradient(ellipse 60% 40% at 50%  100%, #07205a 0%, transparent 60%),
          #030712
        `,
      }}
    >
      {/* decorative curves sit at z=0, behind everything */}
      <CurveUpperRight />
      <CurveLowerLeft />

      {/* ── centered login content ── */}
      <div
        style={{
          position: 'relative',
          zIndex: 1,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          width: '100%',
          maxWidth: '400px',
          padding: '0 24px',
          boxSizing: 'border-box',
        }}
      >
        {/* 1 ── badge */}
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            height: '34px',
            gap: '6px',
            padding: '0 12px 0 4px',
            background: 'rgba(10, 20, 45, 0.80)',
            border: '1px solid rgba(100, 130, 190, 0.30)',
            borderRadius: '20px',
            fontSize: '9px',
            fontWeight: 500,
            color: '#D1DCF0',
            letterSpacing: '0.02em',
            marginBottom: '20px',
          }}
        >
          <img src="/logo.png" alt="" width="30" height="30" style={{ objectFit: 'contain' }} />
          penpal
        </div>

        {/* 2 ── headline */}
        <h1
          style={{
            margin: 0,
            marginBottom: '14px',
            fontSize: '45px',
            fontWeight: 700,
            lineHeight: 1.05,
            letterSpacing: '-1.5px',
            color: '#FFFFFF',
            textAlign: 'center',
            whiteSpace: 'nowrap',
          }}
        >
          Test with intent.<br />
          Confirm with a human.
        </h1>

        {/* 3 ── description */}
        <p
          style={{
            margin: 0,
            marginBottom: '24px',
            fontSize: '12px',
            fontWeight: 400,
            lineHeight: '16px',
            color: '#A9C8F5',
            textAlign: 'center',
            maxWidth: '340px',
          }}
        >
          Sign in to run scoped scans, review AI suggestions, and<br />
          report only what you verified.
        </p>

        {/* error alerts */}
        {sessionExpired && !formError && (
          <div
            role="alert"
            style={{
              width: '251px',
              marginBottom: '10px',
              padding: '8px 12px',
              background: 'rgba(251,191,36,0.1)',
              border: '1px solid rgba(251,191,36,0.4)',
              borderRadius: '0px',
              fontSize: '10px',
              color: '#FBBF24',
              boxSizing: 'border-box',
            }}
          >
            Your session ended. Sign in again to continue.
          </div>
        )}
        {formError && (
          <div
            role="alert"
            style={{
              width: '251px',
              marginBottom: '10px',
              padding: '8px 12px',
              background: 'rgba(244,63,94,0.1)',
              border: '1px solid rgba(244,63,94,0.4)',
              borderRadius: '0px',
              fontSize: '10px',
              color: '#F43F5E',
              boxSizing: 'border-box',
            }}
          >
            {formError}
          </div>
        )}

        {/* 4+5 ── form */}
        <form
          onSubmit={onSubmit}
          noValidate
          style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' }}
        >
          {/* email */}
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <input
              id="email"
              type="email"
              autoComplete="username"
              autoFocus
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              aria-invalid={!!fieldErrors.email}
              aria-describedby={fieldErrors.email ? 'email-err' : undefined}
              placeholder="Email address"
              style={inputStyle(fieldErrors.email)}
              onFocus={(e) => { if (!fieldErrors.email) e.target.style.border = '1px solid rgba(105,130,180,0.55)' }}
              onBlur={(e)  => { if (!fieldErrors.email) e.target.style.border = '1px solid rgba(105,130,180,0.22)' }}
            />
            {fieldErrors.email && (
              <span id="email-err" style={{ marginTop: '3px', fontSize: '9px', color: '#F43F5E', width: '251px' }}>
                {fieldErrors.email}
              </span>
            )}
          </div>

          {/* password */}
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              aria-invalid={!!fieldErrors.password}
              aria-describedby={fieldErrors.password ? 'pw-err' : undefined}
              placeholder="Password"
              style={inputStyle(fieldErrors.password)}
              onFocus={(e) => { if (!fieldErrors.password) e.target.style.border = '1px solid rgba(105,130,180,0.55)' }}
              onBlur={(e)  => { if (!fieldErrors.password) e.target.style.border = '1px solid rgba(105,130,180,0.22)' }}
            />
            {fieldErrors.password && (
              <span id="pw-err" style={{ marginTop: '3px', fontSize: '9px', color: '#F43F5E', width: '251px' }}>
                {fieldErrors.password}
              </span>
            )}
          </div>

          {/* 6 ── sign in button */}
          <button
            type="submit"
            disabled={submitting}
            style={{
              width: '251px',
              height: '35px',
              background: '#E8EDF7',
              color: '#050914',
              fontSize: '10px',
              fontWeight: 600,
              border: 'none',
              borderRadius: '0px',
              cursor: submitting ? 'not-allowed' : 'pointer',
              opacity: submitting ? 0.7 : 1,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '6px',
              transition: 'background 0.15s',
              boxSizing: 'border-box',
            }}
            onMouseEnter={(e) => { if (!submitting) e.currentTarget.style.background = '#D6DCF0' }}
            onMouseLeave={(e) => { e.currentTarget.style.background = submitting ? '#E8EDF7' : '#E8EDF7' }}
            onMouseDown={(e)  => { if (!submitting) e.currentTarget.style.background = '#C8CEEA' }}
            onMouseUp={(e)    => { if (!submitting) e.currentTarget.style.background = '#D6DCF0' }}
          >
            {submitting && <Loader2 style={{ width: '12px', height: '12px', animation: 'spin 1s linear infinite' }} aria-hidden="true" />}
            {submitting ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        {/* 7 ── security footer */}
        <div
          style={{
            marginTop: '25px',
            fontSize: '9px',
            color: '#A9C8F5',
            textAlign: 'center',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            flexWrap: 'wrap',
            justifyContent: 'center',
          }}
        >
          <span>Scope guard active</span>
          <span style={{ color: 'rgba(169,200,245,0.4)' }}>·</span>
          <span>Every action audited</span>
          <span style={{ color: 'rgba(169,200,245,0.4)' }}>·</span>
          <span>AI is advisory only</span>
        </div>
      </div>

      {/* keyframe for spinner */}
      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  )
}
