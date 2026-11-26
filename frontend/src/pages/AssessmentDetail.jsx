import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import api from '../services/api'
import Spinner from '../components/common/Spinner'
import { getErrorMessage } from '../utils/errors'

const SCAN_TYPES = [
  { label: 'Nmap · quick', key: 'nmap_quick' },
  { label: 'Nmap · standard', key: 'nmap_standard' },
  { label: 'ZAP · baseline', key: 'zap_baseline' },
  { label: 'ZAP · active_limited', key: 'zap_active_limited' },
]

export default function AssessmentDetail() {
  const { id } = useParams()
  const [assessment, setAssessment] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [confirming, setConfirming] = useState(false)
  const [dryRunUrl, setDryRunUrl] = useState('')
  const [dryRunResult, setDryRunResult] = useState(null)
  const [scanLaunching, setScanLaunching] = useState(null)

  useEffect(() => {
    api.get(`/assessments/${id}`)
      .then((r) => setAssessment(r.data))
      .catch((e) => setError(getErrorMessage(e)))
      .finally(() => setLoading(false))
  }, [id])

  const confirmAuth = async () => {
    setConfirming(true)
    try { const { data } = await api.post(`/assessments/${id}/confirm-authorization`); setAssessment(data) }
    catch (e) { alert(getErrorMessage(e)) }
    finally { setConfirming(false) }
  }

  const dryRun = async () => {
    if (!dryRunUrl.trim()) return
    try { const { data } = await api.post(`/assessments/${id}/scope-check`, { url: dryRunUrl }); setDryRunResult(data) }
    catch (e) { setDryRunResult({ error: getErrorMessage(e) }) }
  }

  const launchScan = async (scanKey) => {
    setScanLaunching(scanKey)
    try {
      await api.post(`/assessments/${id}/scans`, { scan_type: scanKey })
      const { data } = await api.get(`/assessments/${id}`)
      setAssessment(data)
    } catch (e) { alert(getErrorMessage(e)) }
    finally { setScanLaunching(null) }
  }

  if (loading) return <Spinner className="mt-16" />
  if (error) return <div className="ui-page ui-panel text-center text-text-secondary">{error}</div>
  if (!assessment) return null

  const authorized = assessment.authorization_status === 'Confirmed'
  const scope = assessment.scope_entries ?? []
  const stats = assessment.stats ?? {}

  return (
    <div className="ui-page space-y-4">
      {/* Breadcrumb + title */}
      <div>
        <p className="ui-caption mb-0.5">
          <Link to="/assessments" className="hover:text-primary-hover">Assessments</Link>
          {' / '}
          <span className="text-text-primary">{assessment.name}</span>
        </p>
        <h1>{assessment.name}</h1>
      </div>

      {/* Auth banner */}
      {!authorized && (
        <div
          className="ui-alert ui-alert--warning flex items-center justify-between gap-4"
        >
          <div className="flex items-center gap-2.5">
            <span className="h-2 w-2 shrink-0 rounded-full bg-warning" />
            <div>
              <p className="text-[12px] font-semibold text-text-primary">Authorization not confirmed</p>
              <p className="text-text-secondary">Scans stay blocked until you confirm written authorization. Never automatic.</p>
            </div>
          </div>
          <button
            onClick={confirmAuth}
            disabled={confirming}
            className="shrink-0"
            data-variant="primary"
          >
            {confirming ? 'Confirming…' : 'Confirm authorization'}
          </button>
        </div>
      )}

      {authorized && (
        <div className="ui-alert ui-alert--success flex items-center gap-2">
          <span className="h-1.5 w-1.5 rounded-full bg-success" />
          <p className="text-success">Authorization confirmed.</p>
        </div>
      )}

      {/* Scope + Run a scan */}
      <div className="grid gap-3 lg:grid-cols-2">
        <div className="ui-panel">
          <p className="ui-section-heading mb-3">Scope</p>
          <div className="mb-3 space-y-1.5">
            {scope.length === 0 ? (
              <p className="text-text-secondary">No scope entries defined.</p>
            ) : (
              scope.map((entry, i) => (
                <div key={i} className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: entry.in_scope === false ? 'var(--color-danger)' : 'var(--color-success)' }} />
                    <span className="truncate font-mono text-text-primary">{entry.value}</span>
                  </div>
                  <span className="shrink-0 text-text-muted">{entry.label}</span>
                </div>
              ))
            )}
          </div>
          <div className="flex gap-2">
            <input
              type="text" placeholder="Dry-run a URL against scope" value={dryRunUrl}
              onChange={(e) => setDryRunUrl(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && dryRun()}
              className="min-w-0 flex-1"
            />
            <button onClick={dryRun} data-variant="outline">
              Check
            </button>
          </div>
          {dryRunResult && (
            <p className="mt-1.5" style={{ color: dryRunResult.error ? 'var(--color-danger)' : dryRunResult.in_scope ? 'var(--color-success)' : 'var(--color-danger)' }}>
              {dryRunResult.error ?? (dryRunResult.in_scope ? 'In scope' : 'Out of scope')}
            </p>
          )}
        </div>

        <div className="ui-panel">
          <p className="ui-section-heading mb-3">Run a Scan</p>
          <div className="mb-3 flex flex-wrap gap-2">
            {SCAN_TYPES.map((s) => (
              <button
                key={s.key}
                onClick={() => authorized && launchScan(s.key)}
                disabled={!authorized || scanLaunching === s.key}
                data-variant="outline"
              >
                {scanLaunching === s.key ? 'Launching…' : s.label}
              </button>
            ))}
          </div>
          <button
            disabled={!authorized}
            className="w-full"
            data-variant="primary"
          >
            {authorized ? 'Start scan' : 'Start scan (locked until authorized)'}
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'Findings', value: stats.findings ?? 0 },
          { label: 'AI Analysis', value: `${stats.ai_pct ?? 0}%` },
          { label: 'Reports', value: stats.reports ?? 0 },
        ].map(({ label, value }) => (
          <div key={label} className="ui-panel">
            <p className="ui-caption uppercase tracking-[0.4px]">{label}</p>
            <p className="ui-stat-value mt-1">{value}</p>
          </div>
        ))}
      </div>
    </div>
  )
}
