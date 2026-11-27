import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { RadialBarChart, RadialBar, PolarAngleAxis } from 'recharts'
import api from '../services/api'
import Spinner from '../components/common/Spinner'
import { getErrorMessage } from '../utils/errors'

const SEV_BAR_COLOR = {
  critical: 'var(--color-severity-critical)',
  high: 'var(--color-severity-high)',
  medium: 'var(--color-severity-medium)',
  low: 'var(--color-severity-low)',
  info: 'var(--color-severity-info)',
}
const SEV_TEXT_COLOR = SEV_BAR_COLOR
const SEV_DOT_COLOR = SEV_BAR_COLOR
const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }
const SCAN_STATUS_COLOR = {
  Completed: 'var(--color-success)',
  Running: 'var(--color-info)',
  Failed: 'var(--color-danger)',
}

function StatCard({ label, value, color }) {
  return (
    <div className="ui-panel">
      <p className="ui-caption uppercase tracking-[0.4px]">{label}</p>
      <p className="ui-stat-value mt-1" style={{ color: color || 'var(--color-text-primary)' }}>{value}</p>
    </div>
  )
}

function SevBar({ label, value, max, sev }) {
  const pct = max > 0 ? (value / max) * 100 : 0
  return (
    <div className="flex items-center gap-2">
      <span className="w-12 text-[10px] font-medium" style={{ color: SEV_TEXT_COLOR[sev] }}>{label}</span>
      <div className="h-[6px] flex-1 overflow-hidden" style={{ background: 'var(--color-border)', borderRadius: 'var(--radius-xs)' }}>
        <div className="h-full" style={{ width: `${pct}%`, background: SEV_BAR_COLOR[sev], borderRadius: 'var(--radius-xs)' }}
          role="progressbar" aria-valuenow={value} aria-valuemin={0} aria-valuemax={max} />
      </div>
    </div>
  )
}

function VerifBar({ label, value, max, color }) {
  const pct = max > 0 ? (value / max) * 100 : 0
  return (
    <div className="flex items-center gap-2">
      <span className="w-16 text-text-secondary">{label}</span>
      <div className="h-[6px] flex-1 overflow-hidden" style={{ background: 'var(--color-border)', borderRadius: 'var(--radius-xs)' }}>
        <div className="h-full" style={{ width: `${pct}%`, background: color, borderRadius: 'var(--radius-xs)' }} />
      </div>
    </div>
  )
}

function AiDonut({ pct }) {
  return (
    <div className="relative flex items-center justify-center">
      <RadialBarChart width={110} height={110} innerRadius="68%" outerRadius="100%"
        data={[{ value: pct }]} startAngle={90} endAngle={-270}>
        <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
        <RadialBar background={{ fill: 'var(--color-border)' }} dataKey="value" angleAxisId={0} fill="var(--color-primary)" cornerRadius={4} />
      </RadialBarChart>
      <span className="absolute text-[16px] font-bold text-text-primary">{pct}%</span>
    </div>
  )
}

export default function Dashboard() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    api.get('/dashboard/')
      .then((r) => setData(r.data))
      .catch((e) => setError(getErrorMessage(e)))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <Spinner className="mt-16" />
  if (error) return <div className="ui-page ui-panel text-center text-text-secondary">{error}</div>

  const counts = data?.severity_counts || {}
  const total = data?.total_findings ?? 0
  const verif = data?.verification_status || {}
  const scans = data?.recent_scans || []
  const topFindings = data?.top_confirmed_findings || []
  const aiPct = data?.ai_coverage_pct ?? 0
  const assessment = data?.assessment
  const maxSev = Math.max(...Object.values(counts), 1)
  const maxVerif = Math.max(...Object.values(verif), 1)

  return (
    <div className="ui-page space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="ui-caption mb-0.5">
            Dashboard
            {assessment && (
              <> / <Link to={`/assessments/${assessment.id}`} className="text-primary hover:underline">Assessment</Link></>
            )}
          </p>
          <h1>{assessment?.name ?? 'Dashboard'}</h1>
        </div>
        {assessment && (
          <div className="flex items-center gap-2">
            <div className="ui-badge ui-badge--neutral">
              Assessment: <span className="font-semibold text-text-primary">{assessment.short_name ?? assessment.name}</span>
            </div>
            <div className="ui-badge ui-badge--success">
              <span className="h-1.5 w-1.5 rounded-full bg-success" />
              Authorized · scope guard on
            </div>
          </div>
        )}
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-3 gap-2 sm:grid-cols-6">
        <StatCard label="Total" value={total} />
        <StatCard label="Critical" value={counts.critical ?? 0} color="var(--color-severity-critical)" />
        <StatCard label="High" value={counts.high ?? 0} color="var(--color-severity-high)" />
        <StatCard label="Medium" value={counts.medium ?? 0} color="var(--color-severity-medium)" />
        <StatCard label="Low" value={counts.low ?? 0} color="var(--color-severity-low)" />
        <StatCard label="Info" value={counts.info ?? 0} color="var(--color-severity-info)" />
      </div>

      {/* Middle row */}
      <div className="grid gap-3 lg:grid-cols-3">
        <div className="ui-panel">
          <p className="ui-section-heading mb-3">Severity · Tool/AI-suggested for unverified</p>
          <div className="space-y-2.5">
            {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
              <SevBar key={s} label={SEV_LABEL[s]} value={counts[s] ?? 0} max={maxSev} sev={s} />
            ))}
          </div>
        </div>

        <div className="ui-panel">
          <p className="ui-section-heading mb-3">Verification Status</p>
          <div className="space-y-2.5">
            <VerifBar label="Pending"    value={verif.pending ?? 0}        max={maxVerif} color="var(--color-info)" />
            <VerifBar label="Confirmed"  value={verif.confirmed ?? 0}      max={maxVerif} color="var(--color-success)" />
            <VerifBar label="False pos." value={verif.false_positive ?? 0} max={maxVerif} color="var(--color-text-muted)" />
            <VerifBar label="Retest"     value={verif.needs_retest ?? 0}   max={maxVerif} color="var(--color-severity-low)" />
          </div>
        </div>

        <div className="ui-panel flex flex-col items-center justify-center">
          <p className="ui-section-heading mb-2">AI Coverage</p>
          <AiDonut pct={aiPct} />
          <p className="ui-caption mt-2">{data?.ai_analyzed ?? 0} of {total} analyzed</p>
        </div>
      </div>

      {/* Bottom row */}
      <div className="grid gap-3 lg:grid-cols-2">
        <div className="ui-panel">
          <p className="ui-section-heading mb-3">Scan History</p>
          {scans.length === 0 ? (
            <p className="text-text-secondary">No scans yet.</p>
          ) : (
            <div className="space-y-2">
              {scans.map((scan, i) => (
                <div key={i} className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <span className="text-[12px] font-semibold text-text-primary">{scan.tool}</span>
                    <span className="text-text-secondary">{scan.profile}</span>
                  </div>
                  <span className="text-[11px] font-medium" style={{ color: SCAN_STATUS_COLOR[scan.status] ?? 'var(--color-text-secondary)' }}>
                    {scan.status}{scan.duration && ` · ${scan.duration}`}{scan.progress != null && scan.status === 'Running' && ` · ${scan.progress}%`}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="ui-panel">
          <p className="ui-section-heading mb-3">Top Confirmed Findings</p>
          {topFindings.length === 0 ? (
            <p className="text-text-secondary">No confirmed findings yet.</p>
          ) : (
            <div className="space-y-2">
              {topFindings.map((f, i) => (
                <div key={i} className="flex items-center justify-between gap-3">
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: SEV_DOT_COLOR[f.severity] ?? 'var(--color-text-muted)' }} />
                    <Link to={`/findings/${f.id}`} className="truncate text-text-primary hover:text-primary hover:underline">{f.title}</Link>
                  </div>
                  <span className="shrink-0 text-text-muted">{f.category}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <p className="ui-caption">
        Sample data for design only · Last updated {new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
      </p>
    </div>
  )
}
