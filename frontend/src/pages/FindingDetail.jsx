import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { Sparkles } from 'lucide-react'
import api from '../services/api'
import Spinner from '../components/common/Spinner'
import { getErrorMessage } from '../utils/errors'

const SEV_OPTS = ['critical', 'high', 'medium', 'low', 'info']

const SEV_TEXT = {
  critical: 'text-sev-critical',
  high: 'text-sev-high',
  medium: 'text-sev-medium',
  low: 'text-sev-low',
  info: 'text-sev-info',
}

export default function FindingDetail() {
  const { id } = useParams()
  const [finding, setFinding] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [finalSeverity, setFinalSeverity] = useState(null)
  const [remediation, setRemediation] = useState('')
  const [reason, setReason] = useState('')
  const [submitting, setSubmitting] = useState(null)

  useEffect(() => {
    api.get(`/findings/${id}`)
      .then((r) => {
        setFinding(r.data)
        setFinalSeverity(r.data.final_severity ?? r.data.ai_severity ?? r.data.tool_severity ?? null)
        setRemediation(r.data.final_remediation ?? '')
      })
      .catch((e) => setError(getErrorMessage(e)))
      .finally(() => setLoading(false))
  }, [id])

  const submitDecision = async (action) => {
    if (action === 'false_positive' && !reason.trim()) {
      alert('Reason is required to mark false positive.')
      return
    }
    setSubmitting(action)
    try {
      const payload = {
        action,
        final_severity: finalSeverity,
        final_remediation: remediation || undefined,
        reason: reason || undefined,
      }
      const { data } = await api.post(`/findings/${id}/decision`, payload)
      setFinding(data)
    } catch (e) {
      alert(getErrorMessage(e))
    } finally {
      setSubmitting(null)
    }
  }

  if (loading) return <Spinner className="mt-20" />
  if (error) return (
    <div className="ui-page ui-panel text-center text-secondary">{error}</div>
  )
  if (!finding) return null

  const tags = finding.tags ?? []
  const toolSev = finding.tool_severity
  const aiSev = finding.ai_severity
  const finalSev = finding.final_severity

  return (
    <div className="ui-page space-y-4">
      {/* Breadcrumb */}
      <div>
        <p className="mb-1 text-xs text-muted">
          <Link to="/findings" className="hover:text-accent-cyan transition-colors">Findings</Link>
          {' / '}
          <span className="text-fg">#{finding.finding_number ?? id}</span>
        </p>
        <h1>{finding.title}</h1>
        <div className="mt-2 flex flex-wrap gap-2">
          {tags.map((tag, i) => (
            <span
              key={i}
              className="ui-badge ui-badge--neutral"
            >
              {tag}
            </span>
          ))}
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
        {/* Left column */}
        <div className="space-y-5">
          {/* Evidence */}
          <div className="ui-panel">
            <p className="ui-section-heading mb-3">Evidence</p>
            <pre
              className="ui-code overflow-x-auto whitespace-pre-wrap break-all font-mono text-fg/90"
            >
              {finding.evidence ?? 'No evidence captured.'}
            </pre>
            {finding.evidence_hash && (
              <p className="mt-2 text-xs text-muted">
                SHA-256 {finding.evidence_hash} · secrets redacted
              </p>
            )}
          </div>

          {/* AI suggestion */}
          {finding.ai_explanation && (
            <div
              className="ui-alert ui-alert--info"
            >
              <div className="mb-3 flex items-center gap-2">
                <span
                  className="ui-badge ui-badge--info"
                >
                  <Sparkles className="h-3 w-3" />
                  AI-suggested
                </span>
                <span className="text-xs text-secondary">
                  Advisory · confidence {finding.ai_confidence ?? 'medium'}
                </span>
              </div>

              {finding.ai_explanation.what_this_means && (
                <>
                  <p className="ui-section-heading mb-1">What this means</p>
                  <p className="mb-3 text-sm text-secondary">{finding.ai_explanation.what_this_means}</p>
                </>
              )}
              {finding.ai_explanation.how_to_confirm && (
                <>
                  <p className="ui-section-heading mb-1">How to confirm</p>
                  <p className="mb-3 text-sm text-secondary">{finding.ai_explanation.how_to_confirm}</p>
                </>
              )}
              {finding.ai_explanation.suggested_fix && (
                <>
                  <p className="ui-section-heading mb-1">Suggested fix</p>
                  <p className="text-sm text-secondary">{finding.ai_explanation.suggested_fix}</p>
                </>
              )}
            </div>
          )}
        </div>

        {/* Right column */}
        <div className="space-y-4">
          {/* Severity comparison */}
          <div className="ui-panel">
            <p className="ui-section-heading mb-3">
              Severity · Three separate fields
            </p>
            <div className="grid grid-cols-3 gap-2 text-center">
              {/* Tool */}
              <div
                className="ui-severity-cell"
              >
                <p className="mb-1 text-xs text-muted">Tool</p>
                <p className={`text-sm font-semibold capitalize ${SEV_TEXT[toolSev] ?? 'text-secondary'}`}>
                  {toolSev ?? 'N/A'}
                </p>
              </div>
              {/* AI */}
              <div
                className={`ui-severity-cell ${aiSev ? 'ui-severity-cell--ai' : ''}`}
              >
                <p className="mb-1 text-xs text-muted">AI</p>
                <p className={`text-sm font-semibold capitalize ${SEV_TEXT[aiSev] ?? 'text-secondary'}`}>
                  {aiSev ?? 'N/A'}
                </p>
              </div>
              {/* Final */}
              <div className="ui-severity-cell">
                <p className="mb-1 text-xs text-muted">Final</p>
                <p className={`text-sm font-semibold capitalize ${SEV_TEXT[finalSev] ?? 'text-secondary'}`}>
                  {finalSev ?? 'Not set'}
                </p>
              </div>
            </div>
          </div>

          {/* Decision panel */}
          <div className="ui-panel space-y-4">
            <p className="ui-section-heading">Your Decision</p>

            {/* Severity buttons */}
            <div className="flex flex-wrap gap-2">
              {SEV_OPTS.map((s) => (
                <button
                  key={s}
                  onClick={() => setFinalSeverity(s)}
                  data-variant={finalSeverity === s ? 'primary' : 'outline'}
                >
                  {s.charAt(0).toUpperCase() + s.slice(1)}
                </button>
              ))}
            </div>

            {/* Remediation */}
            <textarea
              rows={3}
              placeholder="Final remediation (optional)"
              value={remediation}
              onChange={(e) => setRemediation(e.target.value)}
              className="w-full resize-none"
            />

            {/* Reason */}
            <textarea
              rows={2}
              placeholder="Reason (required to mark false positive)"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="w-full resize-none"
            />

            {/* Primary action */}
            <button
              onClick={() => submitDecision('confirm')}
              disabled={!!submitting}
              className="w-full"
              data-variant="primary"
            >
              {submitting === 'confirm' ? 'Confirming…' : 'Confirm finding'}
            </button>

            {/* Secondary actions */}
            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={() => submitDecision('false_positive')}
                disabled={!!submitting}
                data-variant="danger"
              >
                {submitting === 'false_positive' ? '…' : 'False positive'}
              </button>
              <button
                onClick={() => submitDecision('needs_retest')}
                disabled={!!submitting}
                data-variant="outline"
              >
                {submitting === 'needs_retest' ? '…' : 'Needs retest'}
              </button>
            </div>

            <p className="text-xs text-muted">
              Name, notes and time are recorded in the audit log. AI never sets these.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
