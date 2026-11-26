import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../services/api'
import { getErrorMessage } from '../utils/errors'

const SEV_OPTS = ['critical', 'high', 'medium', 'low', 'info']
const CAT_OPTS = ['access_control', 'configuration', 'session', 'injection', 'other']

export default function ManualFinding() {
  const navigate = useNavigate()
  const [assessments, setAssessments] = useState([])
  const [form, setForm] = useState({
    assessment_id: '',
    title: '',
    severity: 'medium',
    category: 'other',
    evidence: '',
    description: '',
    remediation: '',
  })
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    api.get('/assessments/').then((r) => {
      const items = r.data?.items ?? r.data ?? []
      setAssessments(items)
      if (items.length > 0) setForm((f) => ({ ...f, assessment_id: items[0].id }))
    }).catch(() => {})
  }, [])

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }))

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSubmitting(true)
    try {
      const { data } = await api.post('/findings/', { ...form, source: 'Manual' })
      navigate(`/findings/${data.id}`)
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setSubmitting(false)
    }
  }

  const inputCls = 'w-full'
  const labelCls = 'mb-1 block'

  return (
    <div className="ui-page mx-auto max-w-2xl space-y-4">
      <div>
        <p className="mb-1 text-xs text-muted">Findings / New</p>
        <h1>Manual finding</h1>
      </div>

      {error && (
        <div
          className="ui-alert ui-alert--danger"
        >
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit} className="ui-panel space-y-4">
        <div>
          <label className={labelCls}>Assessment *</label>
          <select required value={form.assessment_id} onChange={set('assessment_id')} className={inputCls}>
            {assessments.length === 0 && <option value="">No assessments available</option>}
            {assessments.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
          </select>
        </div>

        <div>
          <label className={labelCls}>Title *</label>
          <input
            required
            placeholder="Staff can open user management"
            value={form.title}
            onChange={set('title')}
            className={inputCls}
          />
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label className={labelCls}>Severity *</label>
            <select required value={form.severity} onChange={set('severity')} className={inputCls}>
              {SEV_OPTS.map((s) => (
                <option key={s} value={s} className="capitalize">
                  {s.charAt(0).toUpperCase() + s.slice(1)}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className={labelCls}>Category *</label>
            <select required value={form.category} onChange={set('category')} className={inputCls}>
              {CAT_OPTS.map((c) => (
                <option key={c} value={c}>
                  {c.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div>
          <label className={labelCls}>Evidence</label>
          <textarea
            rows={5}
            placeholder="HTTP request/response, screenshots, raw output…"
            value={form.evidence}
            onChange={set('evidence')}
            className={`${inputCls} resize-y font-mono`}
          />
        </div>

        <div>
          <label className={labelCls}>Description</label>
          <textarea
            rows={3}
            placeholder="What was found and how it was found…"
            value={form.description}
            onChange={set('description')}
            className={`${inputCls} resize-y`}
          />
        </div>

        <div>
          <label className={labelCls}>Recommended remediation</label>
          <textarea
            rows={3}
            placeholder="Steps to fix…"
            value={form.remediation}
            onChange={set('remediation')}
            className={`${inputCls} resize-y`}
          />
        </div>

        <div className="flex justify-end gap-3 pt-2">
          <button
            type="button"
            onClick={() => navigate('/findings')}
            data-variant="outline"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={submitting}
            data-variant="primary"
          >
            {submitting ? 'Saving…' : 'Save finding'}
          </button>
        </div>
      </form>
    </div>
  )
}
