import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, Search, ChevronDown } from 'lucide-react'
import api from '../services/api'
import Spinner from '../components/common/Spinner'
import { getErrorMessage } from '../utils/errors'

const STATUS_OPTS = ['All', 'Draft', 'In progress', 'Completed']
function NewAssessmentModal({ onClose, onCreated }) {
  const [form, setForm] = useState({
    name: '', description: '', target_name: '', target_url: '',
    authorizing_person: '', authorization_reference: '', hosting_environment: '', categories: '',
  })
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }))

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSubmitting(true)
    try {
      const payload = { ...form, categories: form.categories ? form.categories.split(',').map((c) => c.trim()).filter(Boolean) : [] }
      const { data } = await api.post('/assessments/', payload)
      onCreated(data)
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setSubmitting(false)
    }
  }

  const fieldCls = 'w-full'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70" onClick={onClose} aria-hidden="true" />
      <div className="ui-panel relative z-10 w-full max-w-lg">
        <h2 className="mb-4 text-[14px] font-semibold text-text-primary">New assessment</h2>
        {error && <p className="ui-alert ui-alert--danger mb-3">{error}</p>}
        <form onSubmit={handleSubmit} className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label className="mb-1 block uppercase tracking-wide">Name *</label>
              <input required placeholder="LSRS Final Assessment" value={form.name} onChange={set('name')} className={fieldCls} />
            </div>
            <div>
              <label className="mb-1 block uppercase tracking-wide">Target name *</label>
              <input required placeholder="host.docker.internal" value={form.target_name} onChange={set('target_name')} className={fieldCls} />
            </div>
          </div>
          <div>
            <label className="mb-1 block uppercase tracking-wide">Target URL *</label>
            <input required placeholder="http://host.docker.internal:8080" value={form.target_url} onChange={set('target_url')} className={fieldCls} />
          </div>
          <div>
            <label className="mb-1 block uppercase tracking-wide">Description</label>
            <textarea rows={2} placeholder="Short description…" value={form.description} onChange={set('description')} className={`${fieldCls} resize-none`} />
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label className="mb-1 block uppercase tracking-wide">Authorizing person</label>
              <input placeholder="John Smith" value={form.authorizing_person} onChange={set('authorizing_person')} className={fieldCls} />
            </div>
            <div>
              <label className="mb-1 block uppercase tracking-wide">Authorization ref.</label>
              <input placeholder="Ticket #123" value={form.authorization_reference} onChange={set('authorization_reference')} className={fieldCls} />
            </div>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label className="mb-1 block uppercase tracking-wide">Hosting environment</label>
              <input placeholder="Docker / local" value={form.hosting_environment} onChange={set('hosting_environment')} className={fieldCls} />
            </div>
            <div>
              <label className="mb-1 block uppercase tracking-wide">Categories (comma-sep.)</label>
              <input placeholder="web, api" value={form.categories} onChange={set('categories')} className={fieldCls} />
            </div>
          </div>
          <div className="flex justify-end gap-2 pt-1">
            <button type="button" onClick={onClose} data-variant="outline">Cancel</button>
            <button type="submit" disabled={submitting} data-variant="primary">{submitting ? 'Creating…' : 'Create'}</button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function Assessments() {
  const navigate = useNavigate()
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('All')
  const [showNew, setShowNew] = useState(false)

  useEffect(() => {
    api.get('/assessments/')
      .then((r) => setItems(r.data?.items ?? r.data ?? []))
      .catch((e) => setError(getErrorMessage(e)))
      .finally(() => setLoading(false))
  }, [])

  const filtered = items.filter((a) => {
    const matchSearch = !search || a.name.toLowerCase().includes(search.toLowerCase())
    const matchStatus = statusFilter === 'All' || a.status === statusFilter
    return matchSearch && matchStatus
  })

  const fmtDate = (d) => {
    if (!d) return '—'
    return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
  }

  return (
    <div className="ui-page space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1>Assessments</h1>
        <button onClick={() => setShowNew(true)} data-variant="primary">
          <Plus className="h-3 w-3" /> New assessment
        </button>
      </div>

      <div className="flex items-center gap-2">
        <div className="ui-search-wrapper">
          <Search className="ui-search-icon" aria-hidden="true" />
          <input
            type="search"
            placeholder="Search assessments"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="ui-search-input"
            style={{ width: '192px' }}
          />
        </div>
        <div className="relative">
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="appearance-none pr-6">
            {STATUS_OPTS.map((s) => <option key={s} value={s}>Status: {s}</option>)}
          </select>
          <ChevronDown className="pointer-events-none absolute right-1.5 top-1/2 h-3 w-3 -translate-y-1/2 text-text-muted" />
        </div>
      </div>

      {loading ? <Spinner className="mt-12" /> : error ? (
        <div className="ui-panel text-center text-text-secondary">{error}</div>
      ) : (
        <div className="ui-table-container">
          <table className="ui-table">
            <thead>
              <tr>
                {['Name', 'Target', 'Status', 'Authorization', 'Created'].map((h) => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr><td colSpan={5} className="text-center text-text-muted">No assessments found.</td></tr>
              ) : (
                filtered.map((a) => (
                  <tr
                    key={a.id}
                    className="cursor-pointer transition-colors"
                    onClick={() => navigate(`/assessments/${a.id}`)}
                  >
                    <td className="px-4 py-2.5 font-semibold text-text-primary">{a.name}</td>
                    <td className="font-mono text-primary">{a.target_url ?? a.target_name}</td>
                    <td className="px-4 py-2.5">
                      <span className={`ui-badge ${a.status === 'Completed' ? 'ui-badge--success' : a.status === 'In progress' ? 'ui-badge--info' : 'ui-badge--neutral'}`}>
                        {a.status}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`ui-badge ${a.authorization_status === 'Confirmed' ? 'ui-badge--success' : 'ui-badge--warning'}`}>
                        {a.authorization_status ?? 'Not confirmed'}
                      </span>
                    </td>
                    <td className="text-text-muted">{fmtDate(a.created_at)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      <p className="ui-caption">
        Sample data · Create form fields: name, description, target name and URL, authorizing person, authorization reference, hosting environment, categories
      </p>

      {showNew && (
        <NewAssessmentModal
          onClose={() => setShowNew(false)}
          onCreated={(a) => { setItems((p) => [a, ...p]); setShowNew(false); navigate(`/assessments/${a.id}`) }}
        />
      )}
    </div>
  )
}
