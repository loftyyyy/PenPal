import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Plus, Search, ChevronDown, ChevronLeft, ChevronRight } from 'lucide-react'
import api from '../services/api'
import Spinner from '../components/common/Spinner'
import { getErrorMessage } from '../utils/errors'

const STATUS_LABEL = {
  confirmed: 'Confirmed',
  pending: 'Pending',
  false_positive: 'False positive',
  needs_retest: 'Needs retest',
}

const PAGE_SIZE = 15

function FilterPill({ label, options, value, onChange }) {
  return (
    <div style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        /* appearance:none removes the native browser arrow so only our SVG shows */
        style={{ appearance: 'none', WebkitAppearance: 'none', paddingRight: '22px', paddingLeft: '8px' }}
        className="appearance-none"
      >
        {/* no ▾ character here — the ChevronDown SVG below is the sole arrow */}
        <option value="">{label}</option>
        {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
      {/* single custom chevron, pointer-events:none so clicks pass through to <select> */}
      <ChevronDown
        aria-hidden="true"
        style={{
          position: 'absolute',
          right: '6px',
          top: '50%',
          transform: 'translateY(-50%)',
          width: '11px',
          height: '11px',
          pointerEvents: 'none',
          color: '#64748B',
          flexShrink: 0,
        }}
      />
    </div>
  )
}

export default function Findings() {
  const navigate = useNavigate()
  const [items, setItems] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [category, setCategory] = useState('')
  const [source, setSource] = useState('')

  const load = () => {
    setLoading(true)
    const params = new URLSearchParams({ page, page_size: PAGE_SIZE })
    if (search) params.set('search', search)
    if (severity) params.set('severity', severity)
    if (status) params.set('status', status)
    if (category) params.set('category', category)
    if (source) params.set('source', source)
    api.get(`/findings/?${params}`)
      .then((r) => { setItems(r.data?.items ?? r.data ?? []); setTotal(r.data?.total ?? r.data?.length ?? 0) })
      .catch((e) => setError(getErrorMessage(e)))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [page, severity, status, category, source]) // eslint-disable-line
  useEffect(() => { const t = setTimeout(load, 300); return () => clearTimeout(t) }, [search]) // eslint-disable-line

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <div className="ui-page space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1>Findings</h1>
        <Link to="/findings/new" className="ui-button" data-variant="primary">
          <Plus className="h-3 w-3" /> Manual finding
        </Link>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="ui-search-wrapper">
          <Search className="ui-search-icon" aria-hidden="true" />
          <input
            type="search"
            placeholder="Search findings"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="ui-search-input"
            style={{ width: '176px' }}
          />
        </div>
        <FilterPill label="Severity" value={severity} onChange={(v) => { setSeverity(v); setPage(1) }}
          options={[{ value: 'critical', label: 'Critical' }, { value: 'high', label: 'High' }, { value: 'medium', label: 'Medium' }, { value: 'low', label: 'Low' }, { value: 'info', label: 'Info' }]} />
        <FilterPill label="Status" value={status} onChange={(v) => { setStatus(v); setPage(1) }}
          options={[{ value: 'pending', label: 'Pending' }, { value: 'confirmed', label: 'Confirmed' }, { value: 'false_positive', label: 'False positive' }, { value: 'needs_retest', label: 'Needs retest' }]} />
        <FilterPill label="Category" value={category} onChange={(v) => { setCategory(v); setPage(1) }}
          options={[{ value: 'access_control', label: 'Access control' }, { value: 'configuration', label: 'Configuration' }, { value: 'session', label: 'Session' }, { value: 'injection', label: 'Injection' }, { value: 'other', label: 'Other' }]} />
        <FilterPill label="Source" value={source} onChange={(v) => { setSource(v); setPage(1) }}
          options={[{ value: 'Manual', label: 'Manual' }, { value: 'ZAP', label: 'ZAP' }, { value: 'Nmap', label: 'Nmap' }]} />
      </div>

      {loading ? <Spinner className="mt-12" /> : error ? (
        <div className="ui-panel text-center text-text-secondary">{error}</div>
      ) : (
        <>
          <div className="ui-table-container">
            <table className="ui-table">
              <thead>
                <tr>
                  {['Title', 'Severity', 'Category', 'Source', 'Status', 'Last Seen'].map((h) => (
                    <th key={h}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {items.length === 0 ? (
                  <tr><td colSpan={6} className="text-center text-text-muted">No findings found.</td></tr>
                ) : (
                  items.map((f) => (
                    <tr
                      key={f.id}
                      className="cursor-pointer transition-colors"
                      onClick={() => navigate(`/findings/${f.id}`)}
                    >
                      <td className="px-4 py-2.5 font-semibold text-text-primary">{f.title}</td>
                      <td className="px-4 py-2.5">
                        <span className={`ui-badge ui-badge--severity ui-badge--${f.severity}`}>
                          {f.severity}
                        </span>
                      </td>
                      <td className="capitalize text-text-secondary">{f.category?.replace(/_/g, ' ')}</td>
                      <td className="text-text-secondary">{f.source}</td>
                      <td className="px-4 py-2.5">
                        <span className={`ui-badge ${f.status === 'confirmed' ? 'ui-badge--success' : f.status === 'needs_retest' ? 'ui-badge--warning' : f.status === 'pending' ? 'ui-badge--info' : 'ui-badge--neutral'}`}>
                          {STATUS_LABEL[f.status] ?? f.status}
                        </span>
                        {f.ai_suggested && f.status === 'pending' && <span className="ml-1 text-text-muted">· +AI</span>}
                      </td>
                      <td className="text-text-muted">
                        {f.last_seen ? new Date(f.last_seen).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '—'}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between text-text-muted">
            <span>Showing {items.length > 0 ? `${(page - 1) * PAGE_SIZE + 1}–${Math.min(page * PAGE_SIZE, total)}` : '0'} of {total}</span>
            <div className="flex items-center gap-1">
              <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} data-variant="ghost"
                className="flex items-center gap-0.5 px-2 py-1 hover:text-text-primary disabled:opacity-40 transition-colors">
                <ChevronLeft className="h-3 w-3" /> Prev
              </button>
              {Array.from({ length: Math.min(totalPages, 5) }, (_, i) => i + 1).map((p) => (
                <button key={p} onClick={() => setPage(p)} data-variant={page === p ? 'outline' : 'ghost'}
                  className="px-2 py-1 transition-colors hover:text-text-primary"
                >
                  {p}
                </button>
              ))}
              <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page === totalPages} data-variant="ghost"
                className="flex items-center gap-0.5 px-2 py-1 hover:text-text-primary disabled:opacity-40 transition-colors">
                Next <ChevronRight className="h-3 w-3" />
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
