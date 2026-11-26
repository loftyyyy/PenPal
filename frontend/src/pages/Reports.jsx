import { useEffect, useState } from 'react'
import { ChevronDown, Download, Eye } from 'lucide-react'
import api from '../services/api'
import Spinner from '../components/common/Spinner'
import { getErrorMessage } from '../utils/errors'

export default function Reports() {
  const [reports, setReports] = useState([])
  const [assessments, setAssessments] = useState([])
  const [selectedAssessment, setSelectedAssessment] = useState('')
  const [format, setFormat] = useState('PDF')
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    Promise.all([
      api.get('/reports/').catch(() => ({ data: [] })),
      api.get('/assessments/').catch(() => ({ data: [] })),
    ]).then(([rRes, aRes]) => {
      setReports(rRes.data?.items ?? rRes.data ?? [])
      const aItems = aRes.data?.items ?? aRes.data ?? []
      setAssessments(aItems)
      if (aItems.length > 0) setSelectedAssessment(aItems[0].id)
    }).catch((e) => setError(getErrorMessage(e)))
      .finally(() => setLoading(false))
  }, [])

  const generate = async () => {
    if (!selectedAssessment) return
    setGenerating(true)
    try {
      const { data } = await api.post('/reports/', {
        assessment_id: selectedAssessment,
        format: format.toLowerCase(),
      })
      setReports((prev) => [data, ...prev])
    } catch (e) {
      alert(getErrorMessage(e))
    } finally {
      setGenerating(false)
    }
  }

  const download = async (report) => {
    try {
      const res = await api.get(`/reports/${report.id}/download`, { responseType: 'blob' })
      const url = URL.createObjectURL(res.data)
      const a = document.createElement('a')
      a.href = url
      a.download = `${report.assessment_name ?? 'report'}.${report.format}`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      alert(getErrorMessage(e))
    }
  }

  const preview = async (report) => {
    try {
      const res = await api.get(`/reports/${report.id}/download`, { responseType: 'blob' })
      const url = URL.createObjectURL(res.data)
      window.open(url, '_blank')
    } catch (e) {
      alert(getErrorMessage(e))
    }
  }

  const fmtDate = (d) => {
    if (!d) return '—'
    return new Date(d).toLocaleString('en-US', {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    })
  }

  const selectedName = assessments.find((a) => a.id === selectedAssessment)?.name ?? 'Assessment'

  return (
    <div className="ui-page space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1>Reports</h1>
        <button
          onClick={generate}
          disabled={generating || !selectedAssessment}
          data-variant="primary"
        >
          {generating ? 'Generating…' : 'Generate report'}
        </button>
      </div>

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative">
          <select
            value={selectedAssessment}
            onChange={(e) => setSelectedAssessment(e.target.value)}
            className="appearance-none pr-7"
          >
            {assessments.length === 0 && (
              <option value="">No assessments</option>
            )}
            {assessments.map((a) => (
              <option key={a.id} value={a.id}>Assessment: {a.name}</option>
            ))}
          </select>
          <ChevronDown className="pointer-events-none absolute right-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
        </div>

        {/* Format toggle */}
        {['PDF', 'HTML'].map((f) => (
          <button
            key={f}
            onClick={() => setFormat(f)}
            data-variant={format === f ? 'primary' : 'outline'}
          >
            {f}
          </button>
        ))}
      </div>

      <p className="text-xs text-accent-cyan">
        ✦ Only confirmed findings are included. Unverified AI suggestions stay out of the main report.
      </p>

      {/* Table */}
      {loading ? (
        <Spinner className="mt-16" />
      ) : error ? (
        <div className="ui-panel text-center text-secondary">{error}</div>
      ) : (
        <div className="ui-table-container">
          <table className="ui-table">
            <thead>
              <tr>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-widest text-muted">Report</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-widest text-muted">Format</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-widest text-muted">Generated</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-widest text-muted">By</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-widest text-muted">Action</th>
              </tr>
            </thead>
            <tbody>
              {reports.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-10 text-center text-secondary">
                    No reports yet. Generate one above.
                  </td>
                </tr>
              ) : (
                reports.map((r) => (
                  <tr
                    key={r.id}
                    className="transition-colors"
                  >
                    <td className="px-4 py-3.5 font-semibold text-fg">
                      {r.assessment_name ?? selectedName}
                    </td>
                    <td className="px-4 py-3.5 text-xs font-medium uppercase text-secondary">
                      {r.format?.toUpperCase()}
                    </td>
                    <td className="px-4 py-3.5 text-xs text-secondary">{fmtDate(r.generated_at ?? r.created_at)}</td>
                    <td className="px-4 py-3.5 capitalize text-secondary">{r.generated_by ?? 'Assessor'}</td>
                    <td className="px-4 py-3.5">
                      {r.format?.toLowerCase() === 'html' ? (
                        <button
                          onClick={() => preview(r)}
                          data-variant="outline"
                        >
                          <Eye className="h-3.5 w-3.5" /> Preview
                        </button>
                      ) : (
                        <button
                          onClick={() => download(r)}
                          data-variant="outline"
                        >
                          <Download className="h-3.5 w-3.5" /> Download
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
