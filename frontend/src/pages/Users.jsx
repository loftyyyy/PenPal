import { useEffect, useState } from 'react'
import { Plus } from 'lucide-react'
import api from '../services/api'
import Spinner from '../components/common/Spinner'
import { getErrorMessage } from '../utils/errors'

const ROLES = ['assessor', 'admin']

const inputCls = 'w-full'

function AddUserModal({ onClose, onCreated }) {
  const [form, setForm] = useState({ full_name: '', email: '', password: '', role: 'assessor' })
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }))

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSubmitting(true)
    try {
      const { data } = await api.post('/users/', form)
      onCreated(data)
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70" onClick={onClose} aria-hidden="true" />
      <div className="ui-panel relative z-10 w-full max-w-md">
        <h2 className="mb-4 text-[14px] font-semibold text-text-primary">Add user</h2>
        {error && (
          <p className="ui-alert ui-alert--danger mb-3">
            {error}
          </p>
        )}
        <form onSubmit={handleSubmit} className="space-y-3">
          {[
            { key: 'full_name', label: 'Full name', placeholder: 'Jane Smith', type: 'text' },
            { key: 'email', label: 'Email', placeholder: 'jane@example.com', type: 'email' },
            { key: 'password', label: 'Password', placeholder: 'Minimum 12 characters', type: 'password' },
          ].map(({ key, label, placeholder, type }) => (
            <div key={key}>
              <label className="mb-1 block uppercase tracking-wide">{label}</label>
              <input required type={type} placeholder={placeholder} value={form[key]} onChange={set(key)} className={inputCls} />
            </div>
          ))}
          <div>
            <label className="mb-1 block uppercase tracking-wide">Role</label>
            <select value={form.role} onChange={set('role')} className={inputCls}>
              {ROLES.map((r) => <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>)}
            </select>
          </div>
          <div className="flex justify-end gap-2 pt-1">
            <button type="button" onClick={onClose} data-variant="outline">Cancel</button>
            <button type="submit" disabled={submitting} data-variant="primary">
              {submitting ? 'Adding…' : 'Add user'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function EditRoleModal({ user, onClose, onSaved }) {
  const [role, setRole] = useState(user.role)
  const [submitting, setSubmitting] = useState(false)

  const save = async () => {
    setSubmitting(true)
    try {
      const { data } = await api.patch(`/users/${user.id}`, { role })
      onSaved(data)
    } catch (e) {
      alert(getErrorMessage(e))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70" onClick={onClose} aria-hidden="true" />
      <div className="ui-panel relative z-10 w-full max-w-xs">
        <h2 className="mb-3 text-[13px] font-semibold text-text-primary">Edit role — {user.full_name}</h2>
        <select value={role} onChange={(e) => setRole(e.target.value)} className={`${inputCls} mb-4`}>
          {ROLES.map((r) => <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>)}
        </select>
        <div className="flex justify-end gap-2">
          <button onClick={onClose} data-variant="outline">Cancel</button>
          <button onClick={save} disabled={submitting} data-variant="primary">
            {submitting ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Users() {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [showAdd, setShowAdd] = useState(false)
  const [editUser, setEditUser] = useState(null)

  useEffect(() => {
    api.get('/users/')
      .then((r) => setUsers(r.data?.items ?? r.data ?? []))
      .catch((e) => setError(getErrorMessage(e)))
      .finally(() => setLoading(false))
  }, [])

  const toggleActive = async (user) => {
    try {
      const { data } = await api.patch(`/users/${user.id}`, { is_active: !user.is_active })
      setUsers((prev) => prev.map((u) => (u.id === data.id ? data : u)))
    } catch (e) { alert(getErrorMessage(e)) }
  }

  const resetPassword = async (user) => {
    const newPw = prompt(`Enter new password for ${user.full_name}:`)
    if (!newPw) return
    try {
      await api.patch(`/users/${user.id}`, { password: newPw })
      alert('Password reset successfully.')
    } catch (e) { alert(getErrorMessage(e)) }
  }

  return (
    <div className="ui-page space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <h1>User management</h1>
          <span className="ui-badge ui-badge--neutral">
            Admin only
          </span>
        </div>
        <button
          onClick={() => setShowAdd(true)}
          data-variant="primary"
        >
          <Plus className="h-3 w-3" />
          + Add user
        </button>
      </div>

      {/* Table */}
      {loading ? (
        <Spinner className="mt-12" />
      ) : error ? (
        <div className="ui-panel text-center text-text-secondary">{error}</div>
      ) : (
        <div className="ui-table-container">
          <table className="ui-table">
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Status</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.length === 0 ? (
                <tr>
                  <td colSpan={4} className="text-center text-text-muted">No users found.</td>
                </tr>
              ) : (
                users.map((u) => (
                  <tr
                    key={u.id}
                    className="transition-colors"
                  >
                    <td className="px-4 py-2.5">
                      <p className="font-semibold text-text-primary leading-tight">{u.full_name}</p>
                      <p className="text-primary leading-tight mt-0.5">{u.email}</p>
                    </td>
                    <td className="capitalize text-text-secondary">{u.role}</td>
                    <td className="px-4 py-2.5">
                      <span className={`ui-badge ${u.is_active ? 'ui-badge--success' : 'ui-badge--neutral'}`}>
                        {u.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <span className="inline-flex items-center gap-2 text-text-secondary">
                        <button onClick={() => setEditUser(u)} data-variant="ghost">
                          Edit role
                        </button>
                        <span className="text-border">·</span>
                        {u.role === 'admin' ? (
                          <button onClick={() => resetPassword(u)} data-variant="ghost">
                            Reset password
                          </button>
                        ) : (
                          <button
                            onClick={() => toggleActive(u)}
                            data-variant={u.is_active ? 'danger' : 'outline'}
                          >
                            {u.is_active ? 'Deactivate' : 'Activate'}
                          </button>
                        )}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {showAdd && <AddUserModal onClose={() => setShowAdd(false)} onCreated={(u) => { setUsers((p) => [...p, u]); setShowAdd(false) }} />}
      {editUser && <EditRoleModal user={editUser} onClose={() => setEditUser(null)} onSaved={(u) => { setUsers((p) => p.map((x) => x.id === u.id ? u : x)); setEditUser(null) }} />}
    </div>
  )
}
