import { Link } from 'react-router-dom'

export default function NotFound() {
  return (
    <div className="ui-page mx-auto mt-16 max-w-md text-center">
      <h2 className="text-xl font-semibold">Page not found</h2>
      <p className="mt-2 text-sm text-muted">That address does not match any PenPal page.</p>
      <Link to="/" className="mt-4 inline-block text-sm text-accent hover:underline">Back to the dashboard</Link>
    </div>
  )
}
