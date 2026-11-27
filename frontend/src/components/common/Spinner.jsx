import { Loader2 } from 'lucide-react'

export default function Spinner({ label = 'Loading', className = '' }) {
  return (
    <div role="status" className={`ui-spinner ${className}`}>
      <Loader2 className="animate-spin" aria-hidden="true" />
      <span>{label}</span>
    </div>
  )
}
