import { Construction } from 'lucide-react'

export default function PagePlaceholder({ title, phase }) {
  return (
    <div className="rounded-lg border border-dashed border-line bg-surface p-10 text-center">
      <Construction className="mx-auto mb-3 h-7 w-7 text-muted" aria-hidden="true" />
      <h2 className="text-lg font-semibold">{title}</h2>
      <p className="mt-1 text-sm text-muted">This page is built in {phase}.</p>
    </div>
  )
}
