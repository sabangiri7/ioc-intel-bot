import { X } from 'lucide-react'
import { cn } from '../../lib/utils'

/**
 * Filter chip. The remove target is a real 16px button, not a glyph, so it
 * has a reliable hit area and is reachable by keyboard.
 */
export function Chip({
  label,
  onRemove,
  className,
}: {
  label: string
  onRemove?: () => void
  className?: string
}) {
  return (
    <span
      className={cn(
        'inline-flex h-[22px] items-center gap-1 rounded-ctl border border-line bg-surface-2 pl-1.5 pr-0.5',
        'text-[12px] text-fg-muted',
        className,
      )}
    >
      <span className="max-w-[220px] truncate">{label}</span>
      {onRemove && (
        <button
          type="button"
          onClick={onRemove}
          aria-label={`Remove filter ${label}`}
          className={cn(
            'flex h-4 w-4 items-center justify-center rounded-[3px] text-fg-subtle',
            'transition-colors duration-[120ms] hover:bg-surface-3 hover:text-fg',
          )}
        >
          <X className="h-3 w-3" strokeWidth={1.5} />
        </button>
      )}
    </span>
  )
}

/** Value chip for the drawer's chip-inputs (categories, tags, folders). */
export function ValueChip({
  label,
  onRemove,
}: {
  label: string
  onRemove: () => void
}) {
  return (
    <span className="inline-flex h-[22px] items-center gap-1 rounded-ctl border border-line bg-surface-3 pl-1.5 pr-0.5 text-[12px] text-fg">
      <span className="max-w-[180px] truncate">{label}</span>
      <button
        type="button"
        onClick={onRemove}
        aria-label={`Remove ${label}`}
        className="flex h-4 w-4 items-center justify-center rounded-[3px] text-fg-subtle transition-colors hover:text-fg"
      >
        <X className="h-3 w-3" strokeWidth={1.5} />
      </button>
    </span>
  )
}

/** Static chip for category overflow ("+3"). */
export function CountChip({ n }: { n: number }) {
  return (
    <span className="inline-flex h-[18px] items-center rounded-[3px] border border-line px-1 font-mono text-[11px] text-fg-subtle">
      +{n}
    </span>
  )
}
