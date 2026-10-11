import { cn } from '../../lib/utils'

export interface SegmentOption<T extends string> {
  value: T
  label: string
  title?: string
}

/**
 * Segmented control for small, mutually exclusive sets (severity/confidence
 * edits in the drawer). Reads as one control, not N buttons.
 */
export function SegmentedControl<T extends string>({
  options,
  value,
  onChange,
  ariaLabel,
  className,
}: {
  options: SegmentOption<T>[]
  value: T
  onChange: (next: T) => void
  ariaLabel: string
  className?: string
}) {
  return (
    <div
      role="radiogroup"
      aria-label={ariaLabel}
      className={cn(
        'inline-flex h-8 items-center gap-0.5 rounded-ctl border border-line bg-surface-2 p-0.5',
        className,
      )}
    >
      {options.map((o) => {
        const active = o.value === value
        return (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={active}
            title={o.title}
            onClick={() => onChange(o.value)}
            className={cn(
              'h-[26px] rounded-[3px] px-2 text-[12px] font-medium transition-colors duration-[120ms]',
              active
                ? 'bg-surface-3 text-fg'
                : 'text-fg-subtle hover:bg-surface-3/60 hover:text-fg-muted',
            )}
          >
            {o.label}
          </button>
        )
      })}
    </div>
  )
}
