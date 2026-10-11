import { Check, Minus } from 'lucide-react'
import { cn } from '../../lib/utils'

export type CheckedState = boolean | 'indeterminate'

/**
 * 14px custom checkbox. Radix handles semantics and the indeterminate state;
 * this only paints it, so it never looks like a default native control.
 */
export function Checkbox({
  state,
  onChange,
  label,
  className,
  size = 14,
}: {
  state: CheckedState
  onChange: (next: boolean) => void
  label: string
  className?: string
  size?: number
}) {
  const checked = state === true
  const indeterminate = state === 'indeterminate'
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={indeterminate ? 'mixed' : checked}
      aria-label={label}
      onClick={(e) => {
        e.stopPropagation()
        onChange(!checked)
      }}
      style={{ width: size, height: size }}
      className={cn(
        'inline-flex shrink-0 items-center justify-center rounded-[3px] border transition-colors duration-[120ms]',
        checked || indeterminate
          ? 'border-accent bg-accent text-app'
          : 'border-line-strong bg-surface-2 hover:border-fg-subtle',
        className,
      )}
    >
      {indeterminate ? (
        <Minus style={{ width: size - 6, height: size - 6 }} strokeWidth={2.5} />
      ) : checked ? (
        <Check style={{ width: size - 6, height: size - 6 }} strokeWidth={2.5} />
      ) : null}
    </button>
  )
}
