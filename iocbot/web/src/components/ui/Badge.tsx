import { cn } from '../../lib/utils'

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

/** Colour is semantic: severity + status only. One accent for focus. */
const SEVERITY_TEXT: Record<string, string> = {
  CRITICAL: 'text-critical',
  HIGH: 'text-high',
  MEDIUM: 'text-medium',
  LOW: 'text-low',
}
const SEVERITY_DOT: Record<string, string> = {
  CRITICAL: 'bg-critical',
  HIGH: 'bg-high',
  MEDIUM: 'bg-medium',
  LOW: 'bg-low',
}

/** 6px dot. Paired with a text label so severity is never colour-only. */
export function SeverityDot({ severity, className }: { severity: string; className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={cn('h-1.5 w-1.5 shrink-0 rounded-full', SEVERITY_DOT[severity] ?? 'bg-fg-subtle', className)}
    />
  )
}

export function SeverityLabel({ severity, className }: { severity: string; className?: string }) {
  return (
    <span className={cn('inline-flex items-center gap-1.5 text-[12px]', SEVERITY_TEXT[severity], className)}>
      <SeverityDot severity={severity} />
      {severity || 'UNKNOWN'}
    </span>
  )
}

/**
 * Flat tag: 1px border, no fill. Used for IOC type and other categorical
 * metadata, where colour would add noise rather than meaning.
 */
export function Tag({
  children,
  className,
  mono,
}: {
  children: React.ReactNode
  className?: string
  mono?: boolean
}) {
  return (
    <span
      className={cn(
        'inline-flex h-[18px] items-center rounded-[3px] border border-line px-1.5 text-[11px] text-fg-muted',
        mono && 'font-mono',
        className,
      )}
    >
      {children}
    </span>
  )
}

const STATUS_TONE: Record<string, string> = {
  valid: 'text-valid border-valid/30',
  invalid: 'text-invalid border-invalid/30',
  unknown: 'text-fg-subtle border-line',
}

/** Validation state: dot + text, again never colour alone. */
export function StatusBadge({ status }: { status: string }) {
  const key = status === 'VALID' ? 'valid' : status ? 'invalid' : 'unknown'
  const dot = key === 'valid' ? 'bg-valid' : key === 'invalid' ? 'bg-invalid' : 'bg-fg-subtle'
  return (
    <span className={cn('inline-flex h-[18px] items-center gap-1.5 rounded-[3px] border px-1.5 text-[11px]', STATUS_TONE[key])}>
      <span aria-hidden="true" className={cn('h-1.5 w-1.5 rounded-full', dot)} />
      {status || 'UNKNOWN'}
    </span>
  )
}

/** Compact 3-segment confidence meter (one indicator, never both). */
export function ConfidenceMeter({ value }: { value: string }) {
  const filled = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 3 }[value] ?? 1
  const tone = SEVERITY_TEXT[value] ?? 'text-fg-subtle'
  const on = {
    LOW: 'bg-low',
    MEDIUM: 'bg-medium',
    HIGH: 'bg-high',
    CRITICAL: 'bg-critical',
  }[value] ?? 'bg-fg-subtle'
  return (
    <span className="inline-flex items-center gap-2" title={`Confidence: ${value}`}>
      <span aria-hidden="true" className="inline-flex gap-[2px]">
        {[0, 1, 2].map((i) => (
          <span
            key={i}
            className={cn('h-3 w-[3px] rounded-[1px]', i < filled ? on : 'bg-line-strong')}
          />
        ))}
      </span>
      <span className={cn('sr-only', tone)}>{value}</span>
    </span>
  )
}
