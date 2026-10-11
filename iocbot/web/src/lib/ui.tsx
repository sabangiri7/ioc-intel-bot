import type { ReactNode } from 'react'
import type { Confidence } from './api'

export const EMPTY = '—'

export function severityColor(s: string): string {
  switch (s) {
    case 'CRITICAL':
      return 'text-crit'
    case 'HIGH':
      return 'text-high'
    case 'MEDIUM':
      return 'text-med'
    default:
      return 'text-low'
  }
}

export function SeverityBadge({ value }: { value: string }) {
  return (
    <span
      className={`inline-block rounded-[4px] px-1.5 py-0.5 text-[11px] font-semibold uppercase ${severityColor(value)}`}
      style={{ background: 'rgb(255 255 255 / 0.05)' }}
    >
      {value || EMPTY}
    </span>
  )
}

/** Confidence is shown as a bar plus its label, so it is not colour-only. */
export function ConfidenceBar({ value }: { value: Confidence | string }) {
  const pct: Record<string, number> = { CRITICAL: 100, HIGH: 75, MEDIUM: 50, LOW: 25 }
  const width = pct[value] ?? 25
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="inline-block h-1.5 w-10 overflow-hidden rounded-full bg-bg4">
        <span
          className={`block h-full ${severityColor(value)}`}
          style={{ width: `${width}%`, background: 'currentColor' }}
        />
      </span>
      <span className="text-[11px] text-dim">{value || EMPTY}</span>
    </span>
  )
}

export function TypeTag({ value }: { value: string }) {
  return (
    <span className="rounded-[4px] border border-line2 bg-bg3 px-1.5 py-0.5 text-[11px] text-dim">
      {value}
    </span>
  )
}

type BtnVariant = 'primary' | 'ghost' | 'danger'

export function Button({
  variant = 'ghost',
  className = '',
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: BtnVariant }) {
  const styles: Record<BtnVariant, string> = {
    primary: 'bg-accent border-accent text-[#05131F] font-semibold hover:bg-[#55A8FF]',
    ghost: 'bg-transparent border-line2 text-text hover:bg-bg4 hover:border-accent',
    danger: 'bg-[rgb(229_72_77/0.12)] border-danger text-danger-ink hover:bg-[rgb(229_72_77/0.2)]',
  }
  return (
    <button
      {...props}
      className={`cursor-pointer rounded-ctl border px-2.5 py-1.5 transition-colors disabled:cursor-default disabled:opacity-45 focus-visible:outline-none focus-visible:border-accent focus-visible:shadow-[0_0_0_2px_rgb(61_155_250/0.13)] active:translate-y-px ${styles[variant]} ${className}`}
    />
  )
}

/** Loading placeholder shaped like the content it replaces (no layout jump). */
export function Skeleton({ className = '' }: { className?: string }) {
  return <span className={`block animate-pulse rounded bg-bg4 ${className}`} />
}

export function EmptyState({
  title,
  hint,
  action,
}: {
  title: string
  hint?: string
  action?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center gap-2 px-5 py-11 text-center">
      <p className="text-[13.5px] text-dim">{title}</p>
      {hint && <p className="max-w-md text-[12px] text-faint">{hint}</p>}
      {action}
    </div>
  )
}

export function Modal({
  title,
  onClose,
  children,
  wide,
}: {
  title: string
  onClose: () => void
  children: ReactNode
  wide?: boolean
}) {
  return (
    <div
      className="fixed inset-0 z-[70] flex items-center justify-center bg-[rgb(4_7_12/0.74)] p-5"
      onClick={onClose}
      role="presentation"
    >
      <div
        className={`max-h-[90vh] w-full overflow-y-auto rounded-card border border-line2 bg-bg2 p-4 shadow-xl ${wide ? 'max-w-[860px]' : 'max-w-[480px]'}`}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <h3 className="mb-2 text-[15px] font-semibold">{title}</h3>
        {children}
      </div>
    </div>
  )
}

export function ErrorText({ children }: { children?: ReactNode }) {
  if (!children) return null
  return <p className="mt-2 text-[12px] text-[#FF8D8D]">{children}</p>
}

export function Toast({ message, error }: { message: string; error?: boolean }) {
  return (
    <div
      className={`fixed bottom-6 left-1/2 z-[90] max-w-[80vw] -translate-x-1/2 rounded-[9px] border px-4 py-2.5 text-[13px] shadow-xl ${
        error ? 'border-danger bg-[#43171B] text-[#FFB3B3]' : 'border-line2 bg-bg3 text-text'
      }`}
      role="status"
    >
      {message}
    </div>
  )
}

export function num(n: number | undefined): string {
  return (n ?? 0).toLocaleString()
}