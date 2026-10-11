import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react'
import { cn } from '../../lib/utils'

type Variant = 'primary' | 'ghost' | 'danger'
type Size = 'sm' | 'md'

/** Quiet, hairline-first button. No gradient, no glow, no bounce. */
export const Button = forwardRef<
  HTMLButtonElement,
  ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: Size }
>(function Button({ variant = 'ghost', size = 'md', className, ...props }, ref) {
  const base =
    'inline-flex shrink-0 items-center justify-center gap-1.5 whitespace-nowrap rounded-ctl ' +
    'font-medium transition-[background-color,border-color,color,transform] duration-[140ms] ease-out ' +
    'disabled:pointer-events-none disabled:opacity-40 active:translate-y-px'
  const sizes: Record<Size, string> = {
    sm: 'h-6 px-2 text-[12px]',
    md: 'h-8 px-2.5 text-[13px]',
  }
  const variants: Record<Variant, string> = {
    // Accent is reserved for the single primary action.
    primary: 'bg-accent text-app hover:bg-accent/90',
    ghost:
      'border border-line bg-transparent text-fg-muted hover:border-line-strong hover:bg-surface-2 hover:text-fg',
    danger:
      'border border-line bg-transparent text-critical hover:border-critical/40 hover:bg-critical/10',
  }
  return (
    <button
      ref={ref}
      {...props}
      className={cn(base, sizes[size], variants[variant], className)}
    />
  )
})

/** Icon-only button: square hit area, no label. Requires aria-label. */
export const IconButton = forwardRef<
  HTMLButtonElement,
  ButtonHTMLAttributes<HTMLButtonElement> & { label: string; size?: Size }
>(function IconButton({ label, size = 'md', className, ...props }, ref) {
  return (
    <Button
      ref={ref}
      aria-label={label}
      title={label}
      {...props}
      className={cn(size === 'sm' ? 'h-6 w-6 p-0' : 'h-8 w-8 p-0', className)}
    />
  )
})

export function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd
      className={cn(
        'inline-flex h-[18px] min-w-[18px] items-center justify-center rounded-[3px]',
        'border border-line bg-surface-2 px-1 font-mono text-[10.5px] text-fg-subtle',
      )}
    >
      {children}
    </kbd>
  )
}
