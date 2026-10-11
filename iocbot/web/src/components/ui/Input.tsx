import { forwardRef, type InputHTMLAttributes, type ReactNode } from 'react'
import { cn } from '../../lib/utils'

export type InputProps = InputHTMLAttributes<HTMLInputElement> & {
  /** Rendered before the field; keeps it out of the tab order. */
  icon?: ReactNode
  suffix?: ReactNode
}

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { icon, suffix, className, ...props },
  ref,
) {
  return (
    <div className="relative flex items-center">
      {icon && (
        <span className="pointer-events-none absolute left-2.5 flex text-fg-subtle [&_svg]:h-4 [&_svg]:w-4">
          {icon}
        </span>
      )}
      <input
        ref={ref}
        {...props}
        className={cn(
          'ctl w-full',
          icon && 'pl-8',
          suffix && 'pr-8',
          className,
        )}
      />
      {suffix && <span className="absolute right-2 flex items-center text-fg-subtle">{suffix}</span>}
    </div>
  )
})

export const Textarea = forwardRef<
  HTMLTextAreaElement,
  React.TextareaHTMLAttributes<HTMLTextAreaElement>
>(function Textarea({ className, ...props }, ref) {
  return (
    <textarea
      ref={ref}
      {...props}
      className={cn(
        'ctl h-auto w-full resize-y py-2 leading-[1.5]',
        className,
      )}
    />
  )
})
