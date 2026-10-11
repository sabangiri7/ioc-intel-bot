import * as PopoverPrimitive from '@radix-ui/react-popover'
import * as TooltipPrimitive from '@radix-ui/react-tooltip'
import type { ReactNode } from 'react'
import { cn } from '../../lib/utils'

export const Popover = PopoverPrimitive.Root
export const PopoverTrigger = PopoverPrimitive.Trigger
export const PopoverAnchor = PopoverPrimitive.Anchor

export function PopoverContent({
  children,
  className,
  align = 'start',
  sideOffset = 6,
  ...props
}: React.ComponentPropsWithoutRef<typeof PopoverPrimitive.Content> & {
  align?: 'start' | 'center' | 'end'
}) {
  return (
    <PopoverPrimitive.Portal>
      <PopoverPrimitive.Content
        align={align}
        sideOffset={sideOffset}
        {...props}
        className={cn(
          // Floating layer: the one place a shadow is allowed.
          'z-50 rounded-panel border border-line-strong bg-surface-3 p-1 shadow-float',
          'data-[state=open]:animate-[fadeIn_120ms_ease-out]',
          className,
        )}
      >
        {children}
      </PopoverPrimitive.Content>
    </PopoverPrimitive.Portal>
  )
}

export const TooltipProvider = TooltipPrimitive.Provider

export function Tooltip({
  content,
  children,
  side = 'top',
  delay = 400,
}: {
  content: ReactNode
  children: ReactNode
  side?: 'top' | 'right' | 'bottom' | 'left'
  delay?: number
}) {
  if (!content) return <>{children}</>
  return (
    <TooltipPrimitive.Root delayDuration={delay}>
      <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
      <TooltipPrimitive.Portal>
        <TooltipPrimitive.Content
          side={side}
          sideOffset={6}
          className={cn(
            'z-50 max-w-[280px] rounded-ctl border border-line-strong bg-surface-3 px-2 py-1',
            'text-[12px] text-fg shadow-float',
          )}
        >
          {content}
        </TooltipPrimitive.Content>
      </TooltipPrimitive.Portal>
    </TooltipPrimitive.Root>
  )
}

/** Row used inside popovers and menus. */
export function MenuItem({
  children,
  onSelect,
  destructive,
  className,
  disabled,
}: {
  children: ReactNode
  onSelect?: () => void
  destructive?: boolean
  className?: string
  disabled?: boolean
}) {
  return (
    <button
      type="button"
      role="menuitem"
      disabled={disabled}
      onClick={onSelect}
      className={cn(
        'flex h-[26px] w-full items-center gap-2 rounded-[3px] px-2 text-left text-[12.5px]',
        'transition-colors duration-[120ms] disabled:opacity-40',
        destructive
          ? 'text-critical hover:bg-critical/10'
          : 'text-fg-muted hover:bg-surface-2 hover:text-fg',
        className,
      )}
    >
      {children}
    </button>
  )
}

/** Checkbox row for the column picker. */
export function MenuCheckItem({
  checked,
  onSelect,
  children,
}: {
  checked: boolean
  onSelect: () => void
  children: ReactNode
}) {
  return (
    <button
      type="button"
      role="menuitemcheckbox"
      aria-checked={checked}
      onClick={onSelect}
      className={cn(
        'flex h-[26px] w-full items-center gap-2 rounded-[3px] px-2 text-left text-[12.5px]',
        'text-fg-muted transition-colors duration-[120ms] hover:bg-surface-2 hover:text-fg',
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          'flex h-3.5 w-3.5 items-center justify-center rounded-[2px] border',
          checked ? 'border-accent bg-accent' : 'border-line-strong',
        )}
      />
      {children}
    </button>
  )
}
