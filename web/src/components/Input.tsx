import { type InputHTMLAttributes, type ReactNode, forwardRef } from 'react'
import { cn } from '@/lib/utils'

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string
  error?: string
  leftIcon?: ReactNode
  rightIcon?: ReactNode
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, label, error, leftIcon, rightIcon, ...props }, ref) => {
    return (
      <div className="space-y-1.5">
        {label && (
          <label className="block text-sm font-medium text-slate-300">
            {label}
          </label>
        )}
        <div className="relative">
          {leftIcon && (
            <div className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400">
              {leftIcon}
            </div>
          )}
          <input
            ref={ref}
            className={cn(
              'w-full bg-slate-900/50 border border-slate-700 rounded-lg',
              'px-4 py-2.5 text-sm text-white placeholder:text-slate-500',
              'focus:outline-none focus:ring-2 focus:ring-neon-green/50 focus:border-neon-green/50',
              'transition-all duration-200',
              leftIcon && 'pl-10',
              rightIcon && 'pr-10',
              error && 'border-severity-critical focus:ring-severity-critical/50 focus:border-severity-critical/50',
              className
            )}
            {...props}
          />
          {rightIcon && (
            <div className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400">
              {rightIcon}
            </div>
          )}
        </div>
        {error && (
          <p className="text-xs text-severity-critical">{error}</p>
        )}
      </div>
    )
  }
)

Input.displayName = 'Input'

interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label?: string
  error?: string
  options: Array<{ value: string; label: string }>
}

export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  ({ className, label, error, options, ...props }, ref) => {
    return (
      <div className="space-y-1.5">
        {label && (
          <label className="block text-sm font-medium text-slate-300">
            {label}
          </label>
        )}
        <select
          ref={ref}
          className={cn(
            'w-full bg-slate-900/50 border border-slate-700 rounded-lg',
            'px-4 py-2.5 text-sm text-white',
            'focus:outline-none focus:ring-2 focus:ring-neon-green/50 focus:border-neon-green/50',
            'transition-all duration-200',
            'cursor-pointer',
            error && 'border-severity-critical',
            className
          )}
          {...props}
        >
          {options.map((option) => (
            <option key={option.value} value={option.value} className="bg-slate-900">
              {option.label}
            </option>
          ))}
        </select>
        {error && (
          <p className="text-xs text-severity-critical">{error}</p>
        )}
      </div>
    )
  }
)

Select.displayName = 'Select'

interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string
  error?: string
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ className, label, error, ...props }, ref) => {
    return (
      <div className="space-y-1.5">
        {label && (
          <label className="block text-sm font-medium text-slate-300">
            {label}
          </label>
        )}
        <textarea
          ref={ref}
          className={cn(
            'w-full bg-slate-900/50 border border-slate-700 rounded-lg',
            'px-4 py-2.5 text-sm text-white placeholder:text-slate-500',
            'focus:outline-none focus:ring-2 focus:ring-neon-green/50 focus:border-neon-green/50',
            'transition-all duration-200 resize-none',
            error && 'border-severity-critical',
            className
          )}
          {...props}
        />
        {error && (
          <p className="text-xs text-severity-critical">{error}</p>
        )}
      </div>
    )
  }
)

Textarea.displayName = 'Textarea'

