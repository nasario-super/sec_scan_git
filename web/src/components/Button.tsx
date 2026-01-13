import { type ButtonHTMLAttributes, type ReactNode, forwardRef } from 'react'
import { cn } from '@/lib/utils'
import { Loader2 } from 'lucide-react'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger'
  size?: 'sm' | 'md' | 'lg'
  isLoading?: boolean
  leftIcon?: ReactNode
  rightIcon?: ReactNode
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      className,
      variant = 'primary',
      size = 'md',
      isLoading = false,
      leftIcon,
      rightIcon,
      children,
      disabled,
      ...props
    },
    ref
  ) => {
    const variants = {
      primary: cn(
        'bg-neon-green text-slate-950 font-semibold',
        'hover:bg-neon-green/90 hover:shadow-lg hover:shadow-neon-green/25',
        'active:scale-[0.98]'
      ),
      secondary: cn(
        'bg-slate-800 text-slate-100 border border-slate-700',
        'hover:bg-slate-700 hover:border-slate-600',
        'active:scale-[0.98]'
      ),
      ghost: cn(
        'bg-transparent text-slate-300',
        'hover:bg-slate-800 hover:text-white',
        'active:scale-[0.98]'
      ),
      danger: cn(
        'bg-severity-critical/20 text-severity-critical border border-severity-critical/40',
        'hover:bg-severity-critical hover:text-white',
        'active:scale-[0.98]'
      ),
    }

    const sizes = {
      sm: 'px-3 py-1.5 text-xs rounded-md',
      md: 'px-4 py-2 text-sm rounded-lg',
      lg: 'px-6 py-3 text-base rounded-lg',
    }

    return (
      <button
        ref={ref}
        className={cn(
          'inline-flex items-center justify-center gap-2 font-medium transition-all duration-200',
          'focus:outline-none focus:ring-2 focus:ring-neon-green/50 focus:ring-offset-2 focus:ring-offset-slate-900',
          'disabled:opacity-50 disabled:cursor-not-allowed disabled:pointer-events-none',
          variants[variant],
          sizes[size],
          className
        )}
        disabled={disabled || isLoading}
        {...props}
      >
        {isLoading ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : (
          leftIcon
        )}
        {children}
        {!isLoading && rightIcon}
      </button>
    )
  }
)

Button.displayName = 'Button'

