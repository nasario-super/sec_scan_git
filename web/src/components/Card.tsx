import { type ReactNode } from 'react'
import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'

interface CardProps {
  children: ReactNode
  className?: string
  hover?: boolean
  glow?: boolean
}

export function Card({ children, className, hover = false, glow = false }: CardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className={cn(
        'card-glass p-5',
        hover && 'card-hover cursor-pointer',
        glow && 'neon-border',
        className
      )}
    >
      {children}
    </motion.div>
  )
}

interface StatCardProps {
  title: string
  value: string | number
  icon?: ReactNode
  trend?: {
    value: number
    label: string
  }
  color?: 'green' | 'red' | 'yellow' | 'blue' | 'purple'
}

export function StatCard({ title, value, icon, trend, color = 'green' }: StatCardProps) {
  const colorClasses = {
    green: 'from-neon-green/20 to-transparent border-neon-green/30 text-neon-green',
    red: 'from-severity-critical/20 to-transparent border-severity-critical/30 text-severity-critical',
    yellow: 'from-severity-medium/20 to-transparent border-severity-medium/30 text-severity-medium',
    blue: 'from-neon-cyan/20 to-transparent border-neon-cyan/30 text-neon-cyan',
    purple: 'from-neon-purple/20 to-transparent border-neon-purple/30 text-neon-purple',
  }

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.3 }}
      className={cn(
        'relative overflow-hidden rounded-xl border p-5',
        'bg-gradient-to-br',
        colorClasses[color]
      )}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">
            {title}
          </p>
          <p className="text-3xl font-bold text-white font-display">
            {value}
          </p>
          {trend && (
            <p className={cn(
              'text-xs mt-2 flex items-center gap-1',
              trend.value >= 0 ? 'text-severity-low' : 'text-severity-critical'
            )}>
              <span>{trend.value >= 0 ? '↑' : '↓'}</span>
              <span>{Math.abs(trend.value)}% {trend.label}</span>
            </p>
          )}
        </div>
        {icon && (
          <div className="p-2 rounded-lg bg-slate-900/50">
            {icon}
          </div>
        )}
      </div>
      
      {/* Decorative gradient */}
      <div className="absolute -bottom-4 -right-4 w-24 h-24 rounded-full bg-current opacity-5 blur-2xl" />
    </motion.div>
  )
}

