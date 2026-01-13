import { cn } from '@/lib/utils'
import type { Severity, RemediationStatus, FindingType } from '@/types'

interface SeverityBadgeProps {
  severity: Severity
  size?: 'sm' | 'md'
}

export function SeverityBadge({ severity, size = 'md' }: SeverityBadgeProps) {
  const colors: Record<Severity, string> = {
    critical: 'bg-severity-critical/20 text-severity-critical border-severity-critical/40',
    high: 'bg-severity-high/20 text-severity-high border-severity-high/40',
    medium: 'bg-severity-medium/20 text-severity-medium border-severity-medium/40',
    low: 'bg-severity-low/20 text-severity-low border-severity-low/40',
    info: 'bg-severity-info/20 text-severity-info border-severity-info/40',
  }

  const labels: Record<Severity, string> = {
    critical: 'Crítico',
    high: 'Alto',
    medium: 'Médio',
    low: 'Baixo',
    info: 'Info',
  }

  return (
    <span
      className={cn(
        'inline-flex items-center font-semibold uppercase tracking-wider border rounded-md',
        colors[severity],
        size === 'sm' ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-1 text-xs'
      )}
    >
      {labels[severity]}
    </span>
  )
}

interface StatusBadgeProps {
  status: RemediationStatus
  size?: 'sm' | 'md'
}

export function StatusBadge({ status, size = 'md' }: StatusBadgeProps) {
  const colors: Record<RemediationStatus, string> = {
    open: 'bg-status-open/20 text-status-open border-status-open/40',
    in_progress: 'bg-status-in-progress/20 text-status-in-progress border-status-in-progress/40',
    fixed: 'bg-status-fixed/20 text-status-fixed border-status-fixed/40',
    wont_fix: 'bg-slate-600/20 text-slate-400 border-slate-500/40',
    false_positive: 'bg-purple-500/20 text-purple-400 border-purple-500/40',
    accepted_risk: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
  }

  const labels: Record<RemediationStatus, string> = {
    open: 'Aberto',
    in_progress: 'Em Progresso',
    fixed: 'Corrigido',
    wont_fix: 'Não Corrigir',
    false_positive: 'Falso Positivo',
    accepted_risk: 'Risco Aceito',
  }

  return (
    <span
      className={cn(
        'inline-flex items-center font-medium border rounded-md',
        colors[status],
        size === 'sm' ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-1 text-xs'
      )}
    >
      {labels[status]}
    </span>
  )
}

interface TypeBadgeProps {
  type: FindingType
  size?: 'sm' | 'md'
}

export function TypeBadge({ type, size = 'md' }: TypeBadgeProps) {
  const colors: Record<FindingType, string> = {
    secret: 'bg-amber-500/20 text-amber-400 border-amber-500/40',
    vulnerability: 'bg-red-500/20 text-red-400 border-red-500/40',
    bug: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
    misconfig: 'bg-blue-500/20 text-blue-400 border-blue-500/40',
  }

  const icons: Record<FindingType, string> = {
    secret: '🔑',
    vulnerability: '⚠️',
    bug: '🐛',
    misconfig: '⚙️',
  }

  const labels: Record<FindingType, string> = {
    secret: 'Segredo',
    vulnerability: 'Vulnerabilidade',
    bug: 'Bug',
    misconfig: 'Config',
  }

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 font-medium border rounded-md',
        colors[type],
        size === 'sm' ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-1 text-xs'
      )}
    >
      <span>{icons[type]}</span>
      <span>{labels[type]}</span>
    </span>
  )
}

