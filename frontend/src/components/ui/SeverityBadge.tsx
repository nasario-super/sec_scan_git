import { clsx } from 'clsx';
import type { Severity } from '../../types';

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

const severityConfig = {
  critical: {
    label: 'Critical',
    className: 'badge-critical',
    icon: '🔴',
  },
  high: {
    label: 'High',
    className: 'badge-high',
    icon: '🟠',
  },
  medium: {
    label: 'Medium',
    className: 'badge-medium',
    icon: '🟡',
  },
  low: {
    label: 'Low',
    className: 'badge-low',
    icon: '🟢',
  },
  info: {
    label: 'Info',
    className: 'badge-info',
    icon: '🔵',
  },
};

const sizeClasses = {
  sm: 'text-xs px-2 py-0.5',
  md: 'text-sm px-2.5 py-1',
  lg: 'text-base px-3 py-1.5',
};

export function SeverityBadge({ severity, size = 'sm', showIcon = false }: SeverityBadgeProps) {
  const config = severityConfig[severity];

  return (
    <span className={clsx(config.className, sizeClasses[size])}>
      {showIcon && <span className="mr-1">{config.icon}</span>}
      {config.label}
    </span>
  );
}
