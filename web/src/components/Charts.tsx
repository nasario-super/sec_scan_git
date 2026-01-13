import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  Legend,
} from 'recharts'
import type { TrendPoint } from '@/types'

interface TrendChartProps {
  data: TrendPoint[]
  height?: number
}

const COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#eab308',
  low: '#22c55e',
  total: '#14b8a6',
}

export function TrendChart({ data, height = 300 }: TrendChartProps) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor={COLORS.total} stopOpacity={0.3} />
            <stop offset="95%" stopColor={COLORS.total} stopOpacity={0} />
          </linearGradient>
          <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor={COLORS.critical} stopOpacity={0.3} />
            <stop offset="95%" stopColor={COLORS.critical} stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
        <XAxis
          dataKey="date"
          stroke="#64748b"
          fontSize={11}
          tickLine={false}
          axisLine={false}
        />
        <YAxis
          stroke="#64748b"
          fontSize={11}
          tickLine={false}
          axisLine={false}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: '#1e293b',
            border: '1px solid #334155',
            borderRadius: '8px',
            fontSize: '12px',
          }}
          labelStyle={{ color: '#94a3b8' }}
        />
        <Area
          type="monotone"
          dataKey="total"
          stroke={COLORS.total}
          fill="url(#colorTotal)"
          strokeWidth={2}
          name="Total"
        />
        <Area
          type="monotone"
          dataKey="critical"
          stroke={COLORS.critical}
          fill="url(#colorCritical)"
          strokeWidth={2}
          name="Críticos"
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}

interface SeverityPieChartProps {
  data: {
    critical: number
    high: number
    medium: number
    low: number
  }
  height?: number
}

export function SeverityPieChart({ data, height = 200 }: SeverityPieChartProps) {
  const chartData = [
    { name: 'Crítico', value: data.critical, color: COLORS.critical },
    { name: 'Alto', value: data.high, color: COLORS.high },
    { name: 'Médio', value: data.medium, color: COLORS.medium },
    { name: 'Baixo', value: data.low, color: COLORS.low },
  ].filter(d => d.value > 0)

  if (chartData.length === 0) {
    return (
      <div className="flex items-center justify-center" style={{ height }}>
        <p className="text-slate-500 text-sm">Sem dados</p>
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie
          data={chartData}
          cx="50%"
          cy="50%"
          innerRadius={50}
          outerRadius={70}
          paddingAngle={2}
          dataKey="value"
        >
          {chartData.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={entry.color} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            backgroundColor: '#1e293b',
            border: '1px solid #334155',
            borderRadius: '8px',
            fontSize: '12px',
          }}
        />
        <Legend
          formatter={(value) => <span className="text-slate-300 text-xs">{value}</span>}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}

interface ComparisonBarChartProps {
  data: Array<{
    name: string
    baseline: number
    current: number
  }>
  height?: number
}

export function ComparisonBarChart({ data, height = 300 }: ComparisonBarChartProps) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
        <XAxis
          dataKey="name"
          stroke="#64748b"
          fontSize={11}
          tickLine={false}
          axisLine={false}
        />
        <YAxis
          stroke="#64748b"
          fontSize={11}
          tickLine={false}
          axisLine={false}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: '#1e293b',
            border: '1px solid #334155',
            borderRadius: '8px',
            fontSize: '12px',
          }}
        />
        <Legend />
        <Bar dataKey="baseline" fill="#64748b" name="Baseline" radius={[4, 4, 0, 0]} />
        <Bar dataKey="current" fill="#14b8a6" name="Atual" radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}

interface TopReposChartProps {
  data: Array<{ repo: string; count: number }>
  height?: number
}

export function TopReposChart({ data, height = 200 }: TopReposChartProps) {
  const chartData = data.map(d => ({
    name: d.repo.length > 20 ? d.repo.slice(0, 20) + '...' : d.repo,
    findings: d.count,
  }))

  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart
        data={chartData}
        layout="vertical"
        margin={{ top: 0, right: 10, left: 0, bottom: 0 }}
      >
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={false} />
        <XAxis type="number" stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
        <YAxis
          type="category"
          dataKey="name"
          stroke="#64748b"
          fontSize={10}
          tickLine={false}
          axisLine={false}
          width={120}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: '#1e293b',
            border: '1px solid #334155',
            borderRadius: '8px',
            fontSize: '12px',
          }}
        />
        <Bar dataKey="findings" fill="#ef4444" radius={[0, 4, 4, 0]} name="Findings" />
      </BarChart>
    </ResponsiveContainer>
  )
}

