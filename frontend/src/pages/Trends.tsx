import { useState, useEffect } from 'react';
import {
  TrendingUp,
  TrendingDown,
  BarChart3,
} from 'lucide-react';
import { clsx } from 'clsx';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import api from '../services/api';
import type { TrendData } from '../types';
import { format } from 'date-fns';

const severityColors = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
  total: '#8b5cf6',
  resolved: '#10b981',
};

export function Trends() {
  const [trends, setTrends] = useState<TrendData[]>([]);
  const [loading, setLoading] = useState(true);
  const [days, setDays] = useState(30);
  const [organization] = useState<string | null>(null);
  const [chartType, setChartType] = useState<'line' | 'area' | 'bar'>('area');

  useEffect(() => {
    const fetchTrends = async () => {
      try {
        setLoading(true);
        const data = await api.getTrends(days);
        setTrends(data);
      } catch (error) {
        console.error('Failed to fetch trends:', error);
        setTrends([]);
      } finally {
        setLoading(false);
      }
    };

    fetchTrends();
  }, [days, organization]);

  // Calculate summary statistics
  const latest = trends[trends.length - 1];
  const previous = trends[trends.length - 2];
  const totalChange = latest && previous
    ? latest.total - previous.total
    : 0;
  const criticalChange = latest && previous
    ? latest.critical - previous.critical
    : 0;
  const resolvedChange = latest && previous
    ? latest.resolved - previous.resolved
    : 0;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-neon-blue border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-400">Loading trends...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Security Trends</h1>
          <p className="text-gray-500">
            Track findings over time and identify patterns
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
            className="input py-2"
          >
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
            <option value={180}>Last 6 months</option>
            <option value={365}>Last year</option>
          </select>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-gray-500">Total Findings</span>
            {totalChange !== 0 && (
              <div className={clsx(
                'flex items-center gap-1 text-xs',
                totalChange > 0 ? 'text-neon-red' : 'text-neon-green'
              )}>
                {totalChange > 0 ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
                {Math.abs(totalChange)}
              </div>
            )}
          </div>
          <p className="text-3xl font-bold text-gray-100">
            {latest?.total || 0}
          </p>
          {previous && (
            <p className="text-xs text-gray-500 mt-1">
              {previous.total} previous period
            </p>
          )}
        </div>

        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-gray-500">Critical Issues</span>
            {criticalChange !== 0 && (
              <div className={clsx(
                'flex items-center gap-1 text-xs',
                criticalChange > 0 ? 'text-neon-red' : 'text-neon-green'
              )}>
                {criticalChange > 0 ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
                {Math.abs(criticalChange)}
              </div>
            )}
          </div>
          <p className="text-3xl font-bold text-neon-red">
            {latest?.critical || 0}
          </p>
          {previous && (
            <p className="text-xs text-gray-500 mt-1">
              {previous.critical} previous period
            </p>
          )}
        </div>

        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-gray-500">Resolved</span>
            {resolvedChange !== 0 && (
              <div className={clsx(
                'flex items-center gap-1 text-xs',
                resolvedChange > 0 ? 'text-neon-green' : 'text-gray-500'
              )}>
                {resolvedChange > 0 ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
                {Math.abs(resolvedChange)}
              </div>
            )}
          </div>
          <p className="text-3xl font-bold text-neon-green">
            {latest?.resolved || 0}
          </p>
          {previous && (
            <p className="text-xs text-gray-500 mt-1">
              {previous.resolved} previous period
            </p>
          )}
        </div>
      </div>

      {/* Chart Type Selector */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-gray-100">Findings Over Time</h2>
          <div className="flex gap-2">
            <button
              onClick={() => setChartType('line')}
              className={clsx(
                'px-3 py-1 text-xs rounded-md border transition-colors',
                chartType === 'line'
                  ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
                  : 'border-cyber-border text-gray-400 hover:border-gray-500'
              )}
            >
              Line
            </button>
            <button
              onClick={() => setChartType('area')}
              className={clsx(
                'px-3 py-1 text-xs rounded-md border transition-colors',
                chartType === 'area'
                  ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
                  : 'border-cyber-border text-gray-400 hover:border-gray-500'
              )}
            >
              Area
            </button>
            <button
              onClick={() => setChartType('bar')}
              className={clsx(
                'px-3 py-1 text-xs rounded-md border transition-colors',
                chartType === 'bar'
                  ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
                  : 'border-cyber-border text-gray-400 hover:border-gray-500'
              )}
            >
              Bar
            </button>
          </div>
        </div>

        {trends.length === 0 ? (
          <div className="h-64 flex items-center justify-center text-gray-500">
            <div className="text-center">
              <BarChart3 className="w-12 h-12 mx-auto mb-2 opacity-50" />
              <p>No trend data available</p>
              <p className="text-sm">Run some scans to see trends</p>
            </div>
          </div>
        ) : (
          <div className="h-96">
            <ResponsiveContainer width="100%" height="100%">
              {chartType === 'line' ? (
                <LineChart data={trends}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis
                    dataKey="date"
                    stroke="#9ca3af"
                    tickFormatter={(value) => format(new Date(value), 'MMM dd')}
                  />
                  <YAxis stroke="#9ca3af" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1f2937',
                      border: '1px solid #374151',
                      borderRadius: '8px',
                    }}
                    labelFormatter={(value) => format(new Date(value), 'MMM dd, yyyy')}
                  />
                  <Legend />
                  <Line
                    type="monotone"
                    dataKey="critical"
                    stroke={severityColors.critical}
                    strokeWidth={2}
                    name="Critical"
                  />
                  <Line
                    type="monotone"
                    dataKey="high"
                    stroke={severityColors.high}
                    strokeWidth={2}
                    name="High"
                  />
                  <Line
                    type="monotone"
                    dataKey="medium"
                    stroke={severityColors.medium}
                    strokeWidth={2}
                    name="Medium"
                  />
                  <Line
                    type="monotone"
                    dataKey="total"
                    stroke={severityColors.total}
                    strokeWidth={3}
                    name="Total"
                    strokeDasharray="5 5"
                  />
                </LineChart>
              ) : chartType === 'area' ? (
                <AreaChart data={trends}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis
                    dataKey="date"
                    stroke="#9ca3af"
                    tickFormatter={(value) => format(new Date(value), 'MMM dd')}
                  />
                  <YAxis stroke="#9ca3af" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1f2937',
                      border: '1px solid #374151',
                      borderRadius: '8px',
                    }}
                    labelFormatter={(value) => format(new Date(value), 'MMM dd, yyyy')}
                  />
                  <Legend />
                  <Area
                    type="monotone"
                    dataKey="critical"
                    stackId="1"
                    stroke={severityColors.critical}
                    fill={severityColors.critical}
                    fillOpacity={0.6}
                    name="Critical"
                  />
                  <Area
                    type="monotone"
                    dataKey="high"
                    stackId="1"
                    stroke={severityColors.high}
                    fill={severityColors.high}
                    fillOpacity={0.6}
                    name="High"
                  />
                  <Area
                    type="monotone"
                    dataKey="medium"
                    stackId="1"
                    stroke={severityColors.medium}
                    fill={severityColors.medium}
                    fillOpacity={0.6}
                    name="Medium"
                  />
                  <Area
                    type="monotone"
                    dataKey="low"
                    stackId="1"
                    stroke={severityColors.low}
                    fill={severityColors.low}
                    fillOpacity={0.6}
                    name="Low"
                  />
                </AreaChart>
              ) : (
                <BarChart data={trends}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis
                    dataKey="date"
                    stroke="#9ca3af"
                    tickFormatter={(value) => format(new Date(value), 'MMM dd')}
                  />
                  <YAxis stroke="#9ca3af" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1f2937',
                      border: '1px solid #374151',
                      borderRadius: '8px',
                    }}
                    labelFormatter={(value) => format(new Date(value), 'MMM dd, yyyy')}
                  />
                  <Legend />
                  <Bar dataKey="critical" fill={severityColors.critical} name="Critical" />
                  <Bar dataKey="high" fill={severityColors.high} name="High" />
                  <Bar dataKey="medium" fill={severityColors.medium} name="Medium" />
                  <Bar dataKey="low" fill={severityColors.low} name="Low" />
                </BarChart>
              )}
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Resolved vs New Findings */}
      {trends.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold text-gray-100 mb-4">Resolved vs New Findings</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trends}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis
                  dataKey="date"
                  stroke="#9ca3af"
                  tickFormatter={(value) => format(new Date(value), 'MMM dd')}
                />
                <YAxis stroke="#9ca3af" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1f2937',
                    border: '1px solid #374151',
                    borderRadius: '8px',
                  }}
                  labelFormatter={(value) => format(new Date(value), 'MMM dd, yyyy')}
                />
                <Legend />
                <Area
                  type="monotone"
                  dataKey="total"
                  stroke={severityColors.total}
                  fill={severityColors.total}
                  fillOpacity={0.3}
                  name="New Findings"
                />
                <Area
                  type="monotone"
                  dataKey="resolved"
                  stroke={severityColors.resolved}
                  fill={severityColors.resolved}
                  fillOpacity={0.3}
                  name="Resolved"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}
    </div>
  );
}
