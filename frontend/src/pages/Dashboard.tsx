import { useEffect, useState } from 'react';
import {
  Shield,
  AlertTriangle,
  GitBranch,
  CheckCircle,
  TrendingUp,
  TrendingDown,
  Activity,
  Clock,
  ArrowRight,
} from 'lucide-react';
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
} from 'recharts';
import { Link } from 'react-router-dom';
import { clsx } from 'clsx';
import api from '../services/api';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import type { DashboardStats, TrendData, Severity } from '../types';
import { formatDistanceToNow } from 'date-fns';

// Empty initial stats
const emptyStats: DashboardStats = {
  total_repositories: 0,
  total_findings: 0,
  open_findings: 0,
  resolved_findings: 0,
  findings_by_severity: {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  },
  findings_by_type: {
    secret: 0,
    vulnerability: 0,
    sast: 0,
    iac: 0,
    history: 0,
  },
  recent_scans: [],
  top_repositories: [],
  trends: [],
};

const SEVERITY_COLORS = {
  critical: '#ff1744',
  high: '#ff5722',
  medium: '#ffc107',
  low: '#4caf50',
  info: '#2196f3',
};

interface StatCardProps {
  title: string;
  value: number | string;
  change?: number;
  icon: React.ElementType;
  color: 'blue' | 'green' | 'red' | 'yellow' | 'purple';
  trend?: 'up' | 'down';
}

function StatCard({ title, value, change, icon: Icon, color, trend }: StatCardProps) {
  const colorClasses = {
    blue: 'text-neon-blue border-neon-blue/30 bg-neon-blue/5',
    green: 'text-neon-green border-neon-green/30 bg-neon-green/5',
    red: 'text-neon-red border-neon-red/30 bg-neon-red/5',
    yellow: 'text-neon-yellow border-neon-yellow/30 bg-neon-yellow/5',
    purple: 'text-neon-purple border-neon-purple/30 bg-neon-purple/5',
  };

  return (
    <div className="stat-card animate-fadeIn">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-gray-500 mb-1">{title}</p>
          <p className="text-3xl font-bold text-gray-100 font-mono">{value}</p>
          {change !== undefined && (
            <div className={clsx(
              'flex items-center gap-1 mt-2 text-sm',
              trend === 'up' ? 'text-neon-red' : 'text-neon-green'
            )}>
              {trend === 'up' ? <TrendingUp className="w-4 h-4" /> : <TrendingDown className="w-4 h-4" />}
              <span>{Math.abs(change)}% from last week</span>
            </div>
          )}
        </div>
        <div className={clsx(
          'p-3 rounded-lg border',
          colorClasses[color]
        )}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </div>
  );
}

function SeverityChart({ data }: { data: Record<Severity, number> }) {
  const chartData = Object.entries(data).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
    color: SEVERITY_COLORS[name as Severity],
  }));

  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={80}
            paddingAngle={2}
            dataKey="value"
          >
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: '#1a2234',
              border: '1px solid #2d3748',
              borderRadius: '8px',
            }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="flex flex-wrap justify-center gap-4 mt-4">
        {chartData.map((entry) => (
          <div key={entry.name} className="flex items-center gap-2">
            <div
              className="w-3 h-3 rounded-full"
              style={{ backgroundColor: entry.color }}
            />
            <span className="text-sm text-gray-400">
              {entry.name}: {entry.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function TrendsChart({ data }: { data: TrendData[] }) {
  return (
    <div className="h-80">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data}>
          <defs>
            <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ff1744" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#ff1744" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ff5722" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#ff5722" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="colorMedium" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ffc107" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#ffc107" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#2d3748" />
          <XAxis dataKey="date" stroke="#6b7280" fontSize={12} />
          <YAxis stroke="#6b7280" fontSize={12} />
          <Tooltip
            contentStyle={{
              backgroundColor: '#1a2234',
              border: '1px solid #2d3748',
              borderRadius: '8px',
            }}
          />
          <Area
            type="monotone"
            dataKey="critical"
            stackId="1"
            stroke="#ff1744"
            fill="url(#colorCritical)"
          />
          <Area
            type="monotone"
            dataKey="high"
            stackId="1"
            stroke="#ff5722"
            fill="url(#colorHigh)"
          />
          <Area
            type="monotone"
            dataKey="medium"
            stackId="1"
            stroke="#ffc107"
            fill="url(#colorMedium)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

function TopRepositoriesChart({ data }: { data: Array<{ name: string; findings_count: number }> }) {
  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical">
          <CartesianGrid strokeDasharray="3 3" stroke="#2d3748" horizontal={false} />
          <XAxis type="number" stroke="#6b7280" fontSize={12} />
          <YAxis
            type="category"
            dataKey="name"
            stroke="#6b7280"
            fontSize={12}
            width={120}
            tick={{ fill: '#9ca3af' }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#1a2234',
              border: '1px solid #2d3748',
              borderRadius: '8px',
            }}
          />
          <Bar dataKey="findings_count" fill="#00d4ff" radius={[0, 4, 4, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// Default empty severity for safety
const defaultSeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
const defaultFindingTypes = { secret: 0, vulnerability: 0, sast: 0, iac: 0, history: 0 };

export function Dashboard() {
  const [stats, setStats] = useState<DashboardStats>(emptyStats);
  const [trends, setTrends] = useState<TrendData[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [dashboardData, trendsData] = await Promise.all([
          api.getDashboard().catch(() => emptyStats),
          api.getTrends(14).catch(() => []),
        ]);
        
        // Ensure findings_by_severity exists with defaults
        const safeData: DashboardStats = {
          ...dashboardData,
          findings_by_severity: {
            ...defaultSeverity,
            ...(dashboardData.findings_by_severity || {}),
          },
          findings_by_type: {
            ...defaultFindingTypes,
            ...(dashboardData.findings_by_type || {}),
          },
          top_repositories: dashboardData.top_repositories || [],
          recent_scans: dashboardData.recent_scans || [],
        };
        
        setStats(safeData);
        setTrends(trendsData || []);
      } catch (error) {
        console.error('Failed to fetch dashboard data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const severityData = stats.findings_by_severity || defaultSeverity;
  const openFindingsCount = (severityData.critical || 0) + (severityData.high || 0);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-neon-blue border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-400">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Repositories"
          value={stats.total_repositories}
          icon={GitBranch}
          color="blue"
        />
        <StatCard
          title="Open Findings"
          value={stats.open_findings}
          change={12}
          trend="up"
          icon={AlertTriangle}
          color="red"
        />
        <StatCard
          title="Resolved"
          value={stats.resolved_findings}
          change={8}
          trend="down"
          icon={CheckCircle}
          color="green"
        />
        <StatCard
          title="Security Score"
          value={`${stats.total_findings > 0 ? Math.round((1 - openFindingsCount / stats.total_findings) * 100) : 100}%`}
          icon={Shield}
          color="purple"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution */}
        <div className="card-glow">
          <h3 className="section-title mb-4">
            <Activity className="w-5 h-5 text-neon-blue" />
            Severity Distribution
          </h3>
          <SeverityChart data={severityData} />
        </div>

        {/* Trends Chart */}
        <div className="card-glow lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h3 className="section-title">
              <TrendingUp className="w-5 h-5 text-neon-blue" />
              Findings Trend (14 days)
            </h3>
            <Link to="/trends" className="text-sm text-neon-blue hover:underline flex items-center gap-1">
              View All <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
          {trends.length > 0 ? (
            <TrendsChart data={trends} />
          ) : (
            <div className="text-center py-8 text-gray-500 h-80 flex flex-col items-center justify-center">
              <TrendingUp className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p>No trend data available</p>
              <p className="text-sm">Run scans over time to see trends</p>
            </div>
          )}
        </div>
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Repositories */}
        <div className="card-glow">
          <div className="flex items-center justify-between mb-4">
            <h3 className="section-title">
              <GitBranch className="w-5 h-5 text-neon-blue" />
              Top Repositories by Findings
            </h3>
            <Link to="/repositories" className="text-sm text-neon-blue hover:underline flex items-center gap-1">
              View All <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
          {stats.top_repositories.length > 0 ? (
            <TopRepositoriesChart data={stats.top_repositories} />
          ) : (
            <div className="text-center py-8 text-gray-500 h-64 flex flex-col items-center justify-center">
              <GitBranch className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p>No repository data available</p>
              <p className="text-sm">Run a scan to see results</p>
            </div>
          )}
        </div>

        {/* Recent Scans */}
        <div className="card-glow">
          <div className="flex items-center justify-between mb-4">
            <h3 className="section-title">
              <Clock className="w-5 h-5 text-neon-blue" />
              Recent Scans
            </h3>
            <Link to="/scans" className="text-sm text-neon-blue hover:underline flex items-center gap-1">
              View All <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
          <div className="space-y-3">
            {stats.recent_scans.length === 0 ? (
              <div className="text-center py-8 text-gray-500">
                <Clock className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>No scans yet</p>
                <Link to="/scans" className="text-neon-blue hover:underline text-sm">Start your first scan →</Link>
              </div>
            ) : stats.recent_scans.map((scan) => (
              <div
                key={scan.id}
                className="flex items-center justify-between p-3 rounded-lg bg-cyber-surface/50 
                         border border-cyber-border/50 hover:border-neon-blue/30 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <div className={clsx(
                    'w-2 h-2 rounded-full',
                    scan.status === 'completed' && 'bg-neon-green',
                    scan.status === 'running' && 'bg-neon-yellow animate-pulse',
                    scan.status === 'failed' && 'bg-neon-red',
                    scan.status === 'pending' && 'bg-gray-500'
                  )} />
                  <div>
                    <p className="text-sm font-medium text-gray-200">
                      {scan.organization || scan.repository}
                    </p>
                    <p className="text-xs text-gray-500">
                      {formatDistanceToNow(new Date(scan.started_at), { addSuffix: true })}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {scan.status === 'completed' && (
                    <div className="flex gap-1">
                      {scan.findings_count.critical > 0 && (
                        <SeverityBadge severity="critical" />
                      )}
                      {scan.findings_count.high > 0 && (
                        <SeverityBadge severity="high" />
                      )}
                      {scan.findings_count.total === 0 && (
                        <span className="text-xs text-neon-green">Clean</span>
                      )}
                    </div>
                  )}
                  {scan.status === 'running' && (
                    <span className="text-xs text-neon-yellow">Scanning...</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Critical Findings Alert */}
      {stats.findings_by_severity.critical > 0 && (
        <div className="card border-neon-red/50 bg-neon-red/5 animate-fadeIn">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-lg bg-neon-red/20 border border-neon-red/30">
                <AlertTriangle className="w-6 h-6 text-neon-red" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-100">
                  {stats.findings_by_severity.critical} Critical Findings Detected
                </h3>
                <p className="text-sm text-gray-400">
                  Immediate action required. Critical vulnerabilities may expose sensitive data.
                </p>
              </div>
            </div>
            <Link to="/findings?severity=critical" className="btn-danger">
              View Critical Findings
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
