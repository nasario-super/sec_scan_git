import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  GitBranch,
  ExternalLink,
  Download,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Clock,
  Key,
  Bug,
  Code,
  Cloud,
  History,
  ShieldAlert,
  ChevronDown,
  ChevronRight,
  FileCode,
  Copy,
  Eye,
  XCircle,
  Filter,
} from 'lucide-react';
import { clsx } from 'clsx';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts';
import { formatDistanceToNow } from 'date-fns';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { useStore } from '../stores/useStore';
import api from '../services/api';
import type { Finding, Severity, FindingType, RemediationStatus } from '../types';

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#ff1744',
  high: '#ff5722',
  medium: '#ffc107',
  low: '#4caf50',
  info: '#2196f3',
};

const TYPE_CONFIG: Record<string, { label: string; icon: React.ElementType; color: string }> = {
  secret: { label: 'Secrets', icon: Key, color: 'text-neon-red' },
  vulnerability: { label: 'CVEs', icon: ShieldAlert, color: 'text-neon-orange' },
  sast: { label: 'SAST', icon: Code, color: 'text-neon-purple' },
  iac: { label: 'IaC', icon: Cloud, color: 'text-neon-blue' },
  history: { label: 'History', icon: History, color: 'text-gray-400' },
  bug: { label: 'Bugs', icon: Bug, color: 'text-neon-yellow' },
};

const statusConfig: Record<RemediationStatus, { label: string; icon: React.ElementType; color: string }> = {
  open: { label: 'Open', icon: AlertTriangle, color: 'text-neon-red' },
  in_progress: { label: 'In Progress', icon: Clock, color: 'text-neon-yellow' },
  resolved: { label: 'Resolved', icon: CheckCircle, color: 'text-neon-green' },
  false_positive: { label: 'False Positive', icon: XCircle, color: 'text-gray-500' },
  accepted_risk: { label: 'Accepted Risk', icon: Eye, color: 'text-neon-purple' },
};

interface RepositoryStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  by_type: Record<string, number>;
  by_status: Record<string, number>;
}

function FindingRow({ finding, expanded, onToggle, onStatusUpdate }: {
  finding: Finding;
  expanded: boolean;
  onToggle: () => void;
  onStatusUpdate: (status: RemediationStatus) => void;
}) {
  const status = statusConfig[finding.remediation_status] || statusConfig.open;
  const StatusIcon = status.icon;
  const typeConfig = TYPE_CONFIG[finding.type] || { label: finding.type, icon: Code, color: 'text-gray-400' };
  const TypeIcon = typeConfig.icon;

  return (
    <>
      <tr className="table-row cursor-pointer hover:bg-cyber-surface/50" onClick={onToggle}>
        <td className="px-4 py-3">
          <button className="text-gray-500 hover:text-gray-300">
            {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          </button>
        </td>
        <td className="px-4 py-3">
          <SeverityBadge severity={finding.severity} />
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <TypeIcon className={clsx('w-4 h-4', typeConfig.color)} />
            <span className="text-sm text-gray-200">{finding.category}</span>
          </div>
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4 text-gray-500" />
            <span className="text-sm text-gray-400 font-mono truncate max-w-xs">
              {finding.file_path}
              {finding.line_number && `:${finding.line_number}`}
            </span>
          </div>
        </td>
        <td className="px-4 py-3">
          <div className={clsx('flex items-center gap-1', status.color)}>
            <StatusIcon className="w-4 h-4" />
            <span className="text-sm">{status.label}</span>
          </div>
        </td>
      </tr>
      {expanded && (
        <tr className="bg-cyber-surface/30">
          <td colSpan={5} className="px-4 py-4">
            <div className="space-y-4">
              {finding.line_content && (
                <div>
                  <p className="text-sm font-medium text-gray-400 mb-2">Affected Code</p>
                  <div className="code-block relative group">
                    <code className="text-neon-yellow">{finding.line_content}</code>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        navigator.clipboard.writeText(finding.line_content || '');
                      }}
                      className="absolute top-2 right-2 p-1 text-gray-500 hover:text-gray-300 
                               opacity-0 group-hover:opacity-100 transition-opacity"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              )}

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div>
                  <p className="text-xs text-gray-500 mb-1">Branch</p>
                  <p className="text-sm text-gray-300">{finding.branch}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-500 mb-1">Rule ID</p>
                  <p className="text-sm text-gray-300 font-mono">{finding.rule_id}</p>
                </div>
                {finding.matched_pattern && (
                  <div>
                    <p className="text-xs text-gray-500 mb-1">Pattern</p>
                    <p className="text-sm text-gray-300 font-mono truncate">{finding.matched_pattern}</p>
                  </div>
                )}
                {finding.false_positive_likelihood && (
                  <div>
                    <p className="text-xs text-gray-500 mb-1">FP Likelihood</p>
                    <p className={clsx(
                      'text-sm capitalize',
                      finding.false_positive_likelihood === 'low' && 'text-neon-green',
                      finding.false_positive_likelihood === 'medium' && 'text-neon-yellow',
                      finding.false_positive_likelihood === 'high' && 'text-neon-red'
                    )}>
                      {finding.false_positive_likelihood}
                    </p>
                  </div>
                )}
              </div>

              <div>
                <p className="text-sm font-medium text-gray-400 mb-1">Description</p>
                <p className="text-sm text-gray-300">{finding.rule_description}</p>
              </div>

              <div className="flex items-center gap-2 pt-2 border-t border-cyber-border">
                <span className="text-sm text-gray-500 mr-2">Update Status:</span>
                {(Object.keys(statusConfig) as RemediationStatus[]).map((s) => {
                  const config = statusConfig[s];
                  return (
                    <button
                      key={s}
                      onClick={(e) => {
                        e.stopPropagation();
                        onStatusUpdate(s);
                      }}
                      className={clsx(
                        'px-3 py-1 text-xs rounded-md border transition-colors',
                        finding.remediation_status === s
                          ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
                          : 'border-cyber-border text-gray-400 hover:border-gray-500 hover:text-gray-300'
                      )}
                    >
                      {config.label}
                    </button>
                  );
                })}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export function RepositoryDetail() {
  const { repoName } = useParams<{ repoName: string }>();
  const navigate = useNavigate();
  const { addNotification } = useStore();
  
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [activeFilter, setActiveFilter] = useState<'all' | Severity | FindingType>('all');

  // Decode repository name (may contain slashes)
  const decodedRepoName = decodeURIComponent(repoName || '');

  useEffect(() => {
    fetchFindings();
  }, [decodedRepoName]);

  const fetchFindings = async () => {
    try {
      setLoading(true);
      const response = await api.getFindings({ repository: decodedRepoName });
      const items = Array.isArray(response) ? response : (response?.items || []);
      setFindings(items);
    } catch (error) {
      console.error('Failed to fetch findings:', error);
      setFindings([]);
    } finally {
      setLoading(false);
    }
  };

  const handleStatusUpdate = async (findingId: string, status: RemediationStatus) => {
    try {
      await api.updateFindingStatus(findingId, status);
      setFindings((prev) =>
        prev.map((f) => (f.id === findingId ? { ...f, remediation_status: status } : f))
      );
      addNotification({
        type: 'success',
        title: 'Status Updated',
        message: `Finding status changed to ${statusConfig[status].label}`,
      });
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Update Failed',
        message: 'Failed to update finding status',
      });
    }
  };

  const handleRescan = async () => {
    const token = localStorage.getItem('github_token');
    if (!token) {
      addNotification({
        type: 'error',
        title: 'Token Required',
        message: 'Please configure your GitHub token in Settings',
      });
      return;
    }

    setScanning(true);
    try {
      await api.startRepoScan(decodedRepoName, token, { full_history: false });
      addNotification({
        type: 'success',
        title: 'Scan Started',
        message: `Scanning ${decodedRepoName}...`,
      });
      // Refresh after delay
      setTimeout(fetchFindings, 5000);
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Scan Failed',
        message: 'Failed to start repository scan',
      });
    } finally {
      setScanning(false);
    }
  };

  const handleExportCSV = async () => {
    try {
      addNotification({
        type: 'info',
        title: 'Exporting...',
        message: `Preparing export for ${decodedRepoName}...`,
      });

      const blob = await api.exportFindingsCSV({ repository: decodedRepoName });

      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `findings_${decodedRepoName.replace('/', '_')}_${new Date().toISOString().split('T')[0]}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

      addNotification({
        type: 'success',
        title: 'Export Complete',
        message: `Exported ${filteredFindings.length} findings`,
      });
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Export Failed',
        message: 'Failed to export findings',
      });
    }
  };

  // Calculate stats
  const stats: RepositoryStats = {
    total: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    info: findings.filter(f => f.severity === 'info').length,
    by_type: {},
    by_status: {},
  };

  // Count by type
  findings.forEach(f => {
    stats.by_type[f.type] = (stats.by_type[f.type] || 0) + 1;
    stats.by_status[f.remediation_status] = (stats.by_status[f.remediation_status] || 0) + 1;
  });

  // Filter findings
  const filteredFindings = findings.filter(f => {
    if (activeFilter === 'all') return true;
    if (['critical', 'high', 'medium', 'low', 'info'].includes(activeFilter)) {
      return f.severity === activeFilter;
    }
    return f.type === activeFilter;
  });

  // Charts data
  const severityChartData = [
    { name: 'Critical', value: stats.critical, color: SEVERITY_COLORS.critical },
    { name: 'High', value: stats.high, color: SEVERITY_COLORS.high },
    { name: 'Medium', value: stats.medium, color: SEVERITY_COLORS.medium },
    { name: 'Low', value: stats.low, color: SEVERITY_COLORS.low },
    { name: 'Info', value: stats.info, color: SEVERITY_COLORS.info },
  ].filter(d => d.value > 0);

  const typeChartData = Object.entries(stats.by_type).map(([type, count]) => ({
    name: TYPE_CONFIG[type]?.label || type,
    value: count,
  }));

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-neon-blue border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-400">Loading repository data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate('/repositories')}
            className="p-2 rounded-lg bg-cyber-surface border border-cyber-border hover:border-neon-blue/50 transition-colors"
          >
            <ArrowLeft className="w-5 h-5 text-gray-400" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <GitBranch className="w-5 h-5 text-neon-blue" />
              <h1 className="text-2xl font-bold text-gray-100">{decodedRepoName}</h1>
            </div>
            <p className="text-gray-500 text-sm mt-1">
              {stats.total} findings • Last scanned {findings[0]?.updated_at ? formatDistanceToNow(new Date(findings[0].updated_at), { addSuffix: true }) : 'N/A'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <a
            href={`https://github.com/${decodedRepoName}`}
            target="_blank"
            rel="noopener noreferrer"
            className="btn-ghost flex items-center gap-2"
          >
            <ExternalLink className="w-4 h-4" />
            GitHub
          </a>
          <button
            onClick={handleRescan}
            disabled={scanning}
            className="btn-ghost flex items-center gap-2"
          >
            <RefreshCw className={clsx('w-4 h-4', scanning && 'animate-spin')} />
            {scanning ? 'Scanning...' : 'Rescan'}
          </button>
          <button
            onClick={handleExportCSV}
            className="btn-primary flex items-center gap-2"
            disabled={findings.length === 0}
          >
            <Download className="w-4 h-4" />
            Export CSV
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <button
          onClick={() => setActiveFilter('critical')}
          className={clsx(
            'p-4 rounded-lg border transition-all',
            activeFilter === 'critical'
              ? 'bg-neon-red/20 border-neon-red'
              : 'bg-cyber-surface border-cyber-border hover:border-neon-red/50'
          )}
        >
          <p className="text-2xl font-bold text-neon-red">{stats.critical}</p>
          <p className="text-sm text-gray-400">Critical</p>
        </button>
        <button
          onClick={() => setActiveFilter('high')}
          className={clsx(
            'p-4 rounded-lg border transition-all',
            activeFilter === 'high'
              ? 'bg-orange-500/20 border-orange-500'
              : 'bg-cyber-surface border-cyber-border hover:border-orange-500/50'
          )}
        >
          <p className="text-2xl font-bold text-orange-500">{stats.high}</p>
          <p className="text-sm text-gray-400">High</p>
        </button>
        <button
          onClick={() => setActiveFilter('medium')}
          className={clsx(
            'p-4 rounded-lg border transition-all',
            activeFilter === 'medium'
              ? 'bg-neon-yellow/20 border-neon-yellow'
              : 'bg-cyber-surface border-cyber-border hover:border-neon-yellow/50'
          )}
        >
          <p className="text-2xl font-bold text-neon-yellow">{stats.medium}</p>
          <p className="text-sm text-gray-400">Medium</p>
        </button>
        <button
          onClick={() => setActiveFilter('low')}
          className={clsx(
            'p-4 rounded-lg border transition-all',
            activeFilter === 'low'
              ? 'bg-neon-green/20 border-neon-green'
              : 'bg-cyber-surface border-cyber-border hover:border-neon-green/50'
          )}
        >
          <p className="text-2xl font-bold text-neon-green">{stats.low}</p>
          <p className="text-sm text-gray-400">Low</p>
        </button>
        <button
          onClick={() => setActiveFilter('all')}
          className={clsx(
            'p-4 rounded-lg border transition-all',
            activeFilter === 'all'
              ? 'bg-neon-blue/20 border-neon-blue'
              : 'bg-cyber-surface border-cyber-border hover:border-neon-blue/50'
          )}
        >
          <p className="text-2xl font-bold text-neon-blue">{stats.total}</p>
          <p className="text-sm text-gray-400">Total</p>
        </button>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <div className="card-glow">
          <h3 className="section-title mb-4">
            <AlertTriangle className="w-5 h-5 text-neon-blue" />
            Severity Distribution
          </h3>
          {severityChartData.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityChartData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={80}
                    paddingAngle={2}
                    dataKey="value"
                  >
                    {severityChartData.map((entry, index) => (
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
              <div className="flex flex-wrap justify-center gap-4 mt-2">
                {severityChartData.map((entry) => (
                  <div key={entry.name} className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full" style={{ backgroundColor: entry.color }} />
                    <span className="text-sm text-gray-400">{entry.name}: {entry.value}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-gray-500">
              <p>No findings data</p>
            </div>
          )}
        </div>

        {/* Type Distribution */}
        <div className="card-glow">
          <h3 className="section-title mb-4">
            <Code className="w-5 h-5 text-neon-blue" />
            Findings by Type
          </h3>
          {typeChartData.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={typeChartData} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="#2d3748" horizontal={false} />
                  <XAxis type="number" stroke="#6b7280" fontSize={12} />
                  <YAxis type="category" dataKey="name" stroke="#6b7280" fontSize={12} width={80} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1a2234',
                      border: '1px solid #2d3748',
                      borderRadius: '8px',
                    }}
                  />
                  <Bar dataKey="value" fill="#00d4ff" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-gray-500">
              <p>No findings data</p>
            </div>
          )}
        </div>
      </div>

      {/* Type Filter Buttons */}
      <div className="card">
        <div className="flex items-center gap-2 flex-wrap">
          <Filter className="w-4 h-4 text-gray-500" />
          <span className="text-sm text-gray-400 mr-2">Filter by type:</span>
          {Object.entries(TYPE_CONFIG).map(([type, config]) => {
            const count = stats.by_type[type] || 0;
            if (count === 0) return null;
            const Icon = config.icon;
            return (
              <button
                key={type}
                onClick={() => setActiveFilter(activeFilter === type ? 'all' : type as FindingType)}
                className={clsx(
                  'flex items-center gap-2 px-3 py-1 rounded-md border transition-colors text-sm',
                  activeFilter === type
                    ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
                    : 'border-cyber-border text-gray-400 hover:border-gray-500'
                )}
              >
                <Icon className={clsx('w-4 h-4', config.color)} />
                {config.label} ({count})
              </button>
            );
          })}
        </div>
      </div>

      {/* Findings Table */}
      <div className="card p-0 overflow-hidden">
        <div className="p-4 border-b border-cyber-border flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-100">
            {activeFilter === 'all' ? 'All Findings' : `${activeFilter.charAt(0).toUpperCase() + activeFilter.slice(1)} Findings`}
            <span className="text-gray-500 font-normal ml-2">({filteredFindings.length})</span>
          </h3>
        </div>
        <table className="w-full">
          <thead>
            <tr className="table-header">
              <th className="w-10 px-4 py-3"></th>
              <th className="px-4 py-3 text-left">Severity</th>
              <th className="px-4 py-3 text-left">Category</th>
              <th className="px-4 py-3 text-left">Location</th>
              <th className="px-4 py-3 text-left">Status</th>
            </tr>
          </thead>
          <tbody>
            {filteredFindings.map((finding) => (
              <FindingRow
                key={finding.id}
                finding={finding}
                expanded={expandedId === finding.id}
                onToggle={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
                onStatusUpdate={(status) => handleStatusUpdate(finding.id, status)}
              />
            ))}
          </tbody>
        </table>

        {filteredFindings.length === 0 && (
          <div className="p-12 text-center">
            <CheckCircle className="w-12 h-12 text-neon-green mx-auto mb-4" />
            <p className="text-gray-400">
              {findings.length === 0 
                ? 'No findings detected in this repository'
                : 'No findings match the selected filter'}
            </p>
          </div>
        )}
      </div>

      {/* Status Summary */}
      {findings.length > 0 && (
        <div className="card">
          <h3 className="section-title mb-4">
            <CheckCircle className="w-5 h-5 text-neon-blue" />
            Remediation Status
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {(Object.keys(statusConfig) as RemediationStatus[]).map((status) => {
              const config = statusConfig[status];
              const count = stats.by_status[status] || 0;
              const Icon = config.icon;
              return (
                <div key={status} className="flex items-center gap-3 p-3 rounded-lg bg-cyber-surface/50 border border-cyber-border/50">
                  <Icon className={clsx('w-5 h-5', config.color)} />
                  <div>
                    <p className="text-lg font-bold text-gray-100">{count}</p>
                    <p className="text-xs text-gray-500">{config.label}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
