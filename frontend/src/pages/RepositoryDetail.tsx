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
  ChevronLeft,
  FileCode,
  Copy,
  Eye,
  XCircle,
  Filter,
  Loader2,
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
import type { Finding, Severity, FindingType, RemediationStatus, RepositoryStats, CategoryCount } from '../types';

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
  const params = useParams<{ owner: string; repo: string }>();
  const { owner, repo } = params;
  const navigate = useNavigate();
  const { addNotification } = useStore();
  
  // Debug: Log params to console
  console.log('RepositoryDetail params:', { owner, repo, fullParams: params });
  
  const [stats, setStats] = useState<RepositoryStats | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  
  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalFindings, setTotalFindings] = useState(0);
  const pageSize = 50;
  
  // Filter state
  const [severityFilter, setSeverityFilter] = useState<Severity | null>(null);
  const [typeFilter, setTypeFilter] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);

  // Full repository name
  const fullRepoName = `${owner}/${repo}`;

  useEffect(() => {
    fetchStats();
  }, [fullRepoName]);

  useEffect(() => {
    fetchFindings();
  }, [fullRepoName, currentPage, severityFilter, typeFilter, categoryFilter]);

  const fetchStats = async () => {
    if (!owner || !repo) return;
    try {
      setLoading(true);
      const data = await api.getRepositoryStats(owner, repo);
      setStats(data);
    } catch (error) {
      console.error('Failed to fetch repository stats:', error);
      addNotification({
        type: 'error',
        title: 'Error',
        message: 'Failed to load repository statistics',
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchFindings = async () => {
    if (!owner || !repo) return;
    try {
      setFindingsLoading(true);
      const response = await api.getRepositoryFindings(owner, repo, {
        page: currentPage,
        page_size: pageSize,
        severity: severityFilter || undefined,
        type: typeFilter || undefined,
        category: categoryFilter || undefined,
      });
      
      // Map response to Finding type
      const items = (response.items || []).map((f: any) => ({
        ...f,
        severity: f.severity as Severity,
        type: f.type as FindingType,
        remediation_status: f.remediation_status as RemediationStatus,
        states: f.states || [],
      }));
      
      setFindings(items);
      setTotalPages(response.total_pages || 1);
      setTotalFindings(response.total || 0);
    } catch (error) {
      console.error('Failed to fetch findings:', error);
      setFindings([]);
    } finally {
      setFindingsLoading(false);
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
      await api.startRepoScan(fullRepoName, token, { full_history: false });
      addNotification({
        type: 'success',
        title: 'Scan Started',
        message: `Scanning ${fullRepoName}...`,
      });
      // Refresh after delay
      setTimeout(() => {
        fetchStats();
        fetchFindings();
      }, 5000);
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
        message: `Preparing export for ${fullRepoName}...`,
      });

      const blob = await api.exportFindingsCSV({ repository: fullRepoName });

      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `findings_${fullRepoName.replace('/', '_')}_${new Date().toISOString().split('T')[0]}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

      addNotification({
        type: 'success',
        title: 'Export Complete',
        message: `Exported ${stats?.total || 0} findings`,
      });
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Export Failed',
        message: 'Failed to export findings',
      });
    }
  };

  const handleSeverityFilter = (sev: Severity | null) => {
    setSeverityFilter(severityFilter === sev ? null : sev);
    setCurrentPage(1);
  };

  const handleTypeFilter = (type: string | null) => {
    setTypeFilter(typeFilter === type ? null : type);
    setCategoryFilter(null); // Reset category filter when type changes
    setCurrentPage(1);
  };

  // Note: Category filter is set directly from category buttons in categoriesByType section

  // Charts data
  const severityChartData = stats ? [
    { name: 'Critical', value: stats.by_severity.critical, color: SEVERITY_COLORS.critical },
    { name: 'High', value: stats.by_severity.high, color: SEVERITY_COLORS.high },
    { name: 'Medium', value: stats.by_severity.medium, color: SEVERITY_COLORS.medium },
    { name: 'Low', value: stats.by_severity.low, color: SEVERITY_COLORS.low },
    { name: 'Info', value: stats.by_severity.info, color: SEVERITY_COLORS.info },
  ].filter(d => d.value > 0) : [];

  const typeChartData = stats ? Object.entries(stats.by_type).map(([type, count]) => ({
    name: TYPE_CONFIG[type]?.label || type,
    value: count,
  })) : [];

  // Group categories by type for display
  const categoriesByType: Record<string, CategoryCount[]> = {};
  if (stats?.by_category) {
    stats.by_category.forEach(cat => {
      if (!categoriesByType[cat.type]) {
        categoriesByType[cat.type] = [];
      }
      categoriesByType[cat.type].push(cat);
    });
  }

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

  if (!stats) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <AlertTriangle className="w-12 h-12 text-neon-yellow mx-auto mb-4" />
          <p className="text-gray-400">Repository not found or no data available</p>
          <button onClick={() => navigate('/repositories')} className="btn-ghost mt-4">
            Back to Repositories
          </button>
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
              <h1 className="text-2xl font-bold text-gray-100">{fullRepoName}</h1>
            </div>
            <p className="text-gray-500 text-sm mt-1">
              {stats.total.toLocaleString()} findings • Last scanned {stats.last_scan_at ? formatDistanceToNow(new Date(stats.last_scan_at), { addSuffix: true }) : 'N/A'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <a
            href={`https://github.com/${fullRepoName}`}
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
            disabled={stats.total === 0}
          >
            <Download className="w-4 h-4" />
            Export CSV
          </button>
        </div>
      </div>

      {/* Stats Cards - Clickable */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        <button
          onClick={() => handleSeverityFilter('critical')}
          className={clsx(
            'p-4 rounded-lg border transition-all text-left',
            severityFilter === 'critical'
              ? 'bg-neon-red/20 border-neon-red'
              : 'bg-cyber-surface border-cyber-border hover:border-neon-red/50'
          )}
        >
          <p className="text-2xl font-bold text-neon-red">{stats.by_severity.critical.toLocaleString()}</p>
          <p className="text-sm text-gray-400">Critical</p>
        </button>
        <button
          onClick={() => handleSeverityFilter('high')}
          className={clsx(
            'p-4 rounded-lg border transition-all text-left',
            severityFilter === 'high'
              ? 'bg-orange-500/20 border-orange-500'
              : 'bg-cyber-surface border-cyber-border hover:border-orange-500/50'
          )}
        >
          <p className="text-2xl font-bold text-orange-500">{stats.by_severity.high.toLocaleString()}</p>
          <p className="text-sm text-gray-400">High</p>
        </button>
        <button
          onClick={() => handleSeverityFilter('medium')}
          className={clsx(
            'p-4 rounded-lg border transition-all text-left',
            severityFilter === 'medium'
              ? 'bg-neon-yellow/20 border-neon-yellow'
              : 'bg-cyber-surface border-cyber-border hover:border-neon-yellow/50'
          )}
        >
          <p className="text-2xl font-bold text-neon-yellow">{stats.by_severity.medium.toLocaleString()}</p>
          <p className="text-sm text-gray-400">Medium</p>
        </button>
        <button
          onClick={() => handleSeverityFilter('low')}
          className={clsx(
            'p-4 rounded-lg border transition-all text-left',
            severityFilter === 'low'
              ? 'bg-neon-green/20 border-neon-green'
              : 'bg-cyber-surface border-cyber-border hover:border-neon-green/50'
          )}
        >
          <p className="text-2xl font-bold text-neon-green">{stats.by_severity.low.toLocaleString()}</p>
          <p className="text-sm text-gray-400">Low</p>
        </button>
        <button
          onClick={() => handleSeverityFilter('info')}
          className={clsx(
            'p-4 rounded-lg border transition-all text-left',
            severityFilter === 'info'
              ? 'bg-neon-blue/20 border-neon-blue'
              : 'bg-cyber-surface border-cyber-border hover:border-neon-blue/50'
          )}
        >
          <p className="text-2xl font-bold text-neon-blue">{stats.by_severity.info.toLocaleString()}</p>
          <p className="text-sm text-gray-400">Info</p>
        </button>
        <button
          onClick={() => handleSeverityFilter(null)}
          className={clsx(
            'p-4 rounded-lg border transition-all text-left',
            !severityFilter
              ? 'bg-neon-purple/20 border-neon-purple'
              : 'bg-cyber-surface border-cyber-border hover:border-neon-purple/50'
          )}
        >
          <p className="text-2xl font-bold text-neon-purple">{stats.total.toLocaleString()}</p>
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
                    formatter={(value) => typeof value === 'number' ? value.toLocaleString() : value}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex flex-wrap justify-center gap-4 mt-2">
                {severityChartData.map((entry) => (
                  <div key={entry.name} className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full" style={{ backgroundColor: entry.color }} />
                    <span className="text-sm text-gray-400">{entry.name}: {entry.value.toLocaleString()}</span>
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
                  <XAxis type="number" stroke="#6b7280" fontSize={12} tickFormatter={(v) => v.toLocaleString()} />
                  <YAxis type="category" dataKey="name" stroke="#6b7280" fontSize={12} width={80} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1a2234',
                      border: '1px solid #2d3748',
                      borderRadius: '8px',
                    }}
                    formatter={(value) => typeof value === 'number' ? value.toLocaleString() : value}
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

      {/* Category Breakdown by Type */}
      <div className="card-glow">
        <h3 className="section-title mb-4">
          <Key className="w-5 h-5 text-neon-blue" />
          Top Vulnerability Categories
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {Object.entries(categoriesByType).map(([type, categories]) => {
            const config = TYPE_CONFIG[type] || { label: type, icon: Code, color: 'text-gray-400' };
            const Icon = config.icon;
            // Show top 10 categories per type
            const topCategories = categories.slice(0, 10);
            
            return (
              <div key={type} className="p-4 rounded-lg bg-cyber-surface/50 border border-cyber-border">
                <div className="flex items-center gap-2 mb-3">
                  <Icon className={clsx('w-5 h-5', config.color)} />
                  <h4 className="font-medium text-gray-200">{config.label}</h4>
                  <span className="text-xs text-gray-500 ml-auto">
                    {categories.reduce((sum, c) => sum + c.count, 0).toLocaleString()} total
                  </span>
                </div>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {topCategories.map((cat, idx) => (
                    <button
                      key={`${cat.category}-${idx}`}
                      onClick={() => {
                        setTypeFilter(type);
                        setCategoryFilter(cat.category);
                        setCurrentPage(1);
                      }}
                      className={clsx(
                        'w-full flex items-center justify-between p-2 rounded text-left text-sm transition-colors',
                        categoryFilter === cat.category
                          ? 'bg-neon-blue/20 text-neon-blue'
                          : 'hover:bg-cyber-darker text-gray-300'
                      )}
                    >
                      <span className="truncate">{cat.category}</span>
                      <span className="flex items-center gap-2 ml-2">
                        <SeverityBadge severity={cat.severity} />
                        <span className="font-mono">{cat.count.toLocaleString()}</span>
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Type Filter Buttons */}
      <div className="card">
        <div className="flex items-center gap-2 flex-wrap">
          <Filter className="w-4 h-4 text-gray-500" />
          <span className="text-sm text-gray-400 mr-2">Filter by type:</span>
          <button
            onClick={() => handleTypeFilter(null)}
            className={clsx(
              'px-3 py-1 rounded-md border transition-colors text-sm',
              !typeFilter
                ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
                : 'border-cyber-border text-gray-400 hover:border-gray-500'
            )}
          >
            All Types
          </button>
          {Object.entries(stats.by_type).map(([type, count]) => {
            if (count === 0) return null;
            const config = TYPE_CONFIG[type] || { label: type, icon: Code, color: 'text-gray-400' };
            const Icon = config.icon;
            return (
              <button
                key={type}
                onClick={() => handleTypeFilter(type)}
                className={clsx(
                  'flex items-center gap-2 px-3 py-1 rounded-md border transition-colors text-sm',
                  typeFilter === type
                    ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
                    : 'border-cyber-border text-gray-400 hover:border-gray-500'
                )}
              >
                <Icon className={clsx('w-4 h-4', config.color)} />
                {config.label} ({count.toLocaleString()})
              </button>
            );
          })}
          {categoryFilter && (
            <span className="text-sm text-gray-500 ml-4">
              Category: <span className="text-neon-blue">{categoryFilter}</span>
              <button onClick={() => setCategoryFilter(null)} className="ml-2 text-gray-400 hover:text-gray-200">✕</button>
            </span>
          )}
        </div>
      </div>

      {/* Findings Table */}
      <div className="card p-0 overflow-hidden">
        <div className="p-4 border-b border-cyber-border flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-100">
            Findings
            <span className="text-gray-500 font-normal ml-2">
              (Showing {findings.length} of {totalFindings.toLocaleString()})
            </span>
          </h3>
          {findingsLoading && <Loader2 className="w-5 h-5 text-neon-blue animate-spin" />}
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
            {findings.map((finding) => (
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

        {findings.length === 0 && !findingsLoading && (
          <div className="p-12 text-center">
            <CheckCircle className="w-12 h-12 text-neon-green mx-auto mb-4" />
            <p className="text-gray-400">
              {stats.total === 0 
                ? 'No findings detected in this repository'
                : 'No findings match the selected filters'}
            </p>
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="p-4 border-t border-cyber-border flex items-center justify-between">
            <p className="text-sm text-gray-500">
              Page {currentPage} of {totalPages} ({totalFindings.toLocaleString()} total)
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                disabled={currentPage === 1}
                className="btn-ghost p-2 disabled:opacity-50"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              
              {/* Page numbers */}
              <div className="flex items-center gap-1">
                {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                  let pageNum;
                  if (totalPages <= 5) {
                    pageNum = i + 1;
                  } else if (currentPage <= 3) {
                    pageNum = i + 1;
                  } else if (currentPage >= totalPages - 2) {
                    pageNum = totalPages - 4 + i;
                  } else {
                    pageNum = currentPage - 2 + i;
                  }
                  return (
                    <button
                      key={pageNum}
                      onClick={() => setCurrentPage(pageNum)}
                      className={clsx(
                        'w-8 h-8 rounded text-sm transition-colors',
                        currentPage === pageNum
                          ? 'bg-neon-blue text-white'
                          : 'text-gray-400 hover:bg-cyber-surface'
                      )}
                    >
                      {pageNum}
                    </button>
                  );
                })}
              </div>

              <button
                onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                disabled={currentPage === totalPages}
                className="btn-ghost p-2 disabled:opacity-50"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Status Summary */}
      {stats.total > 0 && (
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
                    <p className="text-lg font-bold text-gray-100">{count.toLocaleString()}</p>
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
