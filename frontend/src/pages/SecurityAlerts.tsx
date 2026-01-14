import { useState } from 'react';
import {
  Shield,
  AlertTriangle,
  Package,
  Code,
  Key,
  ExternalLink,
  RefreshCw,
  Filter,
  Loader2,
  CheckCircle,
  XCircle,
  Clock,
} from 'lucide-react';
import { clsx } from 'clsx';
import { useStore } from '../stores/useStore';

interface AlertSummary {
  repository: string;
  dependabot_total: number;
  dependabot_critical: number;
  dependabot_high: number;
  dependabot_open: number;
  code_scanning_total: number;
  code_scanning_critical: number;
  code_scanning_high: number;
  code_scanning_open: number;
  secret_scanning_total: number;
  secret_scanning_open: number;
  total_alerts: number;
  total_critical: number;
  total_high: number;
  total_open: number;
}

interface ConsolidatedAlert {
  id: string;
  source: 'dependabot' | 'code_scanning' | 'secret_scanning';
  number: number;
  state: string;
  severity: string;
  title: string;
  description?: string;
  repository: string;
  location?: string;
  line_number?: number;
  html_url: string;
  created_at: string;
}

const severityColors: Record<string, string> = {
  critical: 'bg-severity-critical/20 text-severity-critical border-severity-critical/30',
  high: 'bg-severity-high/20 text-severity-high border-severity-high/30',
  medium: 'bg-severity-medium/20 text-severity-medium border-severity-medium/30',
  low: 'bg-severity-low/20 text-severity-low border-severity-low/30',
};

const sourceIcons: Record<string, React.ElementType> = {
  dependabot: Package,
  code_scanning: Code,
  secret_scanning: Key,
};

const sourceLabels: Record<string, string> = {
  dependabot: 'Dependabot',
  code_scanning: 'Code Scanning',
  secret_scanning: 'Secret Scanning',
};

const sourceColors: Record<string, string> = {
  dependabot: 'text-blue-400 bg-blue-400/10',
  code_scanning: 'text-purple-400 bg-purple-400/10',
  secret_scanning: 'text-red-400 bg-red-400/10',
};

export function SecurityAlerts() {
  const { scanSettings } = useStore();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [repository, setRepository] = useState('');
  const [summary, setSummary] = useState<AlertSummary | null>(null);
  const [alerts, setAlerts] = useState<ConsolidatedAlert[]>([]);
  const [filterState, setFilterState] = useState<string>('all');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterSource, setFilterSource] = useState<string>('all');

  const fetchAlerts = async () => {
    if (!repository || !scanSettings.githubToken) {
      setError('Please enter a repository and ensure GitHub token is configured in Settings');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const [owner, repo] = repository.split('/');
      if (!owner || !repo) {
        throw new Error('Invalid repository format. Use owner/repo');
      }

      // Fetch all alerts
      const response = await fetch(
        `/api/alerts/repository/${owner}/${repo}/all?token=${encodeURIComponent(scanSettings.githubToken)}`
      );

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Failed to fetch alerts');
      }

      const data = await response.json();
      setAlerts(data.alerts || []);

      // Fetch summary
      const summaryResponse = await fetch(
        `/api/alerts/repository/${owner}/${repo}/summary?token=${encodeURIComponent(scanSettings.githubToken)}`
      );

      if (summaryResponse.ok) {
        const summaryData = await summaryResponse.json();
        setSummary(summaryData);
      }
    } catch (err: any) {
      setError(err.message);
      setAlerts([]);
      setSummary(null);
    } finally {
      setLoading(false);
    }
  };

  // Filter alerts
  const filteredAlerts = alerts.filter((alert) => {
    if (filterState !== 'all' && alert.state !== filterState) return false;
    if (filterSeverity !== 'all' && alert.severity !== filterSeverity) return false;
    if (filterSource !== 'all' && alert.source !== filterSource) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
            <Shield className="w-7 h-7 text-neon-blue" />
            GitHub Security Alerts
          </h1>
          <p className="text-gray-500 mt-1">
            Consolidated view of Dependabot, Code Scanning, and Secret Scanning alerts
          </p>
        </div>
      </div>

      {/* Repository Input */}
      <div className="card">
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex-1">
            <label className="block text-sm font-medium text-gray-400 mb-2">
              Repository
            </label>
            <input
              type="text"
              value={repository}
              onChange={(e) => setRepository(e.target.value)}
              placeholder="owner/repository"
              className="input w-full"
            />
          </div>
          <div className="flex items-end">
            <button
              onClick={fetchAlerts}
              disabled={loading || !repository}
              className="btn-primary flex items-center gap-2 h-10"
            >
              {loading ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <RefreshCw className="w-4 h-4" />
              )}
              Fetch Alerts
            </button>
          </div>
        </div>
        {!scanSettings.githubToken && (
          <p className="text-severity-medium text-sm mt-2">
            ⚠️ GitHub token not configured. Go to Settings to add your token.
          </p>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="card border-severity-critical/30 bg-severity-critical/5">
          <div className="flex items-center gap-2 text-severity-critical">
            <XCircle className="w-5 h-5" />
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {/* Total Alerts */}
          <div className="stat-card">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-neon-blue/20 text-neon-blue">
                <Shield className="w-5 h-5" />
              </div>
              <div>
                <p className="text-2xl font-bold text-gray-100">{summary.total_alerts}</p>
                <p className="text-xs text-gray-500">Total Alerts</p>
              </div>
            </div>
          </div>

          {/* Dependabot */}
          <div className="stat-card">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-400/20 text-blue-400">
                <Package className="w-5 h-5" />
              </div>
              <div>
                <p className="text-2xl font-bold text-gray-100">{summary.dependabot_open}</p>
                <p className="text-xs text-gray-500">Dependabot Open</p>
              </div>
            </div>
          </div>

          {/* Code Scanning */}
          <div className="stat-card">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-400/20 text-purple-400">
                <Code className="w-5 h-5" />
              </div>
              <div>
                <p className="text-2xl font-bold text-gray-100">{summary.code_scanning_open}</p>
                <p className="text-xs text-gray-500">Code Scanning Open</p>
              </div>
            </div>
          </div>

          {/* Secret Scanning */}
          <div className="stat-card">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-red-400/20 text-red-400">
                <Key className="w-5 h-5" />
              </div>
              <div>
                <p className="text-2xl font-bold text-gray-100">{summary.secret_scanning_open}</p>
                <p className="text-xs text-gray-500">Secrets Open</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Severity Summary */}
      {summary && (
        <div className="grid grid-cols-4 gap-4">
          <div className="card border-severity-critical/30 bg-severity-critical/5">
            <div className="text-center">
              <p className="text-3xl font-bold text-severity-critical">{summary.total_critical}</p>
              <p className="text-sm text-gray-400">Critical</p>
            </div>
          </div>
          <div className="card border-severity-high/30 bg-severity-high/5">
            <div className="text-center">
              <p className="text-3xl font-bold text-severity-high">{summary.total_high}</p>
              <p className="text-sm text-gray-400">High</p>
            </div>
          </div>
          <div className="card border-severity-medium/30 bg-severity-medium/5">
            <div className="text-center">
              <p className="text-3xl font-bold text-severity-medium">
                {(summary.dependabot_total - summary.dependabot_critical - summary.dependabot_high) + 
                 (summary.code_scanning_total - summary.code_scanning_critical - summary.code_scanning_high)}
              </p>
              <p className="text-sm text-gray-400">Medium/Low</p>
            </div>
          </div>
          <div className="card border-neon-green/30 bg-neon-green/5">
            <div className="text-center">
              <p className="text-3xl font-bold text-neon-green">{summary.total_open}</p>
              <p className="text-sm text-gray-400">Open</p>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      {alerts.length > 0 && (
        <div className="card">
          <div className="flex flex-wrap gap-4">
            {/* State Filter */}
            <div>
              <label className="block text-xs text-gray-500 mb-1">State</label>
              <select
                value={filterState}
                onChange={(e) => setFilterState(e.target.value)}
                className="input py-1 text-sm"
              >
                <option value="all">All States</option>
                <option value="open">Open</option>
                <option value="fixed">Fixed</option>
                <option value="dismissed">Dismissed</option>
              </select>
            </div>

            {/* Severity Filter */}
            <div>
              <label className="block text-xs text-gray-500 mb-1">Severity</label>
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="input py-1 text-sm"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            {/* Source Filter */}
            <div>
              <label className="block text-xs text-gray-500 mb-1">Source</label>
              <select
                value={filterSource}
                onChange={(e) => setFilterSource(e.target.value)}
                className="input py-1 text-sm"
              >
                <option value="all">All Sources</option>
                <option value="dependabot">Dependabot</option>
                <option value="code_scanning">Code Scanning</option>
                <option value="secret_scanning">Secret Scanning</option>
              </select>
            </div>

            <div className="flex items-end">
              <span className="text-sm text-gray-400">
                Showing {filteredAlerts.length} of {alerts.length} alerts
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Alerts List */}
      {alerts.length > 0 && (
        <div className="card overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-cyber-border">
                <th className="text-left py-3 px-4 text-gray-400 font-medium text-sm">Source</th>
                <th className="text-left py-3 px-4 text-gray-400 font-medium text-sm">Severity</th>
                <th className="text-left py-3 px-4 text-gray-400 font-medium text-sm">Alert</th>
                <th className="text-left py-3 px-4 text-gray-400 font-medium text-sm">Location</th>
                <th className="text-left py-3 px-4 text-gray-400 font-medium text-sm">State</th>
                <th className="text-right py-3 px-4 text-gray-400 font-medium text-sm">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map((alert) => {
                const SourceIcon = sourceIcons[alert.source] || AlertTriangle;
                return (
                  <tr
                    key={alert.id}
                    className="border-b border-cyber-border/50 hover:bg-cyber-surface/50 transition-colors"
                  >
                    {/* Source */}
                    <td className="py-3 px-4">
                      <div className={clsx(
                        'inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs',
                        sourceColors[alert.source]
                      )}>
                        <SourceIcon className="w-3 h-3" />
                        {sourceLabels[alert.source]}
                      </div>
                    </td>

                    {/* Severity */}
                    <td className="py-3 px-4">
                      <span className={clsx(
                        'px-2 py-1 rounded text-xs font-medium border',
                        severityColors[alert.severity]
                      )}>
                        {alert.severity}
                      </span>
                    </td>

                    {/* Alert Info */}
                    <td className="py-3 px-4">
                      <div>
                        <p className="font-medium text-gray-200 text-sm">
                          #{alert.number} - {alert.title}
                        </p>
                        {alert.description && (
                          <p className="text-xs text-gray-500 truncate max-w-md">
                            {alert.description}
                          </p>
                        )}
                      </div>
                    </td>

                    {/* Location */}
                    <td className="py-3 px-4">
                      {alert.location && (
                        <code className="text-xs text-gray-400 bg-cyber-bg px-2 py-1 rounded">
                          {alert.location}
                          {alert.line_number && `:${alert.line_number}`}
                        </code>
                      )}
                    </td>

                    {/* State */}
                    <td className="py-3 px-4">
                      {alert.state === 'open' ? (
                        <span className="flex items-center gap-1 text-severity-high text-xs">
                          <Clock className="w-3 h-3" />
                          Open
                        </span>
                      ) : alert.state === 'fixed' ? (
                        <span className="flex items-center gap-1 text-neon-green text-xs">
                          <CheckCircle className="w-3 h-3" />
                          Fixed
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-gray-500 text-xs">
                          <XCircle className="w-3 h-3" />
                          {alert.state}
                        </span>
                      )}
                    </td>

                    {/* Actions */}
                    <td className="py-3 px-4 text-right">
                      <a
                        href={alert.html_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-neon-blue hover:underline text-sm"
                      >
                        View
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {filteredAlerts.length === 0 && (
            <div className="text-center py-12">
              <Filter className="w-12 h-12 text-gray-600 mx-auto mb-4" />
              <p className="text-gray-400">No alerts match the current filters</p>
            </div>
          )}
        </div>
      )}

      {/* Empty State */}
      {!loading && alerts.length === 0 && !error && (
        <div className="card text-center py-12">
          <Shield className="w-16 h-16 text-gray-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-300 mb-2">
            No Alerts Loaded
          </h3>
          <p className="text-gray-500 max-w-md mx-auto">
            Enter a repository name above and click "Fetch Alerts" to view 
            GitHub Security Alerts including Dependabot, Code Scanning, and Secret Scanning.
          </p>
        </div>
      )}

      {/* Info Box */}
      <div className="card border-neon-blue/30 bg-neon-blue/5">
        <h3 className="font-medium text-neon-blue mb-2">ℹ️ About GitHub Security Alerts</h3>
        <div className="text-sm text-gray-400 space-y-2">
          <p>
            <strong className="text-blue-400">Dependabot:</strong> Alerts for vulnerable dependencies 
            in your package files (package.json, requirements.txt, etc.)
          </p>
          <p>
            <strong className="text-purple-400">Code Scanning:</strong> SAST findings from CodeQL 
            or other code analysis tools configured in your repository.
          </p>
          <p>
            <strong className="text-red-400">Secret Scanning:</strong> Exposed secrets like API keys, 
            tokens, and passwords detected by GitHub.
          </p>
        </div>
      </div>
    </div>
  );
}
