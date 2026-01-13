import { useState, useEffect } from 'react';
import {
  Play,
  RefreshCw,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle,
  Loader2,
  GitBranch,
  Building2,
  ChevronRight,
  Calendar,
  BarChart3,
} from 'lucide-react';
import { clsx } from 'clsx';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { useStore } from '../stores/useStore';
import api from '../services/api';
import type { Scan, ScanStatus } from '../types';
import { format, formatDistanceToNow, formatDuration, intervalToDuration } from 'date-fns';


const statusConfig: Record<ScanStatus, { label: string; icon: React.ElementType; color: string; bgColor: string }> = {
  pending: { label: 'Pending', icon: Clock, color: 'text-gray-400', bgColor: 'bg-gray-500/20' },
  running: { label: 'Running', icon: Loader2, color: 'text-neon-yellow', bgColor: 'bg-neon-yellow/20' },
  completed: { label: 'Completed', icon: CheckCircle, color: 'text-neon-green', bgColor: 'bg-neon-green/20' },
  failed: { label: 'Failed', icon: XCircle, color: 'text-neon-red', bgColor: 'bg-neon-red/20' },
  cancelled: { label: 'Cancelled', icon: AlertCircle, color: 'text-gray-500', bgColor: 'bg-gray-500/20' },
};

function formatDurationFromSeconds(seconds: number): string {
  const duration = intervalToDuration({ start: 0, end: seconds * 1000 });
  return formatDuration(duration, { format: ['hours', 'minutes', 'seconds'], delimiter: ' ' });
}

interface NewScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (type: 'org' | 'repo', target: string, token: string, options: {
    includeHistorical: boolean;
    includeArchived: boolean;
    includeForks: boolean;
    scanMode: 'full' | 'api_only' | 'shallow';
  }) => void;
  defaultToken?: string;
  defaultOrg?: string;
}

function NewScanModal({ isOpen, onClose, onSubmit, defaultToken = '', defaultOrg = '' }: NewScanModalProps) {
  const [scanType, setScanType] = useState<'org' | 'repo'>('org');
  const [target, setTarget] = useState(defaultOrg);
  const [token, setToken] = useState(defaultToken);
  const [includeHistorical, setIncludeHistorical] = useState(false);
  const [includeArchived, setIncludeArchived] = useState(false);
  const [includeForks, setIncludeForks] = useState(false);
  const [showToken, setShowToken] = useState(false);
  const [scanMode, setScanMode] = useState<'full' | 'api_only' | 'shallow'>('api_only');

  // Update target when defaultOrg changes
  useEffect(() => {
    if (defaultOrg && scanType === 'org') {
      setTarget(defaultOrg);
    }
  }, [defaultOrg, scanType]);

  useEffect(() => {
    setToken(defaultToken);
  }, [defaultToken]);

  if (!isOpen) return null;

  const canSubmit = target && token;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-cyber-card border border-cyber-border rounded-xl p-6 w-full max-w-lg animate-slideUp">
        <h2 className="text-xl font-semibold text-gray-100 mb-4">Start New Scan</h2>
        
        {/* Scan type selection */}
        <div className="flex gap-2 mb-4">
          <button
            onClick={() => setScanType('org')}
            className={clsx(
              'flex-1 py-3 rounded-lg border transition-all flex items-center justify-center gap-2',
              scanType === 'org'
                ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
                : 'border-cyber-border text-gray-400 hover:border-gray-500'
            )}
          >
            <Building2 className="w-5 h-5" />
            Organization
          </button>
          <button
            onClick={() => setScanType('repo')}
            className={clsx(
              'flex-1 py-3 rounded-lg border transition-all flex items-center justify-center gap-2',
              scanType === 'repo'
                ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
                : 'border-cyber-border text-gray-400 hover:border-gray-500'
            )}
          >
            <GitBranch className="w-5 h-5" />
            Repository
          </button>
        </div>

        {/* GitHub Token */}
        <div className="mb-4">
          <label className="block text-sm text-gray-400 mb-2">
            GitHub Token <span className="text-neon-red">*</span>
          </label>
          <div className="relative">
            <input
              type={showToken ? 'text' : 'password'}
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
              className="input pr-20"
            />
            <button
              type="button"
              onClick={() => setShowToken(!showToken)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-xs text-gray-500 hover:text-gray-300"
            >
              {showToken ? 'Hide' : 'Show'}
            </button>
          </div>
          <p className="text-xs text-gray-500 mt-1">
            Personal Access Token with <code className="text-neon-blue">repo</code> scope
          </p>
        </div>

        {/* Target input */}
        <div className="mb-4">
          <label className="block text-sm text-gray-400 mb-2">
            {scanType === 'org' ? 'Organization Name' : 'Repository (owner/repo)'} <span className="text-neon-red">*</span>
          </label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={scanType === 'org' ? 'my-organization' : 'owner/repository'}
            className="input"
          />
        </div>

        {/* Scan Mode - NEW! */}
        <div className="mb-4">
          <label className="block text-sm text-gray-400 mb-2">Scan Mode</label>
          <div className="grid grid-cols-3 gap-2">
            <button
              type="button"
              onClick={() => setScanMode('api_only')}
              className={clsx(
                'py-2 px-3 rounded-lg border text-xs transition-all',
                scanMode === 'api_only'
                  ? 'bg-neon-green/20 border-neon-green text-neon-green'
                  : 'border-cyber-border text-gray-400 hover:border-gray-500'
              )}
            >
              ⚡ API Only
            </button>
            <button
              type="button"
              onClick={() => setScanMode('shallow')}
              className={clsx(
                'py-2 px-3 rounded-lg border text-xs transition-all',
                scanMode === 'shallow'
                  ? 'bg-neon-yellow/20 border-neon-yellow text-neon-yellow'
                  : 'border-cyber-border text-gray-400 hover:border-gray-500'
              )}
            >
              🔍 Shallow
            </button>
            <button
              type="button"
              onClick={() => setScanMode('full')}
              className={clsx(
                'py-2 px-3 rounded-lg border text-xs transition-all',
                scanMode === 'full'
                  ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
                  : 'border-cyber-border text-gray-400 hover:border-gray-500'
              )}
            >
              📦 Full Clone
            </button>
          </div>
          <p className="text-xs text-gray-500 mt-2">
            {scanMode === 'api_only' && '⚡ Fastest: Search via GitHub API without cloning (recommended for large orgs)'}
            {scanMode === 'shallow' && '🔍 Fast: Clone only latest commit (good balance)'}
            {scanMode === 'full' && '📦 Thorough: Full clone with history analysis (slowest)'}
          </p>
        </div>

        {/* Options */}
        <div className="mb-6 space-y-3">
          <p className="text-sm text-gray-400">Scan Options</p>
          {scanMode !== 'api_only' && (
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={includeHistorical}
                onChange={(e) => setIncludeHistorical(e.target.checked)}
                className="w-4 h-4 rounded border-cyber-border bg-cyber-surface"
              />
              <span className="text-sm text-gray-300">Analyze Git History</span>
            </label>
          )}
          {scanType === 'org' && (
            <>
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeArchived}
                  onChange={(e) => setIncludeArchived(e.target.checked)}
                  className="w-4 h-4 rounded border-cyber-border bg-cyber-surface"
                />
                <span className="text-sm text-gray-300">Include Archived Repositories</span>
              </label>
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeForks}
                  onChange={(e) => setIncludeForks(e.target.checked)}
                  className="w-4 h-4 rounded border-cyber-border bg-cyber-surface"
                />
                <span className="text-sm text-gray-300">Include Forked Repositories</span>
              </label>
            </>
          )}
        </div>

        {/* Warning if no token */}
        {!token && (
          <div className="mb-4 p-3 bg-neon-yellow/10 border border-neon-yellow/30 rounded-lg">
            <p className="text-sm text-neon-yellow">
              ⚠️ GitHub Token is required. Go to Settings to save your token for future scans.
            </p>
          </div>
        )}

        {/* Actions */}
        <div className="flex gap-3">
          <button onClick={onClose} className="btn-ghost flex-1">
            Cancel
          </button>
          <button
            onClick={() => {
              onSubmit(scanType, target, token, { includeHistorical, includeArchived, includeForks, scanMode });
              onClose();
            }}
            disabled={!canSubmit}
            className="btn-primary flex-1 flex items-center justify-center gap-2 disabled:opacity-50"
          >
            <Play className="w-4 h-4" />
            Start Scan ({scanMode === 'api_only' ? '⚡ Fast' : scanMode === 'shallow' ? '🔍 Quick' : '📦 Full'})
          </button>
        </div>
      </div>
    </div>
  );
}

function ScanCard({ scan }: { scan: Scan }) {
  const status = statusConfig[scan.status];
  const StatusIcon = status.icon;
  const [elapsedTime, setElapsedTime] = useState('');

  // Real-time elapsed time for running scans
  useEffect(() => {
    if (scan.status === 'running') {
      const updateElapsed = () => {
        const started = new Date(scan.started_at).getTime();
        const now = Date.now();
        const seconds = Math.floor((now - started) / 1000);
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        setElapsedTime(`${mins}m ${secs}s`);
      };
      updateElapsed();
      const timer = setInterval(updateElapsed, 1000);
      return () => clearInterval(timer);
    }
  }, [scan.status, scan.started_at]);

  return (
    <div className={clsx(
      'card hover:border-neon-blue/30 transition-all cursor-pointer group relative overflow-hidden',
      scan.status === 'running' && 'border-neon-yellow/30',
      scan.status === 'failed' && 'border-neon-red/30'
    )}>
      {/* Animated progress bar for running scans */}
      {scan.status === 'running' && (
        <div className="absolute top-0 left-0 right-0 h-1 bg-neon-yellow/20">
          <div className="h-full bg-neon-yellow animate-pulse" style={{ width: '100%' }} />
        </div>
      )}
      
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className={clsx('p-2 rounded-lg', status.bgColor)}>
            <StatusIcon className={clsx('w-5 h-5', status.color, scan.status === 'running' && 'animate-spin')} />
          </div>
          <div>
            <h3 className="font-medium text-gray-100">
              {scan.organization || scan.repository}
            </h3>
            <p className="text-sm text-gray-500">
              {scan.organization ? 'Organization Scan' : 'Repository Scan'}
              {scan.status === 'running' && elapsedTime && (
                <span className="ml-2 text-neon-yellow font-mono">• {elapsedTime}</span>
              )}
            </p>
          </div>
        </div>
        <ChevronRight className="w-5 h-5 text-gray-600 group-hover:text-gray-400 transition-colors" />
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4 mb-4">
        <div className="text-center p-3 bg-cyber-surface/50 rounded-lg">
          <p className="text-2xl font-bold text-gray-100 font-mono">
            {scan.repositories_scanned}
          </p>
          <p className="text-xs text-gray-500">Repositories</p>
        </div>
        <div className="text-center p-3 bg-cyber-surface/50 rounded-lg">
          <p className="text-2xl font-bold text-gray-100 font-mono">
            {scan.findings_count.total}
          </p>
          <p className="text-xs text-gray-500">Findings</p>
        </div>
        <div className="text-center p-3 bg-cyber-surface/50 rounded-lg">
          <p className="text-2xl font-bold text-gray-100 font-mono">
            {scan.duration_seconds ? formatDurationFromSeconds(scan.duration_seconds) : '--'}
          </p>
          <p className="text-xs text-gray-500">Duration</p>
        </div>
      </div>

      {/* Severity breakdown */}
      {scan.findings_count.total > 0 && (
        <div className="flex gap-2 mb-4">
          {scan.findings_count.critical > 0 && (
            <div className="flex items-center gap-1">
              <SeverityBadge severity="critical" />
              <span className="text-sm text-gray-400">{scan.findings_count.critical}</span>
            </div>
          )}
          {scan.findings_count.high > 0 && (
            <div className="flex items-center gap-1">
              <SeverityBadge severity="high" />
              <span className="text-sm text-gray-400">{scan.findings_count.high}</span>
            </div>
          )}
          {scan.findings_count.medium > 0 && (
            <div className="flex items-center gap-1">
              <SeverityBadge severity="medium" />
              <span className="text-sm text-gray-400">{scan.findings_count.medium}</span>
            </div>
          )}
        </div>
      )}

      {/* Error message */}
      {scan.error_message && (
        <div className="p-3 bg-neon-red/10 border border-neon-red/30 rounded-lg mb-4">
          <p className="text-sm text-neon-red">{scan.error_message}</p>
        </div>
      )}

      {/* Footer */}
      <div className="flex items-center justify-between text-sm text-gray-500 pt-4 border-t border-cyber-border">
        <div className="flex items-center gap-1">
          <Calendar className="w-4 h-4" />
          <span>{format(new Date(scan.started_at), 'MMM dd, yyyy HH:mm')}</span>
        </div>
        <span>{formatDistanceToNow(new Date(scan.started_at), { addSuffix: true })}</span>
      </div>
    </div>
  );
}

export function Scans() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [showNewScanModal, setShowNewScanModal] = useState(false);
  const [statusFilter, setStatusFilter] = useState<ScanStatus | 'all'>('all');

  const { addNotification, setActiveScan, scanSettings, setScanSettings } = useStore();

  // Track previous scan states to detect changes
  const [prevScanStates, setPrevScanStates] = useState<Record<string, ScanStatus>>({});

  const fetchScans = async (checkStatusChanges = false) => {
    try {
      const response = await api.getScans();
      // Handle both array and paginated response
      const items = Array.isArray(response) ? response : (response?.items || []);
      
      // Check for status changes and notify
      if (checkStatusChanges && items.length > 0) {
        items.forEach((scan: Scan) => {
          const prevStatus = prevScanStates[scan.id];
          if (prevStatus && prevStatus !== scan.status) {
            // Scan status changed!
            if (scan.status === 'failed') {
              addNotification({
                type: 'error',
                title: '❌ Scan Failed',
                message: scan.error_message || `Scan for ${scan.organization || scan.repository} failed`,
              });
            } else if (scan.status === 'completed') {
              addNotification({
                type: 'success',
                title: '✅ Scan Completed',
                message: `Found ${scan.findings_count.total} findings in ${scan.organization || scan.repository}`,
              });
            }
          }
        });
      }
      
      // Update previous states
      const newStates: Record<string, ScanStatus> = {};
      items.forEach((scan: Scan) => {
        newStates[scan.id] = scan.status;
      });
      setPrevScanStates(newStates);
      
      setScans(items);
    } catch (error) {
      console.error('Failed to fetch scans:', error);
      setScans([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans(false);  // Initial load, don't check for changes
    // Poll every 5 seconds always (faster feedback)
    const interval = setInterval(() => {
      fetchScans(true);  // Check for status changes
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleStartScan = async (
    type: 'org' | 'repo',
    target: string,
    token: string,
    options: { includeHistorical: boolean; includeArchived: boolean; includeForks: boolean; scanMode: 'full' | 'api_only' | 'shallow' }
  ) => {
    try {
      // Save token to settings for future use
      if (token && token !== scanSettings.githubToken) {
        setScanSettings({ githubToken: token });
      }
      if (type === 'org' && target !== scanSettings.defaultOrganization) {
        setScanSettings({ defaultOrganization: target });
      }

      const response = type === 'org'
        ? await api.startOrgScan(target, token, {
            include_historical: options.includeHistorical,
            include_archived: options.includeArchived,
            include_forks: options.includeForks,
            scan_mode: options.scanMode,
          })
        : await api.startRepoScan(target, token, {
            full_history: options.includeHistorical,
          });

      setActiveScan(response.scan_id);
      
      addNotification({
        type: 'success',
        title: 'Scan Started',
        message: `Scanning ${type === 'org' ? 'organization' : 'repository'}: ${target}`,
      });

      // Refresh scans list
      await fetchScans();
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Scan Failed',
        message: error instanceof Error ? error.message : 'Failed to start scan',
      });
    }
  };

  const filteredScans = statusFilter === 'all'
    ? scans
    : scans.filter((s) => s.status === statusFilter);

  const runningScans = scans.filter((s) => s.status === 'running');

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-neon-blue border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-400">Loading scans...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Scan History</h1>
          <p className="text-gray-500">
            {scans.length} scans total • {runningScans.length} running
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => window.location.reload()}
            className="btn-ghost flex items-center gap-2"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
          <button
            onClick={() => setShowNewScanModal(true)}
            className="btn-primary flex items-center gap-2"
          >
            <Play className="w-4 h-4" />
            New Scan
          </button>
        </div>
      </div>

      {/* Running scans alert */}
      {runningScans.length > 0 && (
        <div className="card border-neon-yellow/30 bg-neon-yellow/5">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded-lg bg-neon-yellow/20">
              <Loader2 className="w-6 h-6 text-neon-yellow animate-spin" />
            </div>
            <div className="flex-1">
              <h3 className="font-medium text-gray-100">
                {runningScans.length} Scan{runningScans.length > 1 ? 's' : ''} in Progress
              </h3>
              <p className="text-sm text-gray-400">
                {runningScans.map((s) => s.organization || s.repository).join(', ')}
              </p>
            </div>
            <button className="btn-ghost text-sm">
              View Progress
            </button>
          </div>
        </div>
      )}

      {/* Status filter */}
      <div className="flex gap-2">
        <button
          onClick={() => setStatusFilter('all')}
          className={clsx(
            'px-4 py-2 text-sm rounded-lg border transition-colors',
            statusFilter === 'all'
              ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
              : 'border-cyber-border text-gray-400 hover:border-gray-500'
          )}
        >
          All ({scans.length})
        </button>
        {Object.entries(statusConfig).map(([status, config]) => {
          const count = scans.filter((s) => s.status === status).length;
          if (count === 0) return null;
          return (
            <button
              key={status}
              onClick={() => setStatusFilter(status as ScanStatus)}
              className={clsx(
                'px-4 py-2 text-sm rounded-lg border transition-colors flex items-center gap-2',
                statusFilter === status
                  ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
                  : 'border-cyber-border text-gray-400 hover:border-gray-500'
              )}
            >
              <config.icon className={clsx('w-4 h-4', config.color)} />
              {config.label} ({count})
            </button>
          );
        })}
      </div>

      {/* Scans grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredScans.map((scan) => (
          <ScanCard key={scan.id} scan={scan} />
        ))}
      </div>

      {filteredScans.length === 0 && (
        <div className="card text-center py-12">
          <BarChart3 className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <p className="text-gray-400 mb-4">No scans found</p>
          <button
            onClick={() => setShowNewScanModal(true)}
            className="btn-primary"
          >
            Start Your First Scan
          </button>
        </div>
      )}

      {/* New Scan Modal */}
      <NewScanModal
        isOpen={showNewScanModal}
        onClose={() => setShowNewScanModal(false)}
        onSubmit={handleStartScan}
        defaultToken={scanSettings.githubToken}
        defaultOrg={scanSettings.defaultOrganization}
      />
    </div>
  );
}
