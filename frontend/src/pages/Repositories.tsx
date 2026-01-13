import { useState, useEffect } from 'react';
import {
  Search,
  GitBranch,
  Lock,
  Unlock,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  ScanLine,
  ExternalLink,
  Code,
  Archive,
} from 'lucide-react';
import { clsx } from 'clsx';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import api from '../services/api';
import type { Repository } from '../types';
import { formatDistanceToNow } from 'date-fns';


const languageColors: Record<string, string> = {
  Go: 'bg-blue-500',
  Python: 'bg-yellow-500',
  Java: 'bg-orange-500',
  TypeScript: 'bg-blue-400',
  JavaScript: 'bg-yellow-400',
  PHP: 'bg-purple-500',
  Ruby: 'bg-red-500',
  Rust: 'bg-orange-600',
  'C#': 'bg-green-500',
  Markdown: 'bg-gray-500',
};

function RepositoryCard({ repo, onScan }: { repo: Repository; onScan: () => void }) {
  const hasCritical = repo.findings_count.critical > 0;
  const hasHigh = repo.findings_count.high > 0;
  const isClean = repo.findings_count.total === 0;

  return (
    <div className={clsx(
      'card group transition-all',
      hasCritical && 'border-severity-critical/30',
      !hasCritical && hasHigh && 'border-severity-high/30',
      repo.is_archived && 'opacity-60'
    )}>
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          {repo.is_private ? (
            <Lock className="w-4 h-4 text-neon-yellow" />
          ) : (
            <Unlock className="w-4 h-4 text-gray-500" />
          )}
          <h3 className="font-medium text-gray-100 group-hover:text-neon-blue transition-colors">
            {repo.name}
          </h3>
          {repo.is_archived && (
            <span className="px-2 py-0.5 text-xs bg-gray-700 text-gray-400 rounded">
              Archived
            </span>
          )}
        </div>
        <a
          href={repo.url}
          target="_blank"
          rel="noopener noreferrer"
          className="text-gray-500 hover:text-gray-300 transition-colors"
        >
          <ExternalLink className="w-4 h-4" />
        </a>
      </div>

      {/* Description */}
      {repo.description && (
        <p className="text-sm text-gray-500 mb-4 line-clamp-2">
          {repo.description}
        </p>
      )}

      {/* Language and branch */}
      <div className="flex items-center gap-4 mb-4 text-sm">
        {repo.language && (
          <div className="flex items-center gap-1">
            <span className={clsx('w-3 h-3 rounded-full', languageColors[repo.language] || 'bg-gray-500')} />
            <span className="text-gray-400">{repo.language}</span>
          </div>
        )}
        <div className="flex items-center gap-1 text-gray-500">
          <GitBranch className="w-4 h-4" />
          <span>{repo.default_branch}</span>
        </div>
      </div>

      {/* Findings summary */}
      <div className="flex items-center gap-2 mb-4">
        {isClean ? (
          <div className="flex items-center gap-2 text-neon-green">
            <CheckCircle className="w-4 h-4" />
            <span className="text-sm">No issues found</span>
          </div>
        ) : (
          <>
            {repo.findings_count.critical > 0 && (
              <div className="flex items-center gap-1">
                <SeverityBadge severity="critical" />
                <span className="text-sm text-gray-400">{repo.findings_count.critical}</span>
              </div>
            )}
            {repo.findings_count.high > 0 && (
              <div className="flex items-center gap-1">
                <SeverityBadge severity="high" />
                <span className="text-sm text-gray-400">{repo.findings_count.high}</span>
              </div>
            )}
            {repo.findings_count.medium > 0 && (
              <div className="flex items-center gap-1">
                <SeverityBadge severity="medium" />
                <span className="text-sm text-gray-400">{repo.findings_count.medium}</span>
              </div>
            )}
            <span className="text-sm text-gray-600">
              ({repo.findings_count.total} total)
            </span>
          </>
        )}
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between pt-4 border-t border-cyber-border">
        <div className="text-sm text-gray-500">
          {repo.last_scan_at ? (
            <span>Scanned {formatDistanceToNow(new Date(repo.last_scan_at), { addSuffix: true })}</span>
          ) : (
            <span className="text-neon-yellow">Never scanned</span>
          )}
        </div>
        <button
          onClick={onScan}
          disabled={repo.is_archived}
          className="btn-ghost text-sm flex items-center gap-1 disabled:opacity-50"
        >
          <ScanLine className="w-4 h-4" />
          Scan
        </button>
      </div>
    </div>
  );
}

export function Repositories() {
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [showArchived, setShowArchived] = useState(false);
  const [sortBy, setSortBy] = useState<'findings' | 'name' | 'recent'>('findings');

  useEffect(() => {
    const fetchRepositories = async () => {
      try {
        const data = await api.getRepositories();
        // API returns array directly
        setRepositories(data || []);
      } catch (error) {
        console.error('Failed to fetch repositories:', error);
        setRepositories([]);
      } finally {
        setLoading(false);
      }
    };

    fetchRepositories();
  }, []);

  const handleScan = async (repoFullName: string) => {
    // Get token from localStorage (stored by useStore)
    const stored = localStorage.getItem('gss-storage');
    const token = stored ? JSON.parse(stored)?.state?.scanSettings?.githubToken : '';
    
    if (!token) {
      console.error('No GitHub token configured. Please go to Settings.');
      alert('Please configure your GitHub token in Settings first.');
      return;
    }
    
    try {
      await api.startRepoScan(repoFullName, token);
    } catch (error) {
      console.error('Failed to start scan:', error);
    }
  };

  let filteredRepos = repositories.filter((repo) => {
    if (!showArchived && repo.is_archived) return false;
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      return (
        repo.name.toLowerCase().includes(query) ||
        repo.description?.toLowerCase().includes(query) ||
        repo.language?.toLowerCase().includes(query)
      );
    }
    return true;
  });

  // Sort
  filteredRepos = [...filteredRepos].sort((a, b) => {
    if (sortBy === 'findings') {
      return b.findings_count.total - a.findings_count.total;
    }
    if (sortBy === 'name') {
      return a.name.localeCompare(b.name);
    }
    if (sortBy === 'recent') {
      if (!a.last_scan_at) return 1;
      if (!b.last_scan_at) return -1;
      return new Date(b.last_scan_at).getTime() - new Date(a.last_scan_at).getTime();
    }
    return 0;
  });

  // Calculate aggregated statistics
  const stats = {
    total: repositories.length,
    // Total findings by severity (sum of all repositories)
    criticalFindings: repositories.reduce((sum, r) => sum + r.findings_count.critical, 0),
    highFindings: repositories.reduce((sum, r) => sum + r.findings_count.high, 0),
    totalFindings: repositories.reduce((sum, r) => sum + r.findings_count.total, 0),
    // Repository counts
    withIssues: repositories.filter((r) => r.findings_count.total > 0).length,
    clean: repositories.filter((r) => r.findings_count.total === 0).length,
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-neon-blue border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-400">Loading repositories...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Repositories</h1>
          <p className="text-gray-500">
            {stats.total.toLocaleString()} repositories • {stats.totalFindings.toLocaleString()} findings • {stats.withIssues} with issues • {stats.clean} clean
          </p>
        </div>
        <button className="btn-ghost flex items-center gap-2">
          <RefreshCw className="w-4 h-4" />
          Sync from GitHub
        </button>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="stat-card">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-neon-blue/20 text-neon-blue">
              <Code className="w-5 h-5" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-100 font-mono">{stats.total.toLocaleString()}</p>
              <p className="text-xs text-gray-500">Total Repos</p>
            </div>
          </div>
        </div>
        <div className="stat-card">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-severity-critical/20 text-severity-critical">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-100 font-mono">{stats.criticalFindings.toLocaleString()}</p>
              <p className="text-xs text-gray-500">Critical</p>
            </div>
          </div>
        </div>
        <div className="stat-card">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-severity-high/20 text-severity-high">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-100 font-mono">{stats.highFindings.toLocaleString()}</p>
              <p className="text-xs text-gray-500">High</p>
            </div>
          </div>
        </div>
        <div className="stat-card">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-neon-yellow/20 text-neon-yellow">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-100 font-mono">{stats.withIssues.toLocaleString()}</p>
              <p className="text-xs text-gray-500">Repos With Issues</p>
            </div>
          </div>
        </div>
        <div className="stat-card">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-neon-green/20 text-neon-green">
              <CheckCircle className="w-5 h-5" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-100 font-mono">{stats.clean.toLocaleString()}</p>
              <p className="text-xs text-gray-500">Clean Repos</p>
            </div>
          </div>
        </div>
      </div>

      {/* Search and filters */}
      <div className="card">
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search repositories..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input pl-10"
            />
          </div>
          <div className="flex items-center gap-2">
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as 'findings' | 'name' | 'recent')}
              className="input py-2 w-auto"
            >
              <option value="findings">Most Findings</option>
              <option value="name">Name</option>
              <option value="recent">Recently Scanned</option>
            </select>
            <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer">
              <input
                type="checkbox"
                checked={showArchived}
                onChange={(e) => setShowArchived(e.target.checked)}
                className="w-4 h-4 rounded border-cyber-border bg-cyber-surface"
              />
              <Archive className="w-4 h-4" />
              Show Archived
            </label>
          </div>
        </div>
      </div>

      {/* Repository grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredRepos.map((repo) => (
          <RepositoryCard
            key={repo.id}
            repo={repo}
            onScan={() => handleScan(repo.full_name)}
          />
        ))}
      </div>

      {filteredRepos.length === 0 && (
        <div className="card text-center py-12">
          <GitBranch className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <p className="text-gray-400">No repositories found</p>
        </div>
      )}
    </div>
  );
}
