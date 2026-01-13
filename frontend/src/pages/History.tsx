import { useState, useEffect } from 'react';
import {
  Clock,
  ScanLine,
  CheckCircle,
  AlertTriangle,
  GitBranch,
  RefreshCw,
} from 'lucide-react';
import { clsx } from 'clsx';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import api from '../services/api';
import { format, formatDistanceToNow } from 'date-fns';

interface Activity {
  id: string;
  type: 'scan' | 'remediation';
  timestamp: string;
  organization: string | null;
  title: string;
  description: string;
  metadata: Record<string, any>;
}

export function History() {
  const [activities, setActivities] = useState<Activity[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<'all' | 'scan' | 'remediation'>('all');
  const [organization] = useState<string | null>(null);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        setLoading(true);
        const response = await api.getHistory(organization);
        const items = Array.isArray(response) ? response : (response?.items || []);
        setActivities(items);
      } catch (error) {
        console.error('Failed to fetch history:', error);
        setActivities([]);
      } finally {
        setLoading(false);
      }
    };

    fetchHistory();
  }, [organization]);

  const filteredActivities = activities.filter((activity) => {
    if (filter === 'all') return true;
    return activity.type === filter;
  });

  const getActivityIcon = (activity: Activity) => {
    if (activity.type === 'scan') {
      return activity.metadata?.total_findings === 0
        ? CheckCircle
        : ScanLine;
    }
    return AlertTriangle;
  };

  const getActivityColor = (activity: Activity) => {
    if (activity.type === 'scan') {
      return 'text-neon-blue';
    }
    const newStatus = activity.metadata?.new_status;
    if (newStatus === 'fixed' || newStatus === 'resolved') {
      return 'text-neon-green';
    }
    if (newStatus === 'false_positive') {
      return 'text-gray-500';
    }
    return 'text-neon-yellow';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-neon-blue border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-400">Loading activity history...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Activity History</h1>
          <p className="text-gray-500">
            Timeline of scans and remediation actions
          </p>
        </div>
        <button
          onClick={() => window.location.reload()}
          className="btn-ghost flex items-center gap-2"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="card">
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex gap-2">
            <button
              onClick={() => setFilter('all')}
              className={clsx(
                'px-4 py-2 text-sm rounded-lg border transition-colors',
                filter === 'all'
                  ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
                  : 'border-cyber-border text-gray-400 hover:border-gray-500'
              )}
            >
              All ({activities.length})
            </button>
            <button
              onClick={() => setFilter('scan')}
              className={clsx(
                'px-4 py-2 text-sm rounded-lg border transition-colors flex items-center gap-2',
                filter === 'scan'
                  ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
                  : 'border-cyber-border text-gray-400 hover:border-gray-500'
              )}
            >
              <ScanLine className="w-4 h-4" />
              Scans ({activities.filter(a => a.type === 'scan').length})
            </button>
            <button
              onClick={() => setFilter('remediation')}
              className={clsx(
                'px-4 py-2 text-sm rounded-lg border transition-colors flex items-center gap-2',
                filter === 'remediation'
                  ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
                  : 'border-cyber-border text-gray-400 hover:border-gray-500'
              )}
            >
              <CheckCircle className="w-4 h-4" />
              Remediations ({activities.filter(a => a.type === 'remediation').length})
            </button>
          </div>
        </div>
      </div>

      {/* Timeline */}
      <div className="space-y-4">
        {filteredActivities.length === 0 ? (
          <div className="card text-center py-12">
            <Clock className="w-12 h-12 text-gray-600 mx-auto mb-4" />
            <p className="text-gray-400">No activity history found</p>
            <p className="text-sm text-gray-500 mt-2">
              Run scans and update finding statuses to see activity here
            </p>
          </div>
        ) : (
          filteredActivities.map((activity, index) => {
            const Icon = getActivityIcon(activity);
            const iconColor = getActivityColor(activity);
            const date = new Date(activity.timestamp);

            return (
              <div key={activity.id} className="card">
                <div className="flex gap-4">
                  {/* Timeline indicator */}
                  <div className="flex flex-col items-center">
                    <div className={clsx(
                      'p-2 rounded-lg',
                      activity.type === 'scan' ? 'bg-neon-blue/20' : 'bg-neon-yellow/20'
                    )}>
                      <Icon className={clsx('w-5 h-5', iconColor)} />
                    </div>
                    {index < filteredActivities.length - 1 && (
                      <div className="w-0.5 h-full bg-cyber-border mt-2" />
                    )}
                  </div>

                  {/* Content */}
                  <div className="flex-1">
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <h3 className="font-medium text-gray-100">
                          {activity.title}
                        </h3>
                        <p className="text-sm text-gray-500 mt-1">
                          {activity.description}
                        </p>
                      </div>
                      <div className="text-right">
                        <p className="text-sm text-gray-400">
                          {format(date, 'MMM dd, yyyy HH:mm')}
                        </p>
                        <p className="text-xs text-gray-600">
                          {formatDistanceToNow(date, { addSuffix: true })}
                        </p>
                      </div>
                    </div>

                    {/* Metadata */}
                    {activity.type === 'scan' && (
                      <div className="mt-3 pt-3 border-t border-cyber-border">
                        <div className="flex flex-wrap gap-4 text-sm">
                          <div>
                            <span className="text-gray-500">Repositories:</span>
                            <span className="ml-2 text-gray-300 font-mono">
                              {activity.metadata?.repositories_scanned || 0}
                            </span>
                          </div>
                          <div>
                            <span className="text-gray-500">Findings:</span>
                            <span className="ml-2 text-gray-300 font-mono">
                              {activity.metadata?.total_findings || 0}
                            </span>
                          </div>
                          {activity.metadata?.critical > 0 && (
                            <div className="flex items-center gap-1">
                              <SeverityBadge severity="critical" />
                              <span className="text-gray-300">{activity.metadata.critical}</span>
                            </div>
                          )}
                          {activity.metadata?.high > 0 && (
                            <div className="flex items-center gap-1">
                              <SeverityBadge severity="high" />
                              <span className="text-gray-300">{activity.metadata.high}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {activity.type === 'remediation' && (
                      <div className="mt-3 pt-3 border-t border-cyber-border">
                        <div className="flex flex-wrap gap-4 text-sm">
                          <div className="flex items-center gap-2">
                            <GitBranch className="w-4 h-4 text-gray-500" />
                            <span className="text-gray-400">{activity.metadata?.repository}</span>
                          </div>
                          {activity.metadata?.severity && (
                            <SeverityBadge severity={activity.metadata.severity} />
                          )}
                          {activity.metadata?.performed_by && (
                            <div>
                              <span className="text-gray-500">By:</span>
                              <span className="ml-2 text-gray-300">{activity.metadata.performed_by}</span>
                            </div>
                          )}
                          {activity.metadata?.comment && (
                            <div className="w-full mt-2 p-2 bg-cyber-surface rounded text-xs text-gray-400">
                              {activity.metadata.comment}
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
