import { useState, useEffect } from 'react';
import {
  Search,
  Filter,
  Download,
  ChevronDown,
  ChevronRight,
  Eye,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  FileCode,
  GitBranch,
  ExternalLink,
  Copy,
  Sparkles,
  Key,
} from 'lucide-react';
import { clsx } from 'clsx';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { useStore } from '../stores/useStore';
import api from '../services/api';
import type {
  Finding,
  FindingsFilter,
  Severity,
  FindingType,
  RemediationStatus,
  AITriageResult,
  AITriageLabel,
  SecretValidationResult,
} from '../types';
import { format } from 'date-fns';


const severityOptions: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const typeOptions: FindingType[] = ['secret', 'vulnerability', 'sast', 'iac', 'history', 'bug'];
const statusOptions: RemediationStatus[] = ['open', 'in_progress', 'resolved', 'false_positive', 'accepted_risk'];

// Type icons and labels for better visualization
const typeConfig: Record<FindingType, { label: string; color: string }> = {
  secret: { label: '🔑 Secret', color: 'text-neon-red' },
  vulnerability: { label: '⚠️ Vulnerability', color: 'text-neon-yellow' },
  sast: { label: '🔍 SAST', color: 'text-neon-purple' },
  iac: { label: '☁️ IaC', color: 'text-neon-blue' },
  history: { label: '📜 History', color: 'text-gray-400' },
  bug: { label: '🐛 Bug', color: 'text-neon-orange' },
};

const statusConfig: Record<RemediationStatus, { label: string; icon: React.ElementType; color: string }> = {
  open: { label: 'Open', icon: AlertTriangle, color: 'text-neon-red' },
  in_progress: { label: 'In Progress', icon: Clock, color: 'text-neon-yellow' },
  resolved: { label: 'Resolved', icon: CheckCircle, color: 'text-neon-green' },
  false_positive: { label: 'False Positive', icon: XCircle, color: 'text-gray-500' },
  accepted_risk: { label: 'Accepted Risk', icon: Eye, color: 'text-neon-purple' },
};

type AITriageFilter = AITriageLabel | 'untriaged';

const triageLabelConfig: Record<AITriageLabel, { label: string; color: string }> = {
  likely_true_positive: { label: 'Likely True Positive', color: 'text-neon-red' },
  false_positive: { label: 'Likely False Positive', color: 'text-neon-green' },
  needs_review: { label: 'Needs Review', color: 'text-neon-yellow' },
};

const aiFilterOptions: AITriageFilter[] = [
  'likely_true_positive',
  'false_positive',
  'needs_review',
  'untriaged',
];

const validatableSecretCategories = new Set([
  'aws_access_key',
  'aws_secret_key',
  'github_token',
  'github_fine_grained',
  'slack_token',
]);

const secretValidationConfig: Record<'valid' | 'invalid' | 'unknown', { label: string; color: string }> = {
  valid: { label: 'Valid', color: 'text-neon-green' },
  invalid: { label: 'Invalid', color: 'text-neon-red' },
  unknown: { label: 'Unknown', color: 'text-neon-yellow' },
};

interface FindingRowProps {
  finding: Finding;
  expanded: boolean;
  onToggle: () => void;
  onStatusUpdate: (status: RemediationStatus) => void;
  aiTriage?: AITriageResult;
  aiLoading?: boolean;
  onAITriage: () => void;
  secretValidation?: SecretValidationResult;
  secretValidationLoading?: boolean;
  onValidateSecret: () => void;
}

function FindingRow({
  finding,
  expanded,
  onToggle,
  onStatusUpdate,
  aiTriage,
  aiLoading,
  onAITriage,
  secretValidation,
  secretValidationLoading,
  onValidateSecret,
}: FindingRowProps) {
  const status = statusConfig[finding.remediation_status];
  const StatusIcon = status.icon;
  const canValidateSecret = finding.type === 'secret' && validatableSecretCategories.has(finding.category);

  return (
    <>
      <tr className="table-row cursor-pointer" onClick={onToggle}>
        <td className="px-4 py-3">
          <button className="text-gray-500 hover:text-gray-300">
            {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          </button>
        </td>
        <td className="px-4 py-3">
          <SeverityBadge severity={finding.severity} />
        </td>
        <td className="px-4 py-3">
          <div>
            <p className="text-sm font-medium text-gray-200">{finding.category}</p>
            <p className={clsx('text-xs capitalize', typeConfig[finding.type]?.color || 'text-gray-500')}>
              {typeConfig[finding.type]?.label || finding.type}
            </p>
          </div>
        </td>
        <td className="px-4 py-3">
          {aiTriage ? (
            <span
              className={clsx(
                'inline-flex items-center px-2 py-0.5 text-xs rounded-md border',
                aiTriage.label === 'likely_true_positive' && 'border-neon-red/40 text-neon-red',
                aiTriage.label === 'false_positive' && 'border-neon-green/40 text-neon-green',
                aiTriage.label === 'needs_review' && 'border-neon-yellow/40 text-neon-yellow'
              )}
            >
              {triageLabelConfig[aiTriage.label].label}
            </span>
          ) : (
            <span className="text-xs text-gray-500">Untriaged</span>
          )}
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-gray-500" />
            <span className="text-sm text-gray-300">{finding.repository}</span>
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
        <td className="px-4 py-3 text-sm text-gray-500">
          {format(new Date(finding.created_at), 'MMM dd, yyyy')}
        </td>
      </tr>
      {expanded && (
        <tr className="bg-cyber-surface/30">
          <td colSpan={8} className="px-4 py-4">
            <div className="space-y-4">
              {/* Code snippet */}
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

              {/* Details grid */}
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

              {/* Rule description */}
              <div>
                <p className="text-sm font-medium text-gray-400 mb-1">Description</p>
                <p className="text-sm text-gray-300">{finding.rule_description}</p>
              </div>

              {/* Remediation notes */}
              {finding.remediation_notes && (
                <div>
                  <p className="text-sm font-medium text-gray-400 mb-1">Notes</p>
                  <p className="text-sm text-gray-300">{finding.remediation_notes}</p>
                </div>
              )}

              {/* Actions */}
              <div className="flex items-center gap-2 pt-2 border-t border-cyber-border">
                <span className="text-sm text-gray-500 mr-2">Update Status:</span>
                {statusOptions.map((s) => {
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
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onAITriage();
                  }}
                  className={clsx(
                    'ml-2 px-3 py-1 text-xs rounded-md border transition-colors flex items-center gap-1',
                    aiLoading
                      ? 'border-cyber-border text-gray-500 cursor-not-allowed'
                      : 'border-neon-purple/50 text-neon-purple hover:border-neon-purple'
                  )}
                  disabled={aiLoading}
                  title="AI triage"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  {aiLoading ? 'AI...' : 'AI Triage'}
                </button>
                {canValidateSecret && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onValidateSecret();
                    }}
                    className={clsx(
                      'px-3 py-1 text-xs rounded-md border transition-colors flex items-center gap-1',
                      secretValidationLoading
                        ? 'border-cyber-border text-gray-500 cursor-not-allowed'
                        : 'border-neon-blue/50 text-neon-blue hover:border-neon-blue'
                    )}
                    disabled={secretValidationLoading}
                    title="Validar secret"
                  >
                    <Key className="w-3.5 h-3.5" />
                    {secretValidationLoading ? 'Validando...' : 'Validar Secret'}
                  </button>
                )}
                <button className="ml-auto btn-ghost text-sm flex items-center gap-1">
                  <ExternalLink className="w-4 h-4" />
                  View on GitHub
                </button>
              </div>

              {aiTriage && (
                <div className="mt-4 rounded-lg border border-cyber-border bg-cyber-surface/40 p-4">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-medium text-gray-300">
                      AI Triage
                    </p>
                    <span className="text-xs text-gray-500 uppercase tracking-wide">
                      {aiTriage.source}
                    </span>
                  </div>
                  <div className="mt-2 flex items-center gap-2">
                    <span className={clsx('text-sm font-medium', triageLabelConfig[aiTriage.label].color)}>
                      {triageLabelConfig[aiTriage.label].label}
                    </span>
                    <span className="text-xs text-gray-500">
                      Confidence {Math.round(aiTriage.confidence * 100)}%
                    </span>
                  </div>
                  <ul className="mt-3 space-y-1 text-sm text-gray-400 list-disc list-inside">
                    {aiTriage.reasons.map((reason, index) => (
                      <li key={`${finding.id}-reason-${index}`}>{reason}</li>
                    ))}
                  </ul>
                </div>
              )}
              
              {secretValidation && (
                <div className="rounded-lg border border-cyber-border bg-cyber-surface/40 p-4">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-medium text-gray-300">
                      Secret Validation
                    </p>
                    <span className="text-xs text-gray-500 uppercase tracking-wide">
                      {secretValidation.provider}
                    </span>
                  </div>
                  <div className="mt-2 flex items-center gap-2">
                    <span className={clsx('text-sm font-medium', secretValidationConfig[secretValidation.status].color)}>
                      {secretValidationConfig[secretValidation.status].label}
                    </span>
                    <span className="text-xs text-gray-500">
                      {new Date(secretValidation.checked_at).toLocaleString()}
                    </span>
                  </div>
                  <p className="mt-2 text-sm text-gray-400">{secretValidation.message}</p>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export function Findings() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [aiTriage, setAiTriage] = useState<Record<string, AITriageResult>>({});
  const [aiLoading, setAiLoading] = useState<Record<string, boolean>>({});
  const [secretValidation, setSecretValidation] = useState<Record<string, SecretValidationResult>>({});
  const [secretValidationLoading, setSecretValidationLoading] = useState<Record<string, boolean>>({});
  const [searchQuery, setSearchQuery] = useState('');
  const [showFilters, setShowFilters] = useState(false);
  const [filters, setFilters] = useState<FindingsFilter>({
    severity: [],
    type: [],
    status: [],
  });
  const [aiFilters, setAiFilters] = useState<AITriageFilter[]>([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalFindings, setTotalFindings] = useState(0);
  const [pageSize, setPageSize] = useState(50);

  const { addNotification } = useStore();

  useEffect(() => {
    const fetchFindings = async () => {
      try {
        const response = await api.getFindings({
          ...filters,
          search: searchQuery || undefined,
          page: currentPage,
          page_size: pageSize,
        });
        // Handle both array and paginated response
        const items = Array.isArray(response) ? response : (response?.items || []);
        setFindings(items);
        if (!Array.isArray(response)) {
          setTotalPages(response?.total_pages || 1);
          setTotalFindings(response?.total || items.length);
        } else {
          setTotalPages(1);
          setTotalFindings(items.length);
        }
        const triageMap = items.reduce<Record<string, AITriageResult>>((acc, item) => {
          if (item.ai_triage) {
            acc[item.id] = item.ai_triage;
          }
          return acc;
        }, {});
        setAiTriage((prev) => ({ ...prev, ...triageMap }));
      } catch (error) {
        console.error('Failed to fetch findings:', error);
        setFindings([]);
      } finally {
        setLoading(false);
      }
    };

    fetchFindings();
  }, [filters, searchQuery, currentPage, pageSize]);

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

  const handleAITriage = async (findingId: string) => {
    if (aiLoading[findingId]) {
      return;
    }
    setAiLoading((prev) => ({ ...prev, [findingId]: true }));
    try {
      const response = await api.getFindingAITriage(findingId);
      setAiTriage((prev) => ({ ...prev, [findingId]: response.result }));
      addNotification({
        type: 'success',
        title: 'AI Triage Ready',
        message: 'Sugestao de triagem gerada com sucesso.',
      });
    } catch (error) {
      console.error('AI triage failed:', error);
      addNotification({
        type: 'error',
        title: 'AI Triage Failed',
        message: 'Nao foi possivel gerar a triagem automatica.',
      });
    } finally {
      setAiLoading((prev) => ({ ...prev, [findingId]: false }));
    }
  };

  const handleBatchAITriage = async () => {
    const targetIds = filteredFindings.map((f) => f.id);
    if (targetIds.length === 0) {
      return;
    }
    setAiLoading((prev) => {
      const next = { ...prev };
      targetIds.forEach((id) => {
        next[id] = true;
      });
      return next;
    });
    try {
      const response = await api.getFindingsAITriageBatch(targetIds);
      setAiTriage((prev) => ({ ...prev, ...response.results }));
      addNotification({
        type: 'success',
        title: 'AI Triage Ready',
        message: `Triagem gerada para ${Object.keys(response.results).length} findings.`,
      });
      if (response.failed?.length) {
        addNotification({
          type: 'warning',
          title: 'AI Triage Partial',
          message: `${response.failed.length} findings falharam na triagem.`,
        });
      }
    } catch (error) {
      console.error('AI triage batch failed:', error);
      addNotification({
        type: 'error',
        title: 'AI Triage Failed',
        message: 'Nao foi possivel gerar a triagem em lote.',
      });
    } finally {
      setAiLoading((prev) => {
        const next = { ...prev };
        targetIds.forEach((id) => {
          next[id] = false;
        });
        return next;
      });
    }
  };

  const handleValidateSecret = async (findingId: string) => {
    if (secretValidationLoading[findingId]) {
      return;
    }
    setSecretValidationLoading((prev) => ({ ...prev, [findingId]: true }));
    try {
      const response = await api.validateFindingSecret(findingId);
      setSecretValidation((prev) => ({ ...prev, [findingId]: response.result }));
      addNotification({
        type: 'success',
        title: 'Secret Validada',
        message: response.result.message || 'Validacao concluida.',
      });
    } catch (error) {
      console.error('Secret validation failed:', error);
      addNotification({
        type: 'error',
        title: 'Validacao Falhou',
        message: 'Nao foi possivel validar a secret.',
      });
    } finally {
      setSecretValidationLoading((prev) => ({ ...prev, [findingId]: false }));
    }
  };

  const toggleFilter = (type: 'severity' | 'type' | 'status', value: string) => {
    setFilters((prev) => {
      const current = prev[type] || [];
      const updated = current.includes(value as never)
        ? current.filter((v) => v !== value)
        : [...current, value as never];
      return { ...prev, [type]: updated };
    });
    setCurrentPage(1);
  };

  const toggleAiFilter = (value: AITriageFilter) => {
    setAiFilters((prev) =>
      prev.includes(value) ? prev.filter((v) => v !== value) : [...prev, value]
    );
    setCurrentPage(1);
  };

  const filteredFindings = findings.filter((f) => {
    if (aiFilters.length > 0) {
      const triage = aiTriage[f.id];
      const label: AITriageFilter = triage?.label || 'untriaged';
      return aiFilters.includes(label);
    }
    return true;
  });

  const activeFiltersCount =
    (filters.severity?.length || 0) +
    (filters.type?.length || 0) +
    (filters.status?.length || 0) +
    aiFilters.length;

  const handleExportCSV = async () => {
    try {
      // Build export filters (include search query)
      const exportFilters: FindingsFilter = {
        ...filters,
        search: searchQuery || undefined,
      };
      
      addNotification({
        type: 'info',
        title: 'Exporting...',
        message: 'Preparing CSV export...',
      });
      
      const blob = await api.exportFindingsCSV(exportFilters);
      
      // Create download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `security_findings_${new Date().toISOString().split('T')[0]}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      
      addNotification({
        type: 'success',
        title: 'Export Complete',
        message: `Exported ${filteredFindings.length} findings to CSV`,
      });
    } catch (error) {
      console.error('Export failed:', error);
      addNotification({
        type: 'error',
        title: 'Export Failed',
        message: error instanceof Error ? error.message : 'Failed to export findings',
      });
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-neon-blue border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-400">Loading findings...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Security Findings</h1>
          <p className="text-gray-500">
            {totalFindings.toLocaleString()} findings found
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleBatchAITriage}
            className="btn-ghost flex items-center gap-2"
            disabled={filteredFindings.length === 0}
          >
            <Sparkles className="w-4 h-4" />
            AI Triage visiveis ({filteredFindings.length})
          </button>
          <button 
            onClick={handleExportCSV}
            className="btn-primary flex items-center gap-2"
            disabled={filteredFindings.length === 0}
          >
            <Download className="w-4 h-4" />
            Export CSV ({filteredFindings.length})
          </button>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="card">
        <div className="flex flex-col md:flex-row gap-4">
          {/* Search */}
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search by repository, category, file path, secret..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setCurrentPage(1);
              }}
              className="input pl-10"
            />
          </div>

          {/* Filter toggle */}
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={clsx(
              'btn-ghost flex items-center gap-2',
              activeFiltersCount > 0 && 'text-neon-blue'
            )}
          >
            <Filter className="w-4 h-4" />
            Filters
            {activeFiltersCount > 0 && (
              <span className="px-1.5 py-0.5 text-xs bg-neon-blue/20 rounded-full">
                {activeFiltersCount}
              </span>
            )}
          </button>
        </div>

        {/* Filter panels */}
        {showFilters && (
          <div className="mt-4 pt-4 border-t border-cyber-border grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Severity */}
            <div>
              <p className="text-sm font-medium text-gray-400 mb-2">Severity</p>
              <div className="flex flex-wrap gap-2">
                {severityOptions.map((s) => (
                  <button
                    key={s}
                    onClick={() => toggleFilter('severity', s)}
                    className={clsx(
                      'px-3 py-1 text-xs rounded-md border transition-colors capitalize',
                      filters.severity?.includes(s)
                        ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
                        : 'border-cyber-border text-gray-400 hover:border-gray-500'
                    )}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>

            {/* Type */}
            <div>
              <p className="text-sm font-medium text-gray-400 mb-2">Type</p>
              <div className="flex flex-wrap gap-2">
                {typeOptions.map((t) => (
                  <button
                    key={t}
                    onClick={() => toggleFilter('type', t)}
                    className={clsx(
                      'px-3 py-1 text-xs rounded-md border transition-colors',
                      filters.type?.includes(t)
                        ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
                        : 'border-cyber-border text-gray-400 hover:border-gray-500'
                    )}
                  >
                    {typeConfig[t]?.label || t}
                  </button>
                ))}
              </div>
            </div>

            {/* Status */}
            <div>
              <p className="text-sm font-medium text-gray-400 mb-2">Status</p>
              <div className="flex flex-wrap gap-2">
                {statusOptions.map((s) => (
                  <button
                    key={s}
                    onClick={() => toggleFilter('status', s)}
                    className={clsx(
                      'px-3 py-1 text-xs rounded-md border transition-colors',
                      filters.status?.includes(s)
                        ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
                        : 'border-cyber-border text-gray-400 hover:border-gray-500'
                    )}
                  >
                    {statusConfig[s].label}
                  </button>
                ))}
              </div>
            </div>

            {/* AI Triage */}
            <div>
              <p className="text-sm font-medium text-gray-400 mb-2">AI Triage</p>
              <div className="flex flex-wrap gap-2">
                {aiFilterOptions.map((label) => {
                  const config = label === 'untriaged'
                    ? { label: 'Untriaged', color: 'text-gray-400' }
                    : triageLabelConfig[label];
                  return (
                    <button
                      key={label}
                      onClick={() => toggleAiFilter(label)}
                      className={clsx(
                        'px-3 py-1 text-xs rounded-md border transition-colors',
                        aiFilters.includes(label)
                          ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
                          : 'border-cyber-border text-gray-400 hover:border-gray-500'
                      )}
                    >
                      <span className={clsx(config.color)}>{config.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Findings Table */}
      <div className="card p-0 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="table-header">
              <th className="w-10 px-4 py-3"></th>
              <th className="px-4 py-3 text-left">Severity</th>
              <th className="px-4 py-3 text-left">Category</th>
              <th className="px-4 py-3 text-left">AI</th>
              <th className="px-4 py-3 text-left">Repository</th>
              <th className="px-4 py-3 text-left">Location</th>
              <th className="px-4 py-3 text-left">Status</th>
              <th className="px-4 py-3 text-left">Found</th>
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
                aiTriage={aiTriage[finding.id]}
                aiLoading={aiLoading[finding.id]}
                onAITriage={() => handleAITriage(finding.id)}
                secretValidation={secretValidation[finding.id]}
                secretValidationLoading={secretValidationLoading[finding.id]}
                onValidateSecret={() => handleValidateSecret(finding.id)}
              />
            ))}
          </tbody>
        </table>

        {filteredFindings.length === 0 && (
          <div className="p-12 text-center">
            <AlertTriangle className="w-12 h-12 text-gray-600 mx-auto mb-4" />
            <p className="text-gray-400">No findings match your criteria</p>
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-gray-500">
            Page {currentPage} of {totalPages} ({totalFindings.toLocaleString()} total)
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="btn-ghost px-3 py-1 text-sm disabled:opacity-50"
            >
              Prev
            </button>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="btn-ghost px-3 py-1 text-sm disabled:opacity-50"
            >
              Next
            </button>
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setCurrentPage(1);
              }}
              className="input text-sm"
            >
              {[50, 100, 200].map((size) => (
                <option key={size} value={size}>
                  {size} / page
                </option>
              ))}
            </select>
          </div>
        </div>
      )}
    </div>
  );
}
