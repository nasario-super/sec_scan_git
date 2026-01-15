import { useEffect, useMemo, useState } from 'react';
import {
  Shield,
  AlertTriangle,
  Package,
  Code,
  Key,
  RefreshCw,
  Filter,
  Loader2,
} from 'lucide-react';
import { useStore } from '../stores/useStore';
import api from '../services/api';

interface AlertSummary {
  repository?: string;
  organization?: string;
  dependabot_total: number;
  dependabot_critical: number;
  dependabot_high: number;
  dependabot_medium: number;
  dependabot_low: number;
  dependabot_open: number;
  dependabot_fixed: number;
  dependabot_dismissed: number;
  code_scanning_total: number;
  code_scanning_critical: number;
  code_scanning_high: number;
  code_scanning_medium: number;
  code_scanning_low: number;
  code_scanning_open: number;
  code_scanning_fixed: number;
  code_scanning_dismissed: number;
  secret_scanning_total: number;
  secret_scanning_open: number;
  secret_scanning_resolved: number;
  total_alerts: number;
  total_critical: number;
  total_high: number;
  total_open: number;
}

interface OrgAlertsSummaryResponse extends AlertSummary {
  organization: string;
  repos_scanned: number;
  repos_with_alerts: number;
  summaries: AlertSummary[];
  errors: { repository: string; error: string }[];
  last_sync_at?: string;
}

export function SecurityAlerts() {
  const { scanSettings } = useStore();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [organizations, setOrganizations] = useState<string[]>([]);
  const [organization, setOrganization] = useState('');
  const [summary, setSummary] = useState<OrgAlertsSummaryResponse | null>(null);
  const [filterQuery, setFilterQuery] = useState('');
  const [onlyWithAlerts, setOnlyWithAlerts] = useState(true);

  useEffect(() => {
    const loadOrganizations = async () => {
      try {
        const orgs = await api.getOrganizations();
        const normalized = (orgs || []).map((org: any) =>
          typeof org === 'string' ? org : org?.name
        ).filter(Boolean) as string[];
        setOrganizations(normalized);
        if (!organization && normalized.length) {
          setOrganization(normalized[0]);
        }
      } catch {
        // Ignore errors, allow manual input
      }
    };
    loadOrganizations();
  }, [organization]);

  const fetchOrgAlerts = async () => {
    if (!organization || !scanSettings.githubToken) {
      setError('Configure o GitHub token e selecione a organização');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `/api/alerts/organization/${encodeURIComponent(organization)}/summary` +
          `?token=${encodeURIComponent(scanSettings.githubToken)}&max_repos=200`
      );

      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || 'Falha ao buscar alertas');
      }

      const data = await response.json();
      setSummary(data);
    } catch (err: any) {
      setError(err.message);
      setSummary(null);
    } finally {
      setLoading(false);
    }
  };

  const filteredSummaries = useMemo(() => {
    if (!summary?.summaries?.length) return [];
    const query = filterQuery.toLowerCase();
    return summary.summaries
      .filter((item) => {
        if (onlyWithAlerts && item.total_alerts === 0) return false;
        if (query && item.repository && !item.repository.toLowerCase().includes(query)) return false;
        return true;
      })
      .sort((a, b) => b.total_alerts - a.total_alerts);
  }, [summary, filterQuery, onlyWithAlerts]);

  const mediumLowCount = summary
    ? summary.dependabot_medium +
      summary.dependabot_low +
      summary.code_scanning_medium +
      summary.code_scanning_low
    : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
            <Shield className="w-7 h-7 text-neon-blue" />
            Alertas de Segurança do GitHub
          </h1>
          <p className="text-gray-500 mt-1">
            Visão centralizada de Dependabot, Code Scanning e Secret Scanning
          </p>
        </div>
      </div>

      {/* Organization Input */}
      <div className="card">
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex-1">
            <label className="block text-sm font-medium text-gray-400 mb-2">
              Organização
            </label>
            {organizations.length > 0 ? (
              <select
                value={organization}
                onChange={(e) => setOrganization(e.target.value)}
                className="input w-full"
              >
                {organizations.map((org) => (
                  <option key={org} value={org}>
                    {org}
                  </option>
                ))}
              </select>
            ) : (
              <input
                type="text"
                value={organization}
                onChange={(e) => setOrganization(e.target.value)}
                placeholder="organization"
                className="input w-full"
              />
            )}
          </div>
          <div className="flex items-end">
            <button
              onClick={fetchOrgAlerts}
              disabled={loading || !organization}
              className="btn-primary flex items-center gap-2 h-10"
            >
              {loading ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <RefreshCw className="w-4 h-4" />
              )}
              Atualizar Alertas
            </button>
          </div>
        </div>
        {!scanSettings.githubToken && (
          <p className="text-severity-medium text-sm mt-2">
            ⚠️ GitHub token não configurado. Configure na tela de Scans.
          </p>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="card border-severity-critical/30 bg-severity-critical/5">
          <div className="flex items-center gap-2 text-severity-critical">
            <AlertTriangle className="w-5 h-5" />
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
                <p className="text-xs text-gray-500">Total de Alertas</p>
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
                <p className="text-xs text-gray-500">Dependabot Abertos</p>
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
                <p className="text-xs text-gray-500">Code Scanning Abertos</p>
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
                <p className="text-xs text-gray-500">Secret Scanning Abertos</p>
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
              <p className="text-sm text-gray-400">Crítico</p>
            </div>
          </div>
          <div className="card border-severity-high/30 bg-severity-high/5">
            <div className="text-center">
              <p className="text-3xl font-bold text-severity-high">{summary.total_high}</p>
              <p className="text-sm text-gray-400">Alto</p>
            </div>
          </div>
          <div className="card border-severity-medium/30 bg-severity-medium/5">
            <div className="text-center">
              <p className="text-3xl font-bold text-severity-medium">
                {mediumLowCount}
              </p>
              <p className="text-sm text-gray-400">Médio/Baixo</p>
            </div>
          </div>
          <div className="card border-neon-green/30 bg-neon-green/5">
            <div className="text-center">
              <p className="text-3xl font-bold text-neon-green">{summary.total_open}</p>
              <p className="text-sm text-gray-400">Abertos</p>
            </div>
          </div>
        </div>
      )}

      {summary && (
        <div className="card">
          <div className="flex flex-col lg:flex-row lg:items-center gap-4 justify-between">
            <div>
              <h3 className="text-lg font-semibold text-gray-100">Controle por repositório</h3>
              <p className="text-sm text-gray-500">
                {summary.repos_with_alerts} repositórios com alertas • {summary.repos_scanned} analisados
              </p>
            </div>
            <div className="flex flex-col md:flex-row gap-3">
              <div className="flex items-center gap-2">
                <Filter className="w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  value={filterQuery}
                  onChange={(e) => setFilterQuery(e.target.value)}
                  placeholder="Filtrar por repositório"
                  className="input"
                />
              </div>
              <label className="flex items-center gap-2 text-sm text-gray-400">
                <input
                  type="checkbox"
                  checked={onlyWithAlerts}
                  onChange={(e) => setOnlyWithAlerts(e.target.checked)}
                />
                Somente com alertas
              </label>
            </div>
          </div>

          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-400">
                  <th className="py-2">Repositório</th>
                  <th className="py-2">Total</th>
                  <th className="py-2">Crítico</th>
                  <th className="py-2">Alto</th>
                  <th className="py-2">Abertos</th>
                  <th className="py-2">Dependabot</th>
                  <th className="py-2">Code Scanning</th>
                  <th className="py-2">Secret Scanning</th>
                </tr>
              </thead>
              <tbody>
                {filteredSummaries.map((item) => (
                  <tr key={item.repository} className="border-t border-cyber-border text-gray-200">
                    <td className="py-2 pr-4">{item.repository}</td>
                    <td className="py-2">{item.total_alerts}</td>
                    <td className="py-2">{item.total_critical}</td>
                    <td className="py-2">{item.total_high}</td>
                    <td className="py-2">{item.total_open}</td>
                    <td className="py-2">{item.dependabot_total}</td>
                    <td className="py-2">{item.code_scanning_total}</td>
                    <td className="py-2">{item.secret_scanning_total}</td>
                  </tr>
                ))}
                {filteredSummaries.length === 0 && (
                  <tr>
                    <td colSpan={8} className="py-4 text-center text-gray-500">
                      Nenhum repositório com alertas encontrado.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {summary?.errors?.length ? (
        <div className="card border-severity-medium/30 bg-severity-medium/5">
          <div className="flex items-center gap-2 text-severity-medium mb-2">
            <AlertTriangle className="w-5 h-5" />
            <span>Alguns repositórios não possuem Security Alerts habilitados ou acesso negado.</span>
          </div>
          <div className="text-xs text-gray-500 space-y-1">
            {summary.errors.slice(0, 10).map((err) => (
              <div key={`${err.repository}-${err.error}`}>{err.repository}: {err.error}</div>
            ))}
            {summary.errors.length > 10 && (
              <div>... e mais {summary.errors.length - 10} erros</div>
            )}
          </div>
        </div>
      ) : null}

      {/* Empty State */}
      {!loading && !summary && !error && (
        <div className="card text-center py-12">
          <Shield className="w-16 h-16 text-gray-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-300 mb-2">
            Nenhum alerta carregado
          </h3>
          <p className="text-gray-500 max-w-md mx-auto">
            Selecione uma organização e clique em "Atualizar Alertas" para centralizar os resultados.
          </p>
        </div>
      )}

      {/* Info Box */}
      <div className="card border-neon-blue/30 bg-neon-blue/5">
        <h3 className="font-medium text-neon-blue mb-2">ℹ️ Sobre os Alertas de Segurança do GitHub</h3>
        <div className="text-sm text-gray-400 space-y-2">
          <p>
            <strong className="text-blue-400">Dependabot:</strong> Alertas de dependências vulneráveis
            em arquivos como package.json, requirements.txt, etc.
          </p>
          <p>
            <strong className="text-purple-400">Code Scanning:</strong> Findings SAST do CodeQL
            ou outras ferramentas configuradas no repositório.
          </p>
          <p>
            <strong className="text-red-400">Secret Scanning:</strong> Segredos expostos como API keys,
            tokens e senhas detectadas pelo GitHub.
          </p>
        </div>
      </div>
    </div>
  );
}
