import { useState } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingDown,
  ArrowRight,
  Scan,
} from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'
import { Card, StatCard } from '@/components/Card'
import { SeverityBadge, StatusBadge } from '@/components/Badge'
import { TrendChart, SeverityPieChart, TopReposChart } from '@/components/Charts'
import { Button } from '@/components/Button'
import { Select } from '@/components/Input'
import { PageLoader } from '@/components/LoadingSpinner'
import { EmptyState } from '@/components/EmptyState'
import { useDashboard, useTrends, useScans, useOpenFindings, useOrganizations } from '@/hooks/useApi'
import { formatRelativeDate, truncate } from '@/lib/utils'

export function DashboardPage() {
  const [selectedOrg, setSelectedOrg] = useState<string>('')
  
  const { data: organizations } = useOrganizations()
  const { data: stats, isLoading: isLoadingStats } = useDashboard(selectedOrg || undefined)
  const { data: trends } = useTrends(selectedOrg || (organizations?.[0]?.name ?? ''), 30)
  const { data: scans } = useScans(selectedOrg || undefined, 5)
  const { data: openFindings } = useOpenFindings(selectedOrg || undefined)

  if (isLoadingStats) {
    return <PageLoader />
  }

  const orgOptions = [
    { value: '', label: 'Todas as Organizações' },
    ...(organizations?.map(o => ({ value: o.name, label: o.name })) || []),
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard de Segurança"
        description="Visão geral do estado de segurança dos seus repositórios"
        actions={
          <div className="flex items-center gap-3">
            <Select
              options={orgOptions}
              value={selectedOrg}
              onChange={(e) => setSelectedOrg(e.target.value)}
              className="w-48"
            />
            <Link to="/scans/new">
              <Button leftIcon={<Scan className="w-4 h-4" />}>
                Novo Scan
              </Button>
            </Link>
          </div>
        }
      />

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total de Scans"
          value={stats?.total_scans ?? 0}
          icon={<Shield className="w-5 h-5 text-neon-green" />}
          color="green"
        />
        <StatCard
          title="Findings Abertos"
          value={stats?.open_findings ?? 0}
          icon={<AlertTriangle className="w-5 h-5 text-severity-critical" />}
          color="red"
        />
        <StatCard
          title="Findings Corrigidos"
          value={stats?.fixed_findings ?? 0}
          icon={<CheckCircle className="w-5 h-5 text-severity-low" />}
          color="green"
        />
        <StatCard
          title="Em Progresso"
          value={stats?.in_progress_findings ?? 0}
          icon={<Clock className="w-5 h-5 text-severity-medium" />}
          color="yellow"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Trend Chart */}
        <Card className="lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold text-white">Tendência de Findings</h3>
            <span className="text-xs text-slate-400">Últimos 30 dias</span>
          </div>
          {trends && trends.length > 0 ? (
            <TrendChart data={trends} height={250} />
          ) : (
            <div className="h-[250px] flex items-center justify-center text-slate-500">
              <TrendingDown className="w-8 h-8 mr-2" />
              Sem dados de tendência
            </div>
          )}
        </Card>

        {/* Severity Distribution */}
        <Card>
          <h3 className="font-semibold text-white mb-4">Distribuição por Severidade</h3>
          <SeverityPieChart
            data={{
              critical: stats?.critical_findings ?? 0,
              high: stats?.high_findings ?? 0,
              medium: 0,
              low: 0,
            }}
            height={220}
          />
        </Card>
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Scans */}
        <Card>
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold text-white">Scans Recentes</h3>
            <Link to="/scans" className="text-xs text-neon-green hover:underline">
              Ver todos
            </Link>
          </div>
          
          {scans && scans.length > 0 ? (
            <div className="space-y-3">
              {scans.slice(0, 5).map((scan, index) => (
                <motion.div
                  key={scan.id}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.05 }}
                >
                  <Link
                    to={`/scans/${scan.id}`}
                    className="flex items-center justify-between p-3 rounded-lg bg-slate-800/30 hover:bg-slate-800/50 transition-colors group"
                  >
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-slate-700/50 flex items-center justify-center">
                        <Scan className="w-4 h-4 text-slate-400" />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-white">
                          {scan.organization}
                        </p>
                        <p className="text-xs text-slate-400">
                          {formatRelativeDate(scan.scan_date)}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="text-right">
                        <p className="text-sm font-bold text-white">
                          {scan.total_findings}
                        </p>
                        <p className="text-[10px] text-slate-500">findings</p>
                      </div>
                      <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-neon-green transition-colors" />
                    </div>
                  </Link>
                </motion.div>
              ))}
            </div>
          ) : (
            <EmptyState
              title="Nenhum scan realizado"
              description="Execute seu primeiro scan para começar"
              action={
                <Link to="/scans/new">
                  <Button size="sm">Iniciar Scan</Button>
                </Link>
              }
            />
          )}
        </Card>

        {/* Top Affected Repos */}
        <Card>
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold text-white">Repositórios Mais Afetados</h3>
          </div>
          
          {stats?.top_affected_repos && stats.top_affected_repos.length > 0 ? (
            <TopReposChart data={stats.top_affected_repos} height={220} />
          ) : (
            <div className="h-[220px] flex items-center justify-center text-slate-500">
              Nenhum finding aberto
            </div>
          )}
        </Card>
      </div>

      {/* Open Findings */}
      {openFindings && openFindings.length > 0 && (
        <Card>
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold text-white">Findings Abertos Críticos</h3>
            <Link to="/findings?status=open" className="text-xs text-neon-green hover:underline">
              Ver todos
            </Link>
          </div>
          
          <div className="space-y-2">
            {openFindings.slice(0, 5).map((finding, index) => (
              <motion.div
                key={finding.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.05 }}
              >
                <Link
                  to={`/findings/${finding.id}`}
                  className="flex items-center justify-between p-3 rounded-lg bg-slate-800/30 hover:bg-slate-800/50 transition-colors"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <SeverityBadge severity={finding.severity} size="sm" />
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-white truncate">
                        {finding.category}
                      </p>
                      <p className="text-xs text-slate-400 truncate">
                        {finding.repository} • {truncate(finding.file_path, 40)}
                      </p>
                    </div>
                  </div>
                  <StatusBadge status={finding.status} size="sm" />
                </Link>
              </motion.div>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}

