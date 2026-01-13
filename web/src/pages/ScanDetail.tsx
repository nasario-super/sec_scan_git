import { useParams, Link } from 'react-router-dom'
import {
  ArrowLeft,
  Clock,
  GitBranch,
  AlertTriangle,
  Shield,
  Key,
  Bug,
  Settings,
} from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'
import { Card, StatCard } from '@/components/Card'
import { SeverityBadge, TypeBadge, StatusBadge } from '@/components/Badge'
import { SeverityPieChart } from '@/components/Charts'
import { Button } from '@/components/Button'
import { DataTable } from '@/components/DataTable'
import { PageLoader } from '@/components/LoadingSpinner'
import { useScan, useFindings } from '@/hooks/useApi'
import { formatDate, formatDuration, truncate } from '@/lib/utils'
import type { Finding } from '@/types'

export function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>()
  
  const { data: scan, isLoading: isLoadingScan } = useScan(scanId || '')
  const { data: findings, isLoading: isLoadingFindings } = useFindings({
    scan_id: scanId,
    limit: 200,
  })

  if (isLoadingScan) {
    return <PageLoader />
  }

  if (!scan) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Card className="text-center">
          <h2 className="text-lg font-semibold text-white mb-2">Scan não encontrado</h2>
          <p className="text-sm text-slate-400 mb-4">O scan solicitado não existe ou foi removido.</p>
          <Link to="/scans">
            <Button variant="secondary">Voltar para Scans</Button>
          </Link>
        </Card>
      </div>
    )
  }

  const findingColumns = [
    {
      key: 'severity',
      header: 'Severidade',
      width: '100px',
      render: (value: unknown) => <SeverityBadge severity={value as Finding['severity']} size="sm" />,
    },
    {
      key: 'finding_type',
      header: 'Tipo',
      width: '140px',
      render: (value: unknown) => <TypeBadge type={value as Finding['finding_type']} size="sm" />,
    },
    {
      key: 'category',
      header: 'Categoria',
      render: (value: unknown) => (
        <span className="text-white font-medium">{value as string}</span>
      ),
    },
    {
      key: 'repository',
      header: 'Repositório',
      render: (value: unknown) => (
        <span className="text-slate-300">{value as string}</span>
      ),
    },
    {
      key: 'file_path',
      header: 'Arquivo',
      render: (value: unknown, finding: Finding) => (
        <div>
          <p className="text-slate-300 text-xs font-mono">{truncate(value as string, 40)}</p>
          <p className="text-slate-500 text-[10px]">Linha {finding.line_number}</p>
        </div>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      width: '120px',
      render: (value: unknown) => <StatusBadge status={value as Finding['status']} size="sm" />,
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title={`Scan: ${scan.organization}`}
        description={`Executado em ${formatDate(scan.scan_date)}`}
        breadcrumbs={[
          { label: 'Scans', href: '/scans' },
          { label: scan.organization },
        ]}
        actions={
          <Link to="/scans">
            <Button variant="secondary" leftIcon={<ArrowLeft className="w-4 h-4" />}>
              Voltar
            </Button>
          </Link>
        }
      />

      {/* Scan Info */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatCard
          title="Repositórios"
          value={scan.repositories_scanned}
          icon={<GitBranch className="w-5 h-5 text-neon-cyan" />}
          color="blue"
        />
        <StatCard
          title="Total Findings"
          value={scan.total_findings}
          icon={<AlertTriangle className="w-5 h-5 text-severity-high" />}
          color="red"
        />
        <StatCard
          title="Críticos"
          value={scan.critical_count}
          icon={<Shield className="w-5 h-5 text-severity-critical" />}
          color="red"
        />
        <StatCard
          title="Duração"
          value={formatDuration(scan.duration_seconds)}
          icon={<Clock className="w-5 h-5 text-neon-purple" />}
          color="purple"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution */}
        <Card>
          <h3 className="font-semibold text-white mb-4">Por Severidade</h3>
          <SeverityPieChart
            data={{
              critical: scan.critical_count,
              high: scan.high_count,
              medium: scan.medium_count || 0,
              low: scan.low_count || 0,
            }}
            height={200}
          />
        </Card>

        {/* Type Distribution */}
        <Card>
          <h3 className="font-semibold text-white mb-4">Por Tipo</h3>
          <div className="space-y-3 pt-4">
            {[
              { icon: Key, label: 'Secrets', value: scan.secrets_count || 0, color: 'text-amber-400' },
              { icon: AlertTriangle, label: 'Vulnerabilidades', value: scan.vulnerabilities_count || 0, color: 'text-red-400' },
              { icon: Bug, label: 'Bugs', value: scan.bugs_count || 0, color: 'text-orange-400' },
              { icon: Settings, label: 'Misconfigs', value: scan.misconfigs_count || 0, color: 'text-blue-400' },
            ].map((item) => (
              <div key={item.label} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <item.icon className={`w-4 h-4 ${item.color}`} />
                  <span className="text-sm text-slate-300">{item.label}</span>
                </div>
                <span className="font-bold text-white">{item.value}</span>
              </div>
            ))}
          </div>
        </Card>

        {/* State Distribution */}
        <Card>
          <h3 className="font-semibold text-white mb-4">Por Estado</h3>
          <div className="space-y-3 pt-4">
            {[
              { label: 'Ativos', value: scan.active_count || 0, color: 'bg-severity-critical' },
              { label: 'Históricos', value: scan.historical_count || 0, color: 'bg-severity-medium' },
              { label: 'Hardcoded', value: scan.hardcoded_count || 0, color: 'bg-severity-low' },
            ].map((item) => (
              <div key={item.label}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm text-slate-300">{item.label}</span>
                  <span className="font-bold text-white">{item.value}</span>
                </div>
                <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${item.color} rounded-full`}
                    style={{
                      width: `${scan.total_findings > 0 ? (item.value / scan.total_findings) * 100 : 0}%`,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Findings Table */}
      <Card>
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-semibold text-white">Findings ({findings?.length || 0})</h3>
          <Link to={`/findings?scan_id=${scanId}`}>
            <Button variant="ghost" size="sm">Ver todos</Button>
          </Link>
        </div>
        
        <DataTable
          columns={findingColumns}
          data={findings || []}
          isLoading={isLoadingFindings}
          emptyMessage="Nenhum finding encontrado neste scan"
        />
      </Card>
    </div>
  )
}

