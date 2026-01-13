import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  GitCompare,
  ArrowRight,
  Plus,
  Minus,
  AlertTriangle,
  CheckCircle,
} from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'
import { Card } from '@/components/Card'
import { SeverityBadge, TypeBadge } from '@/components/Badge'
import { Select } from '@/components/Input'
import { DataTable } from '@/components/DataTable'
import { ComparisonBarChart } from '@/components/Charts'
import { PageLoader } from '@/components/LoadingSpinner'
import { EmptyState } from '@/components/EmptyState'
import { useScans, useCompareScans } from '@/hooks/useApi'
import { formatDate, truncate, cn } from '@/lib/utils'
import type { Finding } from '@/types'

export function ComparePage() {
  const navigate = useNavigate()
  
  const [baseline, setBaseline] = useState('')
  const [current, setCurrent] = useState('')
  
  const { data: scans, isLoading: isLoadingScans } = useScans(undefined, 100)
  const { data: comparison, isLoading: isLoadingComparison } = useCompareScans(baseline, current)

  const scanOptions = [
    { value: '', label: 'Selecione um scan...' },
    ...(scans?.map(s => ({
      value: s.id,
      label: `${s.organization} - ${formatDate(s.scan_date)} (${s.total_findings} findings)`,
    })) || []),
  ]

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
      width: '130px',
      render: (value: unknown) => <TypeBadge type={value as Finding['finding_type']} size="sm" />,
    },
    {
      key: 'category',
      header: 'Categoria',
      render: (value: unknown) => (
        <span className="font-medium text-white">{value as string}</span>
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
      render: (value: unknown) => (
        <span className="text-xs font-mono text-slate-400">{truncate(value as string, 40)}</span>
      ),
    },
  ]

  // Prepare chart data
  const chartData = comparison ? [
    {
      name: 'Crítico',
      baseline: comparison.fixed_findings.filter(f => f.severity === 'critical').length,
      current: comparison.new_findings.filter(f => f.severity === 'critical').length,
    },
    {
      name: 'Alto',
      baseline: comparison.fixed_findings.filter(f => f.severity === 'high').length,
      current: comparison.new_findings.filter(f => f.severity === 'high').length,
    },
    {
      name: 'Médio',
      baseline: comparison.fixed_findings.filter(f => f.severity === 'medium').length,
      current: comparison.new_findings.filter(f => f.severity === 'medium').length,
    },
    {
      name: 'Baixo',
      baseline: comparison.fixed_findings.filter(f => f.severity === 'low').length,
      current: comparison.new_findings.filter(f => f.severity === 'low').length,
    },
  ] : []

  if (isLoadingScans) {
    return <PageLoader />
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Comparar Scans"
        description="Compare dois scans para identificar novos findings e correções"
      />

      {/* Scan Selector */}
      <Card>
        <div className="flex items-end gap-4">
          <div className="flex-1">
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Scan Base (anterior)
            </label>
            <Select
              options={scanOptions}
              value={baseline}
              onChange={(e) => setBaseline(e.target.value)}
            />
          </div>
          
          <div className="pb-2.5">
            <ArrowRight className="w-6 h-6 text-slate-500" />
          </div>
          
          <div className="flex-1">
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Scan Atual (novo)
            </label>
            <Select
              options={scanOptions}
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
            />
          </div>
        </div>
      </Card>

      {/* Loading state */}
      {baseline && current && isLoadingComparison && (
        <Card className="text-center py-12">
          <p className="text-slate-400 animate-pulse">Comparando scans...</p>
        </Card>
      )}

      {/* Comparison Results */}
      {comparison && (
        <>
          {/* Summary Stats */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card className={cn(
              '!p-6 border-2',
              comparison.new_count > 0 ? 'border-severity-critical/50' : 'border-slate-800'
            )}>
              <div className="flex items-center gap-4">
                <div className={cn(
                  'w-12 h-12 rounded-xl flex items-center justify-center',
                  comparison.new_count > 0 ? 'bg-severity-critical/20' : 'bg-slate-800'
                )}>
                  <Plus className={cn(
                    'w-6 h-6',
                    comparison.new_count > 0 ? 'text-severity-critical' : 'text-slate-500'
                  )} />
                </div>
                <div>
                  <p className="text-3xl font-bold text-white">{comparison.new_count}</p>
                  <p className="text-sm text-slate-400">Novos Findings</p>
                </div>
              </div>
            </Card>

            <Card className={cn(
              '!p-6 border-2',
              comparison.fixed_count > 0 ? 'border-status-fixed/50' : 'border-slate-800'
            )}>
              <div className="flex items-center gap-4">
                <div className={cn(
                  'w-12 h-12 rounded-xl flex items-center justify-center',
                  comparison.fixed_count > 0 ? 'bg-status-fixed/20' : 'bg-slate-800'
                )}>
                  <Minus className={cn(
                    'w-6 h-6',
                    comparison.fixed_count > 0 ? 'text-status-fixed' : 'text-slate-500'
                  )} />
                </div>
                <div>
                  <p className="text-3xl font-bold text-white">{comparison.fixed_count}</p>
                  <p className="text-sm text-slate-400">Findings Corrigidos</p>
                </div>
              </div>
            </Card>

            <Card className="!p-6 border-2 border-slate-800">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-xl bg-slate-800 flex items-center justify-center">
                  <AlertTriangle className="w-6 h-6 text-slate-500" />
                </div>
                <div>
                  <p className="text-3xl font-bold text-white">{comparison.unchanged_count}</p>
                  <p className="text-sm text-slate-400">Inalterados</p>
                </div>
              </div>
            </Card>
          </div>

          {/* Chart */}
          {(comparison.new_count > 0 || comparison.fixed_count > 0) && (
            <Card>
              <h3 className="font-semibold text-white mb-4">Comparação por Severidade</h3>
              <ComparisonBarChart data={chartData} height={250} />
              <div className="flex items-center justify-center gap-6 mt-4 text-xs text-slate-400">
                <span className="flex items-center gap-2">
                  <span className="w-3 h-3 bg-slate-500 rounded" />
                  Corrigidos (baseline)
                </span>
                <span className="flex items-center gap-2">
                  <span className="w-3 h-3 bg-cyber-500 rounded" />
                  Novos (atual)
                </span>
              </div>
            </Card>
          )}

          {/* New Findings */}
          {comparison.new_findings.length > 0 && (
            <Card>
              <div className="flex items-center gap-2 mb-4">
                <Plus className="w-5 h-5 text-severity-critical" />
                <h3 className="font-semibold text-white">
                  Novos Findings ({comparison.new_count})
                </h3>
              </div>
              <DataTable
                columns={findingColumns}
                data={comparison.new_findings as unknown as Finding[]}
                onRowClick={(f) => navigate(`/findings/${(f as unknown as Finding).id}`)}
              />
            </Card>
          )}

          {/* Fixed Findings */}
          {comparison.fixed_findings.length > 0 && (
            <Card>
              <div className="flex items-center gap-2 mb-4">
                <CheckCircle className="w-5 h-5 text-status-fixed" />
                <h3 className="font-semibold text-white">
                  Findings Corrigidos ({comparison.fixed_count})
                </h3>
              </div>
              <DataTable
                columns={findingColumns}
                data={comparison.fixed_findings as unknown as Finding[]}
              />
            </Card>
          )}

          {/* No changes */}
          {comparison.new_count === 0 && comparison.fixed_count === 0 && (
            <Card>
              <EmptyState
                icon={<CheckCircle className="w-8 h-8 text-status-fixed" />}
                title="Nenhuma diferença encontrada"
                description="Os dois scans têm os mesmos findings"
              />
            </Card>
          )}
        </>
      )}

      {/* No scans selected */}
      {(!baseline || !current) && !isLoadingComparison && (
        <Card>
          <EmptyState
            icon={<GitCompare className="w-8 h-8 text-slate-500" />}
            title="Selecione dois scans para comparar"
            description="Escolha um scan base e um scan atual para ver as diferenças"
          />
        </Card>
      )}
    </div>
  )
}

