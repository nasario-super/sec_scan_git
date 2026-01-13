import { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import {
  AlertTriangle,
  Search,
  Download,
  RefreshCw,
} from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'
import { Card } from '@/components/Card'
import { SeverityBadge, TypeBadge, StatusBadge } from '@/components/Badge'
import { Button } from '@/components/Button'
import { Input, Select } from '@/components/Input'
import { DataTable } from '@/components/DataTable'
import { PageLoader } from '@/components/LoadingSpinner'
import { EmptyState } from '@/components/EmptyState'
import { useFindings } from '@/hooks/useApi'
import { formatRelativeDate, truncate } from '@/lib/utils'
import type { Finding, RemediationStatus, Severity } from '@/types'

const severityOptions = [
  { value: '', label: 'Todas as Severidades' },
  { value: 'critical', label: 'Crítico' },
  { value: 'high', label: 'Alto' },
  { value: 'medium', label: 'Médio' },
  { value: 'low', label: 'Baixo' },
]

const statusOptions = [
  { value: '', label: 'Todos os Status' },
  { value: 'open', label: 'Aberto' },
  { value: 'in_progress', label: 'Em Progresso' },
  { value: 'fixed', label: 'Corrigido' },
  { value: 'false_positive', label: 'Falso Positivo' },
  { value: 'accepted_risk', label: 'Risco Aceito' },
]

export function FindingsPage() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState(searchParams.get('severity') || '')
  const [status, setStatus] = useState(searchParams.get('status') || '')

  const { data: findings, isLoading, refetch } = useFindings({
    severity: severity || undefined,
    status: status as RemediationStatus || undefined,
    limit: 500,
  })

  const filteredFindings = findings?.filter(f => {
    if (!search) return true
    const searchLower = search.toLowerCase()
    return (
      f.category.toLowerCase().includes(searchLower) ||
      f.repository.toLowerCase().includes(searchLower) ||
      f.file_path.toLowerCase().includes(searchLower) ||
      f.rule_id?.toLowerCase().includes(searchLower)
    )
  })

  const columns = [
    {
      key: 'severity',
      header: 'Severidade',
      width: '100px',
      render: (value: unknown) => <SeverityBadge severity={value as Severity} size="sm" />,
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
      render: (value: unknown, finding: Finding) => (
        <div>
          <p className="font-medium text-white">{value as string}</p>
          {finding.rule_id && (
            <p className="text-xs text-slate-500">{finding.rule_id}</p>
          )}
        </div>
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
      header: 'Localização',
      render: (value: unknown, finding: Finding) => (
        <div>
          <p className="text-slate-300 text-xs font-mono">{truncate(value as string, 35)}</p>
          <p className="text-slate-500 text-[10px]">
            Linha {finding.line_number}
          </p>
        </div>
      ),
    },
    {
      key: 'first_seen_date',
      header: 'Detectado',
      width: '120px',
      render: (value: unknown) => (
        <span className="text-xs text-slate-400">{formatRelativeDate(value as string)}</span>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      width: '120px',
      render: (value: unknown) => <StatusBadge status={value as RemediationStatus} size="sm" />,
    },
  ]

  // Stats
  const stats = findings ? {
    total: findings.length,
    open: findings.filter(f => f.status === 'open').length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
  } : { total: 0, open: 0, critical: 0, high: 0 }

  if (isLoading) {
    return <PageLoader />
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Findings de Segurança"
        description="Gerencie e acompanhe todos os findings detectados"
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              leftIcon={<RefreshCw className="w-4 h-4" />}
              onClick={() => refetch()}
            >
              Atualizar
            </Button>
            <Button
              variant="secondary"
              size="sm"
              leftIcon={<Download className="w-4 h-4" />}
            >
              Exportar
            </Button>
          </div>
        }
      />

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="!p-4">
          <p className="text-sm text-slate-400">Total</p>
          <p className="text-2xl font-bold text-white">{stats.total}</p>
        </Card>
        <Card className="!p-4">
          <p className="text-sm text-slate-400">Abertos</p>
          <p className="text-2xl font-bold text-status-open">{stats.open}</p>
        </Card>
        <Card className="!p-4">
          <p className="text-sm text-slate-400">Críticos</p>
          <p className="text-2xl font-bold text-severity-critical">{stats.critical}</p>
        </Card>
        <Card className="!p-4">
          <p className="text-sm text-slate-400">Altos</p>
          <p className="text-2xl font-bold text-severity-high">{stats.high}</p>
        </Card>
      </div>

      {/* Filters */}
      <Card className="!p-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex-1 min-w-[200px]">
            <Input
              placeholder="Buscar findings..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              leftIcon={<Search className="w-4 h-4" />}
            />
          </div>
          <div className="w-48">
            <Select
              options={severityOptions}
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            />
          </div>
          <div className="w-48">
            <Select
              options={statusOptions}
              value={status}
              onChange={(e) => setStatus(e.target.value)}
            />
          </div>
          {(severity || status || search) && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setSeverity('')
                setStatus('')
                setSearch('')
              }}
            >
              Limpar Filtros
            </Button>
          )}
        </div>
      </Card>

      {/* Findings Table */}
      {filteredFindings && filteredFindings.length > 0 ? (
        <DataTable
          columns={columns}
          data={filteredFindings}
          onRowClick={(finding) => navigate(`/findings/${finding.id}`)}
        />
      ) : (
        <Card>
          <EmptyState
            icon={<AlertTriangle className="w-8 h-8 text-slate-500" />}
            title="Nenhum finding encontrado"
            description={
              search || severity || status
                ? 'Tente ajustar os filtros de busca'
                : 'Execute um scan para detectar findings de segurança'
            }
          />
        </Card>
      )}
    </div>
  )
}

