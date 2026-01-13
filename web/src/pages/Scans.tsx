import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Scan,
  Plus,
  Calendar,
  GitBranch,
  AlertTriangle,
  Clock,
  ExternalLink,
} from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'
import { Card } from '@/components/Card'
import { Button } from '@/components/Button'
import { Select } from '@/components/Input'
import { DataTable } from '@/components/DataTable'
import { PageLoader } from '@/components/LoadingSpinner'
import { EmptyState } from '@/components/EmptyState'
import { useScans, useOrganizations } from '@/hooks/useApi'
import { formatDate, formatDuration } from '@/lib/utils'
import type { Scan as ScanType } from '@/types'

export function ScansPage() {
  const [selectedOrg, setSelectedOrg] = useState<string>('')
  const navigate = useNavigate()
  
  const { data: organizations } = useOrganizations()
  const { data: scans, isLoading } = useScans(selectedOrg || undefined, 100)

  const orgOptions = [
    { value: '', label: 'Todas as Organizações' },
    ...(organizations?.map(o => ({ value: o.name, label: o.name })) || []),
  ]

  const columns = [
    {
      key: 'organization',
      header: 'Organização',
      render: (_: unknown, scan: ScanType) => (
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-slate-700/50 flex items-center justify-center">
            <GitBranch className="w-4 h-4 text-neon-green" />
          </div>
          <div>
            <p className="font-medium text-white">{scan.organization}</p>
            <p className="text-xs text-slate-500">{scan.repositories_scanned} repos</p>
          </div>
        </div>
      ),
    },
    {
      key: 'scan_date',
      header: 'Data',
      render: (value: unknown) => (
        <div className="flex items-center gap-2 text-slate-300">
          <Calendar className="w-3.5 h-3.5 text-slate-500" />
          {formatDate(value as string)}
        </div>
      ),
    },
    {
      key: 'duration_seconds',
      header: 'Duração',
      render: (value: unknown) => (
        <div className="flex items-center gap-2 text-slate-400">
          <Clock className="w-3.5 h-3.5" />
          {formatDuration(value as number)}
        </div>
      ),
    },
    {
      key: 'total_findings',
      header: 'Findings',
      render: (value: unknown, scan: ScanType) => (
        <div className="flex items-center gap-3">
          <span className="font-bold text-white">{value as number}</span>
          <div className="flex items-center gap-1">
            {scan.critical_count > 0 && (
              <span className="px-1.5 py-0.5 text-[10px] bg-severity-critical/20 text-severity-critical rounded">
                {scan.critical_count} C
              </span>
            )}
            {scan.high_count > 0 && (
              <span className="px-1.5 py-0.5 text-[10px] bg-severity-high/20 text-severity-high rounded">
                {scan.high_count} H
              </span>
            )}
          </div>
        </div>
      ),
    },
    {
      key: 'actions',
      header: '',
      width: '80px',
      render: (_: unknown, scan: ScanType) => (
        <Link to={`/scans/${scan.id}`}>
          <Button variant="ghost" size="sm">
            <ExternalLink className="w-4 h-4" />
          </Button>
        </Link>
      ),
    },
  ]

  if (isLoading) {
    return <PageLoader />
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Histórico de Scans"
        description="Visualize e gerencie todos os scans de segurança realizados"
        actions={
          <div className="flex items-center gap-3">
            <Select
              options={orgOptions}
              value={selectedOrg}
              onChange={(e) => setSelectedOrg(e.target.value)}
              className="w-48"
            />
            <Link to="/scans/new">
              <Button leftIcon={<Plus className="w-4 h-4" />}>
                Novo Scan
              </Button>
            </Link>
          </div>
        }
      />

      {/* Stats Summary */}
      {scans && scans.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="!p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-neon-green/10 flex items-center justify-center">
                <Scan className="w-5 h-5 text-neon-green" />
              </div>
              <div>
                <p className="text-2xl font-bold text-white">{scans.length}</p>
                <p className="text-xs text-slate-400">Total de Scans</p>
              </div>
            </div>
          </Card>
          
          <Card className="!p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-severity-critical/10 flex items-center justify-center">
                <AlertTriangle className="w-5 h-5 text-severity-critical" />
              </div>
              <div>
                <p className="text-2xl font-bold text-white">
                  {scans.reduce((sum, s) => sum + s.total_findings, 0)}
                </p>
                <p className="text-xs text-slate-400">Total Findings</p>
              </div>
            </div>
          </Card>
          
          <Card className="!p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-severity-critical/10 flex items-center justify-center">
                <span className="text-severity-critical font-bold text-sm">C</span>
              </div>
              <div>
                <p className="text-2xl font-bold text-white">
                  {scans.reduce((sum, s) => sum + s.critical_count, 0)}
                </p>
                <p className="text-xs text-slate-400">Críticos</p>
              </div>
            </div>
          </Card>
          
          <Card className="!p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-severity-high/10 flex items-center justify-center">
                <span className="text-severity-high font-bold text-sm">H</span>
              </div>
              <div>
                <p className="text-2xl font-bold text-white">
                  {scans.reduce((sum, s) => sum + s.high_count, 0)}
                </p>
                <p className="text-xs text-slate-400">Altos</p>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Scans Table */}
      {scans && scans.length > 0 ? (
        <DataTable
          columns={columns}
          data={scans}
          onRowClick={(scan) => navigate(`/scans/${scan.id}`)}
        />
      ) : (
        <Card>
          <EmptyState
            icon={<Scan className="w-8 h-8 text-slate-500" />}
            title="Nenhum scan encontrado"
            description="Execute seu primeiro scan de segurança para começar a monitorar seus repositórios"
            action={
              <Link to="/scans/new">
                <Button leftIcon={<Plus className="w-4 h-4" />}>
                  Iniciar Primeiro Scan
                </Button>
              </Link>
            }
          />
        </Card>
      )}
    </div>
  )
}

