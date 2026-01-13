import { useState } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  FolderGit2,
  Search,
  CheckCircle,
} from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'
import { Card } from '@/components/Card'
import { Button } from '@/components/Button'
import { Input, Select } from '@/components/Input'
import { PageLoader } from '@/components/LoadingSpinner'
import { EmptyState } from '@/components/EmptyState'
import { useOrganizations, useFindings } from '@/hooks/useApi'
import { cn } from '@/lib/utils'

export function RepositoriesPage() {
  const [selectedOrg, setSelectedOrg] = useState<string>('')
  const [search, setSearch] = useState('')
  
  const { data: organizations, isLoading: isLoadingOrgs } = useOrganizations()
  const { data: findings, isLoading: isLoadingFindings } = useFindings({ limit: 1000 })

  // Build repository list from scans and findings
  const repositories = new Map<string, {
    name: string
    organization: string
    lastScan?: string
    totalFindings: number
    openFindings: number
    criticalFindings: number
    highFindings: number
  }>()

  findings?.forEach(f => {
    const existing = repositories.get(f.repository) || {
      name: f.repository,
      organization: '',
      totalFindings: 0,
      openFindings: 0,
      criticalFindings: 0,
      highFindings: 0,
    }
    
    existing.totalFindings++
    if (f.status === 'open') existing.openFindings++
    if (f.severity === 'critical') existing.criticalFindings++
    if (f.severity === 'high') existing.highFindings++
    
    repositories.set(f.repository, existing)
  })

  const repoList = Array.from(repositories.values())
    .filter(r => !search || r.name.toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => b.openFindings - a.openFindings)

  const orgOptions = [
    { value: '', label: 'Todas as Organizações' },
    ...(organizations?.map(o => ({ value: o.name, label: o.name })) || []),
  ]

  const isLoading = isLoadingOrgs || isLoadingFindings

  if (isLoading) {
    return <PageLoader />
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Repositórios"
        description="Visão geral de segurança por repositório"
      />

      {/* Filters */}
      <Card className="!p-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex-1 min-w-[200px]">
            <Input
              placeholder="Buscar repositório..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              leftIcon={<Search className="w-4 h-4" />}
            />
          </div>
          <div className="w-48">
            <Select
              options={orgOptions}
              value={selectedOrg}
              onChange={(e) => setSelectedOrg(e.target.value)}
            />
          </div>
        </div>
      </Card>

      {/* Repository Grid */}
      {repoList.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {repoList.map((repo, index) => (
            <motion.div
              key={repo.name}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.02 }}
            >
              <Link to={`/findings?repository=${encodeURIComponent(repo.name)}`}>
                <Card hover className="h-full">
                  <div className="flex items-start gap-3 mb-4">
                    <div className="w-10 h-10 rounded-lg bg-slate-700/50 flex items-center justify-center flex-shrink-0">
                      <FolderGit2 className="w-5 h-5 text-neon-green" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <h3 className="font-semibold text-white truncate">
                        {repo.name}
                      </h3>
                      {repo.organization && (
                        <p className="text-xs text-slate-500">{repo.organization}</p>
                      )}
                    </div>
                  </div>

                  {/* Stats */}
                  <div className="grid grid-cols-2 gap-3 mb-4">
                    <div className="bg-slate-800/30 rounded-lg p-2 text-center">
                      <p className="text-lg font-bold text-white">{repo.totalFindings}</p>
                      <p className="text-[10px] text-slate-500 uppercase">Total</p>
                    </div>
                    <div className="bg-slate-800/30 rounded-lg p-2 text-center">
                      <p className={cn(
                        'text-lg font-bold',
                        repo.openFindings > 0 ? 'text-status-open' : 'text-status-fixed'
                      )}>
                        {repo.openFindings}
                      </p>
                      <p className="text-[10px] text-slate-500 uppercase">Abertos</p>
                    </div>
                  </div>

                  {/* Severity breakdown */}
                  <div className="flex items-center gap-2">
                    {repo.criticalFindings > 0 && (
                      <span className="px-1.5 py-0.5 text-[10px] bg-severity-critical/20 text-severity-critical rounded font-bold">
                        {repo.criticalFindings} C
                      </span>
                    )}
                    {repo.highFindings > 0 && (
                      <span className="px-1.5 py-0.5 text-[10px] bg-severity-high/20 text-severity-high rounded font-bold">
                        {repo.highFindings} H
                      </span>
                    )}
                    {repo.criticalFindings === 0 && repo.highFindings === 0 && repo.openFindings === 0 && (
                      <span className="flex items-center gap-1 text-xs text-status-fixed">
                        <CheckCircle className="w-3 h-3" />
                        Limpo
                      </span>
                    )}
                  </div>
                </Card>
              </Link>
            </motion.div>
          ))}
        </div>
      ) : (
        <Card>
          <EmptyState
            icon={<FolderGit2 className="w-8 h-8 text-slate-500" />}
            title="Nenhum repositório encontrado"
            description={
              search
                ? 'Tente ajustar sua busca'
                : 'Execute um scan para ver os repositórios analisados'
            }
            action={
              <Link to="/scans/new">
                <Button>Iniciar Scan</Button>
              </Link>
            }
          />
        </Card>
      )}
    </div>
  )
}

