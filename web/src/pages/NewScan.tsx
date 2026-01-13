import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  Scan,
  GitBranch,
  Lock,
  Archive,
  GitFork,
  Clock,
  CheckCircle,
  AlertCircle,
  Loader2,
} from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'
import { Card } from '@/components/Card'
import { Button } from '@/components/Button'
import { Input } from '@/components/Input'
import { useStartScan, useStartRepoScan, useScanStatus } from '@/hooks/useApi'
import { cn } from '@/lib/utils'

type ScanType = 'organization' | 'repository'

export function NewScanPage() {
  const navigate = useNavigate()
  
  const [scanType, setScanType] = useState<ScanType>('organization')
  const [organization, setOrganization] = useState('')
  const [repository, setRepository] = useState('')
  const [token, setToken] = useState('')
  const [branch, setBranch] = useState('')
  const [includeHistorical, setIncludeHistorical] = useState(false)
  const [includeArchived, setIncludeArchived] = useState(false)
  const [includeForks, setIncludeForks] = useState(false)
  
  const [activeScanId, setActiveScanId] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  
  const startOrgScan = useStartScan()
  const startRepoScan = useStartRepoScan()
  const { data: scanStatus } = useScanStatus(activeScanId || '', !!activeScanId)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    
    try {
      if (scanType === 'organization') {
        if (!organization || !token) {
          setError('Preencha todos os campos obrigatórios')
          return
        }
        
        const result = await startOrgScan.mutateAsync({
          organization,
          token,
          include_historical: includeHistorical,
          include_archived: includeArchived,
          include_forks: includeForks,
        })
        
        setActiveScanId(result.scan_id)
      } else {
        if (!repository || !token) {
          setError('Preencha todos os campos obrigatórios')
          return
        }
        
        const result = await startRepoScan.mutateAsync({
          repository,
          token,
          branch: branch || undefined,
          full_history: includeHistorical,
        })
        
        setActiveScanId(result.scan_id)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Erro ao iniciar scan')
    }
  }

  const isRunning = Boolean(activeScanId && scanStatus?.status === 'running')
  const isCompleted = scanStatus?.status === 'completed'
  const isFailed = scanStatus?.status === 'failed'

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <PageHeader
        title="Novo Scan de Segurança"
        description="Execute um scan de segurança em uma organização ou repositório"
      />

      {/* Scan Type Selector */}
      <Card>
        <div className="flex gap-4">
          <button
            type="button"
            onClick={() => setScanType('organization')}
            className={cn(
              'flex-1 p-4 rounded-lg border-2 transition-all duration-200 text-left',
              scanType === 'organization'
                ? 'border-neon-green bg-neon-green/10'
                : 'border-slate-700 hover:border-slate-600'
            )}
          >
            <div className="flex items-center gap-3 mb-2">
              <GitBranch className={cn(
                'w-5 h-5',
                scanType === 'organization' ? 'text-neon-green' : 'text-slate-400'
              )} />
              <span className="font-semibold text-white">Organização</span>
            </div>
            <p className="text-xs text-slate-400">
              Escaneia todos os repositórios de uma organização GitHub
            </p>
          </button>
          
          <button
            type="button"
            onClick={() => setScanType('repository')}
            className={cn(
              'flex-1 p-4 rounded-lg border-2 transition-all duration-200 text-left',
              scanType === 'repository'
                ? 'border-neon-green bg-neon-green/10'
                : 'border-slate-700 hover:border-slate-600'
            )}
          >
            <div className="flex items-center gap-3 mb-2">
              <Scan className={cn(
                'w-5 h-5',
                scanType === 'repository' ? 'text-neon-green' : 'text-slate-400'
              )} />
              <span className="font-semibold text-white">Repositório</span>
            </div>
            <p className="text-xs text-slate-400">
              Escaneia um único repositório específico
            </p>
          </button>
        </div>
      </Card>

      {/* Scan Form */}
      <Card>
        <form onSubmit={handleSubmit} className="space-y-6">
          {scanType === 'organization' ? (
            <Input
              label="Nome da Organização *"
              placeholder="ex: my-company"
              value={organization}
              onChange={(e) => setOrganization(e.target.value)}
              leftIcon={<GitBranch className="w-4 h-4" />}
              disabled={isRunning}
            />
          ) : (
            <>
              <Input
                label="URL do Repositório *"
                placeholder="https://github.com/org/repo"
                value={repository}
                onChange={(e) => setRepository(e.target.value)}
                leftIcon={<GitBranch className="w-4 h-4" />}
                disabled={isRunning}
              />
              <Input
                label="Branch (opcional)"
                placeholder="main"
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
                disabled={isRunning}
              />
            </>
          )}

          <Input
            label="Token de Acesso GitHub *"
            type="password"
            placeholder="ghp_..."
            value={token}
            onChange={(e) => setToken(e.target.value)}
            leftIcon={<Lock className="w-4 h-4" />}
            disabled={isRunning}
          />

          {/* Options */}
          <div className="space-y-3">
            <p className="text-sm font-medium text-slate-300">Opções</p>
            
            <label className="flex items-center gap-3 cursor-pointer group">
              <input
                type="checkbox"
                checked={includeHistorical}
                onChange={(e) => setIncludeHistorical(e.target.checked)}
                className="w-4 h-4 rounded border-slate-600 bg-slate-800 text-neon-green focus:ring-neon-green/50"
                disabled={isRunning}
              />
              <div>
                <span className="text-sm text-white group-hover:text-neon-green transition-colors">
                  <Clock className="w-4 h-4 inline mr-2" />
                  Analisar histórico Git
                </span>
                <p className="text-xs text-slate-500">Detecta secrets e bugs em commits antigos</p>
              </div>
            </label>

            {scanType === 'organization' && (
              <>
                <label className="flex items-center gap-3 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={includeArchived}
                    onChange={(e) => setIncludeArchived(e.target.checked)}
                    className="w-4 h-4 rounded border-slate-600 bg-slate-800 text-neon-green focus:ring-neon-green/50"
                    disabled={isRunning}
                  />
                  <div>
                    <span className="text-sm text-white group-hover:text-neon-green transition-colors">
                      <Archive className="w-4 h-4 inline mr-2" />
                      Incluir repositórios arquivados
                    </span>
                  </div>
                </label>

                <label className="flex items-center gap-3 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={includeForks}
                    onChange={(e) => setIncludeForks(e.target.checked)}
                    className="w-4 h-4 rounded border-slate-600 bg-slate-800 text-neon-green focus:ring-neon-green/50"
                    disabled={isRunning}
                  />
                  <div>
                    <span className="text-sm text-white group-hover:text-neon-green transition-colors">
                      <GitFork className="w-4 h-4 inline mr-2" />
                      Incluir forks
                    </span>
                  </div>
                </label>
              </>
            )}
          </div>

          {error && (
            <div className="flex items-center gap-2 p-3 rounded-lg bg-severity-critical/10 border border-severity-critical/30">
              <AlertCircle className="w-4 h-4 text-severity-critical" />
              <span className="text-sm text-severity-critical">{error}</span>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex items-center gap-3 pt-4">
            <Button
              type="submit"
              isLoading={startOrgScan.isPending || startRepoScan.isPending || isRunning}
              disabled={isRunning || isCompleted}
              leftIcon={<Scan className="w-4 h-4" />}
              className="flex-1"
            >
              {isRunning ? 'Escaneando...' : 'Iniciar Scan'}
            </Button>
            
            <Button
              type="button"
              variant="secondary"
              onClick={() => navigate('/scans')}
            >
              Cancelar
            </Button>
          </div>
        </form>
      </Card>

      {/* Scan Progress */}
      {activeScanId && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <Card className={cn(
            'border-2',
            isRunning && 'border-neon-cyan',
            isCompleted && 'border-status-fixed',
            isFailed && 'border-severity-critical'
          )}>
            <div className="flex items-center gap-4">
              {isRunning && (
                <Loader2 className="w-8 h-8 text-neon-cyan animate-spin" />
              )}
              {isCompleted && (
                <CheckCircle className="w-8 h-8 text-status-fixed" />
              )}
              {isFailed && (
                <AlertCircle className="w-8 h-8 text-severity-critical" />
              )}
              
              <div className="flex-1">
                <p className="font-semibold text-white">
                  {isRunning && 'Scan em progresso...'}
                  {isCompleted && 'Scan concluído!'}
                  {isFailed && 'Scan falhou'}
                </p>
                <p className="text-sm text-slate-400">
                  {isRunning && 'Aguarde enquanto analisamos os repositórios'}
                  {isCompleted && `${scanStatus.total_findings || 0} findings detectados`}
                  {isFailed && (scanStatus.error || 'Ocorreu um erro durante o scan')}
                </p>
              </div>
              
              {isCompleted && scanStatus.db_scan_id && (
                <Button
                  onClick={() => navigate(`/scans/${scanStatus.db_scan_id}`)}
                >
                  Ver Resultados
                </Button>
              )}
            </div>
          </Card>
        </motion.div>
      )}
    </div>
  )
}

