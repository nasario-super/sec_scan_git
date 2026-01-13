import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  ArrowLeft,
  Clock,
  GitBranch,
  FileCode,
  User,
  Calendar,
  ExternalLink,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Loader2,
} from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'
import { Card } from '@/components/Card'
import { SeverityBadge, TypeBadge, StatusBadge } from '@/components/Badge'
import { Button } from '@/components/Button'
import { Textarea } from '@/components/Input'
import { PageLoader } from '@/components/LoadingSpinner'
import { useFinding, useUpdateFindingStatus } from '@/hooks/useApi'
import { formatRelativeDate } from '@/lib/utils'
import type { RemediationStatus } from '@/types'

const statusActions: Array<{
  status: RemediationStatus
  label: string
  icon: React.ReactNode
  variant: 'primary' | 'secondary' | 'ghost' | 'danger'
}> = [
  { status: 'in_progress', label: 'Em Progresso', icon: <Clock className="w-4 h-4" />, variant: 'secondary' },
  { status: 'fixed', label: 'Corrigido', icon: <CheckCircle className="w-4 h-4" />, variant: 'primary' },
  { status: 'false_positive', label: 'Falso Positivo', icon: <XCircle className="w-4 h-4" />, variant: 'ghost' },
  { status: 'accepted_risk', label: 'Aceitar Risco', icon: <AlertTriangle className="w-4 h-4" />, variant: 'ghost' },
  { status: 'wont_fix', label: 'Não Corrigir', icon: <XCircle className="w-4 h-4" />, variant: 'danger' },
]

export function FindingDetailPage() {
  const { findingId } = useParams<{ findingId: string }>()
  const [comment, setComment] = useState('')
  const [isUpdating, setIsUpdating] = useState<RemediationStatus | null>(null)
  
  const { data: finding, isLoading, refetch } = useFinding(findingId || '')
  const updateStatus = useUpdateFindingStatus()

  const handleStatusUpdate = async (newStatus: RemediationStatus) => {
    if (!findingId) return
    
    setIsUpdating(newStatus)
    try {
      await updateStatus.mutateAsync({
        findingId,
        status: newStatus,
        comment: comment || undefined,
        performed_by: 'web-user',
      })
      setComment('')
      refetch()
    } catch (error) {
      console.error('Failed to update status:', error)
    } finally {
      setIsUpdating(null)
    }
  }

  if (isLoading) {
    return <PageLoader />
  }

  if (!finding) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Card className="text-center">
          <h2 className="text-lg font-semibold text-white mb-2">Finding não encontrado</h2>
          <p className="text-sm text-slate-400 mb-4">O finding solicitado não existe ou foi removido.</p>
          <Link to="/findings">
            <Button variant="secondary">Voltar para Findings</Button>
          </Link>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={finding.category}
        description={finding.rule_description || finding.rule_id}
        breadcrumbs={[
          { label: 'Findings', href: '/findings' },
          { label: finding.category },
        ]}
        actions={
          <Link to="/findings">
            <Button variant="secondary" leftIcon={<ArrowLeft className="w-4 h-4" />}>
              Voltar
            </Button>
          </Link>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Info */}
        <div className="lg:col-span-2 space-y-6">
          {/* Summary */}
          <Card>
            <div className="flex items-start gap-4 mb-6">
              <div className="flex-1 space-y-4">
                <div className="flex items-center gap-3 flex-wrap">
                  <SeverityBadge severity={finding.severity} />
                  <TypeBadge type={finding.finding_type} />
                  <StatusBadge status={finding.status} />
                </div>
                
                <div className="grid grid-cols-2 gap-4 pt-2">
                  <div className="flex items-center gap-2 text-sm">
                    <GitBranch className="w-4 h-4 text-slate-500" />
                    <span className="text-slate-400">Repositório:</span>
                    <span className="text-white font-medium">{finding.repository}</span>
                  </div>
                  {finding.branch && (
                    <div className="flex items-center gap-2 text-sm">
                      <GitBranch className="w-4 h-4 text-slate-500" />
                      <span className="text-slate-400">Branch:</span>
                      <span className="text-white">{finding.branch}</span>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* File Location */}
            <div className="bg-slate-800/50 rounded-lg p-4 mb-4">
              <div className="flex items-center gap-2 mb-2">
                <FileCode className="w-4 h-4 text-neon-green" />
                <span className="text-sm text-slate-300 font-mono">{finding.file_path}</span>
                <span className="text-xs text-slate-500">: linha {finding.line_number}</span>
              </div>
              
              {finding.line_content && (
                <div className="bg-slate-900 rounded p-3 mt-2 overflow-x-auto">
                  <code className="text-xs text-slate-300 font-mono whitespace-pre">
                    {finding.line_content}
                  </code>
                </div>
              )}
            </div>

            {/* Remediation */}
            {finding.remediation && (
              <div className="border-t border-slate-800 pt-4">
                <h4 className="text-sm font-semibold text-white mb-2">Remediação</h4>
                <p className="text-sm text-slate-300">{finding.remediation}</p>
              </div>
            )}
          </Card>

          {/* Update Status */}
          {finding.status !== 'fixed' && (
            <Card>
              <h3 className="font-semibold text-white mb-4">Atualizar Status</h3>
              
              <div className="space-y-4">
                <Textarea
                  label="Comentário (opcional)"
                  placeholder="Adicione um comentário sobre esta alteração..."
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  rows={3}
                />
                
                <div className="flex flex-wrap gap-2">
                  {statusActions
                    .filter(a => a.status !== finding.status)
                    .map((action) => (
                      <Button
                        key={action.status}
                        variant={action.variant}
                        size="sm"
                        leftIcon={
                          isUpdating === action.status ? (
                            <Loader2 className="w-4 h-4 animate-spin" />
                          ) : (
                            action.icon
                          )
                        }
                        disabled={isUpdating !== null}
                        onClick={() => handleStatusUpdate(action.status)}
                      >
                        {action.label}
                      </Button>
                    ))}
                </div>
              </div>
            </Card>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Metadata */}
          <Card>
            <h3 className="font-semibold text-white mb-4">Detalhes</h3>
            
            <div className="space-y-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-slate-400 flex items-center gap-2">
                  <Calendar className="w-3.5 h-3.5" />
                  Detectado
                </span>
                <span className="text-white">{formatRelativeDate(finding.first_seen_date)}</span>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-slate-400 flex items-center gap-2">
                  <Clock className="w-3.5 h-3.5" />
                  Última vez
                </span>
                <span className="text-white">{formatRelativeDate(finding.last_seen_date)}</span>
              </div>

              {finding.commit_sha && (
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Commit</span>
                  <code className="text-xs text-neon-green">{finding.commit_sha.slice(0, 7)}</code>
                </div>
              )}

              {finding.commit_author && (
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 flex items-center gap-2">
                    <User className="w-3.5 h-3.5" />
                    Autor
                  </span>
                  <span className="text-white">{finding.commit_author}</span>
                </div>
              )}

              {finding.cwe_id && (
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">CWE</span>
                  <a
                    href={`https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace('CWE-', '')}.html`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-neon-cyan hover:underline flex items-center gap-1"
                  >
                    {finding.cwe_id}
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              )}

              {finding.cvss_score && (
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">CVSS</span>
                  <span className="text-white font-bold">{finding.cvss_score}</span>
                </div>
              )}

              {finding.confidence && (
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Confiança</span>
                  <span className="text-white">{(finding.confidence * 100).toFixed(0)}%</span>
                </div>
              )}
            </div>
          </Card>

          {/* States */}
          {finding.states && (
            <Card>
              <h3 className="font-semibold text-white mb-4">Estados</h3>
              <div className="flex flex-wrap gap-2">
                {finding.states.split(',').map((state) => (
                  <span
                    key={state}
                    className="px-2 py-1 text-xs bg-slate-800 text-slate-300 rounded"
                  >
                    {state.trim()}
                  </span>
                ))}
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}

