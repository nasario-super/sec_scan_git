import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import * as api from '@/lib/api'
import type { RemediationStatus } from '@/types'

// Dashboard
export function useDashboard(organization?: string) {
  return useQuery({
    queryKey: ['dashboard', organization],
    queryFn: () => api.getDashboard(organization),
  })
}

export function useTrends(organization: string, days: number = 30) {
  return useQuery({
    queryKey: ['trends', organization, days],
    queryFn: () => api.getTrends(organization, days),
    enabled: !!organization,
  })
}

// Scans
export function useScans(organization?: string, limit: number = 50) {
  return useQuery({
    queryKey: ['scans', organization, limit],
    queryFn: () => api.getScans(organization, limit),
  })
}

export function useScan(scanId: string) {
  return useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => api.getScan(scanId),
    enabled: !!scanId,
  })
}

export function useScanStatus(scanId: string, enabled: boolean = false) {
  return useQuery({
    queryKey: ['scanStatus', scanId],
    queryFn: () => api.getScanStatus(scanId),
    enabled: enabled && !!scanId,
    refetchInterval: enabled ? 2000 : false,
  })
}

export function useStartScan() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: api.startScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })
}

export function useStartRepoScan() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: api.startRepoScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })
}

export function useCompareScans(baseline: string, current: string) {
  return useQuery({
    queryKey: ['compare', baseline, current],
    queryFn: () => api.compareScans(baseline, current),
    enabled: !!baseline && !!current,
  })
}

// Findings
export function useFindings(params: {
  scan_id?: string
  repository?: string
  status?: RemediationStatus
  severity?: string
  limit?: number
}) {
  return useQuery({
    queryKey: ['findings', params],
    queryFn: () => api.getFindings(params),
  })
}

export function useOpenFindings(organization?: string) {
  return useQuery({
    queryKey: ['openFindings', organization],
    queryFn: () => api.getOpenFindings(organization),
  })
}

export function useFinding(findingId: string) {
  return useQuery({
    queryKey: ['finding', findingId],
    queryFn: () => api.getFinding(findingId),
    enabled: !!findingId,
  })
}

export function useUpdateFindingStatus() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: ({
      findingId,
      status,
      comment,
      performed_by,
    }: {
      findingId: string
      status: RemediationStatus
      comment?: string
      performed_by?: string
    }) => api.updateFindingStatus(findingId, status, comment, performed_by),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
      queryClient.invalidateQueries({ queryKey: ['openFindings'] })
      queryClient.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })
}

// Organizations
export function useOrganizations() {
  return useQuery({
    queryKey: ['organizations'],
    queryFn: api.getOrganizations,
  })
}

// Health
export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: api.checkHealth,
    refetchInterval: 30000,
  })
}

