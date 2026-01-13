// API Types

export interface Scan {
  id: string
  organization: string
  scan_date: string
  duration_seconds: number
  repositories_scanned: number
  repositories_failed: number
  total_findings: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  secrets_count?: number
  vulnerabilities_count?: number
  bugs_count?: number
  misconfigs_count?: number
  active_count?: number
  historical_count?: number
  hardcoded_count?: number
}

export interface Finding {
  id: string
  scan_id: string
  repository: string
  finding_type: FindingType
  category: string
  severity: Severity
  states: string
  file_path: string
  line_number: number
  line_content?: string
  rule_id: string
  rule_description?: string
  remediation?: string
  branch?: string
  commit_sha?: string
  commit_author?: string
  fingerprint?: string
  first_seen_date: string
  last_seen_date: string
  status: RemediationStatus
  assigned_to?: string
  due_date?: string
  resolved_date?: string
  confidence?: number
  cwe_id?: string
  cvss_score?: number
  notes?: string
}

export interface Repository {
  id: string
  organization: string
  name: string
  full_name: string
  url: string
  default_branch: string
  visibility: string
  last_scan_id?: string
  last_scan_date?: string
  total_scans: number
  current_findings: number
  open_findings: number
  fixed_findings: number
  risk_score: number
}

export interface Organization {
  name: string
  scan_count: number
  last_scan?: string
}

export interface DashboardStats {
  total_scans: number
  open_findings: number
  fixed_findings: number
  in_progress_findings: number
  average_findings_per_scan: number
  critical_findings: number
  high_findings: number
  top_affected_repos: Array<{ repo: string; count: number }>
}

export interface TrendPoint {
  date: string
  total: number
  critical: number
  high: number
  medium: number
  low: number
}

export interface ComparisonResult {
  scan_1: string
  scan_2: string
  new_count: number
  fixed_count: number
  unchanged_count: number
  new_findings: Finding[]
  fixed_findings: Finding[]
}

export interface ScanRequest {
  organization: string
  token: string
  include_historical?: boolean
  include_archived?: boolean
  include_forks?: boolean
}

export interface RepoScanRequest {
  repository: string
  token: string
  branch?: string
  full_history?: boolean
}

export interface ScanStatus {
  status: 'running' | 'completed' | 'failed'
  scan_id?: string
  db_scan_id?: string
  total_findings?: number
  progress?: number
  error?: string
  started_at?: string
  completed_at?: string
}

// Enums
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type FindingType = 'secret' | 'vulnerability' | 'bug' | 'misconfig'

export type RemediationStatus = 
  | 'open'
  | 'in_progress'
  | 'fixed'
  | 'wont_fix'
  | 'false_positive'
  | 'accepted_risk'

export type FindingState = 'active' | 'historical' | 'hardcoded'

// Utility types
export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  per_page: number
}

export interface ApiError {
  detail: string
}

