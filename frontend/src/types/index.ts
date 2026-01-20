// Severity levels for findings
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// Finding types
export type FindingType = 'secret' | 'vulnerability' | 'sast' | 'iac' | 'history' | 'bug';

// Finding states
export type FindingState = 
  | 'active' 
  | 'historical' 
  | 'hardcoded' 
  | 'in_default_branch' 
  | 'in_config_file';

// Remediation status
export type RemediationStatus = 
  | 'open' 
  | 'in_progress' 
  | 'resolved' 
  | 'false_positive' 
  | 'accepted_risk';

// AI triage
export type AITriageLabel = 'likely_true_positive' | 'false_positive' | 'needs_review';

export interface AITriageResult {
  label: AITriageLabel;
  confidence: number;
  reasons: string[];
  source: 'llm' | 'heuristic';
}

export interface AITriageResponse {
  finding_id: string;
  result: AITriageResult;
}

export interface AITriageBatchResponse {
  results: Record<string, AITriageResult>;
  failed: string[];
}

export type SecretValidationStatus = 'valid' | 'invalid' | 'unknown';

export interface SecretValidationResult {
  status: SecretValidationStatus;
  provider: string;
  message: string;
  checked_at: string;
}

export interface SecretValidationResponse {
  finding_id: string;
  result: SecretValidationResult;
}

// Scan status
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

// Finding interface
export interface Finding {
  id: string;
  repository: string;
  type: FindingType;
  category: string;
  severity: Severity;
  states: FindingState[];
  file_path: string;
  line_number?: number;
  line_content?: string;
  matched_pattern?: string;
  commit_sha?: string;
  commit_date?: string;
  commit_author?: string;
  branch: string;
  rule_id: string;
  rule_description: string;
  remediation_status: RemediationStatus;
  remediation_notes?: string;
  false_positive_likelihood?: 'low' | 'medium' | 'high';
  ai_triage?: AITriageResult | null;
  created_at: string;
  updated_at: string;
}

// Repository interface
export interface Repository {
  id: string;
  name: string;
  full_name: string;
  description?: string;
  url: string;
  default_branch: string;
  language?: string;
  is_private: boolean;
  is_archived: boolean;
  last_scan_at?: string;
  findings_count: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
}

// Scan interface
export interface Scan {
  id: string;
  organization?: string;
  repository?: string;
  status: ScanStatus;
  started_at: string;
  completed_at?: string;
  duration_seconds?: number;
  repositories_scanned: number;
  findings_count: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  error_message?: string;
}

// Dashboard statistics
export interface DashboardStats {
  total_repositories: number;
  total_findings: number;
  open_findings: number;
  resolved_findings: number;
  findings_by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  findings_by_type: {
    secret: number;
    vulnerability: number;
    sast: number;
    iac: number;
    history: number;
  };
  ai_triage_counts?: {
    likely_true_positive: number;
    false_positive: number;
    needs_review: number;
    untriaged: number;
  };
  recent_scans: Scan[];
  top_repositories: Array<{
    name: string;
    findings_count: number;
  }>;
  trends: {
    date: string;
    findings: number;
    resolved: number;
  }[];
}

// Trend data
export interface TrendData {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
  resolved: number;
}

// API Response types
export interface ApiResponse<T> {
  data: T;
  success: boolean;
  message?: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

// Repository Statistics (aggregated)
export interface CategoryCount {
  category: string;
  type: string;
  severity: Severity;
  count: number;
}

export interface RepositoryStats {
  repository: string;
  total: number;
  by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  by_type: Record<string, number>;
  by_status: Record<string, number>;
  by_category: CategoryCount[];
  last_scan_at?: string;
}

// Filter types
export interface FindingsFilter {
  severity?: Severity[];
  type?: FindingType[];
  status?: RemediationStatus[];
  repository?: string;
  search?: string;
  page?: number;
  page_size?: number;
}

export interface ScansFilter {
  status?: ScanStatus[];
  organization?: string;
  repository?: string;
  page?: number;
  page_size?: number;
}

// Auth types
export interface User {
  id: string;
  username: string;
  email: string | null;
  full_name: string | null;
  role: string;
  is_active?: boolean;
  last_login_at?: string | null;
  created_at?: string;
}

export interface AuthState {
  isAuthenticated: boolean;
  user: User | null;
  token: string | null;
}

// Notification type
export interface Notification {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message?: string;
  duration?: number;
}
