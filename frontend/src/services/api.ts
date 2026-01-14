import type {
  DashboardStats,
  Finding,
  FindingsFilter,
  PaginatedResponse,
  Repository,
  RepositoryStats,
  Scan,
  ScansFilter,
  TrendData,
  RemediationStatus,
} from '../types';

// Use relative URL by default (for Nginx proxy), or explicit URL from env
const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

class ApiService {
  private token: string | null = null;

  setToken(token: string | null) {
    this.token = token;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    // Merge existing headers
    if (options.headers) {
      const existingHeaders = options.headers as Record<string, string>;
      Object.assign(headers, existingHeaders);
    }

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Request failed' }));
      throw new Error(error.detail || `HTTP ${response.status}`);
    }

    return response.json();
  }

  // Health check
  async healthCheck(): Promise<{ status: string; version: string; database: string }> {
    return this.request('/health');
  }

  // Authentication
  async login(username: string, password: string): Promise<{
    access_token: string;
    refresh_token: string;
    token_type: string;
    expires_in: number;
    user: {
      id: string;
      username: string;
      email: string | null;
      full_name: string | null;
      role: string;
    };
  }> {
    return this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
  }

  async refreshToken(refreshToken: string): Promise<{
    access_token: string;
    refresh_token: string;
    token_type: string;
    expires_in: number;
  }> {
    return this.request(`/auth/refresh?refresh_token=${encodeURIComponent(refreshToken)}`, {
      method: 'POST',
    });
  }

  async getCurrentUser(): Promise<{
    id: string;
    username: string;
    email: string | null;
    full_name: string | null;
    role: string;
    is_active: boolean;
    last_login_at: string | null;
    created_at: string;
  }> {
    return this.request('/auth/me');
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<{ message: string }> {
    return this.request('/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    });
  }

  // User Management (Admin)
  async getUsers(includeInactive: boolean = false): Promise<{ users: any[]; total: number }> {
    return this.request(`/users?include_inactive=${includeInactive}`);
  }

  async createUser(data: {
    username: string;
    password: string;
    email?: string;
    full_name?: string;
    role?: string;
  }): Promise<{ message: string; user: any }> {
    return this.request('/users', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async updateUser(userId: string, data: {
    email?: string | null;
    full_name?: string | null;
    role?: string;
    is_active?: boolean;
  }): Promise<{ message: string; user: any }> {
    return this.request(`/users/${userId}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  async deleteUser(userId: string): Promise<{ message: string }> {
    return this.request(`/users/${userId}`, {
      method: 'DELETE',
    });
  }

  async resetUserPassword(userId: string, newPassword: string): Promise<{ message: string }> {
    return this.request(`/users/${userId}/reset-password`, {
      method: 'POST',
      body: JSON.stringify({ new_password: newPassword }),
    });
  }

  async activateUser(userId: string): Promise<{ message: string; user: any }> {
    return this.request(`/users/${userId}/activate`, {
      method: 'POST',
    });
  }

  // Dashboard
  async getDashboard(): Promise<DashboardStats> {
    return this.request('/dashboard');
  }

  async getTrends(days: number = 30): Promise<TrendData[]> {
    return this.request(`/trends?days=${days}`);
  }

  async getHistory(organization?: string | null): Promise<{ items: any[]; total: number }> {
    const params = new URLSearchParams();
    if (organization) params.set('organization', organization);
    const query = params.toString();
    return this.request(`/history${query ? `?${query}` : ''}`);
  }

  // Scans
  async getScans(filters?: ScansFilter): Promise<PaginatedResponse<Scan>> {
    const params = new URLSearchParams();
    if (filters?.status?.length) params.set('status', filters.status.join(','));
    if (filters?.organization) params.set('organization', filters.organization);
    if (filters?.repository) params.set('repository', filters.repository);
    if (filters?.page) params.set('page', String(filters.page));
    if (filters?.page_size) params.set('page_size', String(filters.page_size));
    
    const query = params.toString();
    return this.request(`/scans${query ? `?${query}` : ''}`);
  }

  async getScan(scanId: string): Promise<Scan> {
    return this.request(`/scans/${scanId}`);
  }

  async getScanStatus(scanId: string): Promise<{ status: string; progress?: number }> {
    return this.request(`/scans/${scanId}/status`);
  }

  async startOrgScan(
    organization: string,
    token: string,
    options?: {
      include_historical?: boolean;
      include_archived?: boolean;
      include_forks?: boolean;
      scan_mode?: 'full' | 'api_only' | 'shallow';
      fetch_github_alerts?: boolean;
    }
  ): Promise<{ scan_id: string; status: string; mode?: string; fetch_github_alerts?: boolean }> {
    return this.request('/scans', {
      method: 'POST',
      body: JSON.stringify({
        organization,
        token,
        include_historical: options?.include_historical ?? false,
        include_archived: options?.include_archived ?? false,
        include_forks: options?.include_forks ?? false,
        scan_mode: options?.scan_mode ?? 'api_only',
        fetch_github_alerts: options?.fetch_github_alerts ?? false,
      }),
    });
  }

  async startRepoScan(
    repository: string,
    token: string,
    options?: {
      branch?: string;
      full_history?: boolean;
    }
  ): Promise<{ scan_id: string; status: string }> {
    return this.request('/scans/repo', {
      method: 'POST',
      body: JSON.stringify({
        repository,
        token,
        branch: options?.branch,
        full_history: options?.full_history ?? false,
      }),
    });
  }

  async compareScans(scan1Id: string, scan2Id: string): Promise<{
    new_findings: number;
    resolved_findings: number;
    unchanged_findings: number;
  }> {
    return this.request(`/scans/compare?scan1=${scan1Id}&scan2=${scan2Id}`);
  }

  // Findings
  async getFindings(filters?: FindingsFilter): Promise<PaginatedResponse<Finding>> {
    const params = new URLSearchParams();
    if (filters?.severity?.length) params.set('severity', filters.severity.join(','));
    if (filters?.type?.length) params.set('type', filters.type.join(','));
    if (filters?.status?.length) params.set('status', filters.status.join(','));
    if (filters?.repository) params.set('repository', filters.repository);
    if (filters?.search) params.set('search', filters.search);
    if (filters?.page) params.set('page', String(filters.page));
    if (filters?.page_size) params.set('page_size', String(filters.page_size));
    
    const query = params.toString();
    return this.request(`/findings${query ? `?${query}` : ''}`);
  }

  // Repository Stats
  async getRepositoryStats(owner: string, repo: string): Promise<RepositoryStats> {
    return this.request(`/repositories/${owner}/${repo}/stats`);
  }

  async getRepositoryFindings(
    owner: string,
    repo: string,
    options?: {
      page?: number;
      page_size?: number;
      severity?: string;
      type?: string;
      category?: string;
    }
  ): Promise<PaginatedResponse<Finding>> {
    const params = new URLSearchParams();
    if (options?.page) params.set('page', String(options.page));
    if (options?.page_size) params.set('page_size', String(options.page_size));
    if (options?.severity) params.set('severity', options.severity);
    if (options?.type) params.set('type', options.type);
    if (options?.category) params.set('category', options.category);
    
    const query = params.toString();
    return this.request(`/repositories/${owner}/${repo}/findings${query ? `?${query}` : ''}`);
  }

  async getOpenFindings(): Promise<Finding[]> {
    return this.request('/findings/open');
  }

  async getFinding(findingId: string): Promise<Finding> {
    return this.request(`/findings/${findingId}`);
  }

  async updateFindingStatus(
    findingId: string,
    status: RemediationStatus,
    notes?: string
  ): Promise<Finding> {
    return this.request(`/findings/${findingId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, notes }),
    });
  }

  async exportFindingsCSV(filters?: FindingsFilter): Promise<Blob> {
    const params = new URLSearchParams();
    if (filters?.severity?.length) params.set('severity', filters.severity.join(','));
    if (filters?.type?.length) params.set('type', filters.type.join(','));
    if (filters?.status?.length) params.set('status', filters.status.join(','));
    if (filters?.repository) params.set('repository', filters.repository);
    if (filters?.search) params.set('search', filters.search);
    
    const query = params.toString();
    const url = `${API_BASE_URL}/findings/export/csv${query ? `?${query}` : ''}`;
    
    const headers: Record<string, string> = {};
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    
    const response = await fetch(url, { headers });
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Export failed' }));
      throw new Error(error.detail || `HTTP ${response.status}`);
    }
    
    return response.blob();
  }

  // Organizations/Repositories
  async getOrganizations(): Promise<string[]> {
    return this.request('/organizations');
  }

  async getRepositories(organization?: string): Promise<Repository[]> {
    const query = organization ? `?organization=${organization}` : '';
    return this.request(`/repositories${query}`);
  }

  // GitHub connection test
  async testGitHubConnection(): Promise<{ success: boolean; user?: string; message?: string }> {
    return this.request('/test-github', { method: 'POST' });
  }
}

export const api = new ApiService();
export default api;
