-- =============================================================================
-- GitHub Security Scanner - Database Schema
-- PostgreSQL (Compatible with AWS Aurora Serverless v2)
-- =============================================================================

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- For text search

-- =============================================================================
-- Enum Types
-- =============================================================================

CREATE TYPE severity_level AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE finding_type AS ENUM ('secret', 'vulnerability', 'sast', 'iac', 'history');
CREATE TYPE remediation_status AS ENUM ('open', 'in_progress', 'resolved', 'false_positive', 'accepted_risk');
CREATE TYPE scan_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled');

-- =============================================================================
-- Organizations Table
-- =============================================================================

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    github_id BIGINT UNIQUE,
    description TEXT,
    avatar_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    settings JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_organizations_name ON organizations(name);

-- =============================================================================
-- Repositories Table
-- =============================================================================

CREATE TABLE repositories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    full_name VARCHAR(511) NOT NULL UNIQUE,
    github_id BIGINT UNIQUE,
    description TEXT,
    url TEXT,
    default_branch VARCHAR(255) DEFAULT 'main',
    language VARCHAR(100),
    is_private BOOLEAN DEFAULT true,
    is_archived BOOLEAN DEFAULT false,
    is_fork BOOLEAN DEFAULT false,
    stars_count INTEGER DEFAULT 0,
    last_pushed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_repositories_org ON repositories(organization_id);
CREATE INDEX idx_repositories_full_name ON repositories(full_name);
CREATE INDEX idx_repositories_language ON repositories(language);
CREATE INDEX idx_repositories_archived ON repositories(is_archived);

-- =============================================================================
-- Scans Table
-- =============================================================================

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    repository_id UUID REFERENCES repositories(id) ON DELETE SET NULL,
    status scan_status DEFAULT 'pending',
    scan_type VARCHAR(50) DEFAULT 'full',  -- 'full', 'incremental', 'quick'
    triggered_by VARCHAR(255),  -- 'manual', 'scheduled', 'webhook'
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER,
    repositories_scanned INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_scans_org ON scans(organization_id);
CREATE INDEX idx_scans_repo ON scans(repository_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at DESC);

-- =============================================================================
-- Findings Table
-- =============================================================================

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    
    -- Finding details
    finding_type finding_type NOT NULL,
    category VARCHAR(255) NOT NULL,
    severity severity_level NOT NULL,
    status remediation_status DEFAULT 'open',
    
    -- Location
    file_path TEXT NOT NULL,
    line_number INTEGER,
    line_content TEXT,
    branch VARCHAR(255),
    commit_sha VARCHAR(40),
    commit_author VARCHAR(255),
    commit_date TIMESTAMP WITH TIME ZONE,
    
    -- Rule information
    rule_id VARCHAR(255) NOT NULL,
    rule_description TEXT,
    matched_pattern TEXT,
    
    -- States (stored as array)
    states TEXT[] DEFAULT '{}',
    
    -- Metadata
    false_positive_likelihood VARCHAR(20),
    remediation_notes TEXT,
    remediation_deadline TIMESTAMP WITH TIME ZONE,
    assigned_to VARCHAR(255),
    
    -- Tracking
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Hash for deduplication
    fingerprint VARCHAR(64) NOT NULL,
    
    UNIQUE(repository_id, fingerprint)
);

CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_repo ON findings(repository_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_type ON findings(finding_type);
CREATE INDEX idx_findings_category ON findings(category);
CREATE INDEX idx_findings_file ON findings(file_path);
CREATE INDEX idx_findings_rule ON findings(rule_id);
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX idx_findings_first_seen ON findings(first_seen_at DESC);

-- Full-text search index
CREATE INDEX idx_findings_search ON findings USING GIN (
    to_tsvector('english', coalesce(file_path, '') || ' ' || coalesce(category, '') || ' ' || coalesce(rule_description, ''))
);

-- =============================================================================
-- Finding History Table (Audit Log)
-- =============================================================================

CREATE TABLE finding_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL,  -- 'created', 'status_changed', 'assigned', 'commented'
    previous_value JSONB,
    new_value JSONB,
    performed_by VARCHAR(255),
    comment TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_finding_history_finding ON finding_history(finding_id);
CREATE INDEX idx_finding_history_created ON finding_history(created_at DESC);

-- =============================================================================
-- Scheduled Tasks Table
-- =============================================================================

CREATE TABLE scheduled_tasks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    schedule VARCHAR(100) NOT NULL,  -- cron expression or 'daily', 'weekly'
    scan_type VARCHAR(50) DEFAULT 'full',
    options JSONB DEFAULT '{}'::jsonb,
    enabled BOOLEAN DEFAULT true,
    last_run_at TIMESTAMP WITH TIME ZONE,
    next_run_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_scheduled_tasks_enabled ON scheduled_tasks(enabled, next_run_at);

-- =============================================================================
-- API Keys Table
-- =============================================================================

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    key_prefix VARCHAR(10) NOT NULL,  -- First 8 chars for identification
    scopes TEXT[] DEFAULT '{"read"}',
    rate_limit INTEGER DEFAULT 1000,  -- requests per hour
    last_used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    revoked_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);

-- =============================================================================
-- Users Table (for local auth)
-- =============================================================================

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'user',  -- 'admin', 'user', 'viewer'
    is_active BOOLEAN DEFAULT true,
    last_login_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);

-- =============================================================================
-- Notifications Table
-- =============================================================================

CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,  -- 'finding', 'scan_complete', 'alert'
    title VARCHAR(255) NOT NULL,
    message TEXT,
    severity severity_level,
    is_read BOOLEAN DEFAULT false,
    link TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_notifications_user ON notifications(user_id, is_read, created_at DESC);

-- =============================================================================
-- Metrics Table (for trends/analytics)
-- =============================================================================

CREATE TABLE daily_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    date DATE NOT NULL,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- Finding counts
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    
    -- Status counts
    open_count INTEGER DEFAULT 0,
    in_progress_count INTEGER DEFAULT 0,
    resolved_count INTEGER DEFAULT 0,
    false_positive_count INTEGER DEFAULT 0,
    
    -- Type counts
    secret_count INTEGER DEFAULT 0,
    vulnerability_count INTEGER DEFAULT 0,
    sast_count INTEGER DEFAULT 0,
    iac_count INTEGER DEFAULT 0,
    
    -- Other metrics
    repositories_scanned INTEGER DEFAULT 0,
    scans_completed INTEGER DEFAULT 0,
    mean_time_to_resolve INTERVAL,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(date, organization_id)
);

CREATE INDEX idx_daily_metrics_date ON daily_metrics(date DESC);
CREATE INDEX idx_daily_metrics_org ON daily_metrics(organization_id, date DESC);

-- =============================================================================
-- GitHub Security Alerts Tables
-- =============================================================================

-- Alert source types
CREATE TYPE alert_source AS ENUM ('dependabot', 'code_scanning', 'secret_scanning', 'custom_scan');
CREATE TYPE alert_state AS ENUM ('open', 'dismissed', 'fixed', 'auto_dismissed');

-- Dependabot Alerts (Vulnerable Dependencies)
CREATE TABLE dependabot_alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    
    -- GitHub Alert Info
    github_alert_number INTEGER NOT NULL,
    state alert_state DEFAULT 'open',
    severity severity_level NOT NULL,
    
    -- Package Info
    package_ecosystem VARCHAR(50) NOT NULL,  -- npm, pip, maven, etc.
    package_name VARCHAR(255) NOT NULL,
    vulnerable_version_range TEXT,
    first_patched_version VARCHAR(100),
    
    -- Vulnerability Details
    ghsa_id VARCHAR(50),  -- GitHub Security Advisory ID
    cve_id VARCHAR(50),
    summary TEXT,
    description TEXT,
    manifest_path TEXT,
    
    -- CVSS
    cvss_score DECIMAL(3,1),
    cvss_vector TEXT,
    cwes TEXT[],  -- Array of CWE IDs
    
    -- Dismissal Info
    dismissed_at TIMESTAMP WITH TIME ZONE,
    dismissed_by VARCHAR(255),
    dismissed_reason VARCHAR(50),
    dismissed_comment TEXT,
    
    -- Fix Info
    fixed_at TIMESTAMP WITH TIME ZONE,
    
    -- URLs
    html_url TEXT,
    advisory_url TEXT,
    
    -- Tracking
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Fingerprint for deduplication
    fingerprint VARCHAR(128) NOT NULL,
    
    UNIQUE(repository_id, fingerprint)
);

CREATE INDEX idx_dependabot_repo ON dependabot_alerts(repository_id);
CREATE INDEX idx_dependabot_state ON dependabot_alerts(state);
CREATE INDEX idx_dependabot_severity ON dependabot_alerts(severity);
CREATE INDEX idx_dependabot_package ON dependabot_alerts(package_ecosystem, package_name);
CREATE INDEX idx_dependabot_ghsa ON dependabot_alerts(ghsa_id);
CREATE INDEX idx_dependabot_cve ON dependabot_alerts(cve_id);

-- Code Scanning Alerts (SAST from CodeQL)
CREATE TABLE code_scanning_alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    
    -- GitHub Alert Info
    github_alert_number INTEGER NOT NULL,
    state alert_state DEFAULT 'open',
    severity severity_level NOT NULL,
    
    -- Rule Info
    rule_id VARCHAR(255) NOT NULL,
    rule_name VARCHAR(255),
    rule_description TEXT,
    rule_severity VARCHAR(50),
    rule_tags TEXT[],
    
    -- Tool Info
    tool_name VARCHAR(100),  -- e.g., "CodeQL"
    tool_version VARCHAR(50),
    
    -- Location
    file_path TEXT NOT NULL,
    start_line INTEGER,
    end_line INTEGER,
    start_column INTEGER,
    end_column INTEGER,
    
    -- Instance Details
    ref VARCHAR(255),  -- Branch reference
    commit_sha VARCHAR(40),
    message TEXT,
    
    -- Dismissal Info
    dismissed_at TIMESTAMP WITH TIME ZONE,
    dismissed_by VARCHAR(255),
    dismissed_reason VARCHAR(50),
    dismissed_comment TEXT,
    
    -- Fix Info
    fixed_at TIMESTAMP WITH TIME ZONE,
    
    -- URL
    html_url TEXT,
    
    -- Tracking
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Fingerprint for deduplication
    fingerprint VARCHAR(128) NOT NULL,
    
    UNIQUE(repository_id, fingerprint)
);

CREATE INDEX idx_code_scanning_repo ON code_scanning_alerts(repository_id);
CREATE INDEX idx_code_scanning_state ON code_scanning_alerts(state);
CREATE INDEX idx_code_scanning_severity ON code_scanning_alerts(severity);
CREATE INDEX idx_code_scanning_rule ON code_scanning_alerts(rule_id);
CREATE INDEX idx_code_scanning_tool ON code_scanning_alerts(tool_name);
CREATE INDEX idx_code_scanning_file ON code_scanning_alerts(file_path);

-- Secret Scanning Alerts
CREATE TABLE secret_scanning_alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    
    -- GitHub Alert Info
    github_alert_number INTEGER NOT NULL,
    state alert_state DEFAULT 'open',
    
    -- Secret Info
    secret_type VARCHAR(100) NOT NULL,
    secret_type_display_name VARCHAR(255),
    secret_masked TEXT,  -- Partially masked secret
    
    -- Locations (stored as JSONB for flexibility)
    locations JSONB DEFAULT '[]',
    
    -- Push Protection
    push_protection_bypassed BOOLEAN DEFAULT FALSE,
    push_protection_bypassed_by VARCHAR(255),
    push_protection_bypassed_at TIMESTAMP WITH TIME ZONE,
    
    -- Resolution
    resolution VARCHAR(50),  -- false_positive, wont_fix, revoked, used_in_tests
    resolution_comment TEXT,
    resolved_by VARCHAR(255),
    resolved_at TIMESTAMP WITH TIME ZONE,
    
    -- URL
    html_url TEXT,
    
    -- Tracking
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Fingerprint for deduplication
    fingerprint VARCHAR(128) NOT NULL,
    
    UNIQUE(repository_id, fingerprint)
);

CREATE INDEX idx_secret_scanning_repo ON secret_scanning_alerts(repository_id);
CREATE INDEX idx_secret_scanning_state ON secret_scanning_alerts(state);
CREATE INDEX idx_secret_scanning_type ON secret_scanning_alerts(secret_type);

-- Alerts Sync History (track when alerts were last fetched)
CREATE TABLE alerts_sync_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    alert_type alert_source NOT NULL,
    
    last_sync_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    alerts_found INTEGER DEFAULT 0,
    alerts_new INTEGER DEFAULT 0,
    alerts_updated INTEGER DEFAULT 0,
    sync_duration_ms INTEGER,
    error_message TEXT,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_alerts_sync_repo ON alerts_sync_history(repository_id);
CREATE INDEX idx_alerts_sync_type ON alerts_sync_history(alert_type);
CREATE INDEX idx_alerts_sync_time ON alerts_sync_history(last_sync_at DESC);

-- Consolidated Alerts View
CREATE OR REPLACE VIEW consolidated_alerts AS
SELECT 
    id,
    repository_id,
    'dependabot' as source,
    github_alert_number as alert_number,
    state::text,
    severity::text,
    package_name as identifier,
    ghsa_id as reference_id,
    summary as title,
    description,
    manifest_path as location,
    NULL::INTEGER as line_number,
    html_url,
    first_seen_at,
    last_seen_at,
    created_at
FROM dependabot_alerts

UNION ALL

SELECT 
    id,
    repository_id,
    'code_scanning' as source,
    github_alert_number as alert_number,
    state::text,
    severity::text,
    rule_id as identifier,
    rule_name as reference_id,
    rule_name as title,
    rule_description as description,
    file_path as location,
    start_line as line_number,
    html_url,
    first_seen_at,
    last_seen_at,
    created_at
FROM code_scanning_alerts

UNION ALL

SELECT 
    id,
    repository_id,
    'secret_scanning' as source,
    github_alert_number as alert_number,
    state::text,
    CASE 
        WHEN secret_type LIKE '%token%' OR secret_type LIKE '%key%' THEN 'critical'
        ELSE 'high'
    END as severity,
    secret_type as identifier,
    NULL as reference_id,
    secret_type_display_name as title,
    NULL as description,
    NULL as location,
    NULL::INTEGER as line_number,
    html_url,
    first_seen_at,
    last_seen_at,
    created_at
FROM secret_scanning_alerts;

-- Alerts Summary View by Repository
CREATE OR REPLACE VIEW repository_alerts_summary AS
SELECT 
    r.id as repository_id,
    r.full_name,
    -- Dependabot
    COUNT(DISTINCT CASE WHEN d.state = 'open' THEN d.id END) as dependabot_open,
    COUNT(DISTINCT CASE WHEN d.state = 'open' AND d.severity = 'critical' THEN d.id END) as dependabot_critical,
    COUNT(DISTINCT CASE WHEN d.state = 'open' AND d.severity = 'high' THEN d.id END) as dependabot_high,
    -- Code Scanning
    COUNT(DISTINCT CASE WHEN cs.state = 'open' THEN cs.id END) as code_scanning_open,
    COUNT(DISTINCT CASE WHEN cs.state = 'open' AND cs.severity = 'critical' THEN cs.id END) as code_scanning_critical,
    COUNT(DISTINCT CASE WHEN cs.state = 'open' AND cs.severity = 'high' THEN cs.id END) as code_scanning_high,
    -- Secret Scanning
    COUNT(DISTINCT CASE WHEN ss.state = 'open' THEN ss.id END) as secret_scanning_open,
    -- Last sync
    MAX(ash.last_sync_at) as last_alerts_sync
FROM repositories r
LEFT JOIN dependabot_alerts d ON d.repository_id = r.id
LEFT JOIN code_scanning_alerts cs ON cs.repository_id = r.id
LEFT JOIN secret_scanning_alerts ss ON ss.repository_id = r.id
LEFT JOIN alerts_sync_history ash ON ash.repository_id = r.id
GROUP BY r.id, r.full_name;

-- =============================================================================
-- Functions and Triggers
-- =============================================================================

-- Update timestamp trigger
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to tables
CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_repositories_updated_at BEFORE UPDATE ON repositories
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_findings_updated_at BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Auto-create finding history on status change
CREATE OR REPLACE FUNCTION log_finding_status_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status != NEW.status THEN
        INSERT INTO finding_history (finding_id, action, previous_value, new_value)
        VALUES (
            NEW.id,
            'status_changed',
            jsonb_build_object('status', OLD.status),
            jsonb_build_object('status', NEW.status)
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER finding_status_change_trigger AFTER UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION log_finding_status_change();

-- =============================================================================
-- Initial Data
-- =============================================================================

-- Create default admin user (password: admin - CHANGE IN PRODUCTION!)
INSERT INTO users (username, email, password_hash, full_name, role)
VALUES (
    'admin',
    'admin@localhost',
    '$2b$12$NVLHVhWIQRGpNpBkwnx71OXz1xO2zvciN/By8joQzrqDQRkCkxiJy', -- bcrypt hash of 'admin'
    'Administrator',
    'admin'
) ON CONFLICT (username) DO NOTHING;

-- =============================================================================
-- Views
-- =============================================================================

-- Repository findings summary view
CREATE OR REPLACE VIEW repository_findings_summary AS
SELECT 
    r.id as repository_id,
    r.full_name,
    r.language,
    COUNT(f.id) as total_findings,
    COUNT(CASE WHEN f.severity = 'critical' AND f.status = 'open' THEN 1 END) as critical_open,
    COUNT(CASE WHEN f.severity = 'high' AND f.status = 'open' THEN 1 END) as high_open,
    COUNT(CASE WHEN f.severity = 'medium' AND f.status = 'open' THEN 1 END) as medium_open,
    COUNT(CASE WHEN f.severity = 'low' AND f.status = 'open' THEN 1 END) as low_open,
    COUNT(CASE WHEN f.status = 'open' THEN 1 END) as open_count,
    COUNT(CASE WHEN f.status = 'resolved' THEN 1 END) as resolved_count,
    MAX(s.completed_at) as last_scan_at
FROM repositories r
LEFT JOIN findings f ON f.repository_id = r.id
LEFT JOIN scans s ON s.repository_id = r.id AND s.status = 'completed'
GROUP BY r.id, r.full_name, r.language;

-- Organization dashboard view
CREATE OR REPLACE VIEW organization_dashboard AS
SELECT 
    o.id as organization_id,
    o.name,
    COUNT(DISTINCT r.id) as repository_count,
    COUNT(DISTINCT f.id) as total_findings,
    COUNT(DISTINCT CASE WHEN f.status = 'open' THEN f.id END) as open_findings,
    COUNT(DISTINCT CASE WHEN f.severity = 'critical' AND f.status = 'open' THEN f.id END) as critical_open,
    COUNT(DISTINCT CASE WHEN f.severity = 'high' AND f.status = 'open' THEN f.id END) as high_open,
    COUNT(DISTINCT s.id) as total_scans,
    MAX(s.completed_at) as last_scan_at
FROM organizations o
LEFT JOIN repositories r ON r.organization_id = o.id
LEFT JOIN findings f ON f.repository_id = r.id
LEFT JOIN scans s ON s.organization_id = o.id AND s.status = 'completed'
GROUP BY o.id, o.name;

-- Grant permissions (adjust as needed)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO gss_app;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO gss_app;

COMMENT ON DATABASE gss_db IS 'GitHub Security Scanner Database';
