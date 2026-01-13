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
