"""
FastAPI application for the Security Scanner.

Provides REST API endpoints for the web dashboard.
"""

import asyncio
import csv
import io
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Annotated, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from rich.console import Console

console = Console()

from ..core.config import Settings, get_settings
from ..core.scanner import SecurityScanner
from ..storage.database import Database
from ..storage.postgres_database import DatabasePostgres
from ..storage.models import RemediationStatus
from .security import (
    AUTH_ENABLED,
    AuthUser,
    check_rate_limit,
    create_access_token,
    get_current_user,
    get_optional_user,
    mask_sensitive_data,
    require_scope,
    sanitize_log_data,
)

# Configure logging to mask sensitive data
logger = logging.getLogger(__name__)


# Pydantic models for API
class ScanRequest(BaseModel):
    """Request to start a new scan."""
    organization: str
    token: str
    include_historical: bool = False
    include_archived: bool = False
    include_forks: bool = False
    scan_mode: str = "full"  # "full" = clone repos, "api_only" = use GitHub API (faster), "shallow" = shallow clone
    fetch_github_alerts: bool = False  # Fetch Dependabot, Code Scanning, Secret Scanning alerts


class RepoScanRequest(BaseModel):
    """Request to scan a single repository."""
    repository: str
    token: str
    branch: Optional[str] = None
    full_history: bool = False


class StatusUpdateRequest(BaseModel):
    """Request to update finding status."""
    status: str
    comment: Optional[str] = None
    performed_by: Optional[str] = None


class FindingsCountDetail(BaseModel):
    """Findings count by severity - for frontend compatibility."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0


class ScanSummary(BaseModel):
    """Summary of a scan - matches frontend Scan interface."""
    id: str
    organization: Optional[str] = None
    repository: Optional[str] = None
    status: str = "completed"
    started_at: str
    completed_at: Optional[str] = None
    duration_seconds: Optional[int] = None
    repositories_scanned: int = 0
    findings_count: FindingsCountDetail = FindingsCountDetail()
    error_message: Optional[str] = None


class FindingSummary(BaseModel):
    """Summary of a finding - matches frontend Finding interface."""
    id: str
    repository: str
    type: str  # Frontend expects 'type' not 'finding_type'
    category: str
    severity: str
    states: list[str] = []
    file_path: str
    line_number: Optional[int] = None
    line_content: Optional[str] = None
    matched_pattern: Optional[str] = None
    commit_sha: Optional[str] = None
    commit_date: Optional[str] = None
    commit_author: Optional[str] = None
    branch: str = "main"
    rule_id: str = ""
    rule_description: str = ""
    remediation_status: str = "open"  # Frontend expects 'remediation_status' not 'status'
    remediation_notes: Optional[str] = None
    false_positive_likelihood: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""


class PaginatedFindings(BaseModel):
    """Paginated findings response - matches frontend PaginatedResponse."""
    items: list[FindingSummary]
    total: int
    page: int
    page_size: int
    total_pages: int


class PaginatedScans(BaseModel):
    """Paginated scans response."""
    items: list[ScanSummary]
    total: int
    page: int
    page_size: int
    total_pages: int


class SeverityCount(BaseModel):
    """Severity counts."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class FindingTypeCount(BaseModel):
    """Finding type counts."""
    secret: int = 0
    vulnerability: int = 0
    sast: int = 0
    iac: int = 0
    history: int = 0


class RepoFindingCount(BaseModel):
    """Repository finding count."""
    name: str
    findings_count: int


class ScanSummaryBrief(BaseModel):
    """Brief scan summary for dashboard."""
    id: str
    status: str
    started_at: str
    repositories_scanned: int = 0
    findings_count: SeverityCount = SeverityCount()


class DashboardStats(BaseModel):
    """Dashboard statistics - matches frontend interface."""
    total_repositories: int = 0
    total_findings: int = 0
    open_findings: int = 0
    resolved_findings: int = 0
    findings_by_severity: SeverityCount = SeverityCount()
    findings_by_type: FindingTypeCount = FindingTypeCount()
    recent_scans: list[ScanSummaryBrief] = []
    top_repositories: list[RepoFindingCount] = []


class TrendPoint(BaseModel):
    """Single point in trend data - matches frontend interface."""
    date: str
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    resolved: int = 0


class ComparisonResult(BaseModel):
    """Result of comparing two scans."""
    scan_1: str
    scan_2: str
    new_count: int
    fixed_count: int
    unchanged_count: int
    new_findings: list[dict]
    fixed_findings: list[dict]


# Global database instance
db: Optional[Database] = None
settings: Optional[Settings] = None
active_scans: dict[str, dict] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global db, settings
    
    # Check if DATABASE_URL is set (PostgreSQL)
    database_url = os.environ.get("DATABASE_URL")
    config_path = os.environ.get("GSS_CONFIG_PATH")
    
    if database_url:
        # Use PostgreSQL
        logger.info(f"Using PostgreSQL database: {database_url.split('@')[-1] if '@' in database_url else 'configured'}")
        db = DatabasePostgres(database_url)
    else:
        # Fallback to SQLite for local development
        db_path = os.environ.get("GSS_DB_PATH", "security_scans.db")
        logger.info(f"Using SQLite database: {db_path}")
        db = Database(db_path)
    
    settings = get_settings(config_path)
    
    yield
    
    # Cleanup
    db = None


def get_allowed_origins() -> list[str]:
    """Get allowed CORS origins from environment."""
    origins_env = os.environ.get("GSS_ALLOWED_ORIGINS", "")
    if origins_env:
        return [origin.strip() for origin in origins_env.split(",") if origin.strip()]
    
    # Default origins for development
    return [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    application = FastAPI(
        title="GitHub Security Scanner API",
        description="REST API for the GitHub Organization Security Scanner",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/api/docs" if not AUTH_ENABLED else None,  # Disable docs if auth enabled
        redoc_url="/api/redoc" if not AUTH_ENABLED else None,
    )

    # Secure CORS configuration
    allowed_origins = get_allowed_origins()
    application.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-API-Key"],
        expose_headers=["X-RateLimit-Remaining-Minute", "X-RateLimit-Remaining-Hour"],
        max_age=600,  # Cache preflight for 10 minutes
    )
    
    # Add request logging middleware
    @application.middleware("http")
    async def log_requests(request: Request, call_next):
        """Log all requests with sanitized data."""
        start_time = datetime.now()
        
        # Log request (sanitize headers)
        headers_dict = dict(request.headers)
        sanitized_headers = sanitize_log_data(headers_dict)
        logger.info(f"Request: {request.method} {request.url.path} headers={sanitized_headers}")
        
        response = await call_next(request)
        
        # Log response time
        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"Response: {response.status_code} duration={duration:.3f}s")
        
        return response

    return application


app = create_app()

# Include routers
from .alerts_router import router as alerts_router
app.include_router(alerts_router)


# === Authentication Endpoints ===

class LoginRequest(BaseModel):
    """Login request for JWT token."""
    username: str
    password: str


class TokenResponse(BaseModel):
    """JWT token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


@app.post("/api/auth/token", response_model=TokenResponse, tags=["Authentication"])
async def login_for_token(request: LoginRequest):
    """
    Get a JWT access token.
    
    For production, implement proper user authentication.
    This is a simplified version for demonstration.
    """
    # Simple authentication (replace with proper auth in production)
    admin_user = os.environ.get("GSS_ADMIN_USER", "admin")
    admin_pass = os.environ.get("GSS_ADMIN_PASS", "")
    
    if not admin_pass:
        raise HTTPException(
            status_code=501,
            detail="Authentication not configured. Set GSS_ADMIN_USER and GSS_ADMIN_PASS environment variables.",
        )
    
    if request.username != admin_user or request.password != admin_pass:
        logger.warning(f"Failed login attempt for user: {request.username}")
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )
    
    # Create token
    token = create_access_token(
        user_id=request.username,
        scopes=["read", "write", "admin"],
    )
    
    logger.info(f"User logged in: {request.username}")
    
    return TokenResponse(
        access_token=token,
        expires_in=24 * 3600,  # 24 hours
    )


@app.get("/api/auth/me", tags=["Authentication"])
async def get_current_user_info(
    user: Annotated[AuthUser, Depends(get_current_user)]
):
    """Get information about the current authenticated user."""
    return {
        "user_id": user.user_id,
        "scopes": user.scopes,
        "is_api_key": user.is_api_key,
    }


# === Dashboard Endpoints ===

@app.get("/api/dashboard", response_model=DashboardStats, tags=["Dashboard"])
async def get_dashboard(
    organization: Optional[str] = None,
    user: Annotated[AuthUser | None, Depends(get_optional_user)] = None,
):
    """Get dashboard statistics."""
    logger.info(f"Dashboard accessed by user: {user.user_id if user else 'anonymous'}")
    stats = db.get_statistics(organization)
    
    status_counts = stats.get("status_counts", {})
    severity_counts = stats.get("severity_counts", {})
    type_counts = stats.get("type_counts", {})
    
    # Get total findings
    total_findings = sum(severity_counts.values()) if severity_counts else 0
    
    return DashboardStats(
        total_repositories=stats.get("total_repositories", 0),
        total_findings=total_findings,
        open_findings=status_counts.get("open", 0),
        resolved_findings=status_counts.get("resolved", 0) + status_counts.get("fixed", 0),
        findings_by_severity=SeverityCount(
            critical=severity_counts.get("critical", 0),
            high=severity_counts.get("high", 0),
            medium=severity_counts.get("medium", 0),
            low=severity_counts.get("low", 0),
            info=severity_counts.get("info", 0),
        ),
        findings_by_type=FindingTypeCount(
            secret=type_counts.get("secret", 0),
            vulnerability=type_counts.get("vulnerability", 0),
            sast=type_counts.get("sast", 0),
            iac=type_counts.get("iac", 0),
            history=type_counts.get("history", 0),
        ),
        recent_scans=[],  # Would need additional query
        top_repositories=[
            RepoFindingCount(name=repo.get("name", ""), findings_count=repo.get("findings_count", 0))
            for repo in stats.get("top_affected_repos", [])
        ],
    )


@app.get("/api/trends")
async def get_trends(
    organization: Optional[str] = None,
    days: int = Query(default=30, ge=7, le=365),
) -> list[TrendPoint]:
    """Get trend data for an organization or all organizations."""
    trends = db.get_trend_data(organization=organization, days=days)
    
    # Return empty sample data if no real data exists
    if not trends:
        from datetime import timedelta
        base_date = datetime.now()
        return [
            TrendPoint(
                date=(base_date - timedelta(days=days-i)).strftime("%Y-%m-%d"),
                total=0,
                critical=0,
                high=0,
                medium=0,
                low=0,
                info=0,
                resolved=0,
            )
            for i in range(min(days, 14))
        ]
    
    return [
        TrendPoint(
            date=t.date.strftime("%Y-%m-%d"),
            total=t.total_findings,
            critical=t.critical,
            high=t.high,
            medium=t.medium,
            low=t.low,
            info=getattr(t, 'info', 0),
            resolved=getattr(t, 'resolved', 0),
        )
        for t in trends
    ]


# === Scan Endpoints ===

@app.get("/api/scans", tags=["Scans"])
async def list_scans(
    organization: Optional[str] = None,
    status: Optional[str] = None,
    repository: Optional[str] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> PaginatedScans:
    """List all scans with pagination (including running scans)."""
    items = []
    
    # First, add active/running scans
    for scan_id, scan_data in active_scans.items():
        scan_status = scan_data.get("status", "running")
        scan_org = scan_data.get("organization")
        scan_repo = scan_data.get("repository")
        
        # Filter by organization if provided
        if organization and scan_org != organization:
            continue
        
        # Filter by status if provided
        if status and scan_status != status:
            continue
        
        items.append(ScanSummary(
            id=scan_id,
            organization=scan_org,
            repository=scan_repo,
            status=scan_status,
            started_at=scan_data.get("started_at", datetime.now().isoformat()),
            completed_at=scan_data.get("completed_at"),
            duration_seconds=scan_data.get("duration_seconds"),
            repositories_scanned=scan_data.get("repositories_scanned", 0),
            findings_count=FindingsCountDetail(
                critical=scan_data.get("critical", 0),
                high=scan_data.get("high", 0),
                medium=scan_data.get("medium", 0),
                low=scan_data.get("low", 0),
                info=scan_data.get("info", 0),
                total=scan_data.get("total_findings", 0),
            ),
            error_message=scan_data.get("error"),
        ))
    
    # Then add completed scans from database
    db_scans = db.get_scans(organization=organization, limit=500)
    
    for s in db_scans:
        scan_status = getattr(s, 'status', 'completed')
        
        # Filter by status if provided
        if status and scan_status != status:
            continue
        
        items.append(ScanSummary(
            id=s.id,
            organization=s.organization,
            repository=getattr(s, 'repository', None),
            status=scan_status,
            started_at=s.scan_date.isoformat() if hasattr(s.scan_date, 'isoformat') else str(s.scan_date),
            completed_at=getattr(s, 'completed_at', None),
            duration_seconds=getattr(s, 'duration_seconds', None),
            repositories_scanned=s.repositories_scanned,
            findings_count=FindingsCountDetail(
                critical=s.critical_count,
                high=s.high_count,
                medium=getattr(s, 'medium_count', 0),
                low=getattr(s, 'low_count', 0),
                info=getattr(s, 'info_count', 0),
                total=s.total_findings,
            ),
            error_message=getattr(s, 'error_message', None),
        ))
    
    total = len(items)
    total_pages = max(1, (total + page_size - 1) // page_size)
    
    # Paginate
    start = (page - 1) * page_size
    end = start + page_size
    paginated = items[start:end]
    
    return PaginatedScans(
        items=paginated,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get scan details."""
    scan = db.get_scan(scan_id)
    if not scan:
        # Try partial match
        scans = db.get_scans(limit=100)
        for s in scans:
            if s.id.startswith(scan_id):
                scan = db.get_scan(s.id)
                break
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan.to_dict()


@app.post("/api/scans", tags=["Scans"], dependencies=[Depends(check_rate_limit)])
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    user: Annotated[AuthUser, Depends(get_current_user)],
):
    """
    Start a new organization scan.
    
    Requires authentication. The GitHub token is used only for API access
    and is never stored or logged.
    """
    # Validate user has write permission
    if "write" not in user.scopes and "admin" not in user.scopes:
        raise HTTPException(status_code=403, detail="Write permission required")
    
    scan_id = f"scan-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    # Log with masked token
    logger.info(
        f"Scan started by {user.user_id}: org={request.organization}, "
        f"token={mask_sensitive_data(request.token)}"
    )
    
    active_scans[scan_id] = {
        "status": "running",
        "organization": request.organization,
        "started_at": datetime.now().isoformat(),
        "started_by": user.user_id,
        "progress": 0,
    }
    
    background_tasks.add_task(
        run_org_scan,
        scan_id,
        request.organization,
        request.token,
        request.include_historical,
        request.include_archived,
        request.include_forks,
        request.scan_mode,
        request.fetch_github_alerts,
    )
    
    return {"scan_id": scan_id, "status": "started", "started_by": user.user_id, "mode": request.scan_mode, "fetch_github_alerts": request.fetch_github_alerts}


@app.post("/api/scans/repo", tags=["Scans"], dependencies=[Depends(check_rate_limit)])
async def start_repo_scan(
    request: RepoScanRequest,
    background_tasks: BackgroundTasks,
    user: Annotated[AuthUser, Depends(get_current_user)],
):
    """
    Start a new repository scan.
    
    Requires authentication. The GitHub token is used only for API access.
    """
    if "write" not in user.scopes and "admin" not in user.scopes:
        raise HTTPException(status_code=403, detail="Write permission required")
    
    scan_id = f"scan-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    logger.info(
        f"Repo scan started by {user.user_id}: repo={request.repository}, "
        f"token={mask_sensitive_data(request.token)}"
    )
    
    active_scans[scan_id] = {
        "status": "running",
        "repository": request.repository,
        "started_at": datetime.now().isoformat(),
        "started_by": user.user_id,
        "progress": 0,
    }
    
    background_tasks.add_task(
        run_repo_scan,
        scan_id,
        request.repository,
        request.token,
        request.branch,
        request.full_history,
    )
    
    return {"scan_id": scan_id, "status": "started", "started_by": user.user_id}


@app.get("/api/scans/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get status of a running scan."""
    if scan_id in active_scans:
        return active_scans[scan_id]
    
    # Check if completed
    scan = db.get_scan(scan_id)
    if scan:
        return {"status": "completed", "scan_id": scan.id}
    
    raise HTTPException(status_code=404, detail="Scan not found")


@app.get("/api/scans/compare")
async def compare_scans(
    baseline: str = Query(..., description="Baseline scan ID"),
    current: str = Query(..., description="Current scan ID"),
) -> ComparisonResult:
    """Compare two scans."""
    # Resolve partial IDs
    scans = db.get_scans(limit=100)
    full_baseline = None
    full_current = None
    
    for scan in scans:
        if scan.id.startswith(baseline):
            full_baseline = scan.id
        if scan.id.startswith(current):
            full_current = scan.id
    
    if not full_baseline or not full_current:
        raise HTTPException(status_code=404, detail="One or both scans not found")
    
    result = db.compare_scans(full_baseline, full_current)
    
    return ComparisonResult(**result)


# === Finding Endpoints ===

@app.get("/api/findings", response_model=PaginatedFindings, tags=["Findings"])
async def list_findings(
    scan_id: Optional[str] = None,
    repository: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> PaginatedFindings:
    """List findings with filters and pagination."""
    status_filter = None
    if status:
        try:
            status_filter = RemediationStatus(status)
        except ValueError:
            pass
    
    # Get all matching findings (we'll paginate in memory for now)
    all_findings = db.get_findings(
        scan_id=scan_id,
        repository=repository,
        status=status_filter,
        severity=severity,
        limit=1000,  # Get more for filtering
    )
    
    # Apply search filter if provided
    if search:
        search_lower = search.lower()
        all_findings = [
            f for f in all_findings
            if search_lower in f.repository.lower()
            or search_lower in f.category.lower()
            or search_lower in f.file_path.lower()
        ]
    
    total = len(all_findings)
    total_pages = max(1, (total + page_size - 1) // page_size)
    
    # Paginate
    start = (page - 1) * page_size
    end = start + page_size
    paginated = all_findings[start:end]
    
    items = [
        FindingSummary(
            id=f.id,
            repository=f.repository,
            type=f.finding_type,
            category=f.category,
            severity=f.severity,
            states=["active"],  # Default state
            file_path=f.file_path,
            line_number=f.line_number,
            line_content=getattr(f, 'line_content', None),
            matched_pattern=getattr(f, 'matched_pattern', None),
            branch=getattr(f, 'branch', 'main'),
            rule_id=getattr(f, 'rule_id', f.category.lower().replace(' ', '-')),
            rule_description=getattr(f, 'rule_description', f.category),
            remediation_status=f.status.value if hasattr(f.status, 'value') else str(f.status),
            created_at=f.first_seen_date.isoformat() if f.first_seen_date else "",
            updated_at=f.last_seen_date.isoformat() if f.last_seen_date else "",
        )
        for f in paginated
    ]
    
    return PaginatedFindings(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@app.get("/api/findings/export/csv", tags=["Findings"])
async def export_findings_csv(
    scan_id: Optional[str] = None,
    repository: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    type: Optional[str] = None,
    search: Optional[str] = None,
):
    """
    Export findings to CSV format.
    
    Supports the same filters as the list_findings endpoint.
    Multiple values can be provided as comma-separated strings.
    """
    status_filter = None
    if status:
        # Support multiple statuses (comma-separated)
        statuses = [s.strip() for s in status.split(',')]
        if len(statuses) == 1:
            try:
                status_filter = RemediationStatus(statuses[0])
            except ValueError:
                pass
    
    # Parse severity filter (can be comma-separated)
    severity_filter = None
    if severity:
        severity_filter = [s.strip() for s in severity.split(',')]
    
    # Parse type filter (can be comma-separated)
    type_filter = None
    if type:
        type_filter = [t.strip() for t in type.split(',')]
    
    # Get all matching findings (no pagination for export)
    all_findings = db.get_findings(
        scan_id=scan_id,
        repository=repository,
        status=status_filter,
        severity=severity_filter[0] if severity_filter and len(severity_filter) == 1 else None,
        limit=10000,  # Large limit for export
    )
    
    # Apply multiple severity filter if provided
    if severity_filter and len(severity_filter) > 1:
        all_findings = [f for f in all_findings if f.severity in severity_filter]
    
    # Apply type filter if provided
    if type_filter:
        all_findings = [f for f in all_findings if f.finding_type in type_filter]
    
    # Apply multiple status filter if provided
    if status and ',' in status:
        statuses = [s.strip() for s in status.split(',')]
        all_findings = [
            f for f in all_findings
            if (hasattr(f.status, 'value') and f.status.value in statuses)
            or str(f.status) in statuses
        ]
    
    # Apply search filter if provided
    if search:
        search_lower = search.lower()
        all_findings = [
            f for f in all_findings
            if search_lower in f.repository.lower()
            or search_lower in f.category.lower()
            or search_lower in f.file_path.lower()
        ]
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        "ID",
        "Repository",
        "Type",
        "Category",
        "Severity",
        "Status",
        "File Path",
        "Line Number",
        "Branch",
        "Rule ID",
        "Rule Description",
        "Matched Pattern",
        "Line Content",
        "False Positive Likelihood",
        "Confidence",
        "First Seen",
        "Last Seen",
        "Remediation Notes",
    ])
    
    # Write findings
    for f in all_findings:
        writer.writerow([
            f.id,
            f.repository,
            f.finding_type,
            f.category,
            f.severity,
            f.status.value if hasattr(f.status, 'value') else str(f.status),
            f.file_path,
            f.line_number or "",
            getattr(f, 'branch', 'main'),
            getattr(f, 'rule_id', f.category.lower().replace(' ', '-')),
            getattr(f, 'rule_description', f.category),
            getattr(f, 'matched_pattern', ''),
            getattr(f, 'line_content', '').replace('\n', ' ').replace('\r', '')[:200],  # Clean and truncate
            getattr(f, 'false_positive_likelihood', ''),
            getattr(f, 'confidence', ''),
            f.first_seen_date.isoformat() if f.first_seen_date else "",
            f.last_seen_date.isoformat() if f.last_seen_date else "",
            getattr(f, 'remediation_notes', ''),
        ])
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"security_findings_{timestamp}.csv"
    
    # Return CSV as response
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@app.get("/api/findings/open")
async def list_open_findings(organization: Optional[str] = None):
    """List all open findings."""
    findings = db.get_open_findings(organization)
    
    return [
        {
            "id": f.id,
            "repository": f.repository,
            "finding_type": f.finding_type,
            "category": f.category,
            "severity": f.severity,
            "file_path": f.file_path,
            "line_number": f.line_number,
        }
        for f in findings
    ]


@app.get("/api/findings/{finding_id}")
async def get_finding(finding_id: str):
    """Get finding details."""
    findings = db.get_findings(limit=1000)
    
    for f in findings:
        if f.id.startswith(finding_id):
            return f.to_dict()
    
    raise HTTPException(status_code=404, detail="Finding not found")


@app.patch("/api/findings/{finding_id}/status", tags=["Findings"])
async def update_finding_status(
    finding_id: str,
    request: StatusUpdateRequest,
    user: Annotated[AuthUser, Depends(get_current_user)],
):
    """
    Update finding status.
    
    Requires authentication. Status changes are logged with user information.
    """
    if "write" not in user.scopes and "admin" not in user.scopes:
        raise HTTPException(status_code=403, detail="Write permission required")
    
    try:
        new_status = RemediationStatus(request.status)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status: {request.status}. Valid values: open, in_progress, fixed, wont_fix, false_positive, accepted_risk"
        )
    
    # Find full ID
    findings = db.get_findings(limit=1000)
    full_id = None
    for f in findings:
        if f.id.startswith(finding_id):
            full_id = f.id
            break
    
    if not full_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Use authenticated user as performer
    performed_by = request.performed_by or user.user_id
    
    logger.info(f"Finding status update by {user.user_id}: {finding_id} -> {new_status.value}")
    
    success = db.update_finding_status(
        full_id,
        new_status,
        performed_by,
        request.comment or "",
    )
    
    if success:
        return {
            "status": "updated",
            "finding_id": full_id,
            "new_status": new_status.value,
            "updated_by": performed_by,
        }
    
    raise HTTPException(status_code=500, detail="Failed to update status")


# === Organizations Endpoint ===

@app.get("/api/organizations")
async def list_organizations():
    """List all scanned organizations."""
    scans = db.get_scans(limit=1000)
    orgs = set(s.organization for s in scans)
    
    return [
        {
            "name": org,
            "scan_count": sum(1 for s in scans if s.organization == org),
            "last_scan": max(
                (s.scan_date for s in scans if s.organization == org),
                default=None
            ),
        }
        for org in sorted(orgs)
    ]


# === Repositories Endpoint ===

class RepositoryResponse(BaseModel):
    """Repository information."""
    id: str
    name: str
    full_name: str
    description: Optional[str] = None
    url: str
    default_branch: str = "main"
    language: Optional[str] = None
    is_private: bool = True
    is_archived: bool = False
    last_scan_at: Optional[datetime] = None
    findings_count: dict


@app.get("/api/repositories", tags=["Repositories"])
async def list_repositories(
    organization: Optional[str] = None,
):
    """
    List repositories with their finding counts.
    
    Returns all repositories from the database, including those without findings.
    Uses the repositories table which is populated during scans.
    """
    # Use the database method that queries the repositories table
    repos = db.get_repositories(organization=organization, limit=10000)
    
    return repos


@app.get("/api/repositories/{repo_owner}/{repo_name}/stats", tags=["Repositories"])
async def get_repository_stats(repo_owner: str, repo_name: str):
    """
    Get aggregated statistics for a specific repository.
    
    Returns severity counts, type counts, category breakdown, and status distribution.
    Uses optimized SQL queries to aggregate data without loading all findings.
    """
    full_name = f"{repo_owner}/{repo_name}"
    stats = db.get_repository_stats(full_name)
    
    if not stats:
        raise HTTPException(status_code=404, detail="Repository not found")
    
    return stats


@app.get("/api/repositories/{repo_owner}/{repo_name}/findings", tags=["Repositories"])
async def get_repository_findings(
    repo_owner: str,
    repo_name: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    severity: Optional[str] = None,
    type: Optional[str] = None,
    category: Optional[str] = None,
):
    """
    Get paginated findings for a specific repository.
    
    Supports filtering by severity, type, and category.
    Returns paginated results with total count for navigation.
    """
    full_name = f"{repo_owner}/{repo_name}"
    
    result = db.get_findings_paginated(
        repository=full_name,
        page=page,
        page_size=page_size,
        severity=severity,
        finding_type=type,
        category=category,
    )
    
    return result


@app.get("/api/history", tags=["History"])
async def get_activity_history(
    organization: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500),
    page: int = Query(default=1, ge=1),
) -> dict:
    """
    Get activity history including scans and remediation actions.
    
    Returns a combined timeline of scans and status changes.
    """
    import sqlite3
    from datetime import datetime
    
    activities = []
    
    # Get scans
    scans = db.get_scans(organization=organization, limit=limit * 2)
    for scan in scans:
        activities.append({
            "id": f"scan-{scan.id}",
            "type": "scan",
            "timestamp": scan.scan_date.isoformat() if hasattr(scan.scan_date, 'isoformat') else str(scan.scan_date),
            "organization": scan.organization,
            "title": f"Scan completed: {scan.organization}",
            "description": f"Scanned {scan.repositories_scanned} repositories, found {scan.total_findings} findings",
            "metadata": {
                "scan_id": scan.id,
                "repositories_scanned": scan.repositories_scanned,
                "total_findings": scan.total_findings,
                "critical": scan.critical_count,
                "high": scan.high_count,
            },
        })
    
    # Get remediation/finding history
    # Check if using PostgreSQL or SQLite
    if hasattr(db, '_session'):  # PostgreSQL
        from ..storage.postgres_database import FindingHistoryModel, FindingModel, RepositoryModel
        with db._session() as session:
            query = (
                session.query(FindingHistoryModel, FindingModel, RepositoryModel)
                .join(FindingModel, FindingHistoryModel.finding_id == FindingModel.id, isouter=True)
                .join(RepositoryModel, FindingModel.repository_id == RepositoryModel.id, isouter=True)
            )
            
            if organization:
                query = query.filter(RepositoryModel.full_name.like(f"{organization}/%"))
            
            rows = query.order_by(FindingHistoryModel.created_at.desc()).limit(limit).all()
            
            for fh, f, repo in rows:
                repo_name = repo.full_name if repo else "unknown"
                activities.append({
                    "id": str(fh.id),
                    "type": "remediation",
                    "timestamp": fh.created_at.isoformat() if hasattr(fh.created_at, 'isoformat') else str(fh.created_at),
                    "organization": organization or (repo_name.split("/")[0] if "/" in repo_name else None),
                    "title": f"Finding status changed",
                    "description": f"{f.category if f else 'N/A'} in {repo_name}",
                    "metadata": {
                        "finding_id": str(fh.finding_id) if fh.finding_id else None,
                        "repository": repo_name,
                        "category": f.category if f else None,
                        "severity": f.severity if f else None,
                        "action": fh.action,
                        "previous_value": fh.previous_value,
                        "new_value": fh.new_value,
                        "performed_by": fh.performed_by,
                        "comment": fh.comment,
                    },
                })
    else:  # SQLite
        import sqlite3
        with db._connection() as conn:
            query = """
                SELECT 
                    rh.*,
                    f.repository,
                    f.category,
                    f.severity
                FROM remediation_history rh
                JOIN findings f ON rh.finding_id = f.id
            """
            params = []
            
            if organization:
                query += " WHERE f.repository LIKE ?"
                params.append(f"{organization}/%")
            
            query += " ORDER BY rh.created_at DESC LIMIT ?"
            params.append(limit)
            
            rows = conn.execute(query, params).fetchall()
            
            for row in rows:
                activities.append({
                    "id": row["id"],
                    "type": "remediation",
                    "timestamp": row["created_at"],
                    "organization": organization or row["repository"].split("/")[0] if "/" in row["repository"] else None,
                    "title": f"Finding status changed: {row['old_status']} → {row['new_status']}",
                    "description": f"{row['category']} in {row['repository']}",
                    "metadata": {
                        "finding_id": row["finding_id"],
                        "repository": row["repository"],
                        "category": row["category"],
                        "severity": row["severity"],
                        "old_status": row["old_status"],
                        "new_status": row["new_status"],
                        "performed_by": row["performed_by"],
                        "comment": row["comment"],
                    },
                })
    
    # Sort by timestamp (newest first)
    activities.sort(key=lambda x: x["timestamp"], reverse=True)
    
    # Paginate
    total = len(activities)
    total_pages = max(1, (total + limit - 1) // limit)
    start = (page - 1) * limit
    end = start + limit
    paginated = activities[start:end]
    
    return {
        "items": paginated,
        "total": total,
        "page": page,
        "page_size": limit,
        "total_pages": total_pages,
    }


# === Background Tasks ===

async def _fetch_and_save_github_alerts(
    token: str,
    organization: str,
    repos_list: list[str],
    scan_id: str,
    db_scan_id: str,
):
    """
    Fetch GitHub Security Alerts (Dependabot, Code Scanning, Secret Scanning)
    for all repositories in the organization and save to database.
    """
    from ..github.security_alerts import (
        GitHubSecurityAlertsClient,
        AlertsNotEnabledError,
        AlertsAccessDeniedError,
    )
    
    console.print(f"\n[cyan]🛡️ Fetching GitHub Security Alerts for {len(repos_list)} repositories...[/cyan]")
    
    active_scans[scan_id]["fetching_alerts"] = True
    active_scans[scan_id]["alerts_progress"] = 0
    
    alerts_summary = {
        "dependabot_total": 0,
        "dependabot_critical": 0,
        "dependabot_high": 0,
        "code_scanning_total": 0,
        "code_scanning_critical": 0,
        "code_scanning_high": 0,
        "secret_scanning_total": 0,
    }
    
    try:
        async with GitHubSecurityAlertsClient(token) as client:
            for i, repo_full_name in enumerate(repos_list):
                # Ensure full name format
                if "/" not in repo_full_name:
                    repo_full_name = f"{organization}/{repo_full_name}"
                
                try:
                    # Fetch all alerts for this repo
                    all_alerts = await client.get_all_alerts(repo_full_name, state="open")
                    
                    # Count by type
                    dep_alerts = all_alerts.get("dependabot", [])
                    cs_alerts = all_alerts.get("code_scanning", [])
                    ss_alerts = all_alerts.get("secret_scanning", [])
                    
                    alerts_summary["dependabot_total"] += len(dep_alerts)
                    alerts_summary["code_scanning_total"] += len(cs_alerts)
                    alerts_summary["secret_scanning_total"] += len(ss_alerts)
                    
                    # Count critical/high
                    for alert in dep_alerts:
                        if alert.severity.value == "critical":
                            alerts_summary["dependabot_critical"] += 1
                        elif alert.severity.value == "high":
                            alerts_summary["dependabot_high"] += 1
                    
                    for alert in cs_alerts:
                        if alert.severity.value == "critical":
                            alerts_summary["code_scanning_critical"] += 1
                        elif alert.severity.value == "high":
                            alerts_summary["code_scanning_high"] += 1
                    
                    # TODO: Save alerts to database tables
                    # This would require implementing save methods in postgres_database.py
                    # For now, we just log and update the summary
                    
                    if len(dep_alerts) + len(cs_alerts) + len(ss_alerts) > 0:
                        logger.info(
                            f"  {repo_full_name}: {len(dep_alerts)} dependabot, "
                            f"{len(cs_alerts)} code scanning, {len(ss_alerts)} secret scanning"
                        )
                
                except AlertsNotEnabledError:
                    # Feature not enabled for this repo, skip silently
                    pass
                except AlertsAccessDeniedError as e:
                    logger.debug(f"Access denied for {repo_full_name} alerts: {e}")
                except Exception as e:
                    logger.warning(f"Error fetching alerts for {repo_full_name}: {e}")
                
                # Update progress
                if i % 20 == 0 or i == len(repos_list) - 1:
                    progress = int((i + 1) / len(repos_list) * 100)
                    active_scans[scan_id]["alerts_progress"] = progress
                    active_scans[scan_id]["github_alerts"] = alerts_summary.copy()
        
        # Final summary
        total_github_alerts = (
            alerts_summary["dependabot_total"] + 
            alerts_summary["code_scanning_total"] + 
            alerts_summary["secret_scanning_total"]
        )
        
        console.print(f"\n[green]✅ GitHub Alerts fetched: {total_github_alerts} total[/green]")
        console.print(f"   📦 Dependabot: {alerts_summary['dependabot_total']} ({alerts_summary['dependabot_critical']} critical)")
        console.print(f"   🔍 Code Scanning: {alerts_summary['code_scanning_total']} ({alerts_summary['code_scanning_critical']} critical)")
        console.print(f"   🔑 Secret Scanning: {alerts_summary['secret_scanning_total']}")
        
        active_scans[scan_id]["github_alerts"] = alerts_summary
        active_scans[scan_id]["fetching_alerts"] = False
        
    except Exception as e:
        logger.error(f"Failed to fetch GitHub alerts: {e}")
        active_scans[scan_id]["alerts_error"] = str(e)
        active_scans[scan_id]["fetching_alerts"] = False


async def run_org_scan(
    scan_id: str,
    organization: str,
    token: str,
    include_historical: bool,
    include_archived: bool,
    include_forks: bool,
    scan_mode: str = "full",
    fetch_github_alerts: bool = False,
):
    """Run organization scan in background with optional GitHub Security Alerts fetching."""
    try:
        settings.github.token = token
        settings.scan.analyze_history = include_historical
        
        # Set clone strategy based on scan mode
        if scan_mode == "shallow":
            settings.scan.clone_strategy = "shallow"
        elif scan_mode == "api_only":
            settings.scan.clone_strategy = "api"  # No cloning
        else:
            settings.scan.clone_strategy = "full"
        
        # Update active scan with mode info
        active_scans[scan_id]["scan_mode"] = scan_mode
        
        if scan_mode == "api_only":
            # Use API-based scanner with INCREMENTAL saving
            from ..analyzers.api_scanner import APIScanner
            import time
            
            start_time = time.time()
            api_scanner = APIScanner(token, settings)
            
            console.print(f"\n🔍 [bold]API Scan[/bold] organization: {organization}\n")
            console.print("Searching for secrets via GitHub API (no clone)...")
            
            # Generate a UUID for the scan
            from uuid import uuid4
            db_scan_id = str(uuid4())
            
            # Create scan record IMMEDIATELY with 'running' status
            try:
                _, org_id = db.create_scan_incremental(db_scan_id, organization, "api_only")
                console.print(f"[green]✅ Scan created in database: {db_scan_id[:8]}...[/green]")
            except Exception as e:
                logger.error(f"Failed to create scan record: {e}")
                raise
            
            # Get list of repositories and save them INCREMENTALLY
            repos_list = await api_scanner._list_org_repos(organization)
            console.print(f"[cyan]📦 Found {len(repos_list)} repositories[/cyan]")
            
            # Save each repository immediately
            for i, repo_full_name in enumerate(repos_list):
                repo_name = repo_full_name.split("/")[-1] if "/" in repo_full_name else repo_full_name
                try:
                    db.save_repository_incremental(org_id, repo_full_name, repo_name, db_scan_id)
                except Exception as e:
                    logger.warning(f"Failed to save repository {repo_full_name}: {e}")
                
                # Update progress in active_scans
                if i % 50 == 0 or i == len(repos_list) - 1:
                    active_scans[scan_id]["repositories_scanned"] = i + 1
                    active_scans[scan_id]["progress"] = int((i + 1) / len(repos_list) * 30)  # First 30% is repo discovery
            
            console.print(f"[green]✅ {len(repos_list)} repositories saved to database[/green]")
            
            # Now scan for findings with INCREMENTAL saving
            findings_count = 0
            
            # Use the scan_organization_incremental method if available, otherwise adapt
            console.print("[cyan]🔎 Scanning for secrets...[/cyan]")
            
            findings = await api_scanner.scan_organization(organization)
            
            # Save each finding INCREMENTALLY
            for i, finding in enumerate(findings):
                try:
                    result = db.save_finding_incremental(db_scan_id, org_id, finding)
                    if result:  # New finding (not duplicate)
                        findings_count += 1
                except Exception as e:
                    logger.warning(f"Failed to save finding: {e}")
                
                # Update progress
                if i % 10 == 0 or i == len(findings) - 1:
                    # Get current counts from database for accuracy
                    progress = db.get_scan_progress(db_scan_id)
                    active_scans[scan_id].update({
                        "total_findings": progress.get("total_findings", 0),
                        "critical": progress.get("critical", 0),
                        "high": progress.get("high", 0),
                        "medium": progress.get("medium", 0),
                        "low": progress.get("low", 0),
                        "info": progress.get("info", 0),
                        "progress": 30 + int((i + 1) / max(len(findings), 1) * 70),  # 30-100%
                    })
            
            # Calculate duration
            duration_seconds = int(time.time() - start_time)
            
            # Mark scan as completed
            db.update_scan_status(db_scan_id, "completed", duration_seconds=duration_seconds)
            
            # Get final counts
            final_progress = db.get_scan_progress(db_scan_id)
            
            active_scans[scan_id] = {
                "status": "completed",
                "organization": organization,
                "db_scan_id": db_scan_id,
                "repositories_scanned": len(repos_list),
                "total_findings": final_progress.get("total_findings", 0),
                "critical": final_progress.get("critical", 0),
                "high": final_progress.get("high", 0),
                "medium": final_progress.get("medium", 0),
                "low": final_progress.get("low", 0),
                "info": final_progress.get("info", 0),
                "scan_mode": scan_mode,
                "duration_seconds": duration_seconds,
                "completed_at": datetime.now().isoformat(),
            }
            
            console.print(f"\n[green]✅ Scan completed! {final_progress.get('total_findings', 0)} findings in {len(repos_list)} repositories[/green]")
            
            # Fetch GitHub Security Alerts if requested
            if fetch_github_alerts:
                await _fetch_and_save_github_alerts(
                    token, organization, repos_list, scan_id, db_scan_id
                )
        else:
            # Full or shallow clone scan
            scanner = SecurityScanner(settings)
            
            result = await scanner.scan_organization(
                org=organization,
                token=token,
                include_archived=include_archived,
                include_forks=include_forks,
            )
            
            # Save to database
            db_scan_id = db.save_scan(result)
            db.mark_fixed_findings(db_scan_id)
            
            # Fetch GitHub Security Alerts if requested
            if fetch_github_alerts:
                repos_list = list(result.repositories.keys()) if result.repositories else []
                await _fetch_and_save_github_alerts(
                    token, organization, repos_list, scan_id, db_scan_id
                )
            
            active_scans[scan_id] = {
                "status": "completed",
                "organization": organization,
                "db_scan_id": db_scan_id,
                "total_findings": result.metadata.total_findings,
                "scan_mode": scan_mode,
                "completed_at": datetime.now().isoformat(),
            }
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        active_scans[scan_id] = {
            "status": "failed",
            "organization": organization,
            "error": str(e),
            "scan_mode": scan_mode,
            "failed_at": datetime.now().isoformat(),
        }


async def run_repo_scan(
    scan_id: str,
    repository: str,
    token: str,
    branch: Optional[str],
    full_history: bool,
):
    """Run repository scan in background."""
    try:
        settings.github.token = token
        settings.scan.analyze_history = full_history
        
        if full_history:
            settings.scan.clone_strategy = "full"
        
        scanner = SecurityScanner(settings)
        
        result = await scanner.scan_repository(
            repo_url=repository,
            token=token,
            branch=branch,
        )
        
        db_scan_id = db.save_scan(result)
        
        active_scans[scan_id] = {
            "status": "completed",
            "repository": repository,
            "db_scan_id": db_scan_id,
            "total_findings": result.metadata.total_findings,
            "completed_at": datetime.now().isoformat(),
        }
        
    except Exception as e:
        active_scans[scan_id] = {
            "status": "failed",
            "error": str(e),
            "failed_at": datetime.now().isoformat(),
        }


# =============================================================================
# Authentication & User Management Endpoints
# =============================================================================

from .auth import (
    UserCreate,
    UserUpdate,
    UserLogin,
    UserResponse,
    PasswordChange,
    PasswordReset,
    Token,
    TokenData,
    UserManager,
    create_tokens,
    decode_token,
    require_auth,
    require_admin,
    require_analyst_or_admin,
)

# Initialize user manager
user_manager: Optional[UserManager] = None


def get_user_manager() -> UserManager:
    """Get user manager instance."""
    global user_manager
    if user_manager is None:
        user_manager = UserManager(db)
    return user_manager


@app.post("/api/auth/login", tags=["Authentication"])
async def login(credentials: UserLogin):
    """
    Authenticate user and return JWT tokens.
    
    Returns access_token and refresh_token for authenticated sessions.
    """
    um = get_user_manager()
    user = um.authenticate(credentials.username, credentials.password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    tokens = create_tokens(user["id"], user["username"], user["role"])
    
    return {
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "token_type": tokens.token_type,
        "expires_in": tokens.expires_in,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
        }
    }


@app.post("/api/auth/refresh", tags=["Authentication"])
async def refresh_token(refresh_token: str):
    """
    Refresh access token using refresh token.
    """
    token_data = decode_token(refresh_token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    # Verify user still exists and is active
    um = get_user_manager()
    user = um.get_user_by_id(token_data.user_id)
    if not user or not user.get("is_active"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    tokens = create_tokens(user["id"], user["username"], user["role"])
    return {
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "token_type": tokens.token_type,
        "expires_in": tokens.expires_in,
    }


@app.get("/api/auth/me", tags=["Authentication"])
async def get_current_user_info(token_data: TokenData = Depends(require_auth)):
    """
    Get current authenticated user information.
    """
    um = get_user_manager()
    user = um.get_user_by_id(token_data.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return UserResponse(**user)


@app.post("/api/auth/change-password", tags=["Authentication"])
async def change_password(
    data: PasswordChange,
    token_data: TokenData = Depends(require_auth)
):
    """
    Change current user's password.
    """
    um = get_user_manager()
    try:
        success = um.change_password(
            token_data.user_id,
            data.current_password,
            data.new_password
        )
        if not success:
            raise HTTPException(status_code=400, detail="Failed to change password")
        return {"message": "Password changed successfully"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# =============================================================================
# User Management (Admin Only)
# =============================================================================

@app.get("/api/users", tags=["User Management"])
async def list_users(
    include_inactive: bool = False,
    token_data: TokenData = Depends(require_admin)
):
    """
    List all users (admin only).
    """
    um = get_user_manager()
    users = um.list_users(include_inactive=include_inactive)
    return {"users": users, "total": len(users)}


@app.post("/api/users", tags=["User Management"])
async def create_user(
    user_data: UserCreate,
    token_data: TokenData = Depends(require_admin)
):
    """
    Create a new user (admin only).
    """
    um = get_user_manager()
    try:
        user = um.create_user(user_data)
        return {"message": "User created successfully", "user": user}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/users/{user_id}", tags=["User Management"])
async def get_user(
    user_id: str,
    token_data: TokenData = Depends(require_admin)
):
    """
    Get user by ID (admin only).
    """
    um = get_user_manager()
    user = um.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.patch("/api/users/{user_id}", tags=["User Management"])
async def update_user(
    user_id: str,
    user_data: UserUpdate,
    token_data: TokenData = Depends(require_admin)
):
    """
    Update user (admin only).
    """
    um = get_user_manager()
    try:
        user = um.update_user(user_id, user_data)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return {"message": "User updated successfully", "user": user}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/users/{user_id}", tags=["User Management"])
async def delete_user(
    user_id: str,
    token_data: TokenData = Depends(require_admin)
):
    """
    Deactivate user (admin only). Soft delete - sets is_active to false.
    """
    um = get_user_manager()
    
    # Prevent self-deletion
    if user_id == token_data.user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    success = um.delete_user(user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deactivated successfully"}


@app.post("/api/users/{user_id}/reset-password", tags=["User Management"])
async def reset_user_password(
    user_id: str,
    data: PasswordReset,
    token_data: TokenData = Depends(require_admin)
):
    """
    Reset user password (admin only). Does not require current password.
    """
    um = get_user_manager()
    success = um.reset_password(user_id, data.new_password)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "Password reset successfully"}


@app.post("/api/users/{user_id}/activate", tags=["User Management"])
async def activate_user(
    user_id: str,
    token_data: TokenData = Depends(require_admin)
):
    """
    Reactivate a deactivated user (admin only).
    """
    um = get_user_manager()
    user = um.update_user(user_id, UserUpdate(is_active=True))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User activated successfully", "user": user}


# Health check
@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "database": "connected" if db else "disconnected",
    }


# Test GitHub connection
@app.post("/api/test-github", tags=["Utilities"])
async def test_github_connection(
    request: ScanRequest,
    user: Annotated[AuthUser, Depends(get_current_user)],
):
    """
    Test GitHub API connection and list repos.
    
    Requires authentication. The token is used for testing only and not stored.
    """
    import httpx
    
    logger.info(f"GitHub connection test by {user.user_id}: org={request.organization}")
    
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {request.token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    
    async with httpx.AsyncClient() as client:
        # Test 1: Check user
        try:
            user_resp = await client.get("https://api.github.com/user", headers=headers)
            if user_resp.status_code != 200:
                return {
                    "success": False,
                    "error": "Token inválido",
                    "details": user_resp.json() if user_resp.status_code != 401 else "Unauthorized",
                }
            user_data = user_resp.json()
        except Exception as e:
            return {"success": False, "error": f"Erro de conexão: {str(e)}"}
        
        # Test 2: List org repos
        try:
            org_resp = await client.get(
                f"https://api.github.com/orgs/{request.organization}/repos",
                headers=headers,
                params={"per_page": 10, "sort": "updated"},
            )
            
            if org_resp.status_code == 404:
                return {
                    "success": False,
                    "error": f"Organização '{request.organization}' não encontrada",
                    "user": user_data.get("login"),
                }
            
            if org_resp.status_code != 200:
                return {
                    "success": False,
                    "error": f"Erro ao acessar organização: {org_resp.status_code}",
                    "details": org_resp.json(),
                    "user": user_data.get("login"),
                }
            
            repos = org_resp.json()
            
            return {
                "success": True,
                "user": user_data.get("login"),
                "organization": request.organization,
                "repos_found": len(repos),
                "sample_repos": [r["name"] for r in repos[:5]],
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Erro ao listar repos: {str(e)}",
                "user": user_data.get("login"),
            }

