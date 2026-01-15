"""
API Router for GitHub Security Alerts.

Provides endpoints for:
- Fetching alerts from GitHub (Dependabot, Code Scanning, Secret Scanning)
- Viewing consolidated alerts
- Alert statistics and summaries
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from ..github.security_alerts import (
    GitHubSecurityAlertsClient,
    AlertsSummary,
    DependabotAlert,
    CodeScanningAlert,
    SecretScanningAlert,
    AlertsNotEnabledError,
    AlertsAccessDeniedError,
    AlertsRateLimitError,
)
from ..github.client import GitHubClient
from ..core.config import get_settings
from .auth import TokenData, require_auth, require_analyst_or_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/alerts", tags=["Security Alerts"])


# =============================================================================
# Pydantic Models
# =============================================================================

class AlertsSyncRequest(BaseModel):
    """Request to sync alerts from GitHub."""
    organization: str = Field(..., description="GitHub organization name")
    token: str = Field(..., description="GitHub token with repo access")
    repositories: Optional[list[str]] = Field(
        None, 
        description="Specific repositories to sync (optional, syncs all if not provided)"
    )


class AlertsSyncResponse(BaseModel):
    """Response from alerts sync."""
    sync_id: str
    status: str
    message: str
    repositories_queued: int


class AlertsSummaryResponse(BaseModel):
    """Summary of alerts for an organization or repository."""
    organization: Optional[str] = None
    repository: Optional[str] = None
    
    # Dependabot
    dependabot_total: int = 0
    dependabot_critical: int = 0
    dependabot_high: int = 0
    dependabot_medium: int = 0
    dependabot_low: int = 0
    dependabot_open: int = 0
    dependabot_fixed: int = 0
    dependabot_dismissed: int = 0
    
    # Code Scanning
    code_scanning_total: int = 0
    code_scanning_critical: int = 0
    code_scanning_high: int = 0
    code_scanning_medium: int = 0
    code_scanning_low: int = 0
    code_scanning_open: int = 0
    code_scanning_fixed: int = 0
    code_scanning_dismissed: int = 0
    
    # Secret Scanning
    secret_scanning_total: int = 0
    secret_scanning_open: int = 0
    secret_scanning_resolved: int = 0
    
    # Aggregated
    total_alerts: int = 0
    total_critical: int = 0
    total_high: int = 0
    total_open: int = 0
    
    last_sync_at: Optional[str] = None


class OrgAlertsSummaryResponse(BaseModel):
    """Organization-level summary with per-repo breakdown."""
    organization: str
    repos_scanned: int = 0
    repos_with_alerts: int = 0
    errors: list[dict] = []
    summaries: list[AlertsSummaryResponse] = []
    last_sync_at: Optional[str] = None

    # Aggregated totals
    dependabot_total: int = 0
    dependabot_critical: int = 0
    dependabot_high: int = 0
    dependabot_medium: int = 0
    dependabot_low: int = 0
    dependabot_open: int = 0
    dependabot_fixed: int = 0
    dependabot_dismissed: int = 0

    code_scanning_total: int = 0
    code_scanning_critical: int = 0
    code_scanning_high: int = 0
    code_scanning_medium: int = 0
    code_scanning_low: int = 0
    code_scanning_open: int = 0
    code_scanning_fixed: int = 0
    code_scanning_dismissed: int = 0

    secret_scanning_total: int = 0
    secret_scanning_open: int = 0
    secret_scanning_resolved: int = 0

    total_alerts: int = 0
    total_critical: int = 0
    total_high: int = 0
    total_open: int = 0


class DependabotAlertResponse(BaseModel):
    """Dependabot alert response model."""
    id: str
    number: int
    state: str
    severity: str
    package_ecosystem: str
    package_name: str
    vulnerable_version_range: str
    first_patched_version: Optional[str]
    ghsa_id: str
    cve_id: Optional[str]
    summary: str
    repository: str
    manifest_path: str
    cvss_score: Optional[float]
    html_url: str
    created_at: str
    
    class Config:
        from_attributes = True


class CodeScanningAlertResponse(BaseModel):
    """Code scanning alert response model."""
    id: str
    number: int
    state: str
    severity: str
    rule_id: str
    rule_name: str
    rule_description: str
    tool_name: str
    repository: str
    file_path: str
    start_line: int
    end_line: int
    html_url: str
    created_at: str
    
    class Config:
        from_attributes = True


class SecretScanningAlertResponse(BaseModel):
    """Secret scanning alert response model."""
    id: str
    number: int
    state: str
    severity: str
    secret_type: str
    secret_type_display_name: str
    repository: str
    html_url: str
    created_at: str
    
    class Config:
        from_attributes = True


class ConsolidatedAlertResponse(BaseModel):
    """Consolidated alert from any source."""
    id: str
    source: str  # dependabot, code_scanning, secret_scanning
    number: int
    state: str
    severity: str
    title: str
    description: Optional[str]
    repository: str
    location: Optional[str]
    line_number: Optional[int]
    html_url: str
    created_at: str


class PaginatedAlertsResponse(BaseModel):
    """Paginated alerts response."""
    items: list[ConsolidatedAlertResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# =============================================================================
# In-memory state for active syncs
# =============================================================================

active_syncs: dict[str, dict] = {}


# =============================================================================
# Endpoints
# =============================================================================

@router.post("/sync", response_model=AlertsSyncResponse)
async def start_alerts_sync(
    request: AlertsSyncRequest,
    background_tasks: BackgroundTasks,
    token_data: TokenData = Depends(require_analyst_or_admin),
):
    """
    Start syncing security alerts from GitHub.
    
    This endpoint triggers a background task that fetches:
    - Dependabot alerts (vulnerable dependencies)
    - Code Scanning alerts (SAST findings)
    - Secret Scanning alerts
    
    Requires analyst or admin role.
    """
    sync_id = str(uuid4())[:8]
    
    # Get list of repositories if not provided
    repos_to_sync = request.repositories or []
    
    if not repos_to_sync:
        # Fetch all repos from organization
        try:
            async with GitHubSecurityAlertsClient(request.token) as client:
                # We'll need to get repos list first
                # For now, return an error if no repos specified
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Please specify repositories to sync or run a scan first"
                )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
    
    # Initialize sync state
    active_syncs[sync_id] = {
        "status": "running",
        "organization": request.organization,
        "repositories": repos_to_sync,
        "started_at": datetime.now().isoformat(),
        "progress": 0,
        "total": len(repos_to_sync),
        "completed": 0,
        "errors": [],
    }
    
    # Start background task
    background_tasks.add_task(
        run_alerts_sync,
        sync_id,
        request.organization,
        request.token,
        repos_to_sync,
    )
    
    return AlertsSyncResponse(
        sync_id=sync_id,
        status="started",
        message=f"Syncing alerts for {len(repos_to_sync)} repositories",
        repositories_queued=len(repos_to_sync),
    )


async def run_alerts_sync(
    sync_id: str,
    organization: str,
    token: str,
    repositories: list[str],
):
    """Background task to sync alerts from GitHub."""
    try:
        async with GitHubSecurityAlertsClient(token) as client:
            for i, repo in enumerate(repositories):
                full_repo = f"{organization}/{repo}" if "/" not in repo else repo
                
                try:
                    logger.info(f"Syncing alerts for {full_repo}...")
                    
                    # Fetch all alert types
                    all_alerts = await client.get_all_alerts(full_repo)
                    
                    # Update progress
                    active_syncs[sync_id]["completed"] = i + 1
                    active_syncs[sync_id]["progress"] = int((i + 1) / len(repositories) * 100)
                    
                    # Log results
                    dep_count = len(all_alerts.get("dependabot", []))
                    cs_count = len(all_alerts.get("code_scanning", []))
                    ss_count = len(all_alerts.get("secret_scanning", []))
                    
                    logger.info(
                        f"  {full_repo}: {dep_count} dependabot, "
                        f"{cs_count} code scanning, {ss_count} secret scanning"
                    )
                    
                    # TODO: Save to database
                    
                except AlertsNotEnabledError as e:
                    logger.debug(f"Alerts not enabled for {full_repo}: {e}")
                except AlertsAccessDeniedError as e:
                    logger.warning(f"Access denied for {full_repo}: {e}")
                    active_syncs[sync_id]["errors"].append(f"{full_repo}: Access denied")
                except Exception as e:
                    logger.error(f"Error syncing {full_repo}: {e}")
                    active_syncs[sync_id]["errors"].append(f"{full_repo}: {str(e)}")
        
        # Mark as completed
        active_syncs[sync_id]["status"] = "completed"
        active_syncs[sync_id]["completed_at"] = datetime.now().isoformat()
        
    except Exception as e:
        logger.error(f"Sync failed: {e}")
        active_syncs[sync_id]["status"] = "failed"
        active_syncs[sync_id]["error"] = str(e)


@router.get("/sync/{sync_id}")
async def get_sync_status(sync_id: str):
    """Get status of an alerts sync operation."""
    if sync_id not in active_syncs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sync not found"
        )
    
    return active_syncs[sync_id]


async def _list_org_repositories(
    organization: str,
    token: str,
    include_archived: bool,
    include_forks: bool,
    max_repos: int,
) -> list[str]:
    """List repositories in an organization using GitHub API."""
    settings = get_settings()
    settings.github.token = token
    repos: list[str] = []
    async with GitHubClient(settings.github) as client:
        async for repo_data in client.list_organization_repos(organization):
            if not include_archived and repo_data.get("archived"):
                continue
            if not include_forks and repo_data.get("fork"):
                continue
            full_name = repo_data.get("full_name")
            if full_name:
                repos.append(full_name)
            if max_repos and len(repos) >= max_repos:
                break
    return repos


def _to_summary_response(summary: AlertsSummary) -> AlertsSummaryResponse:
    """Convert AlertsSummary to response model."""
    return AlertsSummaryResponse(
        organization=summary.organization,
        repository=summary.repository,
        dependabot_total=summary.dependabot_total,
        dependabot_critical=summary.dependabot_critical,
        dependabot_high=summary.dependabot_high,
        dependabot_medium=summary.dependabot_medium,
        dependabot_low=summary.dependabot_low,
        dependabot_open=summary.dependabot_open,
        dependabot_fixed=summary.dependabot_fixed,
        dependabot_dismissed=summary.dependabot_dismissed,
        code_scanning_total=summary.code_scanning_total,
        code_scanning_critical=summary.code_scanning_critical,
        code_scanning_high=summary.code_scanning_high,
        code_scanning_medium=summary.code_scanning_medium,
        code_scanning_low=summary.code_scanning_low,
        code_scanning_open=summary.code_scanning_open,
        code_scanning_fixed=summary.code_scanning_fixed,
        code_scanning_dismissed=summary.code_scanning_dismissed,
        secret_scanning_total=summary.secret_scanning_total,
        secret_scanning_open=summary.secret_scanning_open,
        secret_scanning_resolved=summary.secret_scanning_resolved,
        total_alerts=summary.total_alerts,
        total_critical=summary.total_critical,
        total_high=summary.total_high,
        total_open=summary.total_open,
    )


def _merge_totals(target: OrgAlertsSummaryResponse, summary: AlertsSummary) -> None:
    """Accumulate alert totals."""
    target.dependabot_total += summary.dependabot_total
    target.dependabot_critical += summary.dependabot_critical
    target.dependabot_high += summary.dependabot_high
    target.dependabot_medium += summary.dependabot_medium
    target.dependabot_low += summary.dependabot_low
    target.dependabot_open += summary.dependabot_open
    target.dependabot_fixed += summary.dependabot_fixed
    target.dependabot_dismissed += summary.dependabot_dismissed

    target.code_scanning_total += summary.code_scanning_total
    target.code_scanning_critical += summary.code_scanning_critical
    target.code_scanning_high += summary.code_scanning_high
    target.code_scanning_medium += summary.code_scanning_medium
    target.code_scanning_low += summary.code_scanning_low
    target.code_scanning_open += summary.code_scanning_open
    target.code_scanning_fixed += summary.code_scanning_fixed
    target.code_scanning_dismissed += summary.code_scanning_dismissed

    target.secret_scanning_total += summary.secret_scanning_total
    target.secret_scanning_open += summary.secret_scanning_open
    target.secret_scanning_resolved += summary.secret_scanning_resolved

    target.total_alerts += summary.total_alerts
    target.total_critical += summary.total_critical
    target.total_high += summary.total_high
    target.total_open += summary.total_open


@router.get("/repository/{owner}/{repo}/summary", response_model=AlertsSummaryResponse)
async def get_repository_alerts_summary(
    owner: str,
    repo: str,
    token: str = Query(..., description="GitHub token"),
):
    """
    Get summary of all security alerts for a repository.
    
    Fetches current data directly from GitHub API.
    """
    full_repo = f"{owner}/{repo}"
    
    try:
        async with GitHubSecurityAlertsClient(token) as client:
            summary = await client.get_alerts_summary(full_repo)
            
            return AlertsSummaryResponse(
                repository=full_repo,
                dependabot_total=summary.dependabot_total,
                dependabot_critical=summary.dependabot_critical,
                dependabot_high=summary.dependabot_high,
                dependabot_medium=summary.dependabot_medium,
                dependabot_low=summary.dependabot_low,
                dependabot_open=summary.dependabot_open,
                dependabot_fixed=summary.dependabot_fixed,
                dependabot_dismissed=summary.dependabot_dismissed,
                code_scanning_total=summary.code_scanning_total,
                code_scanning_critical=summary.code_scanning_critical,
                code_scanning_high=summary.code_scanning_high,
                code_scanning_medium=summary.code_scanning_medium,
                code_scanning_low=summary.code_scanning_low,
                code_scanning_open=summary.code_scanning_open,
                code_scanning_fixed=summary.code_scanning_fixed,
                code_scanning_dismissed=summary.code_scanning_dismissed,
                secret_scanning_total=summary.secret_scanning_total,
                secret_scanning_open=summary.secret_scanning_open,
                secret_scanning_resolved=summary.secret_scanning_resolved,
                total_alerts=summary.total_alerts,
                total_critical=summary.total_critical,
                total_high=summary.total_high,
                total_open=summary.total_open,
                last_sync_at=datetime.now().isoformat(),
            )
    
    except AlertsAccessDeniedError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: {e}"
        )
    except AlertsRateLimitError as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limited: {e}"
        )
    except Exception as e:
        logger.error(f"Error fetching alerts summary: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/organization/{organization}/summary", response_model=OrgAlertsSummaryResponse)
async def get_organization_alerts_summary(
    organization: str,
    token: str = Query(..., description="GitHub token"),
    include_archived: bool = Query(False, description="Include archived repositories"),
    include_forks: bool = Query(False, description="Include forked repositories"),
    max_repos: int = Query(200, ge=1, le=1000, description="Max repositories to scan"),
    max_concurrency: int = Query(8, ge=1, le=20, description="Max concurrent requests"),
):
    """
    Get consolidated security alerts summary for an organization.
    
    Fetches per-repo summaries and aggregates totals.
    """
    try:
        repos = await _list_org_repositories(
            organization, token, include_archived, include_forks, max_repos
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list repositories: {e}"
        )

    response = OrgAlertsSummaryResponse(
        organization=organization,
        repos_scanned=len(repos),
        summaries=[],
        errors=[],
        last_sync_at=datetime.now().isoformat(),
    )

    if not repos:
        return response

    semaphore = asyncio.Semaphore(max_concurrency)
    summaries: list[AlertsSummary] = []

    async def fetch_summary(repo_full: str):
        async with semaphore:
            try:
                async with GitHubSecurityAlertsClient(token) as client:
                    return await client.get_alerts_summary(repo_full)
            except AlertsNotEnabledError as e:
                response.errors.append({"repository": repo_full, "error": f"Not enabled: {e}"})
            except AlertsAccessDeniedError as e:
                response.errors.append({"repository": repo_full, "error": f"Access denied: {e}"})
            except AlertsRateLimitError as e:
                response.errors.append({"repository": repo_full, "error": f"Rate limited: {e}"})
            except Exception as e:
                response.errors.append({"repository": repo_full, "error": str(e)})
            return None

    tasks = [fetch_summary(repo_full) for repo_full in repos]
    results = await asyncio.gather(*tasks)

    for summary in results:
        if not summary:
            continue
        summaries.append(summary)
        response.summaries.append(_to_summary_response(summary))
        _merge_totals(response, summary)
        if summary.total_alerts > 0:
            response.repos_with_alerts += 1

    return response


@router.get("/repository/{owner}/{repo}/dependabot")
async def get_repository_dependabot_alerts(
    owner: str,
    repo: str,
    token: str = Query(..., description="GitHub token"),
    state: Optional[str] = Query(None, description="Filter by state"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    ecosystem: Optional[str] = Query(None, description="Filter by ecosystem"),
):
    """
    Get Dependabot alerts for a repository.
    
    Returns list of vulnerable dependencies detected by GitHub.
    """
    full_repo = f"{owner}/{repo}"
    
    try:
        async with GitHubSecurityAlertsClient(token) as client:
            alerts = await client.get_dependabot_alerts(
                full_repo,
                state=state,
                severity=severity,
                ecosystem=ecosystem,
            )
            
            return {
                "repository": full_repo,
                "total": len(alerts),
                "alerts": [
                    DependabotAlertResponse(
                        id=a.id,
                        number=a.number,
                        state=a.state.value,
                        severity=a.severity.value,
                        package_ecosystem=a.package_ecosystem,
                        package_name=a.package_name,
                        vulnerable_version_range=a.vulnerable_version_range,
                        first_patched_version=a.first_patched_version,
                        ghsa_id=a.ghsa_id,
                        cve_id=a.cve_id,
                        summary=a.summary,
                        repository=a.repository,
                        manifest_path=a.manifest_path,
                        cvss_score=a.cvss_score,
                        html_url=a.html_url,
                        created_at=a.created_at.isoformat(),
                    )
                    for a in alerts
                ]
            }
    
    except AlertsNotEnabledError:
        return {
            "repository": full_repo,
            "total": 0,
            "alerts": [],
            "message": "Dependabot alerts not enabled for this repository"
        }
    except AlertsAccessDeniedError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Error fetching Dependabot alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/repository/{owner}/{repo}/code-scanning")
async def get_repository_code_scanning_alerts(
    owner: str,
    repo: str,
    token: str = Query(..., description="GitHub token"),
    state: Optional[str] = Query(None, description="Filter by state"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    tool_name: Optional[str] = Query(None, description="Filter by tool"),
):
    """
    Get Code Scanning alerts for a repository.
    
    Returns SAST findings from CodeQL and other tools.
    """
    full_repo = f"{owner}/{repo}"
    
    try:
        async with GitHubSecurityAlertsClient(token) as client:
            alerts = await client.get_code_scanning_alerts(
                full_repo,
                state=state,
                severity=severity,
                tool_name=tool_name,
            )
            
            return {
                "repository": full_repo,
                "total": len(alerts),
                "alerts": [
                    CodeScanningAlertResponse(
                        id=a.id,
                        number=a.number,
                        state=a.state.value,
                        severity=a.severity.value,
                        rule_id=a.rule_id,
                        rule_name=a.rule_name,
                        rule_description=a.rule_description,
                        tool_name=a.tool_name,
                        repository=a.repository,
                        file_path=a.file_path,
                        start_line=a.start_line,
                        end_line=a.end_line,
                        html_url=a.html_url,
                        created_at=a.created_at.isoformat(),
                    )
                    for a in alerts
                ]
            }
    
    except AlertsNotEnabledError:
        return {
            "repository": full_repo,
            "total": 0,
            "alerts": [],
            "message": "Code Scanning not enabled for this repository"
        }
    except AlertsAccessDeniedError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Error fetching Code Scanning alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/repository/{owner}/{repo}/secret-scanning")
async def get_repository_secret_scanning_alerts(
    owner: str,
    repo: str,
    token: str = Query(..., description="GitHub token"),
    state: Optional[str] = Query(None, description="Filter by state"),
    secret_type: Optional[str] = Query(None, description="Filter by secret type"),
):
    """
    Get Secret Scanning alerts for a repository.
    
    Returns secrets detected by GitHub's secret scanning feature.
    """
    full_repo = f"{owner}/{repo}"
    
    try:
        async with GitHubSecurityAlertsClient(token) as client:
            alerts = await client.get_secret_scanning_alerts(
                full_repo,
                state=state,
                secret_type=secret_type,
            )
            
            return {
                "repository": full_repo,
                "total": len(alerts),
                "alerts": [
                    SecretScanningAlertResponse(
                        id=a.id,
                        number=a.number,
                        state=a.state.value,
                        severity=a.severity.value,
                        secret_type=a.secret_type,
                        secret_type_display_name=a.secret_type_display_name,
                        repository=a.repository,
                        html_url=a.html_url,
                        created_at=a.created_at.isoformat(),
                    )
                    for a in alerts
                ]
            }
    
    except AlertsNotEnabledError:
        return {
            "repository": full_repo,
            "total": 0,
            "alerts": [],
            "message": "Secret Scanning not enabled for this repository"
        }
    except AlertsAccessDeniedError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Error fetching Secret Scanning alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/repository/{owner}/{repo}/all")
async def get_repository_all_alerts(
    owner: str,
    repo: str,
    token: str = Query(..., description="GitHub token"),
    state: Optional[str] = Query(None, description="Filter by state"),
):
    """
    Get all security alerts for a repository (consolidated view).
    
    Returns Dependabot, Code Scanning, and Secret Scanning alerts together.
    """
    full_repo = f"{owner}/{repo}"
    
    try:
        async with GitHubSecurityAlertsClient(token) as client:
            all_alerts = await client.get_all_alerts(full_repo, state=state)
            
            # Convert to consolidated format
            consolidated = []
            
            # Dependabot
            for a in all_alerts.get("dependabot", []):
                consolidated.append(ConsolidatedAlertResponse(
                    id=a.id,
                    source="dependabot",
                    number=a.number,
                    state=a.state.value,
                    severity=a.severity.value,
                    title=f"{a.package_name} - {a.summary[:50]}..." if len(a.summary) > 50 else a.summary,
                    description=a.description[:200] if a.description else None,
                    repository=a.repository,
                    location=a.manifest_path,
                    line_number=None,
                    html_url=a.html_url,
                    created_at=a.created_at.isoformat(),
                ))
            
            # Code Scanning
            for a in all_alerts.get("code_scanning", []):
                consolidated.append(ConsolidatedAlertResponse(
                    id=a.id,
                    source="code_scanning",
                    number=a.number,
                    state=a.state.value,
                    severity=a.severity.value,
                    title=a.rule_name,
                    description=a.rule_description[:200] if a.rule_description else None,
                    repository=a.repository,
                    location=a.file_path,
                    line_number=a.start_line,
                    html_url=a.html_url,
                    created_at=a.created_at.isoformat(),
                ))
            
            # Secret Scanning
            for a in all_alerts.get("secret_scanning", []):
                consolidated.append(ConsolidatedAlertResponse(
                    id=a.id,
                    source="secret_scanning",
                    number=a.number,
                    state=a.state.value,
                    severity=a.severity.value,
                    title=a.secret_type_display_name,
                    description=f"Secret type: {a.secret_type}",
                    repository=a.repository,
                    location=None,
                    line_number=None,
                    html_url=a.html_url,
                    created_at=a.created_at.isoformat(),
                ))
            
            # Sort by severity then date
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            consolidated.sort(key=lambda x: (severity_order.get(x.severity, 4), x.created_at))
            
            return {
                "repository": full_repo,
                "total": len(consolidated),
                "by_source": {
                    "dependabot": len(all_alerts.get("dependabot", [])),
                    "code_scanning": len(all_alerts.get("code_scanning", [])),
                    "secret_scanning": len(all_alerts.get("secret_scanning", [])),
                },
                "alerts": consolidated,
            }
    
    except AlertsAccessDeniedError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Error fetching all alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard")
async def get_alerts_dashboard(
    token: str = Query(..., description="GitHub token"),
    organization: Optional[str] = Query(None, description="Organization to filter"),
):
    """
    Get dashboard data for security alerts.
    
    Returns aggregated statistics across all synced repositories.
    """
    # This would typically query the database
    # For now, return a placeholder structure
    return {
        "message": "Use /repository/{owner}/{repo}/summary for per-repo data",
        "hint": "Run a sync first to populate the database",
        "total_repositories": 0,
        "total_alerts": 0,
        "by_severity": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        },
        "by_source": {
            "dependabot": 0,
            "code_scanning": 0,
            "secret_scanning": 0,
        },
        "by_state": {
            "open": 0,
            "fixed": 0,
            "dismissed": 0,
        },
    }
