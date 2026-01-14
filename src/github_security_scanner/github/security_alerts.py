"""
GitHub Security Alerts Client.

This module provides a client for fetching security alerts from GitHub's API:
- Dependabot Alerts (vulnerable dependencies)
- Code Scanning Alerts (SAST findings from CodeQL)
- Secret Scanning Alerts (exposed secrets detected by GitHub)

All APIs work with member-level access tokens that have read access to the repository.

Rate Limiting:
- Primary: 5000 requests/hour for authenticated users
- Secondary: Varies by endpoint, handled automatically with retries

Error Handling:
- 404: Repository not found or no access
- 403: Feature not enabled for repository or rate limited
- 401: Invalid or expired token
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import AsyncGenerator, Optional
from uuid import uuid4

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class AlertState(str, Enum):
    """State of a security alert."""
    OPEN = "open"
    DISMISSED = "dismissed"
    FIXED = "fixed"
    AUTO_DISMISSED = "auto_dismissed"


class AlertSeverity(str, Enum):
    """Severity levels for alerts (GitHub's classification)."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    
    @classmethod
    def from_string(cls, value: str) -> "AlertSeverity":
        """Safely convert string to AlertSeverity."""
        try:
            return cls(value.lower())
        except ValueError:
            return cls.LOW


class DismissedReason(str, Enum):
    """Reasons for dismissing an alert."""
    FALSE_POSITIVE = "false_positive"
    WONT_FIX = "wont_fix"
    REVOKED = "revoked"
    USED_IN_TESTS = "used_in_tests"
    TOLERABLE_RISK = "tolerable_risk"
    NO_BANDWIDTH = "no_bandwidth"
    INACCURATE = "inaccurate"


class AlertSource(str, Enum):
    """Source of the alert."""
    DEPENDABOT = "dependabot"
    CODE_SCANNING = "code_scanning"
    SECRET_SCANNING = "secret_scanning"
    CUSTOM_SCAN = "custom_scan"  # Our own findings


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class DependabotAlert:
    """
    Represents a Dependabot security alert for a vulnerable dependency.
    
    Reference: https://docs.github.com/en/rest/dependabot/alerts
    """
    id: str
    number: int
    state: AlertState
    severity: AlertSeverity
    
    # Package information
    package_ecosystem: str  # npm, pip, maven, etc.
    package_name: str
    vulnerable_version_range: str
    first_patched_version: Optional[str]
    
    # Vulnerability details
    ghsa_id: str  # GitHub Security Advisory ID
    cve_id: Optional[str]
    summary: str
    description: str
    
    # Location
    repository: str
    manifest_path: str  # e.g., "package.json", "requirements.txt"
    
    # Metadata
    created_at: datetime
    updated_at: datetime
    fixed_at: Optional[datetime] = None
    dismissed_at: Optional[datetime] = None
    dismissed_by: Optional[str] = None
    dismissed_reason: Optional[DismissedReason] = None
    dismissed_comment: Optional[str] = None
    
    # URLs
    html_url: str = ""
    security_advisory_url: str = ""
    
    # CVSS
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    
    # CWE
    cwes: list[str] = field(default_factory=list)
    
    @property
    def source(self) -> AlertSource:
        return AlertSource.DEPENDABOT
    
    @property
    def fingerprint(self) -> str:
        """Unique identifier for deduplication."""
        return f"dependabot:{self.repository}:{self.package_name}:{self.ghsa_id}"


@dataclass
class CodeScanningAlert:
    """
    Represents a Code Scanning alert (typically from CodeQL).
    
    Reference: https://docs.github.com/en/rest/code-scanning
    """
    # Required fields (no defaults)
    id: str
    number: int
    state: AlertState
    severity: AlertSeverity
    rule_id: str
    rule_name: str
    rule_description: str
    tool_name: str  # e.g., "CodeQL"
    repository: str
    file_path: str
    start_line: int
    end_line: int
    
    # Optional fields (with defaults)
    rule_security_severity_level: Optional[str] = None
    rule_tags: list[str] = field(default_factory=list)
    tool_version: Optional[str] = None
    start_column: Optional[int] = None
    end_column: Optional[int] = None
    ref: str = ""  # Branch reference
    commit_sha: str = ""
    message: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    fixed_at: Optional[datetime] = None
    dismissed_at: Optional[datetime] = None
    dismissed_by: Optional[str] = None
    dismissed_reason: Optional[DismissedReason] = None
    dismissed_comment: Optional[str] = None
    html_url: str = ""
    
    @property
    def source(self) -> AlertSource:
        return AlertSource.CODE_SCANNING
    
    @property
    def fingerprint(self) -> str:
        """Unique identifier for deduplication."""
        return f"codescan:{self.repository}:{self.rule_id}:{self.file_path}:{self.start_line}"


@dataclass
class SecretScanningAlert:
    """
    Represents a Secret Scanning alert.
    
    Reference: https://docs.github.com/en/rest/secret-scanning
    """
    # Required fields (no defaults)
    id: str
    number: int
    state: AlertState
    secret_type: str  # e.g., "github_personal_access_token"
    secret_type_display_name: str
    repository: str
    
    # Optional fields (with defaults)
    secret: Optional[str] = None  # Masked or partial
    locations: list[dict] = field(default_factory=list)  # Can be in multiple places
    push_protection_bypassed: bool = False
    push_protection_bypassed_by: Optional[str] = None
    push_protection_bypassed_at: Optional[datetime] = None
    resolution: Optional[str] = None  # "false_positive", "wont_fix", "revoked", "used_in_tests"
    resolution_comment: Optional[str] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    html_url: str = ""
    
    @property
    def source(self) -> AlertSource:
        return AlertSource.SECRET_SCANNING
    
    @property
    def severity(self) -> AlertSeverity:
        """Secret scanning alerts are always critical/high."""
        if "token" in self.secret_type.lower() or "key" in self.secret_type.lower():
            return AlertSeverity.CRITICAL
        return AlertSeverity.HIGH
    
    @property
    def fingerprint(self) -> str:
        """Unique identifier for deduplication."""
        return f"secretscan:{self.repository}:{self.secret_type}:{self.number}"


@dataclass
class AlertsSummary:
    """Summary of all security alerts for a repository or organization."""
    repository: Optional[str] = None
    organization: Optional[str] = None
    
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
    @property
    def total_alerts(self) -> int:
        return self.dependabot_total + self.code_scanning_total + self.secret_scanning_total
    
    @property
    def total_critical(self) -> int:
        return self.dependabot_critical + self.code_scanning_critical
    
    @property
    def total_high(self) -> int:
        return self.dependabot_high + self.code_scanning_high
    
    @property
    def total_open(self) -> int:
        return self.dependabot_open + self.code_scanning_open + self.secret_scanning_open


# =============================================================================
# Exceptions
# =============================================================================

class AlertsAPIError(Exception):
    """Base exception for alerts API errors."""
    pass


class AlertsNotEnabledError(AlertsAPIError):
    """Raised when security feature is not enabled for repository."""
    pass


class AlertsAccessDeniedError(AlertsAPIError):
    """Raised when user doesn't have access to alerts."""
    pass


class AlertsRateLimitError(AlertsAPIError):
    """Raised when rate limit is exceeded."""
    def __init__(self, reset_at: datetime):
        self.reset_at = reset_at
        super().__init__(f"Rate limit exceeded. Resets at {reset_at}")


# =============================================================================
# GitHub Security Alerts Client
# =============================================================================

class GitHubSecurityAlertsClient:
    """
    Client for fetching security alerts from GitHub API.
    
    Usage:
        async with GitHubSecurityAlertsClient(token) as client:
            alerts = await client.get_dependabot_alerts("owner/repo")
    
    Thread Safety: Not thread-safe. Create one instance per async context.
    """
    
    BASE_URL = "https://api.github.com"
    
    # API endpoints
    DEPENDABOT_ALERTS_URL = "/repos/{owner}/{repo}/dependabot/alerts"
    CODE_SCANNING_ALERTS_URL = "/repos/{owner}/{repo}/code-scanning/alerts"
    SECRET_SCANNING_ALERTS_URL = "/repos/{owner}/{repo}/secret-scanning/alerts"
    
    # Pagination
    DEFAULT_PER_PAGE = 100
    MAX_PAGES = 100  # Safety limit
    
    def __init__(
        self,
        token: str,
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        """
        Initialize the client.
        
        Args:
            token: GitHub personal access token with repo access
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries for failed requests
        """
        if not token:
            raise ValueError("GitHub token is required")
        
        self._token = token
        self._timeout = timeout
        self._max_retries = max_retries
        self._client: Optional[httpx.AsyncClient] = None
        
        # Rate limiting tracking
        self._rate_limit_remaining: int = 5000
        self._rate_limit_reset: Optional[datetime] = None
    
    async def __aenter__(self) -> "GitHubSecurityAlertsClient":
        """Context manager entry."""
        self._client = httpx.AsyncClient(
            timeout=self._timeout,
            headers=self._get_headers(),
            follow_redirects=True,
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    def _get_headers(self) -> dict[str, str]:
        """Get headers for API requests."""
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "GitHubSecurityScanner/1.0",
        }
    
    def _update_rate_limits(self, response: httpx.Response) -> None:
        """Update rate limit tracking from response headers."""
        if "X-RateLimit-Remaining" in response.headers:
            self._rate_limit_remaining = int(response.headers["X-RateLimit-Remaining"])
        
        if "X-RateLimit-Reset" in response.headers:
            self._rate_limit_reset = datetime.fromtimestamp(
                int(response.headers["X-RateLimit-Reset"])
            )
        
        if self._rate_limit_remaining < 100:
            logger.warning(
                f"GitHub API rate limit low: {self._rate_limit_remaining} remaining. "
                f"Resets at {self._rate_limit_reset}"
            )
    
    def _parse_repo(self, repo: str) -> tuple[str, str]:
        """Parse 'owner/repo' format into (owner, repo)."""
        parts = repo.split("/")
        if len(parts) != 2:
            raise ValueError(f"Invalid repository format: {repo}. Expected 'owner/repo'")
        return parts[0], parts[1]
    
    @retry(
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.NetworkError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    async def _request(
        self,
        method: str,
        url: str,
        params: Optional[dict] = None,
    ) -> dict:
        """
        Make an authenticated request to GitHub API.
        
        Handles:
        - Rate limiting
        - Retries with exponential backoff
        - Error response parsing
        """
        if self._client is None:
            raise RuntimeError("Client not initialized. Use 'async with' context manager.")
        
        full_url = f"{self.BASE_URL}{url}"
        
        response = await self._client.request(method, full_url, params=params)
        self._update_rate_limits(response)
        
        # Handle errors
        if response.status_code == 404:
            error_data = response.json() if response.content else {}
            raise AlertsAccessDeniedError(
                f"Repository not found or no access: {error_data.get('message', 'Not found')}"
            )
        
        if response.status_code == 403:
            error_data = response.json() if response.content else {}
            message = error_data.get("message", "")
            
            # Check if it's rate limiting
            if "rate limit" in message.lower():
                raise AlertsRateLimitError(self._rate_limit_reset or datetime.now())
            
            # Check if feature is not enabled
            if "not enabled" in message.lower() or "disabled" in message.lower():
                raise AlertsNotEnabledError(f"Feature not enabled: {message}")
            
            raise AlertsAccessDeniedError(f"Access denied: {message}")
        
        if response.status_code == 401:
            raise AlertsAccessDeniedError("Invalid or expired token")
        
        response.raise_for_status()
        
        return response.json() if response.content else {}
    
    async def _paginate(
        self,
        url: str,
        params: Optional[dict] = None,
    ) -> AsyncGenerator[dict, None]:
        """
        Paginate through API results.
        
        Yields individual items from paginated responses.
        """
        params = params or {}
        params["per_page"] = self.DEFAULT_PER_PAGE
        page = 1
        
        while page <= self.MAX_PAGES:
            params["page"] = page
            
            try:
                results = await self._request("GET", url, params)
            except AlertsNotEnabledError:
                # Feature not enabled, return empty
                logger.debug(f"Feature not enabled for {url}")
                return
            except AlertsAccessDeniedError as e:
                logger.warning(f"Access denied for {url}: {e}")
                return
            
            if not results:
                break
            
            # Handle both list and dict responses
            items = results if isinstance(results, list) else results.get("alerts", [])
            
            if not items:
                break
            
            for item in items:
                yield item
            
            # Check if there are more pages
            if len(items) < self.DEFAULT_PER_PAGE:
                break
            
            page += 1
            
            # Small delay between pages to be nice to the API
            await asyncio.sleep(0.1)
    
    # =========================================================================
    # Dependabot Alerts
    # =========================================================================
    
    async def get_dependabot_alerts(
        self,
        repo: str,
        state: Optional[str] = None,
        severity: Optional[str] = None,
        ecosystem: Optional[str] = None,
    ) -> list[DependabotAlert]:
        """
        Fetch Dependabot alerts for a repository.
        
        Args:
            repo: Repository in "owner/repo" format
            state: Filter by state ("open", "dismissed", "fixed")
            severity: Filter by severity ("critical", "high", "medium", "low")
            ecosystem: Filter by ecosystem ("npm", "pip", etc.)
        
        Returns:
            List of DependabotAlert objects
        """
        owner, repo_name = self._parse_repo(repo)
        url = self.DEPENDABOT_ALERTS_URL.format(owner=owner, repo=repo_name)
        
        params = {}
        if state:
            params["state"] = state
        if severity:
            params["severity"] = severity
        if ecosystem:
            params["ecosystem"] = ecosystem
        
        alerts = []
        async for alert_data in self._paginate(url, params):
            try:
                alert = self._parse_dependabot_alert(alert_data, repo)
                alerts.append(alert)
            except Exception as e:
                logger.warning(f"Failed to parse Dependabot alert: {e}")
                continue
        
        logger.info(f"Fetched {len(alerts)} Dependabot alerts for {repo}")
        return alerts
    
    def _parse_dependabot_alert(self, data: dict, repo: str) -> DependabotAlert:
        """Parse raw API response into DependabotAlert."""
        security_advisory = data.get("security_advisory", {})
        security_vulnerability = data.get("security_vulnerability", {})
        dependency = data.get("dependency", {})
        package = dependency.get("package", {})
        
        # Parse CVSS
        cvss = security_advisory.get("cvss", {})
        
        # Parse CWEs
        cwes = [cwe.get("cwe_id", "") for cwe in security_advisory.get("cwes", [])]
        
        return DependabotAlert(
            id=str(uuid4()),
            number=data.get("number", 0),
            state=AlertState(data.get("state", "open")),
            severity=AlertSeverity.from_string(
                security_vulnerability.get("severity", "low")
            ),
            package_ecosystem=package.get("ecosystem", "unknown"),
            package_name=package.get("name", "unknown"),
            vulnerable_version_range=security_vulnerability.get(
                "vulnerable_version_range", ""
            ),
            first_patched_version=security_vulnerability.get(
                "first_patched_version", {}
            ).get("identifier"),
            ghsa_id=security_advisory.get("ghsa_id", ""),
            cve_id=security_advisory.get("cve_id"),
            summary=security_advisory.get("summary", ""),
            description=security_advisory.get("description", ""),
            repository=repo,
            manifest_path=dependency.get("manifest_path", ""),
            created_at=self._parse_datetime(data.get("created_at")),
            updated_at=self._parse_datetime(data.get("updated_at")),
            fixed_at=self._parse_datetime(data.get("fixed_at")),
            dismissed_at=self._parse_datetime(data.get("dismissed_at")),
            dismissed_by=data.get("dismissed_by", {}).get("login") if data.get("dismissed_by") else None,
            dismissed_reason=DismissedReason(data["dismissed_reason"]) if data.get("dismissed_reason") else None,
            dismissed_comment=data.get("dismissed_comment"),
            html_url=data.get("html_url", ""),
            security_advisory_url=security_advisory.get("html_url", ""),
            cvss_score=cvss.get("score"),
            cvss_vector=cvss.get("vector_string"),
            cwes=cwes,
        )
    
    # =========================================================================
    # Code Scanning Alerts
    # =========================================================================
    
    async def get_code_scanning_alerts(
        self,
        repo: str,
        state: Optional[str] = None,
        severity: Optional[str] = None,
        tool_name: Optional[str] = None,
        ref: Optional[str] = None,
    ) -> list[CodeScanningAlert]:
        """
        Fetch Code Scanning alerts for a repository.
        
        Args:
            repo: Repository in "owner/repo" format
            state: Filter by state ("open", "dismissed", "fixed")
            severity: Filter by severity
            tool_name: Filter by tool (e.g., "CodeQL")
            ref: Git reference to filter (e.g., "refs/heads/main")
        
        Returns:
            List of CodeScanningAlert objects
        """
        owner, repo_name = self._parse_repo(repo)
        url = self.CODE_SCANNING_ALERTS_URL.format(owner=owner, repo=repo_name)
        
        params = {}
        if state:
            params["state"] = state
        if severity:
            params["severity"] = severity
        if tool_name:
            params["tool_name"] = tool_name
        if ref:
            params["ref"] = ref
        
        alerts = []
        async for alert_data in self._paginate(url, params):
            try:
                alert = self._parse_code_scanning_alert(alert_data, repo)
                alerts.append(alert)
            except Exception as e:
                logger.warning(f"Failed to parse Code Scanning alert: {e}")
                continue
        
        logger.info(f"Fetched {len(alerts)} Code Scanning alerts for {repo}")
        return alerts
    
    def _parse_code_scanning_alert(self, data: dict, repo: str) -> CodeScanningAlert:
        """Parse raw API response into CodeScanningAlert."""
        rule = data.get("rule", {})
        tool = data.get("tool", {})
        most_recent = data.get("most_recent_instance", {})
        location = most_recent.get("location", {})
        
        return CodeScanningAlert(
            id=str(uuid4()),
            number=data.get("number", 0),
            state=AlertState(data.get("state", "open")),
            severity=AlertSeverity.from_string(
                rule.get("security_severity_level") or rule.get("severity") or "low"
            ),
            rule_id=rule.get("id", ""),
            rule_name=rule.get("name", ""),
            rule_description=rule.get("description", ""),
            rule_security_severity_level=rule.get("security_severity_level"),
            rule_tags=rule.get("tags", []),
            tool_name=tool.get("name", "unknown"),
            tool_version=tool.get("version"),
            repository=repo,
            file_path=location.get("path", ""),
            start_line=location.get("start_line", 0),
            end_line=location.get("end_line", 0),
            start_column=location.get("start_column"),
            end_column=location.get("end_column"),
            ref=most_recent.get("ref", ""),
            commit_sha=most_recent.get("commit_sha", ""),
            message=most_recent.get("message", {}).get("text", ""),
            created_at=self._parse_datetime(data.get("created_at")),
            updated_at=self._parse_datetime(data.get("updated_at")),
            fixed_at=self._parse_datetime(data.get("fixed_at")),
            dismissed_at=self._parse_datetime(data.get("dismissed_at")),
            dismissed_by=data.get("dismissed_by", {}).get("login") if data.get("dismissed_by") else None,
            dismissed_reason=DismissedReason(data["dismissed_reason"]) if data.get("dismissed_reason") else None,
            dismissed_comment=data.get("dismissed_comment"),
            html_url=data.get("html_url", ""),
        )
    
    # =========================================================================
    # Secret Scanning Alerts
    # =========================================================================
    
    async def get_secret_scanning_alerts(
        self,
        repo: str,
        state: Optional[str] = None,
        secret_type: Optional[str] = None,
        resolution: Optional[str] = None,
    ) -> list[SecretScanningAlert]:
        """
        Fetch Secret Scanning alerts for a repository.
        
        Args:
            repo: Repository in "owner/repo" format
            state: Filter by state ("open", "resolved")
            secret_type: Filter by secret type
            resolution: Filter by resolution
        
        Returns:
            List of SecretScanningAlert objects
        """
        owner, repo_name = self._parse_repo(repo)
        url = self.SECRET_SCANNING_ALERTS_URL.format(owner=owner, repo=repo_name)
        
        params = {}
        if state:
            params["state"] = state
        if secret_type:
            params["secret_type"] = secret_type
        if resolution:
            params["resolution"] = resolution
        
        alerts = []
        async for alert_data in self._paginate(url, params):
            try:
                alert = self._parse_secret_scanning_alert(alert_data, repo)
                alerts.append(alert)
            except Exception as e:
                logger.warning(f"Failed to parse Secret Scanning alert: {e}")
                continue
        
        logger.info(f"Fetched {len(alerts)} Secret Scanning alerts for {repo}")
        return alerts
    
    def _parse_secret_scanning_alert(self, data: dict, repo: str) -> SecretScanningAlert:
        """Parse raw API response into SecretScanningAlert."""
        return SecretScanningAlert(
            id=str(uuid4()),
            number=data.get("number", 0),
            state=AlertState.OPEN if data.get("state") == "open" else AlertState.FIXED,
            secret_type=data.get("secret_type", "unknown"),
            secret_type_display_name=data.get("secret_type_display_name", ""),
            secret=data.get("secret"),  # May be masked
            repository=repo,
            locations=data.get("locations", []),
            push_protection_bypassed=data.get("push_protection_bypassed", False),
            push_protection_bypassed_by=data.get("push_protection_bypassed_by", {}).get("login") if data.get("push_protection_bypassed_by") else None,
            push_protection_bypassed_at=self._parse_datetime(data.get("push_protection_bypassed_at")),
            resolution=data.get("resolution"),
            resolution_comment=data.get("resolution_comment"),
            resolved_by=data.get("resolved_by", {}).get("login") if data.get("resolved_by") else None,
            resolved_at=self._parse_datetime(data.get("resolved_at")),
            created_at=self._parse_datetime(data.get("created_at")),
            updated_at=self._parse_datetime(data.get("updated_at")),
            html_url=data.get("html_url", ""),
        )
    
    # =========================================================================
    # Aggregation Methods
    # =========================================================================
    
    async def get_all_alerts(
        self,
        repo: str,
        state: Optional[str] = None,
    ) -> dict[str, list]:
        """
        Fetch all types of security alerts for a repository.
        
        Args:
            repo: Repository in "owner/repo" format
            state: Filter by state
        
        Returns:
            Dict with keys: dependabot, code_scanning, secret_scanning
        """
        # Fetch all types concurrently
        dependabot_task = asyncio.create_task(
            self.get_dependabot_alerts(repo, state=state)
        )
        code_scanning_task = asyncio.create_task(
            self.get_code_scanning_alerts(repo, state=state)
        )
        secret_scanning_task = asyncio.create_task(
            self.get_secret_scanning_alerts(repo, state=state)
        )
        
        # Wait for all
        dependabot_alerts = await dependabot_task
        code_scanning_alerts = await code_scanning_task
        secret_scanning_alerts = await secret_scanning_task
        
        return {
            "dependabot": dependabot_alerts,
            "code_scanning": code_scanning_alerts,
            "secret_scanning": secret_scanning_alerts,
        }
    
    async def get_alerts_summary(self, repo: str) -> AlertsSummary:
        """
        Get a summary of all alerts for a repository.
        
        Args:
            repo: Repository in "owner/repo" format
        
        Returns:
            AlertsSummary with counts by type and severity
        """
        all_alerts = await self.get_all_alerts(repo)
        
        summary = AlertsSummary(repository=repo)
        
        # Dependabot
        for alert in all_alerts["dependabot"]:
            summary.dependabot_total += 1
            if alert.severity == AlertSeverity.CRITICAL:
                summary.dependabot_critical += 1
            elif alert.severity == AlertSeverity.HIGH:
                summary.dependabot_high += 1
            elif alert.severity == AlertSeverity.MEDIUM:
                summary.dependabot_medium += 1
            else:
                summary.dependabot_low += 1
            
            if alert.state == AlertState.OPEN:
                summary.dependabot_open += 1
            elif alert.state == AlertState.FIXED:
                summary.dependabot_fixed += 1
            elif alert.state == AlertState.DISMISSED:
                summary.dependabot_dismissed += 1
        
        # Code Scanning
        for alert in all_alerts["code_scanning"]:
            summary.code_scanning_total += 1
            if alert.severity == AlertSeverity.CRITICAL:
                summary.code_scanning_critical += 1
            elif alert.severity == AlertSeverity.HIGH:
                summary.code_scanning_high += 1
            elif alert.severity == AlertSeverity.MEDIUM:
                summary.code_scanning_medium += 1
            else:
                summary.code_scanning_low += 1
            
            if alert.state == AlertState.OPEN:
                summary.code_scanning_open += 1
            elif alert.state == AlertState.FIXED:
                summary.code_scanning_fixed += 1
            elif alert.state == AlertState.DISMISSED:
                summary.code_scanning_dismissed += 1
        
        # Secret Scanning
        for alert in all_alerts["secret_scanning"]:
            summary.secret_scanning_total += 1
            if alert.state == AlertState.OPEN:
                summary.secret_scanning_open += 1
            else:
                summary.secret_scanning_resolved += 1
        
        return summary
    
    async def get_organization_alerts_summary(
        self,
        org: str,
        repos: list[str],
        max_concurrent: int = 5,
    ) -> AlertsSummary:
        """
        Get aggregated alerts summary for multiple repositories.
        
        Args:
            org: Organization name
            repos: List of repository names (without org prefix)
            max_concurrent: Maximum concurrent API calls
        
        Returns:
            Aggregated AlertsSummary
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def fetch_with_limit(repo: str) -> AlertsSummary:
            async with semaphore:
                try:
                    return await self.get_alerts_summary(f"{org}/{repo}")
                except Exception as e:
                    logger.warning(f"Failed to fetch alerts for {org}/{repo}: {e}")
                    return AlertsSummary(repository=f"{org}/{repo}")
        
        tasks = [fetch_with_limit(repo) for repo in repos]
        summaries = await asyncio.gather(*tasks)
        
        # Aggregate
        total = AlertsSummary(organization=org)
        for s in summaries:
            total.dependabot_total += s.dependabot_total
            total.dependabot_critical += s.dependabot_critical
            total.dependabot_high += s.dependabot_high
            total.dependabot_medium += s.dependabot_medium
            total.dependabot_low += s.dependabot_low
            total.dependabot_open += s.dependabot_open
            total.dependabot_fixed += s.dependabot_fixed
            total.dependabot_dismissed += s.dependabot_dismissed
            
            total.code_scanning_total += s.code_scanning_total
            total.code_scanning_critical += s.code_scanning_critical
            total.code_scanning_high += s.code_scanning_high
            total.code_scanning_medium += s.code_scanning_medium
            total.code_scanning_low += s.code_scanning_low
            total.code_scanning_open += s.code_scanning_open
            total.code_scanning_fixed += s.code_scanning_fixed
            total.code_scanning_dismissed += s.code_scanning_dismissed
            
            total.secret_scanning_total += s.secret_scanning_total
            total.secret_scanning_open += s.secret_scanning_open
            total.secret_scanning_resolved += s.secret_scanning_resolved
        
        return total
    
    # =========================================================================
    # Utilities
    # =========================================================================
    
    @staticmethod
    def _parse_datetime(value: Optional[str]) -> datetime:
        """Parse ISO datetime string to datetime object."""
        if not value:
            return datetime.now()
        try:
            # Handle GitHub's ISO format
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return datetime.now()
