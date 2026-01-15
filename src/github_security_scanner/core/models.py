"""
Data models for the GitHub Security Scanner.

This module defines all the dataclasses, enums and types used throughout
the scanner for representing findings, repositories and scan results.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import uuid4


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Convert CVSS score to severity level."""
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0:
            return cls.LOW
        return cls.INFO


class FindingType(str, Enum):
    """Types of security findings."""

    SECRET = "secret"
    VULNERABILITY = "vulnerability"
    SAST = "sast"
    IAC = "iac"
    HISTORY = "history"
    BUG = "bug"
    MISCONFIG = "misconfig"


class FindingState(str, Enum):
    """
    State classification for findings.

    - ACTIVE: Present in current HEAD, immediate risk
    - HISTORICAL: Was present but removed, still in git history
    - HARDCODED: Literal value written directly in code
    """

    ACTIVE = "active"
    HISTORICAL = "historical"
    HARDCODED = "hardcoded"


class FalsePositiveLikelihood(str, Enum):
    """Likelihood that a finding is a false positive."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ScanStatus(str, Enum):
    """Status of repository scan."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class StateDetails:
    """
    Detailed information about the finding state.

    Contains specific details depending on whether the finding is
    ACTIVE, HISTORICAL, or HARDCODED.
    """

    # For ACTIVE findings
    is_in_default_branch: bool = False

    # For HISTORICAL findings
    removed_in_commit: Optional[str] = None
    removed_date: Optional[datetime] = None
    exposure_duration_days: int = 0
    still_in_git_history: bool = True

    # For HARDCODED findings
    is_literal_value: bool = False
    is_in_config_file: bool = False
    has_env_var_alternative: bool = False

    # Common fields
    first_introduced: Optional[datetime] = None
    introduced_by: Optional[str] = None
    last_seen: Optional[datetime] = None


@dataclass
class Finding:
    """
    Represents a security finding detected by the scanner.

    A finding can have multiple states (e.g., ACTIVE and HARDCODED simultaneously).
    """

    # Identification
    id: str = field(default_factory=lambda: str(uuid4()))
    repository: str = ""
    type: FindingType = FindingType.SECRET
    category: str = ""
    severity: Severity = Severity.MEDIUM

    # Classification of State
    states: list[FindingState] = field(default_factory=list)
    state_details: StateDetails = field(default_factory=StateDetails)

    # Location
    file_path: str = ""
    line_number: int = 0
    line_content: str = ""
    column_start: Optional[int] = None
    column_end: Optional[int] = None

    # Git Context
    branch: str = ""
    commit_sha: str = ""
    commit_date: Optional[datetime] = None
    commit_author: str = ""

    # Metadata
    confidence: float = 0.0
    false_positive_likelihood: FalsePositiveLikelihood = FalsePositiveLikelihood.LOW
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    rule_id: str = ""
    rule_description: str = ""

    # SARIF compatibility
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None

    # Additional context
    matched_pattern: str = ""
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def is_active(self) -> bool:
        """Check if finding is currently active."""
        return FindingState.ACTIVE in self.states

    def is_historical(self) -> bool:
        """Check if finding is historical."""
        return FindingState.HISTORICAL in self.states

    def is_hardcoded(self) -> bool:
        """Check if finding is hardcoded."""
        return FindingState.HARDCODED in self.states

    def sanitized_content(self, redact_pattern: str = "[REDACTED]") -> str:
        """Return line content with sensitive data redacted."""
        if not self.line_content or not self.matched_pattern:
            return self.line_content

        # Simple redaction - replace the matched pattern
        import re

        try:
            return re.sub(self.matched_pattern, redact_pattern, self.line_content)
        except re.error:
            # If pattern is invalid, do simple truncation
            if len(self.line_content) > 50:
                return self.line_content[:25] + redact_pattern + self.line_content[-10:]
            return self.line_content

    def to_dict(self) -> dict:
        """Convert finding to dictionary for serialization."""
        return {
            "id": self.id,
            "repository": self.repository,
            "type": self.type.value,
            "category": self.category,
            "severity": self.severity.value,
            "states": [s.value for s in self.states],
            "state_details": {
                "is_in_default_branch": self.state_details.is_in_default_branch,
                "is_literal_value": self.state_details.is_literal_value,
                "is_in_config_file": self.state_details.is_in_config_file,
                "has_env_var_alternative": self.state_details.has_env_var_alternative,
                "first_introduced": (
                    self.state_details.first_introduced.isoformat()
                    if self.state_details.first_introduced
                    else None
                ),
                "introduced_by": self.state_details.introduced_by,
                "removed_in_commit": self.state_details.removed_in_commit,
                "removed_date": (
                    self.state_details.removed_date.isoformat()
                    if self.state_details.removed_date
                    else None
                ),
                "exposure_duration_days": self.state_details.exposure_duration_days,
                "still_in_git_history": self.state_details.still_in_git_history,
            },
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.sanitized_content(),
            "branch": self.branch,
            "commit_sha": self.commit_sha,
            "commit_date": self.commit_date.isoformat() if self.commit_date else None,
            "commit_author": self.commit_author,
            "confidence": self.confidence,
            "false_positive_likelihood": self.false_positive_likelihood.value,
            "remediation": self.remediation,
            "references": self.references,
            "rule_id": self.rule_id,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
        }


@dataclass
class Repository:
    """Represents a GitHub repository being scanned."""

    name: str
    full_name: str
    url: str
    clone_url: str
    default_branch: str = "main"
    languages: list[str] = field(default_factory=list)
    visibility: str = "private"
    size_kb: int = 0
    last_commit: Optional[datetime] = None
    archived: bool = False
    fork: bool = False

    # Scan-related fields
    local_path: Optional[str] = None
    scan_status: ScanStatus = ScanStatus.PENDING
    scan_error: Optional[str] = None
    findings_count: int = 0

    def to_dict(self) -> dict:
        """Convert repository to dictionary for serialization."""
        return {
            "name": self.name,
            "full_name": self.full_name,
            "url": self.url,
            "default_branch": self.default_branch,
            "languages": self.languages,
            "visibility": self.visibility,
            "last_commit": self.last_commit.isoformat() if self.last_commit else None,
            "scan_status": self.scan_status.value,
            "findings_count": self.findings_count,
        }


@dataclass
class ScanMetadata:
    """Metadata about a security scan."""

    scan_id: str = field(default_factory=lambda: str(uuid4()))
    organization: str = ""
    scan_date: datetime = field(default_factory=datetime.now)
    scan_duration_seconds: float = 0.0
    tool_version: str = "1.0.0"
    repositories_scanned: int = 0
    repositories_failed: int = 0
    total_findings: int = 0

    # Configuration used
    include_historical: bool = False
    languages_filter: list[str] = field(default_factory=list)
    exclude_repos: list[str] = field(default_factory=list)
    severity_threshold: Optional[Severity] = None

    def to_dict(self) -> dict:
        """Convert metadata to dictionary for serialization."""
        return {
            "scan_id": self.scan_id,
            "organization": self.organization,
            "scan_date": self.scan_date.isoformat(),
            "scan_duration_seconds": self.scan_duration_seconds,
            "tool_version": self.tool_version,
            "repositories_scanned": self.repositories_scanned,
            "repositories_failed": self.repositories_failed,
            "total_findings": self.total_findings,
        }


@dataclass
class ScanSummary:
    """Summary statistics for a scan."""

    by_severity: dict[str, int] = field(default_factory=dict)
    by_type: dict[str, int] = field(default_factory=dict)
    by_state: dict[str, int] = field(default_factory=dict)
    top_affected_repos: list[dict[str, int | str]] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert summary to dictionary for serialization."""
        return {
            "by_severity": self.by_severity,
            "by_type": self.by_type,
            "by_state": self.by_state,
            "top_affected_repos": self.top_affected_repos,
        }


@dataclass
class ScanResult:
    """Complete result of a security scan."""

    metadata: ScanMetadata = field(default_factory=ScanMetadata)
    summary: ScanSummary = field(default_factory=ScanSummary)
    findings: list[Finding] = field(default_factory=list)
    repositories: dict[str, Repository] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        """Add a finding and update summary statistics."""
        self.findings.append(finding)
        self.metadata.total_findings += 1

        # Update severity counts
        sev = finding.severity.value
        self.summary.by_severity[sev] = self.summary.by_severity.get(sev, 0) + 1

        # Update type counts
        ftype = finding.type.value
        self.summary.by_type[ftype] = self.summary.by_type.get(ftype, 0) + 1

        # Update state counts
        for state in finding.states:
            state_val = state.value
            self.summary.by_state[state_val] = self.summary.by_state.get(state_val, 0) + 1

        # Update repository findings count
        if finding.repository in self.repositories:
            self.repositories[finding.repository].findings_count += 1
        else:
            # Handle full_name vs name mismatches
            short_name = finding.repository.split("/")[-1] if "/" in finding.repository else None
            if short_name and short_name in self.repositories:
                self.repositories[short_name].findings_count += 1

    def calculate_top_repos(self, limit: int = 10) -> None:
        """Calculate top affected repositories."""
        repo_findings = [
            {"repo": name, "findings": repo.findings_count}
            for name, repo in self.repositories.items()
            if repo.findings_count > 0
        ]
        repo_findings.sort(key=lambda x: x["findings"], reverse=True)
        self.summary.top_affected_repos = repo_findings[:limit]

    def filter_by_severity(self, min_severity: Severity) -> list[Finding]:
        """Filter findings by minimum severity."""
        severity_order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        min_level = severity_order[min_severity]
        return [f for f in self.findings if severity_order[f.severity] >= min_level]

    def to_dict(self) -> dict:
        """Convert scan result to dictionary for serialization."""
        return {
            "scan_metadata": self.metadata.to_dict(),
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "repositories": {name: repo.to_dict() for name, repo in self.repositories.items()},
        }

