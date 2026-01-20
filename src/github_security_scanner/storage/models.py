"""
Database models for persistent storage.

Defines the schema for storing scan results, findings,
and remediation tracking.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import uuid4


class RemediationStatus(str, Enum):
    """Status of finding remediation.
    
    PostgreSQL enum values: open, in_progress, resolved, false_positive, accepted_risk
    """
    
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"  # Maps to "resolved" in PostgreSQL
    RESOLVED = "resolved"  # PostgreSQL native value
    WONT_FIX = "wont_fix"  # Maps to "accepted_risk" in PostgreSQL
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


@dataclass
class ScanRecord:
    """Record of a security scan."""
    
    id: str = field(default_factory=lambda: str(uuid4()))
    organization: str = ""
    scan_date: datetime = field(default_factory=datetime.now)
    duration_seconds: float = 0.0
    repositories_scanned: int = 0
    repositories_failed: int = 0
    total_findings: int = 0
    
    # Severity counts
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    # Type counts
    secrets_count: int = 0
    vulnerabilities_count: int = 0
    bugs_count: int = 0
    misconfigs_count: int = 0
    
    # State counts
    active_count: int = 0
    historical_count: int = 0
    hardcoded_count: int = 0
    
    # Metadata
    tool_version: str = "1.0.0"
    config_hash: str = ""
    notes: str = ""
    
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "organization": self.organization,
            "scan_date": self.scan_date.isoformat(),
            "duration_seconds": self.duration_seconds,
            "repositories_scanned": self.repositories_scanned,
            "repositories_failed": self.repositories_failed,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "secrets_count": self.secrets_count,
            "vulnerabilities_count": self.vulnerabilities_count,
            "bugs_count": self.bugs_count,
            "misconfigs_count": self.misconfigs_count,
            "active_count": self.active_count,
            "historical_count": self.historical_count,
            "hardcoded_count": self.hardcoded_count,
        }


@dataclass
class FindingRecord:
    """Record of a security finding with tracking info."""
    
    id: str = field(default_factory=lambda: str(uuid4()))
    scan_id: str = ""
    
    # Finding details
    repository: str = ""
    finding_type: str = ""
    category: str = ""
    severity: str = ""
    states: str = ""  # Comma-separated states
    
    file_path: str = ""
    line_number: int = 0
    line_content: str = ""
    
    rule_id: str = ""
    rule_description: str = ""
    remediation: str = ""
    
    # Git context
    branch: str = ""
    commit_sha: str = ""
    commit_date: Optional[datetime] = None
    commit_author: str = ""
    
    # Tracking
    fingerprint: str = ""  # Unique identifier for deduplication
    first_seen_scan_id: str = ""
    first_seen_date: datetime = field(default_factory=datetime.now)
    last_seen_scan_id: str = ""
    last_seen_date: datetime = field(default_factory=datetime.now)
    
    # Remediation status
    status: RemediationStatus = RemediationStatus.OPEN
    assigned_to: str = ""
    due_date: Optional[datetime] = None
    resolved_date: Optional[datetime] = None
    resolved_in_scan_id: str = ""
    
    # Metadata
    confidence: float = 0.0
    cwe_id: str = ""
    cvss_score: Optional[float] = None
    tags: str = ""  # Comma-separated tags
    notes: str = ""
    
    # AI triage (optional)
    ai_label: str = ""
    ai_confidence: float = 0.0
    ai_reasons: list[str] = field(default_factory=list)
    ai_source: str = ""
    ai_updated_at: Optional[datetime] = None
    
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def generate_fingerprint(self) -> str:
        """Generate a unique fingerprint for this finding."""
        import hashlib
        content = f"{self.repository}:{self.finding_type}:{self.category}:{self.file_path}:{self.line_content[:100]}"
        return hashlib.sha256(content.encode()).hexdigest()[:32]
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "repository": self.repository,
            "finding_type": self.finding_type,
            "category": self.category,
            "severity": self.severity,
            "states": self.states,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "rule_id": self.rule_id,
            "status": self.status.value,
            "first_seen_date": self.first_seen_date.isoformat(),
            "last_seen_date": self.last_seen_date.isoformat(),
            "ai_triage": (
                {
                    "label": self.ai_label,
                    "confidence": self.ai_confidence,
                    "reasons": self.ai_reasons,
                    "source": self.ai_source,
                }
                if self.ai_label
                else None
            ),
        }


@dataclass
class RemediationRecord:
    """Record of remediation activity."""
    
    id: str = field(default_factory=lambda: str(uuid4()))
    finding_id: str = ""
    
    # Status change
    old_status: RemediationStatus = RemediationStatus.OPEN
    new_status: RemediationStatus = RemediationStatus.OPEN
    
    # Activity details
    action: str = ""  # e.g., "status_changed", "assigned", "comment_added"
    performed_by: str = ""
    comment: str = ""
    
    # Verification
    verified_in_scan_id: str = ""
    verification_result: str = ""  # "still_present", "fixed", "new_location"
    
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "old_status": self.old_status.value,
            "new_status": self.new_status.value,
            "action": self.action,
            "performed_by": self.performed_by,
            "comment": self.comment,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class RepositoryRecord:
    """Record of a scanned repository."""
    
    id: str = field(default_factory=lambda: str(uuid4()))
    organization: str = ""
    name: str = ""
    full_name: str = ""
    url: str = ""
    default_branch: str = "main"
    visibility: str = "private"
    
    # Scan stats
    last_scan_id: str = ""
    last_scan_date: Optional[datetime] = None
    total_scans: int = 0
    
    # Finding stats
    current_findings: int = 0
    open_findings: int = 0
    fixed_findings: int = 0
    
    # Risk score (0-100)
    risk_score: float = 0.0
    
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class TrendData:
    """Trend data for analytics."""
    
    date: datetime
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    open_count: int = 0
    fixed_count: int = 0

