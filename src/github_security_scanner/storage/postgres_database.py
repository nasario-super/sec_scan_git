"""
PostgreSQL database adapter for persistent storage.

Uses SQLAlchemy for database operations, compatible with PostgreSQL
and AWS Aurora Serverless v2.
"""

import os
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Iterator, Optional
from uuid import uuid4

from sqlalchemy import (
    create_engine,
    text,
    Column,
    String,
    Integer,
    DateTime,
    Text,
    Boolean,
    JSON,
    ForeignKey,
    func,
    case,
    TypeDecorator,
    Enum,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, ARRAY
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship

from ..core.models import Finding, ScanResult
from .models import (
    FindingRecord,
    RemediationRecord,
    RemediationStatus,
    RepositoryRecord,
    ScanRecord,
    TrendData,
)

Base = declarative_base()


# PostgreSQL ENUM types - must match init-db.sql
FindingTypeEnum = Enum('secret', 'vulnerability', 'sast', 'iac', 'history', name='finding_type', create_type=False)
SeverityLevelEnum = Enum('critical', 'high', 'medium', 'low', 'info', name='severity_level', create_type=False)
RemediationStatusEnum = Enum('open', 'in_progress', 'resolved', 'false_positive', 'accepted_risk', name='remediation_status', create_type=False)
ScanStatusEnum = Enum('pending', 'running', 'completed', 'failed', 'cancelled', name='scan_status', create_type=False)


# UUID Type that converts to/from string
class UUIDString(TypeDecorator):
    impl = PG_UUID
    cache_ok = True
    
    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if isinstance(value, str):
            return value
        return str(value)
    
    def process_result_value(self, value, dialect):
        if value is None:
            return value
        return str(value)


# SQLAlchemy Models
class OrganizationModel(Base):
    __tablename__ = "organizations"
    
    id = Column(UUIDString, primary_key=True)
    name = Column(String, nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), default=func.now())


class ScanModel(Base):
    __tablename__ = "scans"
    
    id = Column(UUIDString, primary_key=True)
    organization_id = Column(UUIDString, ForeignKey("organizations.id"), nullable=True)
    repository_id = Column(UUIDString, ForeignKey("repositories.id"), nullable=True)
    status = Column(ScanStatusEnum, default="pending")
    scan_type = Column(String, default="full")
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    duration_seconds = Column(Integer, default=0)
    repositories_scanned = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    error_message = Column(Text)
    created_at = Column(DateTime(timezone=True), default=func.now())
    scan_metadata = Column("metadata", JSON, default={})  # Use scan_metadata as attribute name, but map to "metadata" column
    
    # Relationships
    organization = relationship("OrganizationModel", foreign_keys=[organization_id])


class FindingModel(Base):
    __tablename__ = "findings"
    
    id = Column(UUIDString, primary_key=True)
    scan_id = Column(UUIDString, ForeignKey("scans.id"), nullable=True)
    repository_id = Column(UUIDString, ForeignKey("repositories.id"), nullable=True)
    finding_type = Column(FindingTypeEnum, nullable=False)
    category = Column(String, nullable=False)
    severity = Column(SeverityLevelEnum, nullable=False)
    status = Column(RemediationStatusEnum, default="open")
    file_path = Column(Text, nullable=False)
    line_number = Column(Integer)
    line_content = Column(Text)
    branch = Column(String)
    commit_sha = Column(String)
    commit_author = Column(String)
    commit_date = Column(DateTime(timezone=True))
    rule_id = Column(String, nullable=False)
    rule_description = Column(Text)
    matched_pattern = Column(Text)
    states = Column(ARRAY(Text))  # PostgreSQL text[] array
    false_positive_likelihood = Column(String)
    remediation_notes = Column(Text)
    remediation_deadline = Column(DateTime(timezone=True))
    assigned_to = Column(String)
    first_seen_at = Column(DateTime(timezone=True), default=func.now())
    last_seen_at = Column(DateTime(timezone=True), default=func.now())
    resolved_at = Column(DateTime(timezone=True))
    resolved_by = Column(String)
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    fingerprint = Column(String, nullable=False)
    
    # Relationships
    repository = relationship("RepositoryModel", foreign_keys=[repository_id])


class RepositoryModel(Base):
    __tablename__ = "repositories"
    
    id = Column(UUIDString, primary_key=True)
    organization_id = Column(UUIDString, ForeignKey("organizations.id"), nullable=True)
    name = Column(String, nullable=False)
    full_name = Column(String, unique=True, nullable=False)
    github_id = Column(Integer)
    description = Column(Text)
    url = Column(Text)
    default_branch = Column(String, default="main")
    language = Column(String)
    is_private = Column(Boolean, default=True)
    is_archived = Column(Boolean, default=False)
    is_fork = Column(Boolean, default=False)
    stars_count = Column(Integer, default=0)
    last_pushed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    repo_metadata = Column("metadata", JSON, default={})  # Use repo_metadata to avoid reserved name
    
    # Relationships
    organization = relationship("OrganizationModel", foreign_keys=[organization_id])


class FindingHistoryModel(Base):
    __tablename__ = "finding_history"
    
    id = Column(UUIDString, primary_key=True)
    finding_id = Column(UUIDString, ForeignKey("findings.id"))
    action = Column(String, nullable=False)
    previous_value = Column(JSON)
    new_value = Column(JSON)
    performed_by = Column(String)
    comment = Column(Text)
    created_at = Column(DateTime(timezone=True), default=func.now())


class UserModel(Base):
    __tablename__ = "users"
    
    id = Column(UUIDString, primary_key=True)
    username = Column(String(255), nullable=False, unique=True)
    email = Column(String(255), unique=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255))
    role = Column(String(50), default="analyst")  # admin, analyst, viewer
    is_active = Column(Boolean, default=True)
    last_login_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())


class DatabasePostgres:
    """
    PostgreSQL database adapter using SQLAlchemy.
    
    Compatible with PostgreSQL and AWS Aurora Serverless v2.
    """
    
    def __init__(self, database_url: str):
        """
        Initialize PostgreSQL database.
        
        Args:
            database_url: PostgreSQL connection string
                e.g., postgresql://user:pass@host:5432/dbname
        """
        self.database_url = database_url
        self.engine = create_engine(
            database_url,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
            echo=False,
        )
        self.SessionLocal = sessionmaker(bind=self.engine)
        self._ensure_schema()
    
    def _ensure_schema(self) -> None:
        """Ensure database schema exists."""
        # Create tables if they don't exist
        # Note: The init-db.sql script should handle this, but we ensure compatibility
        try:
            Base.metadata.create_all(self.engine)
        except Exception as e:
            # If tables already exist from init-db.sql, that's fine
            pass
    
    @contextmanager
    def _session(self) -> Iterator[Session]:
        """Get database session context manager."""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    # === Scan Operations ===
    
    def save_scan(self, result: ScanResult) -> str:
        """Save a scan result to database."""
        scan_id = result.metadata.scan_id
        
        with self._session() as session:
            # Get or create organization
            org_name = result.metadata.organization
            org = session.query(OrganizationModel).filter_by(name=org_name).first()
            if not org:
                org = OrganizationModel(id=str(uuid4()), name=org_name)
                session.add(org)
                session.flush()  # Get the ID
            
            # Insert or update scan
            scan = ScanModel(
                id=scan_id,
                organization_id=org.id,
                status="completed",
                scan_type="full",
                started_at=result.metadata.scan_date,
                completed_at=datetime.now(),
                duration_seconds=int(result.metadata.scan_duration_seconds),
                repositories_scanned=result.metadata.repositories_scanned,
                total_findings=result.metadata.total_findings,
                critical_count=result.summary.by_severity.get("critical", 0),
                high_count=result.summary.by_severity.get("high", 0),
                medium_count=result.summary.by_severity.get("medium", 0),
                low_count=result.summary.by_severity.get("low", 0),
                info_count=result.summary.by_severity.get("info", 0),
            )
            session.merge(scan)
            
            # Insert findings
            for finding in result.findings:
                self._save_finding(session, finding, scan_id, org.id)
            
            # Update repositories
            for repo_name, repo in result.repositories.items():
                self._update_repository(session, repo, scan_id, org.id)
        
        return scan_id
    
    # === Incremental Save Methods ===
    
    def create_scan_incremental(
        self,
        scan_id: str,
        organization: str,
        scan_type: str = "api_only",
    ) -> tuple[str, str]:
        """
        Create a scan record with 'running' status for incremental saving.
        
        Returns:
            Tuple of (scan_id, organization_id)
        """
        with self._session() as session:
            # Get or create organization
            org = session.query(OrganizationModel).filter_by(name=organization).first()
            if not org:
                org = OrganizationModel(id=str(uuid4()), name=organization)
                session.add(org)
                session.flush()
            
            # Create scan with running status
            scan = ScanModel(
                id=scan_id,
                organization_id=org.id,
                status="running",  # Custom status for running scans
                scan_type=scan_type,
                started_at=datetime.now(),
                repositories_scanned=0,
                total_findings=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                info_count=0,
            )
            session.add(scan)
            
            return scan_id, org.id
    
    def save_repository_incremental(
        self,
        org_id: str,
        repo_full_name: str,
        repo_name: str,
        scan_id: str,
    ) -> str:
        """
        Save a repository immediately during scan.
        
        Returns:
            Repository ID
        """
        with self._session() as session:
            # Check if exists
            existing = session.query(RepositoryModel).filter_by(full_name=repo_full_name).first()
            
            if existing:
                existing.updated_at = datetime.now()
                return str(existing.id)
            
            # Create new repository
            repo_id = str(uuid4())
            repo = RepositoryModel(
                id=repo_id,
                organization_id=org_id,
                name=repo_name,
                full_name=repo_full_name,
                url=f"https://github.com/{repo_full_name}",
            )
            session.add(repo)
            
            # Update scan repository count
            scan = session.query(ScanModel).filter_by(id=scan_id).first()
            if scan:
                scan.repositories_scanned = (scan.repositories_scanned or 0) + 1
            
            return repo_id
    
    def save_finding_incremental(
        self,
        scan_id: str,
        org_id: str,
        finding: Finding,
    ) -> Optional[str]:
        """
        Save a single finding immediately and update scan counts.
        
        Returns:
            Finding ID if saved (None if duplicate)
        """
        import hashlib
        
        with self._session() as session:
            # Generate fingerprint
            content = f"{finding.repository}:{finding.type.value}:{finding.category}:{finding.file_path}:{finding.line_content[:100] if finding.line_content else ''}"
            fingerprint = hashlib.sha256(content.encode()).hexdigest()[:32]
            
            # Get or create repository
            repo = session.query(RepositoryModel).filter_by(full_name=finding.repository).first()
            if not repo:
                repo_name = finding.repository.split('/')[-1] if '/' in finding.repository else finding.repository
                repo = RepositoryModel(
                    id=str(uuid4()),
                    organization_id=org_id,
                    name=repo_name,
                    full_name=finding.repository,
                    url=f"https://github.com/{finding.repository}",
                )
                session.add(repo)
                session.flush()
            
            # Check if finding exists
            existing = session.query(FindingModel).filter_by(
                fingerprint=fingerprint,
                repository_id=repo.id
            ).first()
            
            if existing:
                # Update existing
                existing.scan_id = scan_id
                existing.last_seen_at = datetime.now()
                existing.updated_at = datetime.now()
                return None  # Not a new finding
            
            # Create new finding
            states_list = [s.value for s in finding.states] if finding.states else []
            finding_id = str(uuid4())
            now = datetime.now()
            
            finding_model = FindingModel(
                id=finding_id,
                scan_id=scan_id,
                repository_id=repo.id,
                finding_type=finding.type.value,
                category=finding.category,
                severity=finding.severity.value,
                status="open",
                file_path=finding.file_path or "",
                line_number=finding.line_number,
                line_content=(finding.line_content or "")[:500],
                branch=finding.branch or "",
                commit_sha=finding.commit_sha or "",
                commit_author=finding.commit_author or "",
                rule_id=finding.rule_id or "unknown",
                rule_description=finding.rule_description,
                matched_pattern=finding.matched_pattern,
                states=states_list,
                false_positive_likelihood=finding.false_positive_likelihood.value if finding.false_positive_likelihood else None,
                fingerprint=fingerprint,
                first_seen_at=now,
                last_seen_at=now,
            )
            session.add(finding_model)
            
            # Update scan counts
            scan = session.query(ScanModel).filter_by(id=scan_id).first()
            if scan:
                scan.total_findings = (scan.total_findings or 0) + 1
                severity = finding.severity.value.lower()
                if severity == "critical":
                    scan.critical_count = (scan.critical_count or 0) + 1
                elif severity == "high":
                    scan.high_count = (scan.high_count or 0) + 1
                elif severity == "medium":
                    scan.medium_count = (scan.medium_count or 0) + 1
                elif severity == "low":
                    scan.low_count = (scan.low_count or 0) + 1
                elif severity == "info":
                    scan.info_count = (scan.info_count or 0) + 1
            
            return finding_id
    
    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        error_message: Optional[str] = None,
        duration_seconds: Optional[int] = None,
    ) -> bool:
        """Update scan status (running -> completed/failed)."""
        with self._session() as session:
            scan = session.query(ScanModel).filter_by(id=scan_id).first()
            if not scan:
                return False
            
            # Valid PostgreSQL scan_status values: pending, running, completed, failed, cancelled
            scan.status = status
            
            if status == "completed":
                scan.completed_at = datetime.now()
            
            if error_message:
                scan.error_message = error_message
            
            if duration_seconds is not None:
                scan.duration_seconds = duration_seconds
            
            return True
    
    def get_scan_progress(self, scan_id: str) -> dict:
        """Get current scan progress (repositories and findings count)."""
        with self._session() as session:
            scan = session.query(ScanModel).filter_by(id=scan_id).first()
            if not scan:
                return {}
            
            return {
                "repositories_scanned": scan.repositories_scanned or 0,
                "total_findings": scan.total_findings or 0,
                "critical": scan.critical_count or 0,
                "high": scan.high_count or 0,
                "medium": scan.medium_count or 0,
                "low": scan.low_count or 0,
                "info": scan.info_count or 0,
                "status": scan.status,
            }
    
    def _save_finding(self, session: Session, finding: Finding, scan_id: str, org_id: str) -> None:
        """Save a single finding."""
        import hashlib
        
        # Generate fingerprint
        content = f"{finding.repository}:{finding.type.value}:{finding.category}:{finding.file_path}:{finding.line_content[:100] if finding.line_content else ''}"
        fingerprint = hashlib.sha256(content.encode()).hexdigest()[:32]
        
        # Get or create repository to get repository_id
        repo = session.query(RepositoryModel).filter_by(full_name=finding.repository).first()
        if not repo:
            # Create repository if it doesn't exist
            repo_name = finding.repository.split('/')[-1] if '/' in finding.repository else finding.repository
            repo = RepositoryModel(
                id=str(uuid4()),
                organization_id=org_id,
                name=repo_name,
                full_name=finding.repository,
                url=f"https://github.com/{finding.repository}",
            )
            session.add(repo)
            session.flush()
        
        repository_id = repo.id
        
        # Check if finding exists by fingerprint and repository_id
        existing = session.query(FindingModel).filter_by(
            fingerprint=fingerprint, 
            repository_id=repository_id
        ).first()
        
        # Convert states to list for PostgreSQL text[] array
        states_list = [s.value for s in finding.states] if finding.states else []
        now = datetime.now()
        
        if existing:
            # Update existing finding
            existing.scan_id = scan_id
            existing.last_seen_at = now
            existing.severity = finding.severity.value
            existing.states = states_list
            existing.line_number = finding.line_number
            existing.line_content = (finding.line_content or "")[:500]
            existing.updated_at = now
        else:
            # Insert new finding
            finding_model = FindingModel(
                id=str(uuid4()),
                scan_id=scan_id,
                repository_id=repository_id,
                finding_type=finding.type.value,
                category=finding.category,
                severity=finding.severity.value,
                status="open",  # Use PostgreSQL enum value directly
                file_path=finding.file_path or "",
                line_number=finding.line_number,
                line_content=(finding.line_content or "")[:500],
                branch=finding.branch or "",
                commit_sha=finding.commit_sha or "",
                commit_author=finding.commit_author or "",
                rule_id=finding.rule_id or "unknown",
                rule_description=finding.rule_description,
                matched_pattern=finding.matched_pattern,
                states=states_list,  # PostgreSQL text[] array
                false_positive_likelihood=finding.false_positive_likelihood.value if finding.false_positive_likelihood else None,
                fingerprint=fingerprint,
                first_seen_at=now,
                last_seen_at=now,
            )
            session.add(finding_model)
    
    def _update_repository(self, session: Session, repo, scan_id: str, org_id: str) -> None:
        """Update or create repository record."""
        existing = session.query(RepositoryModel).filter_by(full_name=repo.full_name).first()
        
        now = datetime.now()
        
        if existing:
            existing.updated_at = now
        else:
            repo_model = RepositoryModel(
                id=str(uuid4()),
                organization_id=org_id,
                name=repo.name,
                full_name=repo.full_name,
                url=repo.url,
                default_branch=repo.default_branch,
                is_private=repo.visibility == "private" if hasattr(repo, 'visibility') else True,
            )
            session.add(repo_model)
    
    def get_scans(self, organization: Optional[str] = None, limit: int = 100) -> list[ScanRecord]:
        """Get scans from database."""
        with self._session() as session:
            query = session.query(ScanModel, OrganizationModel).join(
                OrganizationModel, ScanModel.organization_id == OrganizationModel.id, isouter=True
            )
            
            if organization:
                query = query.filter(OrganizationModel.name == organization)
            
            query = query.order_by(ScanModel.created_at.desc()).limit(limit)
            
            results = query.all()
            scans = []
            for scan, org in results:
                org_name = org.name if org else None
                scans.append(ScanRecord(
                    id=scan.id,
                    organization=org_name or "",
                    scan_date=scan.started_at or scan.created_at,
                    duration_seconds=scan.duration_seconds,
                    repositories_scanned=scan.repositories_scanned,
                    repositories_failed=0,  # Not stored in new schema
                    total_findings=scan.total_findings,
                    critical_count=scan.critical_count,
                    high_count=scan.high_count,
                ))
            return scans
    
    def get_scan(self, scan_id: str) -> Optional[ScanRecord]:
        """Get a scan by ID."""
        with self._session() as session:
            result = session.query(ScanModel, OrganizationModel).join(
                OrganizationModel, ScanModel.organization_id == OrganizationModel.id, isouter=True
            ).filter(ScanModel.id == scan_id).first()
            
            if not result:
                return None
            
            scan, org = result
            return ScanRecord(
                id=scan.id,
                organization=org.name if org else "",
                scan_date=scan.started_at or scan.created_at,
                duration_seconds=scan.duration_seconds,
                repositories_scanned=scan.repositories_scanned,
                repositories_failed=0,
                total_findings=scan.total_findings,
                critical_count=scan.critical_count,
                high_count=scan.high_count,
            )
    
    def get_findings(
        self,
        scan_id: Optional[str] = None,
        repository: Optional[str] = None,
        status: Optional[RemediationStatus] = None,
        severity: Optional[str] = None,
        limit: int = 1000,
    ) -> list[FindingRecord]:
        """Get findings from database."""
        with self._session() as session:
            query = session.query(FindingModel, RepositoryModel).join(
                RepositoryModel, FindingModel.repository_id == RepositoryModel.id, isouter=True
            )
            
            if scan_id:
                query = query.filter(FindingModel.scan_id == scan_id)
            if repository:
                query = query.filter(RepositoryModel.full_name == repository)
            if status:
                query = query.filter(FindingModel.status == status.value)
            if severity:
                query = query.filter(FindingModel.severity == severity)
            
            query = query.order_by(
                case(
                    (FindingModel.severity == "critical", 1),
                    (FindingModel.severity == "high", 2),
                    (FindingModel.severity == "medium", 3),
                    else_=4,
                )
            ).limit(limit)
            
            results = query.all()
            return [
                FindingRecord(
                    id=str(f.id),
                    scan_id=str(f.scan_id) if f.scan_id else None,
                    repository=repo.full_name if repo else "",
                    finding_type=f.finding_type,
                    category=f.category,
                    severity=f.severity,
                    states=",".join(f.states) if f.states else "",
                    file_path=f.file_path,
                    line_number=f.line_number,
                    rule_id=f.rule_id,
                    status=self._pg_to_remediation_status(f.status),
                    first_seen_date=f.first_seen_at or datetime.now(),
                    last_seen_date=f.last_seen_at or datetime.now(),
                )
                for f, repo in results
            ]
    
    def _pg_to_remediation_status(self, pg_status: str) -> RemediationStatus:
        """Convert PostgreSQL status enum to Python RemediationStatus."""
        status_map = {
            "open": RemediationStatus.OPEN,
            "in_progress": RemediationStatus.IN_PROGRESS,
            "resolved": RemediationStatus.FIXED,  # Map back to FIXED for compatibility
            "false_positive": RemediationStatus.FALSE_POSITIVE,
            "accepted_risk": RemediationStatus.ACCEPTED_RISK,
        }
        return status_map.get(pg_status, RemediationStatus.OPEN)
    
    def get_open_findings(self, organization: Optional[str] = None) -> list[FindingRecord]:
        """Get all open findings."""
        with self._session() as session:
            query = session.query(FindingModel, RepositoryModel).join(
                RepositoryModel, FindingModel.repository_id == RepositoryModel.id, isouter=True
            ).filter(FindingModel.status == "open")
            
            if organization:
                # Filter by organization name
                org = session.query(OrganizationModel).filter_by(name=organization).first()
                if org:
                    query = query.filter(RepositoryModel.organization_id == org.id)
            
            query = query.order_by(
                case(
                    (FindingModel.severity == "critical", 1),
                    (FindingModel.severity == "high", 2),
                    (FindingModel.severity == "medium", 3),
                    else_=4,
                )
            )
            
            results = query.all()
            return [
                FindingRecord(
                    id=str(f.id),
                    repository=repo.full_name if repo else "",
                    finding_type=f.finding_type,
                    category=f.category,
                    severity=f.severity,
                    file_path=f.file_path,
                    line_number=f.line_number,
                    status=self._pg_to_remediation_status(f.status),
                )
                for f, repo in results
            ]
    
    def update_finding_status(
        self,
        finding_id: str,
        new_status: RemediationStatus,
        performed_by: str = "",
        comment: str = "",
    ) -> bool:
        """Update the status of a finding."""
        with self._session() as session:
            finding = session.query(FindingModel).filter_by(id=finding_id).first()
            if not finding:
                return False
            
            old_status = RemediationStatus(finding.status) if finding.status in [e.value for e in RemediationStatus] else RemediationStatus.OPEN
            now = datetime.now()
            
            finding.updated_at = now
            
            # Map internal status to PostgreSQL enum values
            # PostgreSQL enum: open, in_progress, resolved, false_positive, accepted_risk
            pg_status_map = {
                RemediationStatus.OPEN: "open",
                RemediationStatus.IN_PROGRESS: "in_progress",
                RemediationStatus.FIXED: "resolved",  # Map FIXED to resolved
                RemediationStatus.WONT_FIX: "accepted_risk",  # Map WONT_FIX to accepted_risk
                RemediationStatus.FALSE_POSITIVE: "false_positive",
                RemediationStatus.ACCEPTED_RISK: "accepted_risk",
            }
            finding.status = pg_status_map.get(new_status, "open")
            
            if new_status in [
                RemediationStatus.FIXED,
                RemediationStatus.WONT_FIX,
                RemediationStatus.FALSE_POSITIVE,
                RemediationStatus.ACCEPTED_RISK,
            ]:
                finding.resolved_at = now
                finding.resolved_by = performed_by or "system"
            
            # Log to finding history
            history = FindingHistoryModel(
                id=str(uuid4()),
                finding_id=finding_id,
                action="status_changed",
                previous_value={"status": old_status.value},
                new_value={"status": new_status.value},
                performed_by=performed_by,
                comment=comment,
            )
            session.add(history)
            
            return True
    
    def mark_fixed_findings(self, scan_id: str) -> int:
        """Mark findings as fixed if they weren't seen in the latest scan."""
        with self._session() as session:
            now = datetime.now()
            
            # Get repository IDs that were scanned in this scan
            scanned_repo_ids = (
                session.query(FindingModel.repository_id)
                .filter(FindingModel.scan_id == scan_id)
                .distinct()
            )
            
            # Find open findings in those repositories that weren't seen in this scan
            result = session.query(FindingModel).filter(
                FindingModel.status == "open",
                FindingModel.scan_id != scan_id,
                FindingModel.repository_id.in_(scanned_repo_ids)
            ).update(
                {
                    FindingModel.status: "resolved",  # Use PostgreSQL enum value
                    FindingModel.resolved_at: now,
                    FindingModel.resolved_by: "auto-resolved",
                    FindingModel.updated_at: now,
                },
                synchronize_session=False
            )
            
            return result
    
    def get_repositories(
        self,
        organization: Optional[str] = None,
        limit: int = 10000,
    ) -> list[dict]:
        """Get all repositories from the repositories table."""
        with self._session() as session:
            query = session.query(RepositoryModel)
            
            if organization:
                # Filter by organization name
                org = session.query(OrganizationModel).filter_by(name=organization).first()
                if org:
                    query = query.filter_by(organization_id=org.id)
                else:
                    return []  # Organization not found
            
            query = query.order_by(RepositoryModel.updated_at.desc().nullslast()).limit(limit)
            
            repos = []
            for row in query.all():
                # Get finding counts by severity
                finding_counts = (
                    session.query(
                        FindingModel.severity,
                        func.count(FindingModel.id).label("count")
                    )
                    .filter(
                        FindingModel.repository_id == row.id,
                        FindingModel.status.in_(["open", "in_progress"])
                    )
                    .group_by(FindingModel.severity)
                    .all()
                )
                
                counts = {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "total": 0,
                }
                
                for fc in finding_counts:
                    severity = fc.severity.lower()
                    count = fc.count
                    if severity in counts:
                        counts[severity] = count
                    counts["total"] += count
                
                # Get organization name
                org_name = ""
                if row.organization_id:
                    org = session.query(OrganizationModel).filter_by(id=row.organization_id).first()
                    if org:
                        org_name = org.name
                
                repos.append({
                    "id": str(row.id),
                    "name": row.name,
                    "full_name": row.full_name,
                    "organization": org_name,
                    "url": row.url or f"https://github.com/{row.full_name}",
                    "default_branch": row.default_branch or "main",
                    "language": row.language,
                    "is_private": row.is_private,
                    "is_archived": row.is_archived,
                    "last_scan_at": row.updated_at.isoformat() if row.updated_at else None,
                    "findings_count": counts,
                })
            
            return repos
    
    def get_trend_data(
        self,
        organization: Optional[str] = None,
        days: int = 30,
    ) -> list[TrendData]:
        """Get trend data for the last N days."""
        with self._session() as session:
            since = datetime.now() - timedelta(days=days)
            
            query = (
                session.query(
                    func.date(ScanModel.started_at).label("date"),
                    func.sum(ScanModel.total_findings).label("total"),
                    func.sum(ScanModel.critical_count).label("critical"),
                    func.sum(ScanModel.high_count).label("high"),
                    func.sum(ScanModel.medium_count).label("medium"),
                    func.sum(ScanModel.low_count).label("low"),
                )
                .filter(ScanModel.started_at >= since)
            )
            
            if organization:
                query = query.join(OrganizationModel).filter(OrganizationModel.name == organization)
            
            rows = query.group_by(func.date(ScanModel.started_at)).order_by("date").all()
            
            return [
                TrendData(
                    date=row.date,
                    total_findings=row.total or 0,
                    critical=row.critical or 0,
                    high=row.high or 0,
                    medium=row.medium or 0,
                    low=row.low or 0,
                )
                for row in rows
            ]
    
    def get_statistics(self, organization: Optional[str] = None) -> dict:
        """Get overall statistics."""
        with self._session() as session:
            # Total scans
            scan_query = session.query(func.count(ScanModel.id))
            if organization:
                scan_query = scan_query.join(OrganizationModel).filter(OrganizationModel.name == organization)
            total_scans = scan_query.scalar() or 0
            
            # Status counts
            status_counts = (
                session.query(
                    FindingModel.status,
                    func.count(FindingModel.id).label("count")
                )
                .group_by(FindingModel.status)
                .all()
            )
            status_dict = {row.status: row.count for row in status_counts}
            
            # Severity counts
            severity_counts = (
                session.query(
                    FindingModel.severity,
                    func.count(FindingModel.id).label("count")
                )
                .group_by(FindingModel.severity)
                .all()
            )
            severity_dict = {row.severity: row.count for row in severity_counts}
            
            # Type counts
            type_counts = (
                session.query(
                    FindingModel.finding_type,
                    func.count(FindingModel.id).label("count")
                )
                .group_by(FindingModel.finding_type)
                .all()
            )
            type_dict = {row.finding_type: row.count for row in type_counts}
            
            # Total repositories (from repositories table for better accuracy)
            total_repos = session.query(func.count(RepositoryModel.id)).scalar() or 0
            
            # Average findings per scan
            avg_query = session.query(func.avg(ScanModel.total_findings))
            if organization:
                avg_query = avg_query.join(OrganizationModel).filter(OrganizationModel.name == organization)
            avg_findings = avg_query.scalar() or 0
            
            return {
                "total_scans": total_scans,
                "total_repositories": total_repos,
                "status_counts": status_dict,
                "severity_counts": severity_dict,
                "type_counts": type_dict,
                "average_findings_per_scan": round(float(avg_findings), 1),
                "open_findings": status_dict.get("open", 0),
                "fixed_findings": status_dict.get("resolved", 0),
            }
