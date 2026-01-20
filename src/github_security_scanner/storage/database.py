"""
SQLite database for persistent storage of scan results.

Provides storage, querying, and analytics for security scans.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator, Optional

from ..core.models import Finding, ScanResult
from .models import (
    FindingRecord,
    RemediationRecord,
    RemediationStatus,
    RepositoryRecord,
    ScanRecord,
    TrendData,
)


class Database:
    """
    SQLite database for storing scan results and tracking remediation.
    """

    def __init__(self, db_path: str | Path = "security_scans.db"):
        """
        Initialize database.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self._ensure_schema()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """Get database connection context manager."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
        """Create database schema if not exists."""
        with self._connection() as conn:
            conn.executescript("""
                -- Scans table
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    organization TEXT NOT NULL,
                    scan_date TIMESTAMP NOT NULL,
                    duration_seconds REAL DEFAULT 0,
                    repositories_scanned INTEGER DEFAULT 0,
                    repositories_failed INTEGER DEFAULT 0,
                    total_findings INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    secrets_count INTEGER DEFAULT 0,
                    vulnerabilities_count INTEGER DEFAULT 0,
                    bugs_count INTEGER DEFAULT 0,
                    misconfigs_count INTEGER DEFAULT 0,
                    active_count INTEGER DEFAULT 0,
                    historical_count INTEGER DEFAULT 0,
                    hardcoded_count INTEGER DEFAULT 0,
                    tool_version TEXT,
                    config_hash TEXT,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                -- Findings table
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    states TEXT,
                    file_path TEXT,
                    line_number INTEGER DEFAULT 0,
                    line_content TEXT,
                    rule_id TEXT,
                    rule_description TEXT,
                    remediation TEXT,
                    branch TEXT,
                    commit_sha TEXT,
                    commit_date TIMESTAMP,
                    commit_author TEXT,
                    fingerprint TEXT NOT NULL,
                    first_seen_scan_id TEXT,
                    first_seen_date TIMESTAMP,
                    last_seen_scan_id TEXT,
                    last_seen_date TIMESTAMP,
                    status TEXT DEFAULT 'open',
                    assigned_to TEXT,
                    due_date TIMESTAMP,
                    resolved_date TIMESTAMP,
                    resolved_in_scan_id TEXT,
                    confidence REAL DEFAULT 0,
                    cwe_id TEXT,
                    cvss_score REAL,
                    tags TEXT,
                    notes TEXT,
                    ai_label TEXT,
                    ai_confidence REAL,
                    ai_reasons TEXT,
                    ai_source TEXT,
                    ai_updated_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                );

                -- Remediation history table
                CREATE TABLE IF NOT EXISTS remediation_history (
                    id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL,
                    old_status TEXT,
                    new_status TEXT,
                    action TEXT,
                    performed_by TEXT,
                    comment TEXT,
                    verified_in_scan_id TEXT,
                    verification_result TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (finding_id) REFERENCES findings(id)
                );

                -- Repositories table
                CREATE TABLE IF NOT EXISTS repositories (
                    id TEXT PRIMARY KEY,
                    organization TEXT NOT NULL,
                    name TEXT NOT NULL,
                    full_name TEXT UNIQUE NOT NULL,
                    url TEXT,
                    default_branch TEXT DEFAULT 'main',
                    visibility TEXT DEFAULT 'private',
                    last_scan_id TEXT,
                    last_scan_date TIMESTAMP,
                    total_scans INTEGER DEFAULT 0,
                    current_findings INTEGER DEFAULT 0,
                    open_findings INTEGER DEFAULT 0,
                    fixed_findings INTEGER DEFAULT 0,
                    risk_score REAL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                -- Indexes for performance
                CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
                CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repository);
                CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
                CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_scans_org ON scans(organization);
                CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(scan_date);
            """)

    # === Scan Operations ===

    def save_scan(self, result: ScanResult) -> str:
        """
        Save a scan result to database.

        Args:
            result: ScanResult to save

        Returns:
            Scan ID
        """
        scan_id = result.metadata.scan_id

        with self._connection() as conn:
            # Insert scan record
            conn.execute("""
                INSERT INTO scans (
                    id, organization, scan_date, duration_seconds,
                    repositories_scanned, repositories_failed, total_findings,
                    critical_count, high_count, medium_count, low_count,
                    secrets_count, vulnerabilities_count, bugs_count, misconfigs_count,
                    active_count, historical_count, hardcoded_count,
                    tool_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                result.metadata.organization,
                result.metadata.scan_date.isoformat(),
                result.metadata.scan_duration_seconds,
                result.metadata.repositories_scanned,
                result.metadata.repositories_failed,
                result.metadata.total_findings,
                result.summary.by_severity.get("critical", 0),
                result.summary.by_severity.get("high", 0),
                result.summary.by_severity.get("medium", 0),
                result.summary.by_severity.get("low", 0),
                result.summary.by_type.get("secret", 0),
                result.summary.by_type.get("vulnerability", 0),
                result.summary.by_type.get("bug", 0),
                result.summary.by_type.get("misconfig", 0),
                result.summary.by_state.get("active", 0),
                result.summary.by_state.get("historical", 0),
                result.summary.by_state.get("hardcoded", 0),
                result.metadata.tool_version,
            ))

            # Insert findings
            for finding in result.findings:
                self._save_finding(conn, finding, scan_id)

            # Update repositories
            for repo_name, repo in result.repositories.items():
                self._update_repository(conn, repo, scan_id, result.metadata.organization)

        return scan_id

    def _save_finding(
        self,
        conn: sqlite3.Connection,
        finding: Finding,
        scan_id: str,
    ) -> None:
        """Save a single finding."""
        # Generate fingerprint for deduplication
        fingerprint = self._generate_fingerprint(finding)

        # Check if finding already exists
        existing = conn.execute(
            "SELECT id, first_seen_scan_id, first_seen_date FROM findings WHERE fingerprint = ?",
            (fingerprint,)
        ).fetchone()

        states_str = ",".join(s.value for s in finding.states)
        now = datetime.now().isoformat()

        if existing:
            # Update existing finding
            conn.execute("""
                UPDATE findings SET
                    last_seen_scan_id = ?,
                    last_seen_date = ?,
                    severity = ?,
                    states = ?,
                    line_number = ?,
                    line_content = ?,
                    updated_at = ?
                WHERE fingerprint = ?
            """, (
                scan_id, now, finding.severity.value, states_str,
                finding.line_number, finding.line_content[:500], now,
                fingerprint,
            ))
        else:
            # Insert new finding
            conn.execute("""
                INSERT INTO findings (
                    id, scan_id, repository, finding_type, category, severity, states,
                    file_path, line_number, line_content, rule_id, rule_description,
                    remediation, branch, commit_sha, commit_author, fingerprint,
                    first_seen_scan_id, first_seen_date, last_seen_scan_id, last_seen_date,
                    status, confidence, cwe_id, cvss_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding.id, scan_id, finding.repository, finding.type.value,
                finding.category, finding.severity.value, states_str,
                finding.file_path, finding.line_number, finding.line_content[:500],
                finding.rule_id, finding.rule_description, finding.remediation,
                finding.branch, finding.commit_sha, finding.commit_author,
                fingerprint, scan_id, now, scan_id, now,
                RemediationStatus.OPEN.value, finding.confidence,
                finding.cwe_id, finding.cvss_score,
            ))

    def _update_repository(
        self,
        conn: sqlite3.Connection,
        repo,
        scan_id: str,
        organization: str,
    ) -> None:
        """Update or create repository record."""
        existing = conn.execute(
            "SELECT id, total_scans FROM repositories WHERE full_name = ?",
            (repo.full_name,)
        ).fetchone()

        now = datetime.now().isoformat()

        if existing:
            conn.execute("""
                UPDATE repositories SET
                    last_scan_id = ?,
                    last_scan_date = ?,
                    total_scans = total_scans + 1,
                    current_findings = ?,
                    updated_at = ?
                WHERE full_name = ?
            """, (scan_id, now, repo.findings_count, now, repo.full_name))
        else:
            from uuid import uuid4
            conn.execute("""
                INSERT INTO repositories (
                    id, organization, name, full_name, url, default_branch,
                    visibility, last_scan_id, last_scan_date, total_scans,
                    current_findings
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(uuid4()), organization, repo.name, repo.full_name,
                repo.url, repo.default_branch, repo.visibility,
                scan_id, now, 1, repo.findings_count,
            ))

    def _generate_fingerprint(self, finding: Finding) -> str:
        """Generate unique fingerprint for a finding."""
        from ..utils.fingerprint import build_finding_fingerprint
        
        return build_finding_fingerprint(finding)

    def get_scan(self, scan_id: str) -> Optional[ScanRecord]:
        """Get a scan by ID."""
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()

            if not row:
                return None

            return ScanRecord(
                id=row["id"],
                organization=row["organization"],
                scan_date=datetime.fromisoformat(row["scan_date"]),
                duration_seconds=row["duration_seconds"],
                repositories_scanned=row["repositories_scanned"],
                repositories_failed=row["repositories_failed"],
                total_findings=row["total_findings"],
                critical_count=row["critical_count"],
                high_count=row["high_count"],
                medium_count=row["medium_count"],
                low_count=row["low_count"],
            )

    def get_finding_by_id(self, finding_id: str) -> Optional[FindingRecord]:
        """Get a single finding by ID."""
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
            
            if not row:
                return None
            
            return FindingRecord(
                id=row["id"],
                scan_id=row["scan_id"],
                repository=row["repository"],
                finding_type=row["finding_type"],
                category=row["category"],
                severity=row["severity"],
                states=row["states"] or "",
                file_path=row["file_path"] or "",
                line_number=row["line_number"] or 0,
                line_content=row["line_content"] or "",
                rule_id=row["rule_id"] or "",
                rule_description=row["rule_description"] or "",
                remediation=row["remediation"] or "",
                branch=row["branch"] or "",
                commit_sha=row["commit_sha"] or "",
                commit_date=datetime.fromisoformat(row["commit_date"]) if row["commit_date"] else None,
                commit_author=row["commit_author"] or "",
                fingerprint=row["fingerprint"] or "",
                first_seen_scan_id=row["first_seen_scan_id"] or "",
                first_seen_date=datetime.fromisoformat(row["first_seen_date"]) if row["first_seen_date"] else datetime.now(),
                last_seen_scan_id=row["last_seen_scan_id"] or "",
                last_seen_date=datetime.fromisoformat(row["last_seen_date"]) if row["last_seen_date"] else datetime.now(),
                status=RemediationStatus(row["status"]) if row["status"] else RemediationStatus.OPEN,
                assigned_to=row["assigned_to"] or "",
                due_date=datetime.fromisoformat(row["due_date"]) if row["due_date"] else None,
                resolved_date=datetime.fromisoformat(row["resolved_date"]) if row["resolved_date"] else None,
                resolved_in_scan_id=row["resolved_in_scan_id"] or "",
                confidence=row["confidence"] or 0.0,
                cwe_id=row["cwe_id"] or "",
                cvss_score=row["cvss_score"],
                tags=row["tags"] or "",
                notes=row["notes"] or "",
                ai_label=row["ai_label"] or "",
                ai_confidence=row["ai_confidence"] or 0.0,
                ai_reasons=self._parse_ai_reasons(row["ai_reasons"]),
                ai_source=row["ai_source"] or "",
                ai_updated_at=datetime.fromisoformat(row["ai_updated_at"]) if row["ai_updated_at"] else None,
            )

    def get_scans(
        self,
        organization: Optional[str] = None,
        limit: int = 50,
    ) -> list[ScanRecord]:
        """Get list of scans."""
        with self._connection() as conn:
            if organization:
                rows = conn.execute(
                    "SELECT * FROM scans WHERE organization = ? ORDER BY scan_date DESC LIMIT ?",
                    (organization, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scans ORDER BY scan_date DESC LIMIT ?",
                    (limit,)
                ).fetchall()

            return [
                ScanRecord(
                    id=row["id"],
                    organization=row["organization"],
                    scan_date=datetime.fromisoformat(row["scan_date"]),
                    total_findings=row["total_findings"],
                    critical_count=row["critical_count"],
                    high_count=row["high_count"],
                    repositories_scanned=row["repositories_scanned"],
                )
                for row in rows
            ]

    # === Finding Operations ===

    def get_findings(
        self,
        scan_id: Optional[str] = None,
        repository: Optional[str] = None,
        status: Optional[RemediationStatus] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> list[FindingRecord]:
        """Get findings with filters."""
        query = "SELECT * FROM findings WHERE 1=1"
        params = []

        if scan_id:
            query += " AND last_seen_scan_id = ?"
            params.append(scan_id)
        if repository:
            query += " AND repository = ?"
            params.append(repository)
        if status:
            query += " AND status = ?"
            params.append(status.value)
        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END LIMIT ?"
        params.append(limit)

        with self._connection() as conn:
            rows = conn.execute(query, params).fetchall()

            return [
                FindingRecord(
                    id=row["id"],
                    scan_id=row["scan_id"],
                    repository=row["repository"],
                    finding_type=row["finding_type"],
                    category=row["category"],
                    severity=row["severity"],
                    states=row["states"],
                    file_path=row["file_path"],
                    line_number=row["line_number"],
                    line_content=row["line_content"] or "",
                    rule_id=row["rule_id"],
                    rule_description=row["rule_description"] or "",
                    status=RemediationStatus(row["status"]),
                    first_seen_date=datetime.fromisoformat(row["first_seen_date"]) if row["first_seen_date"] else datetime.now(),
                    last_seen_date=datetime.fromisoformat(row["last_seen_date"]) if row["last_seen_date"] else datetime.now(),
                    ai_label=row["ai_label"] or "",
                    ai_confidence=row["ai_confidence"] or 0.0,
                    ai_reasons=self._parse_ai_reasons(row["ai_reasons"]),
                    ai_source=row["ai_source"] or "",
                    ai_updated_at=datetime.fromisoformat(row["ai_updated_at"]) if row["ai_updated_at"] else None,
                )
                for row in rows
            ]

    def get_findings_paginated_all(
        self,
        scan_id: Optional[str] = None,
        repository: Optional[str] = None,
        status: Optional[RemediationStatus] = None,
        severity: Optional[str | list[str]] = None,
        finding_type: Optional[str | list[str]] = None,
        category: Optional[str] = None,
        search: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> dict:
        """Get paginated findings across all repositories with filters."""
        query = "SELECT * FROM findings WHERE 1=1"
        params: list = []
        
        if scan_id:
            query += " AND last_seen_scan_id = ?"
            params.append(scan_id)
        if repository:
            query += " AND repository = ?"
            params.append(repository)
        if status:
            query += " AND status = ?"
            params.append(status.value)
        if severity:
            if isinstance(severity, list):
                placeholders = ",".join("?" * len(severity))
                query += f" AND severity IN ({placeholders})"
                params.extend(severity)
            else:
                query += " AND severity = ?"
                params.append(severity)
        if finding_type:
            if isinstance(finding_type, list):
                placeholders = ",".join("?" * len(finding_type))
                query += f" AND finding_type IN ({placeholders})"
                params.extend(finding_type)
            else:
                query += " AND finding_type = ?"
                params.append(finding_type)
        if category:
            query += " AND category = ?"
            params.append(category)
        if search:
            like = f"%{search}%"
            query += " AND (repository LIKE ? OR category LIKE ? OR file_path LIKE ? OR line_content LIKE ? OR rule_id LIKE ?)"
            params.extend([like, like, like, like, like])
        
        count_query = f"SELECT COUNT(*) as count FROM ({query}) as subquery"
        
        order_query = query + " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, created_at DESC LIMIT ? OFFSET ?"
        offset = (page - 1) * page_size
        page_params = params + [page_size, offset]
        
        with self._connection() as conn:
            total = conn.execute(count_query, params).fetchone()["count"]
            rows = conn.execute(order_query, page_params).fetchall()
            
            items = [
                FindingRecord(
                    id=row["id"],
                    scan_id=row["scan_id"],
                    repository=row["repository"],
                    finding_type=row["finding_type"],
                    category=row["category"],
                    severity=row["severity"],
                    states=row["states"],
                    file_path=row["file_path"],
                    line_number=row["line_number"],
                    line_content=row["line_content"] or "",
                    rule_id=row["rule_id"],
                    rule_description=row["rule_description"] or "",
                    status=RemediationStatus(row["status"]),
                    first_seen_date=datetime.fromisoformat(row["first_seen_date"]) if row["first_seen_date"] else datetime.now(),
                    last_seen_date=datetime.fromisoformat(row["last_seen_date"]) if row["last_seen_date"] else datetime.now(),
                    ai_label=row["ai_label"] or "",
                    ai_confidence=row["ai_confidence"] or 0.0,
                    ai_reasons=self._parse_ai_reasons(row["ai_reasons"]),
                    ai_source=row["ai_source"] or "",
                    ai_updated_at=datetime.fromisoformat(row["ai_updated_at"]) if row["ai_updated_at"] else None,
                )
                for row in rows
            ]
        
        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": max(1, (total + page_size - 1) // page_size),
        }

    def get_open_findings(self, organization: Optional[str] = None) -> list[FindingRecord]:
        """Get all open (unresolved) findings."""
        query = """
            SELECT f.* FROM findings f
            JOIN repositories r ON f.repository = r.name
            WHERE f.status = 'open'
        """
        params = []

        if organization:
            query += " AND r.organization = ?"
            params.append(organization)

        query += " ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END"

        with self._connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [
                FindingRecord(
                    id=row["id"],
                    repository=row["repository"],
                    finding_type=row["finding_type"],
                    category=row["category"],
                    severity=row["severity"],
                    file_path=row["file_path"],
                    line_number=row["line_number"],
                    status=RemediationStatus(row["status"]),
                )
                for row in rows
            ]

    def update_finding_ai_triage(
        self,
        finding_id: str,
        ai_label: str,
        ai_confidence: float,
        ai_reasons: list[str],
        ai_source: str,
    ) -> bool:
        """Persist AI triage data for a finding."""
        import json
        
        with self._connection() as conn:
            now = datetime.now().isoformat()
            result = conn.execute("""
                UPDATE findings
                SET ai_label = ?, ai_confidence = ?, ai_reasons = ?, ai_source = ?, ai_updated_at = ?, updated_at = ?
                WHERE id = ?
            """, (
                ai_label,
                ai_confidence,
                json.dumps(ai_reasons or []),
                ai_source,
                now,
                now,
                finding_id,
            ))
            return result.rowcount > 0

    def _parse_ai_reasons(self, value: Optional[str]) -> list[str]:
        if not value:
            return []
        try:
            import json
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except (ValueError, TypeError):
            return []

    def update_finding_status(
        self,
        finding_id: str,
        new_status: RemediationStatus,
        performed_by: str = "",
        comment: str = "",
    ) -> bool:
        """Update the status of a finding."""
        with self._connection() as conn:
            # Get current status
            row = conn.execute(
                "SELECT status FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()

            if not row:
                return False

            old_status = RemediationStatus(row["status"])
            now = datetime.now().isoformat()

            # Update finding
            update_fields = ["status = ?", "updated_at = ?"]
            params = [new_status.value, now]

            if new_status in [RemediationStatus.FIXED, RemediationStatus.WONT_FIX,
                              RemediationStatus.FALSE_POSITIVE, RemediationStatus.ACCEPTED_RISK]:
                update_fields.append("resolved_date = ?")
                params.append(now)

            params.append(finding_id)

            conn.execute(
                f"UPDATE findings SET {', '.join(update_fields)} WHERE id = ?",
                params
            )

            # Record history
            from uuid import uuid4
            conn.execute("""
                INSERT INTO remediation_history (
                    id, finding_id, old_status, new_status, action, performed_by, comment
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                str(uuid4()), finding_id, old_status.value, new_status.value,
                "status_changed", performed_by, comment,
            ))

            return True

    # === Comparison and Analytics ===

    def compare_scans(self, scan_id_1: str, scan_id_2: str) -> dict:
        """
        Compare two scans and return differences.

        Returns dict with 'new', 'fixed', and 'unchanged' findings.
        """
        with self._connection() as conn:
            # Get fingerprints from each scan
            scan1_fingerprints = set(
                row["fingerprint"] for row in conn.execute(
                    "SELECT DISTINCT fingerprint FROM findings WHERE scan_id = ?",
                    (scan_id_1,)
                ).fetchall()
            )

            scan2_fingerprints = set(
                row["fingerprint"] for row in conn.execute(
                    "SELECT DISTINCT fingerprint FROM findings WHERE last_seen_scan_id = ?",
                    (scan_id_2,)
                ).fetchall()
            )

            new_findings = scan2_fingerprints - scan1_fingerprints
            fixed_findings = scan1_fingerprints - scan2_fingerprints
            unchanged = scan1_fingerprints & scan2_fingerprints

            # Get details for new findings
            new_details = []
            if new_findings:
                placeholders = ",".join("?" * len(new_findings))
                rows = conn.execute(
                    f"SELECT * FROM findings WHERE fingerprint IN ({placeholders})",
                    list(new_findings)
                ).fetchall()
                new_details = [dict(row) for row in rows]

            # Get details for fixed findings
            fixed_details = []
            if fixed_findings:
                placeholders = ",".join("?" * len(fixed_findings))
                rows = conn.execute(
                    f"SELECT * FROM findings WHERE fingerprint IN ({placeholders})",
                    list(fixed_findings)
                ).fetchall()
                fixed_details = [dict(row) for row in rows]

            return {
                "scan_1": scan_id_1,
                "scan_2": scan_id_2,
                "new_count": len(new_findings),
                "fixed_count": len(fixed_findings),
                "unchanged_count": len(unchanged),
                "new_findings": new_details,
                "fixed_findings": fixed_details,
            }

    def get_trend_data(
        self,
        organization: Optional[str] = None,
        days: int = 30,
    ) -> list[TrendData]:
        """Get trend data for the last N days."""
        with self._connection() as conn:
            since = (datetime.now() - timedelta(days=days)).isoformat()

            if organization:
                rows = conn.execute("""
                    SELECT 
                        DATE(scan_date) as date,
                        SUM(total_findings) as total,
                        SUM(critical_count) as critical,
                        SUM(high_count) as high,
                        SUM(medium_count) as medium,
                        SUM(low_count) as low
                    FROM scans
                    WHERE organization = ? AND scan_date >= ?
                    GROUP BY DATE(scan_date)
                    ORDER BY date
                """, (organization, since)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT 
                        DATE(scan_date) as date,
                        SUM(total_findings) as total,
                        SUM(critical_count) as critical,
                        SUM(high_count) as high,
                        SUM(medium_count) as medium,
                        SUM(low_count) as low
                    FROM scans
                    WHERE scan_date >= ?
                    GROUP BY DATE(scan_date)
                    ORDER BY date
                """, (since,)).fetchall()

            return [
                TrendData(
                    date=datetime.strptime(row["date"], "%Y-%m-%d"),
                    total_findings=row["total"] or 0,
                    critical=row["critical"] or 0,
                    high=row["high"] or 0,
                    medium=row["medium"] or 0,
                    low=row["low"] or 0,
                )
                for row in rows
            ]

    def get_statistics(self, organization: Optional[str] = None) -> dict:
        """Get overall statistics."""
        with self._connection() as conn:
            base_query = ""
            params = []

            if organization:
                base_query = "WHERE organization = ?"
                params = [organization]

            # Total scans
            total_scans = conn.execute(
                f"SELECT COUNT(*) as count FROM scans {base_query}", params
            ).fetchone()["count"]

            # Total findings by status
            status_query = "SELECT status, COUNT(*) as count FROM findings GROUP BY status"
            status_rows = conn.execute(status_query).fetchall()
            status_counts = {row["status"]: row["count"] for row in status_rows}

            # Total findings by severity
            severity_query = "SELECT severity, COUNT(*) as count FROM findings GROUP BY severity"
            severity_rows = conn.execute(severity_query).fetchall()
            severity_counts = {row["severity"]: row["count"] for row in severity_rows}

            # Total findings by type
            type_query = "SELECT finding_type, COUNT(*) as count FROM findings GROUP BY finding_type"
            type_rows = conn.execute(type_query).fetchall()
            type_counts = {row["finding_type"]: row["count"] for row in type_rows}

            # AI triage counts
            total_findings = conn.execute(
                "SELECT COUNT(*) as count FROM findings"
            ).fetchone()["count"]
            ai_rows = conn.execute("""
                SELECT ai_label, COUNT(*) as count
                FROM findings
                WHERE ai_label IS NOT NULL AND ai_label != ''
                GROUP BY ai_label
            """).fetchall()
            ai_counts = {row["ai_label"]: row["count"] for row in ai_rows}
            ai_labeled_total = sum(ai_counts.values())
            ai_counts["untriaged"] = max(0, total_findings - ai_labeled_total)

            # Count unique repositories
            total_repos = conn.execute(
                "SELECT COUNT(DISTINCT repository) as count FROM findings"
            ).fetchone()["count"]

            # Average findings per scan
            avg_findings = conn.execute(
                f"SELECT AVG(total_findings) as avg FROM scans {base_query}", params
            ).fetchone()["avg"] or 0

            # Most affected repositories
            top_repos = conn.execute("""
                SELECT repository, COUNT(*) as count 
                FROM findings 
                WHERE status = 'open'
                GROUP BY repository 
                ORDER BY count DESC 
                LIMIT 5
            """).fetchall()

            return {
                "total_scans": total_scans,
                "total_repositories": total_repos,
                "status_counts": status_counts,
                "severity_counts": severity_counts,
                "type_counts": type_counts,
                "ai_triage_counts": ai_counts,
                "average_findings_per_scan": round(avg_findings, 1),
                "open_findings": status_counts.get("open", 0),
                "fixed_findings": status_counts.get("fixed", 0),
                "top_affected_repos": [
                    {"name": row["repository"], "findings_count": row["count"]}
                    for row in top_repos
                ],
            }

    def mark_fixed_findings(self, scan_id: str) -> int:
        """
        Mark findings as fixed if they weren't seen in the latest scan.

        Returns number of findings marked as fixed.
        """
        with self._connection() as conn:
            now = datetime.now().isoformat()

            # Find open findings that weren't seen in this scan
            result = conn.execute("""
                UPDATE findings 
                SET status = 'fixed', resolved_date = ?, resolved_in_scan_id = ?, updated_at = ?
                WHERE status = 'open' 
                AND last_seen_scan_id != ?
                AND repository IN (
                    SELECT DISTINCT repository FROM findings WHERE scan_id = ?
                )
            """, (now, scan_id, now, scan_id, scan_id))

            return result.rowcount

    def get_repositories(
        self,
        organization: Optional[str] = None,
        limit: int = 10000,
    ) -> list[dict]:
        """
        Get all repositories from the repositories table.
        
        Returns repositories with aggregated finding counts.
        """
        with self._connection() as conn:
            query = "SELECT * FROM repositories"
            params = []
            
            if organization:
                query += " WHERE organization = ?"
                params.append(organization)
            
            query += " ORDER BY last_scan_date DESC LIMIT ?"
            params.append(limit)
            
            rows = conn.execute(query, params).fetchall()
            
            # Get finding counts by severity for each repository
            repos = []
            for row in rows:
                repo_full_name = row["full_name"]
                
                # Get finding counts by severity
                finding_counts = conn.execute("""
                    SELECT 
                        severity,
                        COUNT(*) as count
                    FROM findings
                    WHERE repository = ? AND status IN ('open', 'in_progress')
                    GROUP BY severity
                """, (repo_full_name,)).fetchall()
                
                counts = {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "total": 0,
                }
                
                for fc in finding_counts:
                    severity = fc["severity"].lower()
                    count = fc["count"]
                    if severity in counts:
                        counts[severity] = count
                    counts["total"] += count
                
                # Handle nullable fields
                url = row["url"] if row["url"] else f"https://github.com/{repo_full_name}"
                default_branch = row["default_branch"] if row["default_branch"] else "main"
                visibility = row["visibility"] if row["visibility"] else "private"
                last_scan_date = row["last_scan_date"] if row["last_scan_date"] else None
                
                repos.append({
                    "id": row["id"],
                    "name": row["name"],
                    "full_name": row["full_name"],
                    "organization": row["organization"],
                    "url": url,
                    "default_branch": default_branch,
                    "language": None,  # Not stored in current schema
                    "is_private": visibility == "private",
                    "is_archived": False,  # Not stored in current schema
                    "last_scan_at": last_scan_date,
                    "findings_count": counts,
                })
            
            return repos
