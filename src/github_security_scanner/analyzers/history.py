"""
Git history analyzer for detecting historical secrets.

Analyzes git history to find secrets that were committed
and later removed but still exist in the repository history.
"""

from datetime import datetime
from pathlib import Path
from typing import Optional

from ..core.config import Settings
from ..core.models import (
    FalsePositiveLikelihood,
    Finding,
    FindingState,
    FindingType,
    Repository,
    Severity,
    StateDetails,
)
from ..utils.git import GitAnalyzer, GitMatch
from .base import BaseAnalyzer
from .secrets import DEFAULT_PATTERNS, SAFE_REFERENCE_PATTERNS, SecretPattern
import re


class HistoryAnalyzer(BaseAnalyzer):
    """
    Analyzes git history for secrets that were added and removed.

    Finds secrets that:
    - Were committed but later deleted
    - Still exist in git history (recoverable)
    - May have been exposed during their lifetime
    """

    name = "history"
    description = "Analyzes git history for historical secrets"

    def __init__(self, settings: Settings):
        """Initialize history analyzer."""
        super().__init__(settings)
        self.patterns = self._load_patterns()
        self.history_depth = settings.scan.history_depth

        # Compile safe reference patterns
        self._safe_patterns = [
            re.compile(p, re.IGNORECASE) for p in SAFE_REFERENCE_PATTERNS
        ]

    def _load_patterns(self) -> list[SecretPattern]:
        """Load secret patterns for history analysis."""
        patterns = [p for p in DEFAULT_PATTERNS if not p.multiline]
        for pattern in patterns:
            pattern.compile()
        return patterns

    async def analyze(self, repo: Repository, repo_path: Path) -> list[Finding]:
        """
        Analyze repository git history for secrets.

        Args:
            repo: Repository metadata
            repo_path: Path to cloned repository

        Returns:
            List of findings
        """
        if not self.settings.scan.analyze_history:
            return []

        findings: list[Finding] = []
        self.log_info(f"Analyzing git history of {repo.name}...")

        git = GitAnalyzer(repo_path)
        if not git.is_valid_repo():
            self.log_warning(f"Not a valid git repository: {repo_path}")
            return findings

        # Track secrets we find to avoid duplicates
        seen_secrets: set[str] = set()

        for pattern in self.patterns:
            if not pattern._compiled_regex:
                continue

            # Search git history for the pattern
            try:
                for match in git.search_history_regex(
                    pattern.regex,
                    max_commits=self.history_depth,
                ):
                    # Create unique key for this secret
                    secret_key = f"{pattern.name}:{match.file_path}:{match.line_content[:50]}"
                    if secret_key in seen_secrets:
                        continue
                    seen_secrets.add(secret_key)

                    # Skip if it's a safe reference
                    if self._is_safe_reference(match.line_content):
                        continue

                    # Determine if secret is still active
                    is_active = self._check_if_active(git, match, repo_path)
                    is_historical = not is_active and not match.is_addition

                    # Only create finding if it's historical (was added and removed)
                    # or if it's a removal we found in history
                    if is_historical or (not match.is_addition and not is_active):
                        finding = self._create_historical_finding(
                            repo=repo,
                            pattern=pattern,
                            match=match,
                            is_still_in_history=True,
                        )
                        findings.append(finding)

            except Exception as e:
                self.log_warning(f"Error searching history for {pattern.name}: {e}")

        # Deduplicate and keep the most relevant findings
        findings = self._deduplicate_findings(findings)

        self.log_info(f"Found {len(findings)} historical secrets in {repo.name}")
        return findings

    def _is_safe_reference(self, content: str) -> bool:
        """Check if content is a safe reference to a secret."""
        for safe_pattern in self._safe_patterns:
            if safe_pattern.search(content):
                return True
        return False

    def _check_if_active(
        self,
        git: GitAnalyzer,
        match: GitMatch,
        repo_path: Path,
    ) -> bool:
        """Check if a secret is still present in current HEAD."""
        # Check if file exists in current HEAD
        if not git.is_file_in_head(match.file_path):
            return False

        # Read current file content
        current_file = repo_path / match.file_path
        if not current_file.exists():
            return False

        try:
            content = current_file.read_text(encoding="utf-8", errors="replace")
            # Check if the exact line content exists
            return match.line_content in content
        except OSError:
            return False

    def _find_removal_commit(
        self,
        git: GitAnalyzer,
        file_path: str,
        secret_content: str,
    ) -> Optional[dict]:
        """Find the commit where a secret was removed."""
        try:
            history = git.get_file_history(file_path, max_commits=100)
            for commit in history:
                content = git.get_file_at_commit(file_path, commit["sha"])
                if content and secret_content not in content:
                    return commit
        except Exception:
            pass
        return None

    def _create_historical_finding(
        self,
        repo: Repository,
        pattern: SecretPattern,
        match: GitMatch,
        is_still_in_history: bool,
    ) -> Finding:
        """Create a finding for a historical secret."""
        # Calculate exposure duration if possible
        exposure_days = 0
        if match.commit_date:
            exposure_days = (datetime.now() - match.commit_date).days

        state_details = StateDetails(
            is_in_default_branch=False,
            is_literal_value=True,
            first_introduced=match.commit_date,
            introduced_by=match.commit_author,
            removed_in_commit=None,  # Would need additional lookup
            removed_date=None,
            exposure_duration_days=exposure_days,
            still_in_git_history=is_still_in_history,
        )

        return Finding(
            repository=repo.name,
            type=FindingType.SECRET,
            category=pattern.name,
            severity=pattern.severity,
            states=[FindingState.HISTORICAL],
            state_details=state_details,
            file_path=match.file_path,
            line_number=match.line_number,
            line_content=match.line_content,
            branch=repo.default_branch,
            commit_sha=match.commit_sha,
            commit_date=match.commit_date,
            commit_author=match.commit_author,
            confidence=pattern.confidence * 0.9,  # Slightly lower confidence for historical
            false_positive_likelihood=FalsePositiveLikelihood.MEDIUM,
            remediation=(
                f"This secret was committed on {match.commit_date.strftime('%Y-%m-%d') if match.commit_date else 'unknown date'}. "
                f"Although removed from current code, it still exists in git history. "
                f"Consider: 1) Rotating the secret, 2) Using git-filter-repo to remove from history, "
                f"3) If repo was public, assume the secret is compromised."
            ),
            references=pattern.references,
            rule_id=f"history/{pattern.name}",
            rule_description=f"Historical {pattern.description}",
            matched_pattern=pattern.regex,
            context_before=match.diff_context[:3] if match.diff_context else [],
            context_after=[],
            tags=["historical", "git-history"],
        )

    def _deduplicate_findings(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings, keeping the earliest occurrence."""
        seen: dict[str, Finding] = {}

        for finding in findings:
            # Create key from pattern and content
            key = f"{finding.category}:{finding.line_content[:50]}"

            if key not in seen:
                seen[key] = finding
            else:
                # Keep the earlier finding (older commit)
                existing = seen[key]
                if (finding.commit_date and existing.commit_date and
                        finding.commit_date < existing.commit_date):
                    seen[key] = finding

        return list(seen.values())


async def analyze_git_diff_for_secrets(
    diff_content: str,
    patterns: list[SecretPattern],
) -> list[dict]:
    """
    Analyze a git diff for secrets.

    Useful for analyzing PRs or specific commits.

    Args:
        diff_content: Git diff content
        patterns: Secret patterns to search for

    Returns:
        List of detected secrets with context
    """
    findings = []

    for line in diff_content.split("\n"):
        # Only check added lines
        if not line.startswith("+") or line.startswith("+++"):
            continue

        content = line[1:]  # Remove the + prefix

        for pattern in patterns:
            if not pattern._compiled_regex:
                continue

            if pattern._compiled_regex.search(content):
                findings.append({
                    "pattern": pattern.name,
                    "severity": pattern.severity.value,
                    "content": content[:100],
                    "is_addition": True,
                })

    return findings

