"""
State classifier for findings.

Classifies findings as ACTIVE, HISTORICAL, or HARDCODED
based on their characteristics and git history.
"""

import re
from pathlib import Path
from typing import Optional

from ..core.models import Finding, FindingState, StateDetails
from ..utils.git import GitAnalyzer


# Patterns that indicate a value is from an environment variable or config
ENV_VAR_PATTERNS = [
    r"os\.environ",
    r"os\.getenv",
    r"environ\.get",
    r"process\.env",
    r"getenv\(",
    r"System\.getenv",
    r"\$\{[A-Z_]+\}",
    r"\$[A-Z_]+",
    r"\{\{[^}]+\}\}",
    r"<%=.*%>",
    r"config\.",
    r"settings\.",
    r"options\.",
    r"vault\.",
    r"secretmanager",
    r"keyvault",
    r"ssm\.get",
    r"parameter_store",
]

# Config file patterns that often contain legitimate secrets
CONFIG_FILE_PATTERNS = [
    r"\.env$",
    r"\.env\.",
    r"config\.ya?ml$",
    r"settings\.ya?ml$",
    r"\.config$",
    r"credentials$",
    r"secrets\.ya?ml$",
]


class StateClassifier:
    """
    Classifies findings into ACTIVE, HISTORICAL, or HARDCODED states.

    A finding can have multiple states (e.g., ACTIVE and HARDCODED).
    """

    def __init__(self):
        """Initialize state classifier."""
        self._env_patterns = [
            re.compile(p, re.IGNORECASE) for p in ENV_VAR_PATTERNS
        ]
        self._config_patterns = [
            re.compile(p, re.IGNORECASE) for p in CONFIG_FILE_PATTERNS
        ]

    def classify(
        self,
        finding: Finding,
        repo_path: Optional[Path] = None,
        git: Optional[GitAnalyzer] = None,
    ) -> Finding:
        """
        Classify a finding's state.

        Args:
            finding: Finding to classify
            repo_path: Path to repository (for additional checks)
            git: GitAnalyzer instance (for history checks)

        Returns:
            Finding with updated states
        """
        states = []
        state_details = finding.state_details or StateDetails()

        # Check if active (present in current code)
        if self._is_active(finding, repo_path):
            states.append(FindingState.ACTIVE)
            state_details.is_in_default_branch = True

        # Check if historical (was in code, now removed)
        if self._is_historical(finding, repo_path, git):
            states.append(FindingState.HISTORICAL)
            state_details.still_in_git_history = True

        # Check if hardcoded (literal value vs reference)
        is_hardcoded, details = self._is_hardcoded(finding)
        if is_hardcoded:
            states.append(FindingState.HARDCODED)
            state_details.is_literal_value = details.get("is_literal", False)
            state_details.is_in_config_file = details.get("is_config_file", False)
            state_details.has_env_var_alternative = details.get("has_env_alternative", False)

        # Update finding
        finding.states = states if states else [FindingState.ACTIVE]
        finding.state_details = state_details

        return finding

    def _is_active(
        self,
        finding: Finding,
        repo_path: Optional[Path],
    ) -> bool:
        """
        Check if a finding is currently active in the codebase.

        Args:
            finding: Finding to check
            repo_path: Path to repository

        Returns:
            True if finding is active
        """
        if not repo_path:
            return True  # Assume active if we can't check

        file_path = repo_path / finding.file_path
        if not file_path.exists():
            return False

        try:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                content = f.read()
                # Check if the line content still exists
                return finding.line_content in content
        except OSError:
            return True

    def _is_historical(
        self,
        finding: Finding,
        repo_path: Optional[Path],
        git: Optional[GitAnalyzer],
    ) -> bool:
        """
        Check if a finding is historical (removed but in git history).

        Args:
            finding: Finding to check
            repo_path: Path to repository
            git: GitAnalyzer instance

        Returns:
            True if finding is historical
        """
        # If it's marked as active, it's not purely historical
        # (though it can be both active and historical)
        if FindingState.HISTORICAL in finding.states:
            return True

        if not git or not repo_path:
            return False

        # Check if file was deleted
        file_path = repo_path / finding.file_path
        if not file_path.exists():
            return True

        # Check if the specific content was removed
        try:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                content = f.read()
                if finding.line_content not in content:
                    return True
        except OSError:
            pass

        return False

    def _is_hardcoded(self, finding: Finding) -> tuple[bool, dict]:
        """
        Check if a finding represents a hardcoded value.

        Args:
            finding: Finding to check

        Returns:
            Tuple of (is_hardcoded, details_dict)
        """
        details = {
            "is_literal": False,
            "is_config_file": False,
            "has_env_alternative": False,
        }

        line = finding.line_content
        file_path = finding.file_path

        # Check if it's a config file
        for pattern in self._config_patterns:
            if pattern.search(file_path):
                details["is_config_file"] = True
                break

        # Check if it's referencing an environment variable
        for pattern in self._env_patterns:
            if pattern.search(line):
                # This is a safe reference, not hardcoded
                return False, details

        # Check for literal assignment patterns
        literal_patterns = [
            r'=\s*["\'][^"\']+["\']',  # = "value" or = 'value'
            r':\s*["\'][^"\']+["\']',  # : "value" or : 'value'
        ]

        for pattern in literal_patterns:
            if re.search(pattern, line):
                details["is_literal"] = True
                break

        # If no env var reference found and has literal assignment, it's hardcoded
        is_hardcoded = details["is_literal"] or not any(
            pattern.search(line) for pattern in self._env_patterns
        )

        return is_hardcoded, details

    def classify_batch(
        self,
        findings: list[Finding],
        repo_path: Optional[Path] = None,
        git: Optional[GitAnalyzer] = None,
    ) -> list[Finding]:
        """
        Classify multiple findings.

        Args:
            findings: List of findings to classify
            repo_path: Path to repository
            git: GitAnalyzer instance

        Returns:
            List of classified findings
        """
        return [self.classify(f, repo_path, git) for f in findings]

    def merge_states(
        self,
        active_findings: list[Finding],
        historical_findings: list[Finding],
    ) -> list[Finding]:
        """
        Merge findings from active and historical analysis.

        Combines findings that refer to the same secret.

        Args:
            active_findings: Findings from active code
            historical_findings: Findings from git history

        Returns:
            Merged list of findings
        """
        # Create lookup by key (file_path + line_content hash)
        active_lookup: dict[str, Finding] = {}
        for f in active_findings:
            key = f"{f.file_path}:{hash(f.line_content[:50])}"
            active_lookup[key] = f

        merged = list(active_findings)

        for hist_finding in historical_findings:
            key = f"{hist_finding.file_path}:{hash(hist_finding.line_content[:50])}"

            if key in active_lookup:
                # Merge states - the active finding also has history
                active = active_lookup[key]
                if FindingState.HISTORICAL not in active.states:
                    active.states.append(FindingState.HISTORICAL)
                    # Update state details with historical info
                    active.state_details.still_in_git_history = True
                    if hist_finding.state_details.first_introduced:
                        active.state_details.first_introduced = hist_finding.state_details.first_introduced
                    if hist_finding.state_details.introduced_by:
                        active.state_details.introduced_by = hist_finding.state_details.introduced_by
            else:
                # Purely historical finding
                merged.append(hist_finding)

        return merged


def get_state_priority(states: list[FindingState]) -> int:
    """
    Get priority score for finding states.

    Higher score = higher priority.

    Args:
        states: List of finding states

    Returns:
        Priority score
    """
    score = 0

    # Active findings are highest priority
    if FindingState.ACTIVE in states:
        score += 100

    # Hardcoded adds to priority
    if FindingState.HARDCODED in states:
        score += 50

    # Historical is lower priority but still important
    if FindingState.HISTORICAL in states:
        score += 25

    return score

