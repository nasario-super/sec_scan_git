"""
Severity classifier and normalizer for findings.

Provides consistent severity classification across different
analyzers and vulnerability sources.
"""

from typing import Optional

from ..core.models import Finding, FindingState, Severity


# CVSS to Severity mapping
CVSS_SEVERITY_MAP = [
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
    (0.0, Severity.INFO),
]

# Severity adjustment factors based on state
STATE_SEVERITY_MODIFIERS = {
    FindingState.ACTIVE: 0,      # No change
    FindingState.HARDCODED: 0,   # No change (already bad)
    FindingState.HISTORICAL: -1,  # Reduce severity by one level
}


class SeverityClassifier:
    """
    Normalizes and adjusts severity levels for findings.

    Provides consistent severity classification based on:
    - CVSS scores
    - Finding states
    - Context factors
    """

    def __init__(
        self,
        adjust_for_state: bool = True,
        min_severity: Optional[Severity] = None,
    ):
        """
        Initialize severity classifier.

        Args:
            adjust_for_state: Whether to adjust severity based on state
            min_severity: Minimum severity to report
        """
        self.adjust_for_state = adjust_for_state
        self.min_severity = min_severity

    def classify(self, finding: Finding) -> Finding:
        """
        Classify/normalize the severity of a finding.

        Args:
            finding: Finding to classify

        Returns:
            Finding with normalized severity
        """
        # If CVSS score is available, use it as primary source
        if finding.cvss_score is not None:
            finding.severity = self.from_cvss(finding.cvss_score)

        # Adjust based on state if enabled
        if self.adjust_for_state:
            finding.severity = self._adjust_for_state(finding)

        # Adjust based on confidence
        finding.severity = self._adjust_for_confidence(finding)

        return finding

    def from_cvss(self, cvss_score: float) -> Severity:
        """
        Convert CVSS score to severity level.

        Args:
            cvss_score: CVSS score (0.0 - 10.0)

        Returns:
            Severity level
        """
        for threshold, severity in CVSS_SEVERITY_MAP:
            if cvss_score >= threshold:
                return severity
        return Severity.INFO

    def _adjust_for_state(self, finding: Finding) -> Severity:
        """Adjust severity based on finding state."""
        severity = finding.severity

        # If only historical, reduce severity
        if (FindingState.HISTORICAL in finding.states and
                FindingState.ACTIVE not in finding.states):
            severity = self._decrease_severity(severity)

        return severity

    def _adjust_for_confidence(self, finding: Finding) -> Severity:
        """Adjust severity based on confidence level."""
        # Very low confidence findings get severity reduced
        if finding.confidence < 0.5:
            return self._decrease_severity(finding.severity)
        return finding.severity

    def _decrease_severity(self, severity: Severity) -> Severity:
        """Decrease severity by one level."""
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        try:
            idx = order.index(severity)
            if idx > 0:
                return order[idx - 1]
        except ValueError:
            pass
        return severity

    def _increase_severity(self, severity: Severity) -> Severity:
        """Increase severity by one level."""
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        try:
            idx = order.index(severity)
            if idx < len(order) - 1:
                return order[idx + 1]
        except ValueError:
            pass
        return severity

    def filter_by_min_severity(self, findings: list[Finding]) -> list[Finding]:
        """
        Filter findings by minimum severity.

        Args:
            findings: List of findings to filter

        Returns:
            Filtered list of findings
        """
        if not self.min_severity:
            return findings

        severity_order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }

        min_level = severity_order.get(self.min_severity, 0)

        return [
            f for f in findings
            if severity_order.get(f.severity, 0) >= min_level
        ]

    def classify_batch(self, findings: list[Finding]) -> list[Finding]:
        """
        Classify multiple findings.

        Args:
            findings: List of findings to classify

        Returns:
            List of classified findings
        """
        classified = [self.classify(f) for f in findings]

        if self.min_severity:
            classified = self.filter_by_min_severity(classified)

        return classified


def get_severity_color(severity: Severity) -> str:
    """
    Get Rich console color for a severity level.

    Args:
        severity: Severity level

    Returns:
        Color name for Rich console
    """
    colors = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }
    return colors.get(severity, "white")


def get_severity_emoji(severity: Severity) -> str:
    """
    Get emoji for a severity level.

    Args:
        severity: Severity level

    Returns:
        Emoji string
    """
    emojis = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
        Severity.INFO: "⚪",
    }
    return emojis.get(severity, "⚪")


def sort_by_severity(
    findings: list[Finding],
    descending: bool = True,
) -> list[Finding]:
    """
    Sort findings by severity.

    Args:
        findings: List of findings to sort
        descending: Sort in descending order (critical first)

    Returns:
        Sorted list of findings
    """
    severity_order = {
        Severity.CRITICAL: 4,
        Severity.HIGH: 3,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
        Severity.INFO: 0,
    }

    return sorted(
        findings,
        key=lambda f: severity_order.get(f.severity, 0),
        reverse=descending,
    )

