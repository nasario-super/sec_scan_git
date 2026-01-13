"""Tests for state and severity classifiers."""

import pytest

from github_security_scanner.classifiers.state import StateClassifier
from github_security_scanner.classifiers.severity import SeverityClassifier, sort_by_severity
from github_security_scanner.core.models import Finding, FindingState, FindingType, Severity


class TestStateClassifier:
    """Test StateClassifier class."""

    @pytest.fixture
    def classifier(self) -> StateClassifier:
        """Create classifier instance."""
        return StateClassifier()

    def test_hardcoded_detection(self, classifier: StateClassifier, sample_finding: Finding):
        """Test hardcoded value detection."""
        # Hardcoded value
        sample_finding.line_content = 'API_KEY = "sk_live_123456789"'
        is_hardcoded, details = classifier._is_hardcoded(sample_finding)

        assert is_hardcoded
        assert details["is_literal"]

    def test_env_var_not_hardcoded(self, classifier: StateClassifier, sample_finding: Finding):
        """Test that env var references are not marked as hardcoded."""
        env_var_lines = [
            'API_KEY = os.environ.get("API_KEY")',
            "secret = os.getenv('SECRET')",
            "token = process.env.TOKEN",
            "password = config.get('password')",
            "key = vault.read('secret/key')",
        ]

        for line in env_var_lines:
            sample_finding.line_content = line
            is_hardcoded, _ = classifier._is_hardcoded(sample_finding)
            assert not is_hardcoded, f"Should not be hardcoded: {line}"

    def test_config_file_detection(self, classifier: StateClassifier, sample_finding: Finding):
        """Test config file detection."""
        config_files = [".env", ".env.local", "config.yaml", "settings.yml"]

        for filename in config_files:
            sample_finding.file_path = filename
            sample_finding.line_content = "password = 'secret123'"
            _, details = classifier._is_hardcoded(sample_finding)
            assert details["is_config_file"], f"Should detect as config file: {filename}"


class TestSeverityClassifier:
    """Test SeverityClassifier class."""

    @pytest.fixture
    def classifier(self) -> SeverityClassifier:
        """Create classifier instance."""
        return SeverityClassifier()

    def test_cvss_to_severity(self, classifier: SeverityClassifier):
        """Test CVSS to severity conversion."""
        assert classifier.from_cvss(9.5) == Severity.CRITICAL
        assert classifier.from_cvss(9.0) == Severity.CRITICAL
        assert classifier.from_cvss(8.0) == Severity.HIGH
        assert classifier.from_cvss(7.0) == Severity.HIGH
        assert classifier.from_cvss(5.0) == Severity.MEDIUM
        assert classifier.from_cvss(4.0) == Severity.MEDIUM
        assert classifier.from_cvss(2.0) == Severity.LOW
        assert classifier.from_cvss(0.0) == Severity.INFO

    def test_severity_filter(self, classifier: SeverityClassifier):
        """Test filtering by minimum severity."""
        classifier.min_severity = Severity.HIGH

        findings = [
            Finding(severity=Severity.CRITICAL, type=FindingType.SECRET, repository="test"),
            Finding(severity=Severity.HIGH, type=FindingType.SECRET, repository="test"),
            Finding(severity=Severity.MEDIUM, type=FindingType.SECRET, repository="test"),
            Finding(severity=Severity.LOW, type=FindingType.SECRET, repository="test"),
        ]

        filtered = classifier.filter_by_min_severity(findings)

        assert len(filtered) == 2
        assert all(f.severity in [Severity.CRITICAL, Severity.HIGH] for f in filtered)

    def test_sort_by_severity(self):
        """Test sorting findings by severity."""
        findings = [
            Finding(severity=Severity.LOW, type=FindingType.SECRET, repository="test"),
            Finding(severity=Severity.CRITICAL, type=FindingType.SECRET, repository="test"),
            Finding(severity=Severity.MEDIUM, type=FindingType.SECRET, repository="test"),
            Finding(severity=Severity.HIGH, type=FindingType.SECRET, repository="test"),
        ]

        sorted_findings = sort_by_severity(findings)

        assert sorted_findings[0].severity == Severity.CRITICAL
        assert sorted_findings[1].severity == Severity.HIGH
        assert sorted_findings[2].severity == Severity.MEDIUM
        assert sorted_findings[3].severity == Severity.LOW

    def test_historical_severity_reduction(self, classifier: SeverityClassifier):
        """Test that historical-only findings have reduced severity."""
        finding = Finding(
            type=FindingType.SECRET,
            repository="test",
            severity=Severity.CRITICAL,
            states=[FindingState.HISTORICAL],
            confidence=0.9,  # High confidence so it doesn't reduce further
        )

        classified = classifier.classify(finding)

        # Historical findings should have reduced severity (CRITICAL -> HIGH)
        assert classified.severity == Severity.HIGH

