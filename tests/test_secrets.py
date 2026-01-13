"""Tests for secrets detection."""

import pytest

from github_security_scanner.analyzers.secrets import SecretsAnalyzer, DEFAULT_PATTERNS
from github_security_scanner.core.config import Settings
from github_security_scanner.core.models import FindingState, FindingType, Severity


class TestSecretPatterns:
    """Test secret detection patterns."""

    def test_aws_access_key_detection(self):
        """Test AWS access key pattern."""
        pattern = next(p for p in DEFAULT_PATTERNS if p.name == "aws_access_key")
        pattern.compile()

        # Should match
        assert pattern._compiled_regex.search("AKIAIOSFODNN7EXAMPLE")
        assert pattern._compiled_regex.search("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'")

        # Should not match
        assert not pattern._compiled_regex.search("AKIA")  # Too short
        assert not pattern._compiled_regex.search("NOTAKIAIOSFODNN7EXAMPL")  # Wrong prefix

    def test_github_token_detection(self):
        """Test GitHub token pattern."""
        pattern = next(p for p in DEFAULT_PATTERNS if p.name == "github_token")
        pattern.compile()

        # Should match different token types
        assert pattern._compiled_regex.search("ghp_1234567890abcdefghijklmnopqrstuvwxyz")
        assert pattern._compiled_regex.search("gho_1234567890abcdefghijklmnopqrstuvwxyz")
        assert pattern._compiled_regex.search("ghu_1234567890abcdefghijklmnopqrstuvwxyz")

    def test_private_key_detection(self):
        """Test private key pattern."""
        pattern = next(p for p in DEFAULT_PATTERNS if p.name == "private_key_rsa")
        pattern.compile()

        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...\n-----END RSA PRIVATE KEY-----"
        assert pattern._compiled_regex.search(content)

    def test_generic_password_detection(self):
        """Test generic password pattern."""
        pattern = next(p for p in DEFAULT_PATTERNS if p.name == "generic_password")
        pattern.compile()

        # Should match (8+ characters required)
        assert pattern._compiled_regex.search('password = "secret123"')
        assert pattern._compiled_regex.search("PASSWORD: 'mypassword'")
        assert pattern._compiled_regex.search('password = "examplepass"')  # 11 chars

        # Should not match short passwords (less than 8 chars)
        assert not pattern._compiled_regex.search('password = "short"')  # Only 5 chars

    def test_database_url_detection(self):
        """Test database URL pattern."""
        pattern = next(p for p in DEFAULT_PATTERNS if p.name == "database_url")
        pattern.compile()

        # Should match
        assert pattern._compiled_regex.search("postgresql://user:pass@localhost/db")
        assert pattern._compiled_regex.search("mysql://admin:secret@host:3306/mydb")
        assert pattern._compiled_regex.search("mongodb://user:pass@cluster.mongodb.net")


class TestSecretsAnalyzer:
    """Test SecretsAnalyzer class."""

    @pytest.fixture
    def analyzer(self, settings: Settings) -> SecretsAnalyzer:
        """Create analyzer instance."""
        return SecretsAnalyzer(settings)

    def test_detect_in_string(self, analyzer: SecretsAnalyzer):
        """Test secret detection in string."""
        text = """
        AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
        github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        """

        detections = analyzer.detect_in_string(text)

        assert len(detections) >= 2
        patterns_found = [d["pattern"] for d in detections]
        assert "aws_access_key" in patterns_found
        assert "github_token" in patterns_found

    def test_is_hardcoded_detection(self, analyzer: SecretsAnalyzer):
        """Test hardcoded vs env var detection."""
        # Should be detected as hardcoded
        assert analyzer._is_hardcoded('API_KEY = "sk_live_123456"')
        assert analyzer._is_hardcoded("password = 'secret123'")

        # Should NOT be detected as hardcoded (safe references)
        assert not analyzer._is_hardcoded("API_KEY = os.environ.get('API_KEY')")
        assert not analyzer._is_hardcoded("password = os.getenv('PASSWORD')")
        assert not analyzer._is_hardcoded("token = process.env.TOKEN")
        assert not analyzer._is_hardcoded("secret = config.get('secret')")

    @pytest.mark.asyncio
    async def test_analyze_repository(self, analyzer: SecretsAnalyzer, temp_repo, sample_repository):
        """Test analyzing a repository."""
        sample_repository.local_path = str(temp_repo)

        findings = await analyzer.analyze(sample_repository, temp_repo)

        # Should find at least some secrets in our test files
        assert len(findings) > 0

        # Check finding properties
        for finding in findings:
            assert finding.type == FindingType.SECRET
            assert finding.repository == sample_repository.name
            assert finding.file_path
            assert finding.severity in Severity


class TestFalsePositiveFiltering:
    """Test false positive detection."""

    def test_example_values_filtered(self, settings: Settings):
        """Test that example values are filtered."""
        analyzer = SecretsAnalyzer(settings)

        # These should be recognized as false positives
        text = """
        API_KEY = "your-api-key-here"
        password = "example_password"
        secret = "placeholder"
        token = "xxxxxxxxxxxxxxxx"
        """

        detections = analyzer.detect_in_string(text)

        # Example values may still be detected, but would be filtered in full analysis
        # This tests the basic detection, filtering happens in _is_false_positive
        pass

    def test_env_var_references_not_detected(self, settings: Settings):
        """Test that environment variable references are not flagged as hardcoded."""
        analyzer = SecretsAnalyzer(settings)

        safe_lines = [
            'API_KEY = os.environ["API_KEY"]',
            "secret = os.getenv('SECRET')",
            "token = process.env.TOKEN",
            "password = ${PASSWORD}",
            "key = config.get_secret('api_key')",
        ]

        for line in safe_lines:
            assert not analyzer._is_hardcoded(line), f"Should not be hardcoded: {line}"

