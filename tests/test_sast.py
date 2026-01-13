"""Tests for SAST analyzer."""

import pytest

from github_security_scanner.analyzers.sast import SASTAnalyzer, DEFAULT_RULES
from github_security_scanner.core.config import Settings
from github_security_scanner.core.models import FindingType, Severity


class TestSASTRules:
    """Test SAST detection rules."""

    def test_sql_injection_format_string(self):
        """Test SQL injection detection with format strings."""
        rule = next(r for r in DEFAULT_RULES if "sql-injection" in r.id)
        rule.compile()

        # Should match format string SQL injection
        assert rule._compiled_pattern.search('cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)')
        assert rule._compiled_pattern.search('cursor.execute(f"SELECT * FROM users WHERE name = {name}")')

    def test_xss_innerhtml(self):
        """Test XSS detection with innerHTML."""
        rule = next(r for r in DEFAULT_RULES if r.id == "sast/xss-innerhtml")
        rule.compile()

        assert rule._compiled_pattern.search('element.innerHTML = userInput')
        assert rule._compiled_pattern.search("div.innerHTML= content")

    def test_command_injection_os_system(self):
        """Test command injection detection."""
        rule = next(r for r in DEFAULT_RULES if r.id == "sast/command-injection-os-system")
        rule.compile()

        assert rule._compiled_pattern.search('os.system("rm -rf " + user_input)')
        assert rule._compiled_pattern.search("os.system(command)")

    def test_insecure_pickle(self):
        """Test pickle deserialization detection."""
        rule = next(r for r in DEFAULT_RULES if r.id == "sast/insecure-pickle")
        rule.compile()

        assert rule._compiled_pattern.search("data = pickle.load(file)")
        assert rule._compiled_pattern.search("pickle.loads(user_data)")

    def test_insecure_yaml(self):
        """Test insecure YAML loading detection."""
        rule = next(r for r in DEFAULT_RULES if r.id == "sast/insecure-yaml")
        rule.compile()

        # Should match insecure usage
        assert rule._compiled_pattern.search("yaml.load(data)")

    def test_weak_crypto_md5(self):
        """Test weak crypto detection for MD5."""
        rule = next(r for r in DEFAULT_RULES if r.id == "sast/weak-crypto-md5")
        rule.compile()

        assert rule._compiled_pattern.search("hashlib.md5(password)")
        assert rule._compiled_pattern.search("MD5.Create()")


class TestSASTAnalyzer:
    """Test SASTAnalyzer class."""

    @pytest.fixture
    def analyzer(self, settings: Settings) -> SASTAnalyzer:
        """Create analyzer instance."""
        return SASTAnalyzer(settings)

    @pytest.mark.asyncio
    async def test_analyze_repository(self, analyzer: SASTAnalyzer, temp_repo, sample_repository):
        """Test analyzing a repository."""
        sample_repository.local_path = str(temp_repo)

        findings = await analyzer.analyze(sample_repository, temp_repo)

        # Should find at least some SAST issues
        for finding in findings:
            assert finding.type == FindingType.BUG
            assert finding.repository == sample_repository.name
            assert finding.rule_id.startswith("sast/")

    def test_language_detection(self, analyzer: SASTAnalyzer, tmp_path):
        """Test programming language detection."""
        # Create test files
        (tmp_path / "test.py").write_text("print('hello')")
        (tmp_path / "test.js").write_text("console.log('hello')")
        (tmp_path / "test.java").write_text("System.out.println('hello')")

        assert analyzer._get_file_language(tmp_path / "test.py") == "python"
        assert analyzer._get_file_language(tmp_path / "test.js") == "javascript"
        assert analyzer._get_file_language(tmp_path / "test.java") == "java"
        assert analyzer._get_file_language(tmp_path / "test.txt") is None

