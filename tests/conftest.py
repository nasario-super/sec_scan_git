"""Pytest configuration and fixtures."""

import tempfile
from pathlib import Path

import pytest

from github_security_scanner.core.config import Settings
from github_security_scanner.core.models import Finding, FindingState, FindingType, Repository, Severity


@pytest.fixture
def settings() -> Settings:
    """Create test settings."""
    return Settings()


@pytest.fixture
def temp_repo(tmp_path: Path) -> Path:
    """Create a temporary repository structure."""
    # Create some test files
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("""
# Example Python file
import os

API_KEY = "test_api_key_12345"
password = os.environ.get("PASSWORD")

def connect():
    conn = f"mysql://user:{password}@localhost/db"
    return conn
""")

    (tmp_path / "config.yaml").write_text("""
database:
  host: localhost
  password: secret123
""")

    (tmp_path / "Dockerfile").write_text("""
FROM python:3.11-slim
USER root
ENV SECRET_KEY=mysecret123
COPY . /app
""")

    return tmp_path


@pytest.fixture
def sample_finding() -> Finding:
    """Create a sample finding."""
    return Finding(
        repository="test-repo",
        type=FindingType.SECRET,
        category="aws_access_key",
        severity=Severity.CRITICAL,
        states=[FindingState.ACTIVE, FindingState.HARDCODED],
        file_path="src/config.py",
        line_number=10,
        line_content="AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
        branch="main",
        confidence=0.95,
        remediation="Use environment variables or AWS Secrets Manager",
        rule_id="secrets/aws_access_key",
    )


@pytest.fixture
def sample_repository() -> Repository:
    """Create a sample repository."""
    return Repository(
        name="test-repo",
        full_name="org/test-repo",
        url="https://github.com/org/test-repo",
        clone_url="https://github.com/org/test-repo.git",
        default_branch="main",
        languages=["python", "javascript"],
        visibility="private",
    )

