"""
Configuration management for the GitHub Security Scanner.

Uses Pydantic Settings for validation and environment variable support.
"""

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class GitHubSettings(BaseSettings):
    """GitHub API configuration."""

    token: str = Field(default="", description="GitHub Personal Access Token")
    app_id: Optional[int] = Field(default=None, description="GitHub App ID")
    private_key_path: Optional[str] = Field(default=None, description="Path to GitHub App private key")
    installation_id: Optional[int] = Field(default=None, description="GitHub App installation ID")
    api_url: str = Field(default="https://api.github.com", description="GitHub API URL")
    timeout: int = Field(default=30, description="API request timeout in seconds")
    retries: int = Field(default=3, description="Number of retries for failed requests")


class ScanSettings(BaseSettings):
    """Scan configuration."""

    parallel_repos: int = Field(default=8, ge=1, le=64, description="Number of repos to scan in parallel")
    parallel_analyzers: int = Field(default=4, ge=1, le=16, description="Number of analyzers to run in parallel")
    repo_timeout: int = Field(default=600, description="Timeout per repository in seconds")
    clone_strategy: str = Field(default="shallow", description="Clone strategy: full, shallow, sparse")
    
    # Batch processing for large organizations
    batch_size: int = Field(default=50, ge=10, le=200, description="Number of repos per batch")
    batch_delay_seconds: int = Field(default=5, ge=0, le=60, description="Delay between batches")
    
    # Multi-branch analysis
    analyze_all_branches: bool = Field(default=False, description="Analyze all branches, not just default")
    max_branches_per_repo: int = Field(default=10, ge=1, le=50, description="Maximum branches to analyze per repo")
    
    # Incremental scanning
    incremental_enabled: bool = Field(default=False, description="Enable incremental scanning")
    incremental_since_hours: int = Field(default=24, description="Hours to look back for incremental scan")
    branches: list[str] = Field(default=["default"], description="Branches to analyze")
    analyze_history: bool = Field(default=True, description="Whether to analyze git history")
    history_depth: Optional[int] = Field(default=1000, description="Number of commits to analyze (None = all)")

    # Filters
    include_languages: list[str] = Field(default_factory=list, description="Languages to include (empty = all)")
    exclude_languages: list[str] = Field(default_factory=list, description="Languages to exclude")
    include_repos: list[str] = Field(default_factory=list, description="Repos to include (patterns)")
    exclude_repos: list[str] = Field(default_factory=list, description="Repos to exclude (patterns)")

    # Skip paths
    exclude_paths: list[str] = Field(
        default=[
            "node_modules/",
            "vendor/",
            ".git/",
            "*.min.js",
            "*.lock",
            "__pycache__/",
            ".venv/",
            "venv/",
            "dist/",
            "build/",
            # Note: .env files are NOT excluded - they often contain secrets!
            # Only exclude example/template env files
            ".env.example",
            ".env.template",
            ".env.sample",
        ],
        description="Paths to exclude from scanning",
    )

    max_file_size_mb: int = Field(default=10, description="Maximum file size to analyze in MB")

    @field_validator("clone_strategy")
    @classmethod
    def validate_clone_strategy(cls, v: str) -> str:
        """Validate clone strategy."""
        valid = ["full", "shallow", "sparse"]
        if v not in valid:
            raise ValueError(f"clone_strategy must be one of {valid}")
        return v


class AnalyzerSettings(BaseSettings):
    """Analyzer configuration."""

    secrets_enabled: bool = Field(default=True, description="Enable secrets detection")
    secrets_patterns_file: str = Field(default="patterns/secrets.yaml", description="Secrets patterns file")
    secrets_entropy_check: bool = Field(default=True, description="Enable entropy checking")
    secrets_entropy_threshold: float = Field(default=3.5, description="Entropy threshold for detection (lowered to catch more secrets)")

    vulnerabilities_enabled: bool = Field(default=True, description="Enable vulnerability scanning")
    vulnerabilities_ecosystems: list[str] = Field(
        default=["python", "javascript", "java", "go"],
        description="Ecosystems to scan for vulnerabilities",
    )
    vulnerabilities_fail_on_severity: str = Field(default="high", description="Fail threshold severity")

    sast_enabled: bool = Field(default=True, description="Enable SAST analysis")
    sast_rules_file: str = Field(default="patterns/sast_rules.yaml", description="SAST rules file")

    iac_enabled: bool = Field(default=True, description="Enable IaC scanning")
    iac_checks_file: str = Field(default="patterns/iac_checks.yaml", description="IaC checks file")


class OutputSettings(BaseSettings):
    """Output configuration."""

    formats: list[str] = Field(default=["json", "html"], description="Output formats")
    directory: str = Field(default="./reports", description="Output directory")
    filename_template: str = Field(default="scan-{org}-{date}", description="Filename template")
    redact_secrets: bool = Field(default=True, description="Redact sensitive values in output")
    redact_pattern: str = Field(default="[REDACTED]", description="Pattern to use for redaction")

    sarif_enabled: bool = Field(default=True, description="Generate SARIF output")
    sarif_upload_to_github: bool = Field(default=False, description="Upload SARIF to GitHub Security")


class NotificationSettings(BaseSettings):
    """Notification configuration."""

    slack_enabled: bool = Field(default=False, description="Enable Slack notifications")
    slack_webhook_url: str = Field(default="", description="Slack webhook URL")
    slack_severity_threshold: str = Field(default="high", description="Minimum severity for notifications")

    email_enabled: bool = Field(default=False, description="Enable email notifications")
    email_smtp_host: str = Field(default="", description="SMTP host")
    email_smtp_port: int = Field(default=587, description="SMTP port")
    email_recipients: list[str] = Field(default_factory=list, description="Email recipients")


class CacheSettings(BaseSettings):
    """Cache configuration."""

    enabled: bool = Field(default=True, description="Enable caching")
    directory: str = Field(default="./.scanner-cache", description="Cache directory")
    ttl_hours: int = Field(default=24, description="Cache TTL in hours")


class LoggingSettings(BaseSettings):
    """Logging configuration."""

    level: str = Field(default="INFO", description="Log level")
    format: str = Field(default="json", description="Log format: json or text")
    file: Optional[str] = Field(default=None, description="Log file path")


class Settings(BaseSettings):
    """
    Main settings class that aggregates all configuration.

    Settings are loaded from:
    1. Environment variables (highest priority)
    2. .env file
    3. config.yaml file
    4. Default values (lowest priority)
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="ignore",
    )

    github: GitHubSettings = Field(default_factory=GitHubSettings)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    analyzers: AnalyzerSettings = Field(default_factory=AnalyzerSettings)
    output: OutputSettings = Field(default_factory=OutputSettings)
    notifications: NotificationSettings = Field(default_factory=NotificationSettings)
    cache: CacheSettings = Field(default_factory=CacheSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Settings":
        """Load settings from a YAML file."""
        path = Path(path)
        if not path.exists():
            return cls()

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        # Process environment variable references in the YAML
        data = cls._process_env_vars(data)

        return cls(**data)

    @classmethod
    def _process_env_vars(cls, data: Any) -> Any:
        """Recursively process environment variable references in config."""
        if isinstance(data, dict):
            return {k: cls._process_env_vars(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [cls._process_env_vars(item) for item in data]
        elif isinstance(data, str):
            # Handle ${ENV_VAR} syntax
            if data.startswith("${") and data.endswith("}"):
                env_var = data[2:-1]
                return os.environ.get(env_var, "")
            return data
        return data

    def get_patterns_dir(self) -> Path:
        """Get the patterns directory path."""
        # Try relative to config file, then package, then cwd
        possible_paths = [
            Path(__file__).parent.parent.parent.parent / "patterns",
            Path.cwd() / "patterns",
            Path(__file__).parent.parent / "patterns",
        ]
        for path in possible_paths:
            if path.exists():
                return path
        return Path.cwd() / "patterns"


@lru_cache
def get_settings(config_path: Optional[str] = None) -> Settings:
    """
    Get cached settings instance.

    Args:
        config_path: Optional path to config.yaml file

    Returns:
        Settings instance
    """
    if config_path:
        return Settings.from_yaml(config_path)

    # Try to find config.yaml in common locations
    possible_configs = [
        Path.cwd() / "config.yaml",
        Path.cwd() / ".github-security-scanner.yaml",
        Path.home() / ".config" / "github-security-scanner" / "config.yaml",
    ]

    for config in possible_configs:
        if config.exists():
            return Settings.from_yaml(config)

    # Return default settings with env vars
    return Settings()


def create_default_config(path: str | Path) -> None:
    """Create a default configuration file."""
    default_config = """# GitHub Security Scanner Configuration

github:
  # Authentication (can use env var GITHUB_TOKEN)
  token: ${GITHUB_TOKEN}
  
  # Or GitHub App authentication
  # app_id: null
  # private_key_path: null
  # installation_id: null
  
  # API settings
  api_url: https://api.github.com
  timeout: 30
  retries: 3

scan:
  # Parallelism
  parallel_repos: 4
  parallel_analyzers: 2
  
  # Timeout per repo (seconds)
  repo_timeout: 600
  
  # Clone strategy: full, shallow, sparse
  clone_strategy: shallow
  
  # Branches to analyze
  branches:
    - default
  
  # History analysis
  analyze_history: true
  history_depth: 1000
  
  # Filters
  include_languages: []
  exclude_languages: []
  include_repos: []
  exclude_repos:
    - "*-deprecated"
    - "archive-*"
  
  # Skip paths
  exclude_paths:
    - "node_modules/"
    - "vendor/"
    - ".git/"
    - "*.min.js"
    - "*.lock"
    - "__pycache__/"
    - ".venv/"
  
  max_file_size_mb: 10

analyzers:
  secrets_enabled: true
  secrets_patterns_file: patterns/secrets.yaml
  secrets_entropy_check: true
  secrets_entropy_threshold: 4.5
  
  vulnerabilities_enabled: true
  vulnerabilities_ecosystems:
    - python
    - javascript
    - java
    - go
  vulnerabilities_fail_on_severity: high
  
  sast_enabled: true
  sast_rules_file: patterns/sast_rules.yaml
  
  iac_enabled: true
  iac_checks_file: patterns/iac_checks.yaml

output:
  formats:
    - json
    - html
  directory: ./reports
  filename_template: "scan-{org}-{date}"
  redact_secrets: true
  redact_pattern: "[REDACTED]"
  sarif_enabled: true
  sarif_upload_to_github: false

notifications:
  slack_enabled: false
  slack_webhook_url: ${SLACK_WEBHOOK}
  slack_severity_threshold: high
  
  email_enabled: false
  email_smtp_host: ""
  email_recipients: []

cache:
  enabled: true
  directory: ./.scanner-cache
  ttl_hours: 24

logging:
  level: INFO
  format: json
  file: null
"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(default_config)

