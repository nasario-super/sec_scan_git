"""
Secrets detection analyzer.

Detects hardcoded secrets, API keys, tokens, and other sensitive
information in source code.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

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
from ..utils.sanitizer import calculate_entropy
from .base import BaseAnalyzer


@dataclass
class SecretPattern:
    """Definition of a secret pattern to detect."""

    name: str
    regex: str
    severity: Severity = Severity.HIGH
    description: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    context_required: bool = False
    context_patterns: list[str] = field(default_factory=list)
    file_patterns: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)
    multiline: bool = False
    entropy_check: bool = True
    min_entropy: float = 3.5
    confidence: float = 0.9

    _compiled_regex: Optional[re.Pattern] = field(default=None, repr=False)
    _compiled_excludes: list[re.Pattern] = field(default_factory=list, repr=False)
    _compiled_contexts: list[re.Pattern] = field(default_factory=list, repr=False)

    def compile(self) -> None:
        """Compile regex patterns for efficiency."""
        flags = re.MULTILINE if self.multiline else 0
        self._compiled_regex = re.compile(self.regex, flags | re.IGNORECASE)

        self._compiled_excludes = [
            re.compile(p, re.IGNORECASE) for p in self.exclude_patterns
        ]

        self._compiled_contexts = [
            re.compile(p, re.IGNORECASE) for p in self.context_patterns
        ]


# Default patterns based on specification
DEFAULT_PATTERNS = [
    SecretPattern(
        name="aws_access_key",
        regex=r"AKIA[0-9A-Z]{16}",
        severity=Severity.CRITICAL,
        description="AWS Access Key ID",
        remediation="Use IAM roles or AWS Secrets Manager instead of hardcoded keys",
        references=["https://docs.aws.amazon.com/secretsmanager/"],
    ),
    SecretPattern(
        name="aws_secret_key",
        regex=r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
        severity=Severity.CRITICAL,
        description="AWS Secret Access Key",
        context_required=True,
        context_patterns=[r"aws", r"secret", r"access"],
        remediation="Use IAM roles or AWS Secrets Manager",
        min_entropy=4.5,
    ),
    SecretPattern(
        name="github_token",
        regex=r"gh[pousr]_[A-Za-z0-9]{36,}",
        severity=Severity.CRITICAL,
        description="GitHub Personal Access Token",
        remediation="Use GitHub Apps or fine-grained tokens with minimal permissions",
        references=["https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"],
    ),
    SecretPattern(
        name="github_fine_grained",
        regex=r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
        severity=Severity.CRITICAL,
        description="GitHub Fine-grained Personal Access Token",
        remediation="Rotate the token and use environment variables",
    ),
    SecretPattern(
        name="private_key_rsa",
        regex=r"-----BEGIN RSA PRIVATE KEY-----",
        severity=Severity.CRITICAL,
        description="RSA Private Key",
        multiline=True,
        remediation="Never commit private keys. Use a secrets manager.",
        entropy_check=False,
    ),
    SecretPattern(
        name="private_key_openssh",
        regex=r"-----BEGIN OPENSSH PRIVATE KEY-----",
        severity=Severity.CRITICAL,
        description="OpenSSH Private Key",
        multiline=True,
        remediation="Never commit private keys. Use a secrets manager.",
        entropy_check=False,
    ),
    SecretPattern(
        name="private_key_ec",
        regex=r"-----BEGIN EC PRIVATE KEY-----",
        severity=Severity.CRITICAL,
        description="EC Private Key",
        multiline=True,
        remediation="Never commit private keys. Use a secrets manager.",
        entropy_check=False,
    ),
    SecretPattern(
        name="jwt_token",
        regex=r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
        severity=Severity.HIGH,
        description="JWT Token",
        remediation="Do not hardcode JWTs. Generate them dynamically.",
        min_entropy=4.0,
    ),
    SecretPattern(
        name="generic_api_key",
        regex=r"(?i)(api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[=:]\s*[\"']?([A-Za-z0-9_\-+/=]{16,})[\"']?",
        severity=Severity.HIGH,
        description="Generic API Key",
        remediation="Use environment variables for API keys",
        exclude_patterns=[r"example", r"placeholder", r"your[_-]?api", r"\$\{", r"<api", r"TODO", r"FIXME"],
        min_entropy=3.5,
    ),
    SecretPattern(
        name="generic_secret_key",
        regex=r"(?i)(secret[_-]?key|secret[_-]?token|secret[_-]?value)\s*[=:]\s*[\"']?([A-Za-z0-9_\-+/=]{20,})[\"']?",
        severity=Severity.HIGH,
        description="Generic Secret Key",
        remediation="Use environment variables or secrets manager",
        exclude_patterns=[r"example", r"placeholder", r"your[_-]?secret", r"\$\{", r"TODO"],
        min_entropy=3.8,
    ),
    SecretPattern(
        name="generic_access_token",
        regex=r"(?i)(access[_-]?token|access_token|accessToken)\s*[=:]\s*[\"']?([A-Za-z0-9_\-+/=]{20,})[\"']?",
        severity=Severity.HIGH,
        description="Generic Access Token",
        remediation="Use environment variables for tokens",
        exclude_patterns=[r"example", r"placeholder", r"your[_-]?token", r"\$\{", r"TODO"],
        min_entropy=3.8,
    ),
    SecretPattern(
        name="generic_password",
        regex=r"(?i)(password|passwd|pwd|secret)\s*[=:]\s*[\"']([^\"']{8,})[\"']",
        severity=Severity.HIGH,
        description="Hardcoded Password",
        remediation="Never hardcode passwords. Use environment variables or a secrets manager.",
        exclude_patterns=[
            r"password.*example",
            r"password.*placeholder",
            r"password.*\$\{",
            r"password.*<%",
            r"password.*\{\{",
            r"getenv",
            r"environ",
            r"process\.env",
        ],
    ),
    SecretPattern(
        name="database_url",
        regex=r"(mysql|postgresql|postgres|mongodb|redis|amqp)://[^:]+:[^@]+@[^\s\"']+",
        severity=Severity.CRITICAL,
        description="Database Connection String with Credentials",
        remediation="Use environment variables for database credentials",
    ),
    SecretPattern(
        name="slack_webhook",
        regex=r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        severity=Severity.HIGH,
        description="Slack Webhook URL",
        remediation="Use environment variables for webhook URLs",
    ),
    SecretPattern(
        name="slack_token",
        regex=r"xox[baprs]-[A-Za-z0-9-]+",
        severity=Severity.CRITICAL,
        description="Slack API Token",
        remediation="Use environment variables and rotate the token",
    ),
    SecretPattern(
        name="stripe_secret_key",
        regex=r"sk_(live|test)_[A-Za-z0-9]{24,}",
        severity=Severity.CRITICAL,
        description="Stripe Secret Key",
        remediation="Use environment variables. Never expose live keys.",
        references=["https://stripe.com/docs/keys"],
    ),
    SecretPattern(
        name="stripe_publishable_key",
        regex=r"pk_(live|test)_[A-Za-z0-9]{24,}",
        severity=Severity.MEDIUM,
        description="Stripe Publishable Key",
        remediation="Publishable keys are less sensitive but should still use env vars",
        confidence=0.7,
    ),
    SecretPattern(
        name="sendgrid_key",
        regex=r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        severity=Severity.HIGH,
        description="SendGrid API Key",
        remediation="Use environment variables for SendGrid keys",
    ),
    SecretPattern(
        name="twilio_key",
        regex=r"SK[a-z0-9]{32}",
        severity=Severity.HIGH,
        description="Twilio API Key",
        remediation="Use environment variables for Twilio credentials",
    ),
    SecretPattern(
        name="azure_storage",
        regex=r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
        severity=Severity.CRITICAL,
        description="Azure Storage Account Key",
        remediation="Use Azure Key Vault or managed identities",
    ),
    SecretPattern(
        name="gcp_service_account",
        regex=r'"type"\s*:\s*"service_account"',
        severity=Severity.CRITICAL,
        description="GCP Service Account Key File",
        file_patterns=["*.json"],
        remediation="Use workload identity or store in a secrets manager",
        entropy_check=False,
    ),
    SecretPattern(
        name="heroku_api_key",
        regex=r"[hH]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        severity=Severity.HIGH,
        description="Heroku API Key",
        remediation="Use environment variables",
    ),
    SecretPattern(
        name="npm_token",
        regex=r"//registry\.npmjs\.org/:_authToken=[A-Za-z0-9-]+",
        severity=Severity.HIGH,
        description="NPM Auth Token",
        remediation="Use environment variables and .npmrc.local",
    ),
    SecretPattern(
        name="pypi_token",
        regex=r"pypi-[A-Za-z0-9_-]{50,}",
        severity=Severity.HIGH,
        description="PyPI API Token",
        remediation="Use environment variables for PyPI tokens",
    ),
    SecretPattern(
        name="google_api_key",
        regex=r"AIza[0-9A-Za-z_-]{35}",
        severity=Severity.HIGH,
        description="Google API Key",
        remediation="Restrict API key and use environment variables",
    ),
    SecretPattern(
        name="firebase_key",
        regex=r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
        severity=Severity.HIGH,
        description="Firebase Cloud Messaging Key",
        remediation="Use environment variables",
    ),
]


# Patterns that indicate a value is safely referenced (not hardcoded)
SAFE_REFERENCE_PATTERNS = [
    r"os\.environ",
    r"os\.getenv",
    r"environ\.get",
    r"process\.env",
    r"getenv\(",
    r"config\.get",
    r"settings\.",
    r"vault\.",
    r"secretmanager",
    r"keyvault",
    r"\$\{",
    r"\{\{",
    r"<%=",
    r"<\?=",
]


class SecretsAnalyzer(BaseAnalyzer):
    """
    Analyzes repositories for hardcoded secrets and sensitive data.
    """

    name = "secrets"
    description = "Detects hardcoded secrets, API keys, and sensitive data"

    def __init__(self, settings: Settings):
        """Initialize secrets analyzer."""
        super().__init__(settings)
        self.patterns = self._load_patterns()
        # Use lower threshold for better detection (can be adjusted per pattern)
        self.entropy_threshold = settings.analyzers.secrets_entropy_threshold
        self.entropy_check_enabled = settings.analyzers.secrets_entropy_check

        # Compile safe reference patterns
        self._safe_patterns = [
            re.compile(p, re.IGNORECASE) for p in SAFE_REFERENCE_PATTERNS
        ]
        
        # Log configuration for debugging
        self.log_info(f"Secrets analyzer initialized: {len(self.patterns)} patterns, entropy_threshold={self.entropy_threshold}")

    def _load_patterns(self) -> list[SecretPattern]:
        """Load and compile secret patterns."""
        patterns = DEFAULT_PATTERNS.copy()

        # Try to load custom patterns from file
        patterns_file = Path(self.settings.analyzers.secrets_patterns_file)
        if patterns_file.exists():
            try:
                with open(patterns_file) as f:
                    custom_patterns = yaml.safe_load(f)

                if custom_patterns and "patterns" in custom_patterns:
                    for p in custom_patterns["patterns"]:
                        patterns.append(SecretPattern(
                            name=p.get("name", "custom"),
                            regex=p["regex"],
                            severity=Severity(p.get("severity", "high")),
                            description=p.get("description", ""),
                            remediation=p.get("remediation", ""),
                            context_required=p.get("context_required", False),
                            exclude_patterns=p.get("exclude_patterns", []),
                        ))
            except (yaml.YAMLError, KeyError, OSError) as e:
                self.log_warning(f"Could not load custom patterns: {e}")

        # Compile all patterns
        for pattern in patterns:
            pattern.compile()

        return patterns

    async def analyze(self, repo: Repository, repo_path: Path) -> list[Finding]:
        """
        Analyze repository for secrets.

        Args:
            repo: Repository metadata
            repo_path: Path to cloned repository

        Returns:
            List of findings
        """
        findings: list[Finding] = []
        self.log_info(f"Analyzing {repo.name} for secrets...")

        for file_path in self.iter_files(repo_path):
            file_findings = self._analyze_file(file_path, repo, repo_path)
            findings.extend(file_findings)

        self.log_info(f"Found {len(findings)} potential secrets in {repo.name}")
        return findings

    def _analyze_file(
        self,
        file_path: Path,
        repo: Repository,
        repo_path: Path,
    ) -> list[Finding]:
        """Analyze a single file for secrets."""
        findings: list[Finding] = []
        relative_path = self.get_relative_path(file_path, repo_path)
        lines = self.read_file_lines(file_path)
        is_noise = self.is_noise_path(file_path)

        for pattern in self.patterns:
            # Check file pattern restrictions
            if pattern.file_patterns:
                if not any(
                    file_path.match(fp) for fp in pattern.file_patterns
                ):
                    continue

            # Search for pattern in file
            for line_num, line_content in lines:
                if not pattern._compiled_regex:
                    continue

                for match in pattern._compiled_regex.finditer(line_content):
                    # Check if this is a false positive
                    if self._is_false_positive(match, line_content, lines, pattern):
                        continue

                    # Check if value is safely referenced (env var, etc.)
                    is_hardcoded = self._is_hardcoded(line_content)

                    # Create finding
                    before, after = self.get_context_lines(lines, line_num)
                    confidence = pattern.confidence * (0.6 if is_noise else 1.0)
                    false_positive = (
                        FalsePositiveLikelihood.HIGH
                        if is_noise
                        else FalsePositiveLikelihood.LOW
                        if is_hardcoded
                        else FalsePositiveLikelihood.MEDIUM
                    )
                    finding = Finding(
                        repository=repo.full_name,
                        type=FindingType.SECRET,
                        category=pattern.name,
                        severity=pattern.severity,
                        states=[FindingState.ACTIVE],
                        state_details=StateDetails(
                            is_in_default_branch=True,
                            is_literal_value=is_hardcoded,
                        ),
                        file_path=relative_path,
                        line_number=line_num,
                        line_content=line_content,
                        column_start=match.start(),
                        column_end=match.end(),
                        branch=repo.default_branch,
                        confidence=confidence,
                        false_positive_likelihood=false_positive,
                        remediation=pattern.remediation,
                        references=pattern.references,
                        rule_id=f"secrets/{pattern.name}",
                        rule_description=pattern.description,
                        matched_pattern=pattern.regex,
                        context_before=before,
                        context_after=after,
                    )

                    # Add HARDCODED state if applicable
                    if is_hardcoded:
                        finding.states.append(FindingState.HARDCODED)

                    findings.append(finding)

        return findings

    def _is_false_positive(
        self,
        match: re.Match,
        line_content: str,
        all_lines: list[tuple[int, str]],
        pattern: SecretPattern,
    ) -> bool:
        """Check if a match is likely a false positive."""
        matched_text = match.group(0)

        # Check exclude patterns
        for exclude in pattern._compiled_excludes:
            if exclude.search(line_content):
                return True

        # Check context requirement
        if pattern.context_required and pattern._compiled_contexts:
            # Look for context in surrounding lines
            context_found = False
            for ctx_pattern in pattern._compiled_contexts:
                if ctx_pattern.search(line_content):
                    context_found = True
                    break

            if not context_found:
                return True

        # Check entropy if enabled (but be less strict for known patterns)
        if pattern.entropy_check and self.entropy_check_enabled:
            # Extract just the secret part from match
            secret_value = matched_text
            if "=" in secret_value or ":" in secret_value:
                # Try to extract value after = or :
                parts = re.split(r'[=:]', secret_value, 1)
                if len(parts) > 1:
                    secret_value = parts[-1]
            secret_value = secret_value.strip("\"' \n\r\t")
            
            # Skip entropy check for very short values (likely false positives)
            if len(secret_value) < 8:
                return True
            
            entropy = calculate_entropy(secret_value)
            # Use a lower threshold for generic patterns to catch more
            threshold = pattern.min_entropy
            if "generic" in pattern.name.lower():
                threshold = max(3.0, threshold - 0.5)  # Lower threshold for generic patterns
            
            if entropy < threshold:
                return True

        # Check common false positive patterns
        false_positive_indicators = [
            r"example",
            r"sample",
            r"test",
            r"dummy",
            r"fake",
            r"mock",
            r"placeholder",
            r"xxx+",
            r"your[_-]?(key|token|secret|password)",
            r"<[^>]+>",  # XML/HTML placeholder tags
            r"\*{3,}",  # Asterisks as placeholder
        ]

        for fp_pattern in false_positive_indicators:
            if re.search(fp_pattern, matched_text, re.IGNORECASE):
                return True

        return False

    def _is_hardcoded(self, line_content: str) -> bool:
        """
        Check if a secret appears to be hardcoded vs safely referenced.

        Args:
            line_content: Line content to check

        Returns:
            True if value appears to be hardcoded (literal value)
        """
        # Check if line contains safe reference patterns
        for safe_pattern in self._safe_patterns:
            if safe_pattern.search(line_content):
                return False

        return True

    def detect_in_string(self, text: str) -> list[dict]:
        """
        Detect secrets in a text string.

        Useful for analyzing git diffs or other non-file content.

        Args:
            text: Text to analyze

        Returns:
            List of detected secrets with pattern info
        """
        detections = []

        for pattern in self.patterns:
            if not pattern._compiled_regex:
                continue

            for match in pattern._compiled_regex.finditer(text):
                detections.append({
                    "pattern": pattern.name,
                    "match": match.group(0),
                    "start": match.start(),
                    "end": match.end(),
                    "severity": pattern.severity.value,
                })

        return detections

