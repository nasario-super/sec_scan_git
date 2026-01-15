"""
Infrastructure as Code (IaC) security analyzer.

Detects security misconfigurations in Terraform, Kubernetes,
Docker, and other infrastructure definition files.
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
from .base import BaseAnalyzer


@dataclass
class IaCCheck:
    """Definition of an IaC security check."""

    id: str
    name: str
    pattern: str
    severity: Severity = Severity.MEDIUM
    description: str = ""
    remediation: str = ""
    iac_type: str = ""  # terraform, kubernetes, docker, cloudformation
    file_patterns: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    multiline: bool = False
    confidence: float = 0.85

    _compiled_pattern: Optional[re.Pattern] = field(default=None, repr=False)
    _compiled_excludes: list[re.Pattern] = field(default_factory=list, repr=False)

    def compile(self) -> None:
        """Compile regex patterns."""
        flags = re.MULTILINE | re.DOTALL if self.multiline else re.MULTILINE
        try:
            self._compiled_pattern = re.compile(self.pattern, flags | re.IGNORECASE)
        except re.error:
            self._compiled_pattern = None

        self._compiled_excludes = []
        for exclude in self.exclude_patterns:
            try:
                self._compiled_excludes.append(re.compile(exclude, re.IGNORECASE))
            except re.error:
                pass


# IaC file type detection
IAC_FILE_TYPES = {
    "terraform": {
        "extensions": {".tf", ".tf.json"},
        "filenames": set(),
    },
    "kubernetes": {
        "extensions": {".yaml", ".yml"},
        "filenames": set(),
        "content_patterns": [r"apiVersion:", r"kind:\s*(?:Deployment|Pod|Service|ConfigMap|Secret)"],
    },
    "docker": {
        "extensions": set(),
        "filenames": {"Dockerfile", "dockerfile", "Containerfile"},
        "name_patterns": [r"Dockerfile.*", r".*\.dockerfile"],
    },
    "cloudformation": {
        "extensions": {".yaml", ".yml", ".json"},
        "content_patterns": [r"AWSTemplateFormatVersion", r"Resources:"],
    },
    "ansible": {
        "extensions": {".yaml", ".yml"},
        "filenames": set(),
        "content_patterns": [r"hosts:", r"tasks:", r"- name:"],
    },
    "helm": {
        "extensions": {".yaml", ".yml"},
        "path_patterns": [r"templates/", r"charts/"],
    },
}


# Default IaC checks based on specification
DEFAULT_CHECKS = [
    # Terraform checks
    IaCCheck(
        id="iac/tf-s3-no-encryption",
        name="S3 Bucket Without Encryption",
        pattern=r'resource\s+"aws_s3_bucket"\s+"[^"]+"\s*\{(?:(?!server_side_encryption).)*\}',
        severity=Severity.HIGH,
        description="S3 bucket does not have server-side encryption enabled",
        remediation="Enable server_side_encryption_configuration for the S3 bucket",
        iac_type="terraform",
        file_patterns=["*.tf"],
        multiline=True,
        references=["https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration"],
    ),
    IaCCheck(
        id="iac/tf-sg-open-ssh",
        name="Security Group Open SSH",
        pattern=r'ingress\s*\{[^}]*(?:from_port\s*=\s*22|to_port\s*=\s*22)[^}]*cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"',
        severity=Severity.CRITICAL,
        description="Security group allows SSH access from anywhere",
        remediation="Restrict SSH access to specific IP ranges",
        iac_type="terraform",
        file_patterns=["*.tf"],
        multiline=True,
    ),
    IaCCheck(
        id="iac/tf-sg-open-all",
        name="Security Group Open to World",
        pattern=r'ingress\s*\{[^}]*from_port\s*=\s*0[^}]*to_port\s*=\s*0[^}]*cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"',
        severity=Severity.CRITICAL,
        description="Security group allows all traffic from anywhere",
        remediation="Restrict ingress rules to specific ports and IP ranges",
        iac_type="terraform",
        file_patterns=["*.tf"],
        multiline=True,
    ),
    IaCCheck(
        id="iac/tf-rds-no-encryption",
        name="RDS Without Encryption",
        pattern=r'resource\s+"aws_db_instance"[^{]*\{[^}]*storage_encrypted\s*=\s*false',
        severity=Severity.HIGH,
        description="RDS instance does not have encryption at rest enabled",
        remediation="Set storage_encrypted = true",
        iac_type="terraform",
        file_patterns=["*.tf"],
        multiline=True,
    ),
    IaCCheck(
        id="iac/tf-rds-public",
        name="RDS Publicly Accessible",
        pattern=r'resource\s+"aws_db_instance"[^{]*\{[^}]*publicly_accessible\s*=\s*true',
        severity=Severity.HIGH,
        description="RDS instance is publicly accessible",
        remediation="Set publicly_accessible = false",
        iac_type="terraform",
        file_patterns=["*.tf"],
        multiline=True,
    ),
    IaCCheck(
        id="iac/tf-cloudtrail-no-encryption",
        name="CloudTrail Without Encryption",
        pattern=r'resource\s+"aws_cloudtrail"[^{]*\{(?:(?!kms_key_id).)*\}',
        severity=Severity.MEDIUM,
        description="CloudTrail logs are not encrypted",
        remediation="Add kms_key_id to encrypt CloudTrail logs",
        iac_type="terraform",
        file_patterns=["*.tf"],
        multiline=True,
    ),

    # Kubernetes checks
    IaCCheck(
        id="iac/k8s-run-as-root",
        name="Container Running as Root",
        pattern=r'runAsUser:\s*0|runAsNonRoot:\s*false',
        severity=Severity.HIGH,
        description="Container is configured to run as root user",
        remediation="Set runAsNonRoot: true and specify a non-root runAsUser",
        iac_type="kubernetes",
        file_patterns=["*.yaml", "*.yml"],
        references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
    ),
    IaCCheck(
        id="iac/k8s-privileged",
        name="Privileged Container",
        pattern=r'privileged:\s*true',
        severity=Severity.CRITICAL,
        description="Container is running in privileged mode",
        remediation="Remove privileged: true unless absolutely necessary",
        iac_type="kubernetes",
        file_patterns=["*.yaml", "*.yml"],
    ),
    IaCCheck(
        id="iac/k8s-host-network",
        name="Host Network Enabled",
        pattern=r'hostNetwork:\s*true',
        severity=Severity.HIGH,
        description="Pod is using host network",
        remediation="Disable hostNetwork unless required",
        iac_type="kubernetes",
        file_patterns=["*.yaml", "*.yml"],
    ),
    IaCCheck(
        id="iac/k8s-host-pid",
        name="Host PID Enabled",
        pattern=r'hostPID:\s*true',
        severity=Severity.HIGH,
        description="Pod is sharing host PID namespace",
        remediation="Disable hostPID unless required",
        iac_type="kubernetes",
        file_patterns=["*.yaml", "*.yml"],
    ),
    IaCCheck(
        id="iac/k8s-secrets-plaintext",
        name="Secrets in Plaintext",
        pattern=r'kind:\s*Secret[\s\S]*?stringData:',
        severity=Severity.MEDIUM,
        description="Kubernetes Secret contains plaintext data",
        remediation="Use external secret management or sealed secrets",
        iac_type="kubernetes",
        file_patterns=["*.yaml", "*.yml"],
        multiline=True,
    ),
    IaCCheck(
        id="iac/k8s-no-resource-limits",
        name="No Resource Limits",
        pattern=r'containers:[\s\S]*?(?:(?!limits:).)*?name:',
        severity=Severity.MEDIUM,
        description="Container does not have resource limits defined",
        remediation="Define CPU and memory limits for containers",
        iac_type="kubernetes",
        file_patterns=["*.yaml", "*.yml"],
        multiline=True,
        confidence=0.6,
    ),
    IaCCheck(
        id="iac/k8s-no-security-context",
        name="No Security Context",
        pattern=r'containers:[\s\S]*?(?:(?!securityContext:).)*?image:',
        severity=Severity.MEDIUM,
        description="Container does not have security context defined",
        remediation="Define securityContext with appropriate restrictions",
        iac_type="kubernetes",
        file_patterns=["*.yaml", "*.yml"],
        multiline=True,
        confidence=0.6,
    ),

    # Docker checks
    IaCCheck(
        id="iac/docker-latest-tag",
        name="Docker Image Using Latest Tag",
        pattern=r'FROM\s+\S+:latest|FROM\s+[^\s:]+\s*$',
        severity=Severity.MEDIUM,
        description="Docker image uses 'latest' tag or no tag",
        remediation="Use specific version tags for reproducible builds",
        iac_type="docker",
        file_patterns=["Dockerfile*", "*.dockerfile"],
    ),
    IaCCheck(
        id="iac/docker-user-root",
        name="Docker Running as Root",
        pattern=r'USER\s+root',
        severity=Severity.MEDIUM,
        description="Dockerfile explicitly runs as root user",
        remediation="Create and use a non-root user",
        iac_type="docker",
        file_patterns=["Dockerfile*", "*.dockerfile"],
    ),
    IaCCheck(
        id="iac/docker-secrets-env",
        name="Secrets in Docker ENV",
        pattern=r'ENV\s+(?:PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY|AWS_ACCESS_KEY|AWS_SECRET)\s*=',
        severity=Severity.HIGH,
        description="Secrets are hardcoded in Docker ENV instructions",
        remediation="Use Docker secrets or environment variables at runtime",
        iac_type="docker",
        file_patterns=["Dockerfile*", "*.dockerfile"],
    ),
    IaCCheck(
        id="iac/docker-add-instead-copy",
        name="Using ADD Instead of COPY",
        pattern=r'^ADD\s+(?!https?://)',
        severity=Severity.LOW,
        description="ADD used instead of COPY for local files",
        remediation="Use COPY unless you need ADD's tar extraction feature",
        iac_type="docker",
        file_patterns=["Dockerfile*", "*.dockerfile"],
    ),
    IaCCheck(
        id="iac/docker-sudo",
        name="Using sudo in Dockerfile",
        pattern=r'RUN\s+.*\bsudo\b',
        severity=Severity.LOW,
        description="sudo is used in Dockerfile",
        remediation="Run commands as root before switching USER, or configure sudoers properly",
        iac_type="docker",
        file_patterns=["Dockerfile*", "*.dockerfile"],
    ),

    # CloudFormation checks
    IaCCheck(
        id="iac/cfn-s3-public",
        name="S3 Bucket with Public Access",
        pattern=r'PublicAccessBlockConfiguration:[\s\S]*?(?:BlockPublicAcls|BlockPublicPolicy|IgnorePublicAcls|RestrictPublicBuckets):\s*false',
        severity=Severity.HIGH,
        description="S3 bucket allows public access",
        remediation="Set all PublicAccessBlockConfiguration options to true",
        iac_type="cloudformation",
        file_patterns=["*.yaml", "*.yml", "*.json"],
        multiline=True,
    ),
]


class IaCAnalyzer(BaseAnalyzer):
    """
    Infrastructure as Code security analyzer.

    Detects security misconfigurations in IaC files.
    """

    name = "iac"
    description = "Scans Infrastructure as Code for misconfigurations"

    def __init__(self, settings: Settings):
        """Initialize IaC analyzer."""
        super().__init__(settings)
        self.checks = self._load_checks()

    def _load_checks(self) -> list[IaCCheck]:
        """Load and compile IaC checks."""
        checks = DEFAULT_CHECKS.copy()

        # Try to load custom checks
        checks_file = Path(self.settings.analyzers.iac_checks_file)
        if checks_file.exists():
            try:
                with open(checks_file) as f:
                    custom_checks = yaml.safe_load(f)

                if custom_checks and "checks" in custom_checks:
                    for c in custom_checks["checks"]:
                        checks.append(IaCCheck(
                            id=c.get("id", f"custom/{c.get('name', 'check')}"),
                            name=c.get("name", "Custom Check"),
                            pattern=c["pattern"],
                            severity=Severity(c.get("severity", "medium")),
                            description=c.get("description", ""),
                            remediation=c.get("remediation", ""),
                            iac_type=c.get("iac_type", ""),
                            file_patterns=c.get("file_patterns", []),
                        ))
            except (yaml.YAMLError, KeyError, OSError) as e:
                self.log_warning(f"Could not load custom IaC checks: {e}")

        # Compile all checks
        for check in checks:
            check.compile()

        return checks

    async def analyze(self, repo: Repository, repo_path: Path) -> list[Finding]:
        """
        Analyze repository for IaC misconfigurations.

        Args:
            repo: Repository metadata
            repo_path: Path to cloned repository

        Returns:
            List of findings
        """
        findings: list[Finding] = []
        self.log_info(f"Scanning {repo.name} for IaC misconfigurations...")

        for file_path in self.iter_files(repo_path):
            iac_type = self._detect_iac_type(file_path, repo_path)
            if not iac_type:
                continue

            file_findings = self._analyze_file(file_path, repo, repo_path, iac_type)
            findings.extend(file_findings)

        self.log_info(f"Found {len(findings)} IaC issues in {repo.name}")
        return findings

    def _detect_iac_type(self, file_path: Path, repo_path: Path) -> Optional[str]:
        """Detect the IaC type of a file."""
        ext = file_path.suffix.lower()
        filename = file_path.name

        for iac_type, config in IAC_FILE_TYPES.items():
            # Check extensions
            if ext in config.get("extensions", set()):
                # For YAML files, need additional content checks
                if ext in {".yaml", ".yml", ".json"}:
                    if "content_patterns" in config:
                        content = self.read_file_content(file_path)
                        for pattern in config["content_patterns"]:
                            if re.search(pattern, content, re.IGNORECASE):
                                return iac_type
                else:
                    return iac_type

            # Check filenames
            if filename in config.get("filenames", set()):
                return iac_type

            # Check name patterns
            for name_pattern in config.get("name_patterns", []):
                if re.match(name_pattern, filename, re.IGNORECASE):
                    return iac_type

            # Check path patterns
            rel_path = str(file_path.relative_to(repo_path))
            for path_pattern in config.get("path_patterns", []):
                if re.search(path_pattern, rel_path):
                    return iac_type

        return None

    def _analyze_file(
        self,
        file_path: Path,
        repo: Repository,
        repo_path: Path,
        iac_type: str,
    ) -> list[Finding]:
        """Analyze a single IaC file."""
        findings: list[Finding] = []
        relative_path = self.get_relative_path(file_path, repo_path)
        content = self.read_file_content(file_path)
        lines = self.read_file_lines(file_path)

        for check in self.checks:
            # Skip checks for different IaC types
            if check.iac_type and check.iac_type != iac_type:
                continue

            # Check file pattern restrictions
            if check.file_patterns:
                if not any(file_path.match(fp) for fp in check.file_patterns):
                    continue

            if not check._compiled_pattern:
                continue

            # Search for pattern
            if check.multiline:
                # Multiline search on entire content
                for match in check._compiled_pattern.finditer(content):
                    # Calculate line number from match position
                    line_num = content[:match.start()].count("\n") + 1

                    # Check exclusions
                    if self._is_excluded(match.group(0), check):
                        continue

                    finding = self._create_finding(
                        repo, relative_path, line_num,
                        match.group(0)[:200], check, iac_type
                    )
                    findings.append(finding)
            else:
                # Line-by-line search
                for line_num, line_content in lines:
                    for match in check._compiled_pattern.finditer(line_content):
                        if self._is_excluded(line_content, check):
                            continue

                        finding = self._create_finding(
                            repo, relative_path, line_num,
                            line_content, check, iac_type
                        )
                        findings.append(finding)

        return findings

    def _is_excluded(self, content: str, check: IaCCheck) -> bool:
        """Check if content should be excluded."""
        for exclude_pattern in check._compiled_excludes:
            if exclude_pattern.search(content):
                return True
        return False

    def _create_finding(
        self,
        repo: Repository,
        file_path: str,
        line_number: int,
        line_content: str,
        check: IaCCheck,
        iac_type: str,
    ) -> Finding:
        """Create a finding from an IaC check match."""
        return Finding(
            repository=repo.full_name,
            type=FindingType.IAC,
            category=check.id.split("/")[-1],
            severity=check.severity,
            states=[FindingState.ACTIVE],
            state_details=StateDetails(
                is_in_default_branch=True,
            ),
            file_path=file_path,
            line_number=line_number,
            line_content=line_content[:200],  # Truncate long content
            branch=repo.default_branch,
            confidence=check.confidence,
            false_positive_likelihood=FalsePositiveLikelihood.LOW,
            remediation=check.remediation,
            references=check.references,
            rule_id=check.id,
            rule_description=check.description,
            matched_pattern=check.pattern,
            tags=[iac_type, check.iac_type] if check.iac_type else [iac_type],
        )

