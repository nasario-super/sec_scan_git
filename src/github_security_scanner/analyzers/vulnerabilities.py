"""
Vulnerability scanner for dependencies.

Analyzes dependency files to find known vulnerabilities
using various package managers and vulnerability databases.
"""

import json
import subprocess
from dataclasses import dataclass
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
from .base import BaseAnalyzer


@dataclass
class Vulnerability:
    """Represents a known vulnerability."""

    id: str  # CVE or advisory ID
    package: str
    installed_version: str
    fixed_version: Optional[str]
    severity: Severity
    title: str
    description: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    references: list[str] = None

    def __post_init__(self):
        if self.references is None:
            self.references = []


# Ecosystem configurations
ECOSYSTEMS = {
    "python": {
        "lockfiles": ["requirements.txt", "Pipfile.lock", "poetry.lock", "setup.py", "pyproject.toml"],
        "manifest": "requirements.txt",
    },
    "javascript": {
        "lockfiles": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"],
        "manifest": "package.json",
    },
    "java": {
        "lockfiles": ["pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile"],
        "manifest": "pom.xml",
    },
    "go": {
        "lockfiles": ["go.mod", "go.sum"],
        "manifest": "go.mod",
    },
    "ruby": {
        "lockfiles": ["Gemfile.lock"],
        "manifest": "Gemfile",
    },
    "php": {
        "lockfiles": ["composer.lock"],
        "manifest": "composer.json",
    },
    "dotnet": {
        "lockfiles": ["packages.lock.json", "packages.config"],
        "manifest": "*.csproj",
    },
    "rust": {
        "lockfiles": ["Cargo.lock"],
        "manifest": "Cargo.toml",
    },
}


class VulnerabilityAnalyzer(BaseAnalyzer):
    """
    Analyzes dependencies for known vulnerabilities.

    Uses multiple strategies including:
    - pip-audit for Python
    - npm audit for JavaScript
    - Built-in vulnerability database checks
    """

    name = "vulnerabilities"
    description = "Scans dependencies for known vulnerabilities"

    def __init__(self, settings: Settings):
        """Initialize vulnerability analyzer."""
        super().__init__(settings)
        self.enabled_ecosystems = settings.analyzers.vulnerabilities_ecosystems

    async def analyze(self, repo: Repository, repo_path: Path) -> list[Finding]:
        """
        Analyze repository for vulnerable dependencies.

        Args:
            repo: Repository metadata
            repo_path: Path to cloned repository

        Returns:
            List of findings
        """
        findings: list[Finding] = []
        self.log_info(f"Scanning {repo.name} for vulnerable dependencies...")

        # Detect ecosystems in use
        detected = self._detect_ecosystems(repo_path)

        for ecosystem in detected:
            if ecosystem not in self.enabled_ecosystems:
                continue

            ecosystem_findings = await self._scan_ecosystem(
                ecosystem, repo, repo_path
            )
            findings.extend(ecosystem_findings)

        self.log_info(f"Found {len(findings)} vulnerabilities in {repo.name}")
        return findings

    def _detect_ecosystems(self, repo_path: Path) -> list[str]:
        """Detect which package ecosystems are present in the repo."""
        detected = []

        for ecosystem, config in ECOSYSTEMS.items():
            for lockfile in config["lockfiles"]:
                if lockfile.startswith("*"):
                    # Glob pattern
                    if list(repo_path.rglob(lockfile)):
                        detected.append(ecosystem)
                        break
                else:
                    if (repo_path / lockfile).exists():
                        detected.append(ecosystem)
                        break

        return detected

    async def _scan_ecosystem(
        self,
        ecosystem: str,
        repo: Repository,
        repo_path: Path,
    ) -> list[Finding]:
        """Scan a specific ecosystem for vulnerabilities."""
        findings: list[Finding] = []

        if ecosystem == "python":
            findings.extend(await self._scan_python(repo, repo_path))
        elif ecosystem == "javascript":
            findings.extend(await self._scan_javascript(repo, repo_path))
        elif ecosystem == "go":
            findings.extend(await self._scan_go(repo, repo_path))
        else:
            # Fallback to generic scanning
            findings.extend(await self._scan_generic(ecosystem, repo, repo_path))

        return findings

    async def _scan_python(
        self,
        repo: Repository,
        repo_path: Path,
    ) -> list[Finding]:
        """Scan Python dependencies using pip-audit."""
        findings: list[Finding] = []

        # Try pip-audit first
        try:
            result = subprocess.run(
                ["pip-audit", "--format", "json", "--strict"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.stdout:
                vulns = json.loads(result.stdout)
                for vuln in vulns.get("dependencies", []):
                    for v in vuln.get("vulns", []):
                        finding = self._create_finding(
                            repo=repo,
                            ecosystem="python",
                            package=vuln.get("name", "unknown"),
                            version=vuln.get("version", "unknown"),
                            vuln_id=v.get("id", ""),
                            severity=self._parse_severity(v.get("severity")),
                            title=v.get("description", "")[:100],
                            description=v.get("description", ""),
                            fixed_version=v.get("fix_versions", [None])[0] if v.get("fix_versions") else None,
                            file_path="requirements.txt",
                        )
                        findings.append(finding)

        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            # pip-audit not available or failed, try safety
            findings.extend(await self._scan_python_safety(repo, repo_path))

        return findings

    async def _scan_python_safety(
        self,
        repo: Repository,
        repo_path: Path,
    ) -> list[Finding]:
        """Fallback Python scanning using safety."""
        findings: list[Finding] = []

        req_file = repo_path / "requirements.txt"
        if not req_file.exists():
            return findings

        try:
            result = subprocess.run(
                ["safety", "check", "--json", "-r", str(req_file)],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.stdout:
                data = json.loads(result.stdout)
                for vuln in data.get("vulnerabilities", []):
                    finding = self._create_finding(
                        repo=repo,
                        ecosystem="python",
                        package=vuln.get("package_name", "unknown"),
                        version=vuln.get("installed_version", "unknown"),
                        vuln_id=vuln.get("vulnerability_id", ""),
                        severity=self._parse_severity(vuln.get("severity")),
                        title=vuln.get("advisory", "")[:100],
                        description=vuln.get("advisory", ""),
                        fixed_version=vuln.get("fixed_versions", [None])[0] if vuln.get("fixed_versions") else None,
                        file_path="requirements.txt",
                    )
                    findings.append(finding)

        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            self.log_warning("Could not run Python vulnerability scan")

        return findings

    async def _scan_javascript(
        self,
        repo: Repository,
        repo_path: Path,
    ) -> list[Finding]:
        """Scan JavaScript dependencies using npm audit."""
        findings: list[Finding] = []

        if not (repo_path / "package.json").exists():
            return findings

        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.stdout:
                data = json.loads(result.stdout)
                vulnerabilities = data.get("vulnerabilities", {})

                for pkg_name, vuln_data in vulnerabilities.items():
                    severity = self._parse_severity(vuln_data.get("severity"))
                    via = vuln_data.get("via", [])

                    # Get vulnerability details
                    for v in via:
                        if isinstance(v, dict):
                            finding = self._create_finding(
                                repo=repo,
                                ecosystem="javascript",
                                package=pkg_name,
                                version=vuln_data.get("range", "unknown"),
                                vuln_id=str(v.get("source", "")),
                                severity=severity,
                                title=v.get("title", "Vulnerability in " + pkg_name),
                                description=v.get("title", ""),
                                fixed_version=vuln_data.get("fixAvailable", {}).get("version") if isinstance(vuln_data.get("fixAvailable"), dict) else None,
                                file_path="package.json",
                                references=[v.get("url")] if v.get("url") else [],
                                cwe_id=v.get("cwe", [None])[0] if v.get("cwe") else None,
                            )
                            findings.append(finding)

        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            self.log_warning("Could not run npm audit")

        return findings

    async def _scan_go(
        self,
        repo: Repository,
        repo_path: Path,
    ) -> list[Finding]:
        """Scan Go dependencies using govulncheck."""
        findings: list[Finding] = []

        if not (repo_path / "go.mod").exists():
            return findings

        try:
            result = subprocess.run(
                ["govulncheck", "-json", "./..."],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=180,
            )

            if result.stdout:
                for line in result.stdout.strip().split("\n"):
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if "osv" in data:
                            osv = data["osv"]
                            finding = self._create_finding(
                                repo=repo,
                                ecosystem="go",
                                package=osv.get("affected", [{}])[0].get("package", {}).get("name", "unknown"),
                                version="unknown",
                                vuln_id=osv.get("id", ""),
                                severity=self._parse_severity(osv.get("severity")),
                                title=osv.get("summary", ""),
                                description=osv.get("details", ""),
                                file_path="go.mod",
                                references=[ref.get("url") for ref in osv.get("references", []) if ref.get("url")],
                            )
                            findings.append(finding)
                    except json.JSONDecodeError:
                        continue

        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.log_warning("Could not run govulncheck")

        return findings

    async def _scan_generic(
        self,
        ecosystem: str,
        repo: Repository,
        repo_path: Path,
    ) -> list[Finding]:
        """Generic vulnerability scanning using trivy if available."""
        findings: list[Finding] = []

        try:
            result = subprocess.run(
                ["trivy", "fs", "--format", "json", "--scanners", "vuln", str(repo_path)],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.stdout:
                data = json.loads(result.stdout)
                for result_item in data.get("Results", []):
                    for vuln in result_item.get("Vulnerabilities", []):
                        finding = self._create_finding(
                            repo=repo,
                            ecosystem=ecosystem,
                            package=vuln.get("PkgName", "unknown"),
                            version=vuln.get("InstalledVersion", "unknown"),
                            vuln_id=vuln.get("VulnerabilityID", ""),
                            severity=self._parse_severity(vuln.get("Severity")),
                            title=vuln.get("Title", ""),
                            description=vuln.get("Description", ""),
                            fixed_version=vuln.get("FixedVersion"),
                            file_path=result_item.get("Target", ""),
                            cvss_score=vuln.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                            references=vuln.get("References", []),
                        )
                        findings.append(finding)

        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            self.log_warning(f"Could not scan {ecosystem} dependencies")

        return findings

    def _parse_severity(self, severity: Optional[str]) -> Severity:
        """Parse severity string to Severity enum."""
        if not severity:
            return Severity.MEDIUM

        severity_lower = severity.lower()
        if severity_lower in ("critical", "very high"):
            return Severity.CRITICAL
        elif severity_lower == "high":
            return Severity.HIGH
        elif severity_lower in ("medium", "moderate"):
            return Severity.MEDIUM
        elif severity_lower == "low":
            return Severity.LOW
        else:
            return Severity.INFO

    def _create_finding(
        self,
        repo: Repository,
        ecosystem: str,
        package: str,
        version: str,
        vuln_id: str,
        severity: Severity,
        title: str,
        description: str,
        file_path: str,
        fixed_version: Optional[str] = None,
        cvss_score: Optional[float] = None,
        references: Optional[list[str]] = None,
        cwe_id: Optional[str] = None,
    ) -> Finding:
        """Create a vulnerability finding."""
        remediation = f"Upgrade {package} to version {fixed_version}" if fixed_version else f"Check for updates to {package}"

        return Finding(
            repository=repo.name,
            type=FindingType.VULNERABILITY,
            category=f"{ecosystem}_dependency",
            severity=severity,
            states=[FindingState.ACTIVE],
            state_details=StateDetails(
                is_in_default_branch=True,
            ),
            file_path=file_path,
            line_number=0,
            line_content=f"{package}=={version}" if version != "unknown" else package,
            branch=repo.default_branch,
            confidence=0.95,
            false_positive_likelihood=FalsePositiveLikelihood.LOW,
            remediation=remediation,
            references=references or [],
            rule_id=f"vuln/{vuln_id}",
            rule_description=title,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            tags=[ecosystem, package, vuln_id],
        )

