"""
Static Application Security Testing (SAST) analyzer.

Detects security vulnerabilities and bugs in source code
through pattern matching and static analysis.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml
from rich.console import Console

console = Console()

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
class SASTRule:
    """Definition of a SAST detection rule."""

    id: str
    name: str
    pattern: str
    severity: Severity = Severity.MEDIUM
    description: str = ""
    remediation: str = ""
    cwe_id: Optional[str] = None
    languages: list[str] = field(default_factory=list)
    file_patterns: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    confidence: float = 0.8

    _compiled_pattern: Optional[re.Pattern] = field(default=None, repr=False)
    _compiled_excludes: list[re.Pattern] = field(default_factory=list, repr=False)

    def compile(self) -> None:
        """Compile regex patterns."""
        try:
            self._compiled_pattern = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
        except re.error:
            self._compiled_pattern = None

        self._compiled_excludes = []
        for exclude in self.exclude_patterns:
            try:
                self._compiled_excludes.append(re.compile(exclude, re.IGNORECASE))
            except re.error:
                pass


# Language to file extension mapping
LANGUAGE_EXTENSIONS = {
    "python": {".py"},
    "javascript": {".js", ".jsx", ".mjs"},
    "typescript": {".ts", ".tsx"},
    "java": {".java"},
    "csharp": {".cs"},
    "php": {".php"},
    "ruby": {".rb"},
    "go": {".go"},
    "rust": {".rs"},
    "c": {".c", ".h"},
    "cpp": {".cpp", ".hpp", ".cc", ".cxx"},
}


# Default SAST rules based on specification
DEFAULT_RULES = [
    # SQL Injection
    SASTRule(
        id="sast/sql-injection-format",
        name="SQL Injection (String Format)",
        pattern=r'execute\s*\(\s*["\'].*%s|execute\s*\(\s*f["\']|\.format\s*\(',
        severity=Severity.CRITICAL,
        description="Potential SQL injection through string formatting",
        remediation="Use parameterized queries or prepared statements",
        cwe_id="CWE-89",
        languages=["python", "java", "csharp", "php"],
        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
    ),
    SASTRule(
        id="sast/sql-injection-concat",
        name="SQL Injection (Concatenation)",
        pattern=r'(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*\+\s*["\']?\s*\w+\s*["\']?\s*\+',
        severity=Severity.CRITICAL,
        description="Potential SQL injection through string concatenation",
        remediation="Use parameterized queries instead of string concatenation",
        cwe_id="CWE-89",
        languages=["python", "java", "csharp", "php", "javascript"],
    ),

    # XSS
    SASTRule(
        id="sast/xss-innerhtml",
        name="XSS (innerHTML)",
        pattern=r'innerHTML\s*=',
        severity=Severity.HIGH,
        description="Direct innerHTML assignment can lead to XSS",
        remediation="Use textContent or sanitize input before using innerHTML",
        cwe_id="CWE-79",
        languages=["javascript", "typescript"],
        references=["https://owasp.org/www-community/attacks/xss/"],
    ),
    SASTRule(
        id="sast/xss-document-write",
        name="XSS (document.write)",
        pattern=r'document\.write\s*\(',
        severity=Severity.HIGH,
        description="document.write can introduce XSS vulnerabilities",
        remediation="Use safer DOM manipulation methods",
        cwe_id="CWE-79",
        languages=["javascript", "typescript"],
    ),
    SASTRule(
        id="sast/xss-v-html",
        name="XSS (Vue v-html)",
        pattern=r'v-html\s*=',
        severity=Severity.HIGH,
        description="v-html directive can introduce XSS vulnerabilities",
        remediation="Use v-text or sanitize content before using v-html",
        cwe_id="CWE-79",
        languages=["javascript", "typescript"],
        file_patterns=["*.vue"],
    ),
    SASTRule(
        id="sast/xss-dangerously-set",
        name="XSS (React dangerouslySetInnerHTML)",
        pattern=r'dangerouslySetInnerHTML',
        severity=Severity.HIGH,
        description="dangerouslySetInnerHTML can introduce XSS vulnerabilities",
        remediation="Sanitize HTML content or use alternative approaches",
        cwe_id="CWE-79",
        languages=["javascript", "typescript"],
    ),

    # Command Injection
    SASTRule(
        id="sast/command-injection-os-system",
        name="Command Injection (os.system)",
        pattern=r'os\.system\s*\(',
        severity=Severity.CRITICAL,
        description="os.system is vulnerable to command injection",
        remediation="Use subprocess with shell=False and proper argument handling",
        cwe_id="CWE-78",
        languages=["python"],
        references=["https://owasp.org/www-community/attacks/Command_Injection"],
    ),
    SASTRule(
        id="sast/command-injection-subprocess-shell",
        name="Command Injection (subprocess shell=True)",
        pattern=r'subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True',
        severity=Severity.CRITICAL,
        description="subprocess with shell=True is vulnerable to command injection",
        remediation="Use shell=False and pass arguments as a list",
        cwe_id="CWE-78",
        languages=["python"],
    ),
    SASTRule(
        id="sast/command-injection-exec",
        name="Command Injection (exec)",
        pattern=r'\bexec\s*\(',
        severity=Severity.HIGH,
        description="exec() can execute arbitrary code",
        remediation="Avoid using exec() with user input",
        cwe_id="CWE-78",
        languages=["python", "php"],
        exclude_patterns=[r'exec\s*\(\s*["\'][^"\']*["\']\s*\)'],  # Exclude static strings
    ),

    # Path Traversal
    SASTRule(
        id="sast/path-traversal",
        name="Path Traversal",
        pattern=r'open\s*\([^)]*\+|os\.path\.join\s*\([^)]*(?:request|input|params)',
        severity=Severity.HIGH,
        description="Potential path traversal vulnerability",
        remediation="Validate and sanitize file paths, use os.path.realpath",
        cwe_id="CWE-22",
        languages=["python"],
    ),

    # Insecure Deserialization
    SASTRule(
        id="sast/insecure-pickle",
        name="Insecure Deserialization (pickle)",
        pattern=r'pickle\.loads?\s*\(',
        severity=Severity.CRITICAL,
        description="pickle.load can execute arbitrary code",
        remediation="Use safer serialization formats like JSON",
        cwe_id="CWE-502",
        languages=["python"],
        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Insecure_Deserialization"],
    ),
    SASTRule(
        id="sast/insecure-yaml",
        name="Insecure YAML Loading",
        pattern=r'yaml\.load\s*\([^)]*(?!Loader\s*=\s*(?:yaml\.)?SafeLoader)',
        severity=Severity.CRITICAL,
        description="yaml.load without SafeLoader can execute arbitrary code",
        remediation="Use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader)",
        cwe_id="CWE-502",
        languages=["python"],
    ),
    SASTRule(
        id="sast/insecure-eval",
        name="Dangerous eval()",
        pattern=r'\beval\s*\(',
        severity=Severity.CRITICAL,
        description="eval() can execute arbitrary code",
        remediation="Avoid eval() with user input. Use ast.literal_eval for safe evaluation",
        cwe_id="CWE-95",
        languages=["python", "javascript", "php"],
    ),

    # Weak Cryptography
    SASTRule(
        id="sast/weak-crypto-md5",
        name="Weak Cryptography (MD5)",
        pattern=r'\bMD5\b|md5\s*\(|hashlib\.md5',
        severity=Severity.MEDIUM,
        description="MD5 is cryptographically broken",
        remediation="Use SHA-256 or stronger hash functions",
        cwe_id="CWE-327",
        exclude_patterns=[r'#.*MD5', r'//.*MD5', r'checksum', r'etag'],
    ),
    SASTRule(
        id="sast/weak-crypto-sha1",
        name="Weak Cryptography (SHA1)",
        pattern=r'\bSHA1\b(?!_)|sha1\s*\(|hashlib\.sha1',
        severity=Severity.MEDIUM,
        description="SHA1 is cryptographically weak",
        remediation="Use SHA-256 or stronger hash functions",
        cwe_id="CWE-327",
        exclude_patterns=[r'#.*SHA1', r'//.*SHA1', r'git'],
    ),
    SASTRule(
        id="sast/weak-random",
        name="Weak Random Number Generator",
        pattern=r'\bRandom\(\)|random\.random\(\)|Math\.random\(\)',
        severity=Severity.MEDIUM,
        description="Weak random number generator used for security",
        remediation="Use cryptographically secure random: secrets module or crypto.randomBytes",
        cwe_id="CWE-330",
        exclude_patterns=[r'test', r'mock', r'sample'],
    ),

    # Debug/Development Settings
    SASTRule(
        id="sast/debug-enabled",
        name="Debug Mode Enabled",
        pattern=r'DEBUG\s*=\s*True|app\.debug\s*=\s*True|FLASK_DEBUG\s*=\s*1',
        severity=Severity.MEDIUM,
        description="Debug mode should not be enabled in production",
        remediation="Disable debug mode in production environments",
        cwe_id="CWE-489",
        languages=["python"],
        exclude_patterns=[r'\.env\.example', r'\.env\.sample', r'#.*DEBUG'],
    ),

    # Hardcoded IPs (informational)
    SASTRule(
        id="sast/hardcoded-ip",
        name="Hardcoded IP Address",
        pattern=r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        severity=Severity.LOW,
        description="Hardcoded IP address found",
        remediation="Use configuration or environment variables for IP addresses",
        cwe_id="CWE-798",
        exclude_patterns=[r'127\.0\.0\.1', r'0\.0\.0\.0', r'255\.255\.255\.\d+', r'localhost', r'#.*\d+\.\d+\.\d+\.\d+'],
        confidence=0.5,
    ),

    # SSRF
    SASTRule(
        id="sast/ssrf",
        name="Potential SSRF",
        pattern=r'requests\.get\s*\([^)]*(?:request|input|params|url)',
        severity=Severity.HIGH,
        description="Potential Server-Side Request Forgery",
        remediation="Validate and whitelist URLs before making requests",
        cwe_id="CWE-918",
        languages=["python"],
    ),

    # XXE
    SASTRule(
        id="sast/xxe",
        name="Potential XXE",
        pattern=r'xml\.etree\.ElementTree\.parse|lxml\.etree\.parse|xml\.dom\.minidom\.parse',
        severity=Severity.HIGH,
        description="XML parsing may be vulnerable to XXE attacks",
        remediation="Disable external entity processing in XML parser",
        cwe_id="CWE-611",
        languages=["python"],
    ),

    # Insecure HTTP
    SASTRule(
        id="sast/insecure-http",
        name="Insecure HTTP URL",
        pattern=r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s"\'"]+',
        severity=Severity.LOW,
        description="HTTP URLs should use HTTPS for security",
        remediation="Use HTTPS instead of HTTP",
        cwe_id="CWE-319",
        exclude_patterns=[r'http://schemas', r'http://www\.w3\.org', r'http://xmlns'],
        confidence=0.6,
    ),
]


class SASTAnalyzer(BaseAnalyzer):
    """
    Static Application Security Testing analyzer.

    Performs pattern-based static analysis to detect
    security vulnerabilities in source code.
    """

    name = "sast"
    description = "Static analysis for security vulnerabilities"

    def __init__(self, settings: Settings):
        """Initialize SAST analyzer."""
        super().__init__(settings)
        self.rules = self._load_rules()

    def _load_rules(self) -> list[SASTRule]:
        """Load and compile SAST rules."""
        rules = DEFAULT_RULES.copy()
        console.print(f"[cyan]SAST: Loading rules, {len(DEFAULT_RULES)} default rules[/cyan]")

        # Try to load custom rules
        rules_file = Path(self.settings.analyzers.sast_rules_file)
        console.print(f"[cyan]SAST: Looking for rules file at: {rules_file.absolute()} (exists: {rules_file.exists()})[/cyan]")
        if rules_file.exists():
            try:
                with open(rules_file) as f:
                    custom_rules = yaml.safe_load(f)

                if custom_rules and "rules" in custom_rules:
                    for r in custom_rules["rules"]:
                        rules.append(SASTRule(
                            id=r.get("id", f"custom/{r.get('name', 'rule')}"),
                            name=r.get("name", "Custom Rule"),
                            pattern=r["pattern"],
                            severity=Severity(r.get("severity", "medium")),
                            description=r.get("description", ""),
                            remediation=r.get("remediation", ""),
                            cwe_id=r.get("cwe_id"),
                            languages=r.get("languages", []),
                        ))
            except (yaml.YAMLError, KeyError, OSError) as e:
                self.log_warning(f"Could not load custom SAST rules: {e}")

        # Compile all rules
        for rule in rules:
            rule.compile()

        return rules

    async def analyze(self, repo: Repository, repo_path: Path) -> list[Finding]:
        """
        Analyze repository for security bugs.

        Args:
            repo: Repository metadata
            repo_path: Path to cloned repository

        Returns:
            List of findings
        """
        findings: list[Finding] = []
        console.print(f"[bold yellow]🔍 SAST: Starting analysis on {repo.name}...[/bold yellow]")
        console.print(f"[cyan]SAST: Loaded {len(self.rules)} rules[/cyan]")

        file_count = 0
        try:
            for file_path in self.iter_files(repo_path):
                file_count += 1
                try:
                    file_findings = self._analyze_file(file_path, repo, repo_path)
                    findings.extend(file_findings)
                except Exception as e:
                    console.print(f"[red]SAST Error analyzing {file_path}: {e}[/red]")
                    continue
        except Exception as e:
            console.print(f"[red]SAST Error iterating files: {e}[/red]")
            import traceback
            traceback.print_exc()

        console.print(f"[bold green]✅ SAST: Analyzed {file_count} files, found {len(findings)} issues in {repo.name}[/bold green]")
        return findings

    def _get_file_language(self, file_path: Path) -> Optional[str]:
        """Determine the programming language of a file."""
        ext = file_path.suffix.lower()
        for lang, extensions in LANGUAGE_EXTENSIONS.items():
            if ext in extensions:
                return lang
        return None

    def _analyze_file(
        self,
        file_path: Path,
        repo: Repository,
        repo_path: Path,
    ) -> list[Finding]:
        """Analyze a single file for SAST issues."""
        findings: list[Finding] = []
        relative_path = self.get_relative_path(file_path, repo_path)
        file_language = self._get_file_language(file_path)
        lines = self.read_file_lines(file_path)
        is_noise = self.is_noise_path(file_path)

        for rule in self.rules:
            # Skip if rule doesn't apply to this language
            if rule.languages and file_language not in rule.languages:
                continue

            # Skip if file pattern doesn't match
            if rule.file_patterns:
                if not any(file_path.match(fp) for fp in rule.file_patterns):
                    continue

            if not rule._compiled_pattern:
                continue

            # Search for pattern
            for line_num, line_content in lines:
                for match in rule._compiled_pattern.finditer(line_content):
                    # Check exclusions
                    if self._is_excluded(line_content, rule):
                        continue

                    before, after = self.get_context_lines(lines, line_num)
                    confidence = rule.confidence * (0.6 if is_noise else 1.0)
                    false_positive = (
                        FalsePositiveLikelihood.HIGH
                        if is_noise
                        else FalsePositiveLikelihood.MEDIUM
                    )
                    finding = Finding(
                        repository=repo.full_name,
                        type=FindingType.SAST,
                        category=rule.id.split("/")[-1],
                        severity=rule.severity,
                        states=[FindingState.ACTIVE],
                        state_details=StateDetails(
                            is_in_default_branch=True,
                        ),
                        file_path=relative_path,
                        line_number=line_num,
                        line_content=line_content,
                        column_start=match.start(),
                        column_end=match.end(),
                        branch=repo.default_branch,
                        confidence=confidence,
                        false_positive_likelihood=false_positive,
                        remediation=rule.remediation,
                        references=rule.references,
                        rule_id=rule.id,
                        rule_description=rule.description,
                        cwe_id=rule.cwe_id,
                        matched_pattern=rule.pattern,
                        context_before=before,
                        context_after=after,
                        tags=[file_language] if file_language else [],
                    )
                    findings.append(finding)

        return findings

    def _is_excluded(self, line_content: str, rule: SASTRule) -> bool:
        """Check if a match should be excluded."""
        for exclude_pattern in rule._compiled_excludes:
            if exclude_pattern.search(line_content):
                return True
        return False

