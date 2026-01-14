"""
API-based scanner that can analyze repositories without cloning.

Uses GitHub's API to search for secrets patterns, which is faster
for large-scale scans but less comprehensive than full clone analysis.
"""

import asyncio
import base64
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import AsyncIterator, Optional

import httpx
from rich.console import Console

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
from ..utils.secure_logging import get_secure_logger
from .secrets import DEFAULT_PATTERNS, SAFE_REFERENCE_PATTERNS, SecretPattern
from .sast import DEFAULT_RULES as SAST_RULES, SASTRule
from ..core.models import Severity

console = Console()
logger = get_secure_logger(__name__)


# SAST search terms for API-based detection
SAST_SEARCH_TERMS = [
    # SQL Injection
    ("execute(", "sql-injection"),
    ("executeQuery", "sql-injection"),
    ("raw_query", "sql-injection"),
    ("rawQuery", "sql-injection"),
    ("cursor.execute", "sql-injection"),
    # XSS
    ("innerHTML", "xss"),
    ("document.write", "xss"),
    ("dangerouslySetInnerHTML", "xss"),
    ("v-html", "xss"),
    (".html(", "xss"),
    # Command Injection
    ("os.system", "command-injection"),
    ("subprocess.call", "command-injection"),
    ("shell=True", "command-injection"),
    ("child_process", "command-injection"),
    ("exec(", "command-injection"),
    # Deserialization
    ("pickle.load", "deserialization"),
    ("yaml.load", "deserialization"),
    ("unserialize", "deserialization"),
    ("ObjectInputStream", "deserialization"),
    # Path Traversal
    ("../", "path-traversal"),
    ("readFileSync", "path-traversal"),
    # SSRF
    ("requests.get", "ssrf"),
    ("urllib.request", "ssrf"),
    ("fetch(", "ssrf"),
    ("axios.get", "ssrf"),
    # XXE
    ("ElementTree.parse", "xxe"),
    ("lxml.etree", "xxe"),
    ("DocumentBuilder", "xxe"),
    # NoSQL Injection
    ("$where", "nosql-injection"),
    # Weak Crypto
    ("MD5", "weak-crypto"),
    ("SHA1", "weak-crypto"),
    ("DES", "weak-crypto"),
    # SSL Issues
    ("verify=False", "ssl-verify"),
    ("CERT_NONE", "ssl-verify"),
    ("rejectUnauthorized", "ssl-verify"),
    # JWT Issues
    ("algorithm='none'", "jwt-none"),
    ("algorithms=['none']", "jwt-none"),
]


@dataclass
class SearchResult:
    """Result from GitHub code search."""
    
    repository: str
    file_path: str
    file_url: str
    text_matches: list[dict]


class APIScanner:
    """
    Scans repositories using GitHub API without cloning.
    
    This is useful for:
    - Quick scans of many repositories
    - Scanning when disk space is limited
    - Pre-filtering before full clone scans
    
    Limitations:
    - Only searches indexed code (no git history)
    - Subject to GitHub search rate limits
    - May miss some patterns due to search limitations
    """
    
    # File extensions to search
    SEARCHABLE_EXTENSIONS = [
        "py", "js", "ts", "jsx", "tsx", "java", "rb", "php",
        "go", "rs", "cs", "cpp", "c", "h", "hpp", "sh", "bash",
        "yaml", "yml", "json", "xml", "toml", "ini", "cfg", "conf",
        "env", "properties", "gradle", "tf", "hcl",
    ]
    
    # Config file patterns that often contain secrets
    CONFIG_FILE_PATTERNS = [
        "*.env*",
        "config.*",
        "settings.*",
        "credentials.*",
        "secrets.*",
        ".env*",
        "docker-compose*",
        "Dockerfile*",
        "*.config.*",
        "application.*",
    ]
    
    def __init__(
        self,
        token: str,
        settings: Settings,
        api_url: str = "https://api.github.com",
    ):
        """
        Initialize API scanner.
        
        Args:
            token: GitHub token
            settings: Scanner settings
            api_url: GitHub API URL
        """
        self.token = token
        self.settings = settings
        self.api_url = api_url
        self.patterns = self._load_patterns()
        self.sast_rules = self._load_sast_rules()
        self.repos_scanned = 0  # Track scanned repos
        self.enable_sast = getattr(settings.analyzers, 'sast_enabled', True)
        
        # Compile safe reference patterns
        self._safe_patterns = [
            re.compile(p, re.IGNORECASE) for p in SAFE_REFERENCE_PATTERNS
        ]
        
        # HTTP client
        self._client: Optional[httpx.AsyncClient] = None
    
    def _load_patterns(self) -> list[SecretPattern]:
        """Load and compile secret patterns."""
        patterns = DEFAULT_PATTERNS.copy()
        for pattern in patterns:
            pattern.compile()
        return patterns
    
    def _load_sast_rules(self) -> list[SASTRule]:
        """Load and compile SAST rules."""
        rules = SAST_RULES.copy()
        for rule in rules:
            rule.compile()
        return rules
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.api_url,
                headers={
                    # IMPORTANT: text-match header required for text_matches in response
                    "Accept": "application/vnd.github.text-match+json",
                    "Authorization": f"Bearer {self.token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=60.0,
            )
        return self._client
    
    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def search_code(
        self,
        query: str,
        org: Optional[str] = None,
        repo: Optional[str] = None,
        per_page: int = 100,
        max_results: int = 1000,
    ) -> AsyncIterator[SearchResult]:
        """
        Search for code using GitHub's code search API.
        
        Args:
            query: Search query
            org: Limit to organization
            repo: Limit to specific repository
            per_page: Results per page
            max_results: Maximum total results
            
        Yields:
            SearchResult objects
        """
        client = await self._get_client()
        
        # Build query
        q = query
        if org:
            q += f" org:{org}"
        if repo:
            q += f" repo:{repo}"
        
        page = 1
        total_yielded = 0
        
        while total_yielded < max_results:
            try:
                response = await client.get(
                    "/search/code",
                    params={
                        "q": q,
                        "per_page": per_page,
                        "page": page,
                    },
                )
                
                # Handle rate limiting
                if response.status_code == 403:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    logger.warning(f"Rate limited, waiting {retry_after}s...")
                    await asyncio.sleep(retry_after)
                    continue
                
                if response.status_code != 200:
                    logger.error(f"Search failed with status {response.status_code}: {response.text[:200]}")
                    console.print(f"  [red]API returned status {response.status_code}[/red]")
                    break
                
                data = response.json()
                total_count = data.get("total_count", 0)
                items = data.get("items", [])
                
                if page == 1:
                    logger.info(f"Search '{query}' returned total_count={total_count}, items={len(items)}")
                    console.print(f"  [cyan]API returned: total_count={total_count}, items={len(items)}[/cyan]")
                    if total_count > 0:
                        console.print(f"  [cyan]API found {total_count} results[/cyan]")
                    else:
                        console.print(f"  [yellow]No results for this search term[/yellow]")
                
                if not items:
                    break
                
                for item in items:
                    yield SearchResult(
                        repository=item.get("repository", {}).get("full_name", ""),
                        file_path=item.get("path", ""),
                        file_url=item.get("html_url", ""),
                        text_matches=item.get("text_matches", []),
                    )
                    total_yielded += 1
                    
                    if total_yielded >= max_results:
                        break
                
                if len(items) < per_page:
                    break
                
                page += 1
                
                # Small delay to avoid rate limiting
                await asyncio.sleep(0.5)
                
            except httpx.HTTPError as e:
                logger.error(f"HTTP error during search: {e}")
                break
    
    async def _list_org_repos(self, org: str) -> list[str]:
        """List all repositories in an organization."""
        client = await self._get_client()
        repos = []
        page = 1
        
        console.print(f"[cyan]📋 Listing repositories in {org}...[/cyan]")
        
        try:
            while True:
                response = await client.get(
                    f"/orgs/{org}/repos",
                    params={
                        "per_page": 100,
                        "page": page,
                        "type": "all",
                    },
                )
                
                if response.status_code == 404:
                    console.print(f"[yellow]⚠️ Organization '{org}' not found. Trying as user...[/yellow]")
                    # Try as user instead
                    response = await client.get(
                        f"/users/{org}/repos",
                        params={
                            "per_page": 100,
                            "page": page,
                            "type": "all",
                        },
                    )
                
                if response.status_code == 401:
                    console.print(f"[red]❌ Authentication failed. Check your GitHub token.[/red]")
                    logger.error("GitHub authentication failed - invalid token")
                    return []
                
                response.raise_for_status()
                data = response.json()
                
                if not data:
                    break
                
                for repo in data:
                    repos.append(repo.get("full_name", ""))
                
                if len(data) < 100:
                    break
                    
                page += 1
                
        except httpx.HTTPError as e:
            logger.error(f"Error listing repos: {e}")
            console.print(f"[red]❌ Error listing repos: {e}[/red]")
        
        console.print(f"[green]✅ Found {len(repos)} repositories[/green]")
        self.repos_scanned = len(repos)
        return repos

    async def scan_organization(
        self,
        org: str,
        include_config_files: bool = True,
    ) -> list[Finding]:
        """
        Scan an organization for secrets using API search.
        
        Args:
            org: Organization name
            include_config_files: Also search config files
            
        Returns:
            List of findings
        """
        findings: list[Finding] = []
        seen_repos: set[str] = set()
        
        console.print(f"\n[bold cyan]🔍 Starting API scan for organization: {org}[/bold cyan]\n")
        
        # Debug: verify token is available
        logger.info(f"Token length in scan_organization: {len(self.token) if self.token else 0}")
        console.print(f"[dim]Token available: {'Yes' if self.token and len(self.token) > 10 else 'NO!'}[/dim]")
        console.print(f"[dim]Patterns loaded: {len(self.patterns)}[/dim]")
        
        # First, list all repos to get count
        repos = await self._list_org_repos(org)
        if not repos:
            console.print("[yellow]No repositories found or access denied.[/yellow]")
            return findings
        
        # Expanded search terms - covering more secret patterns
        search_terms = [
            # Generic terms
            "password",
            "secret",
            "api_key",
            "apikey",
            "api_secret",
            "token",
            "private_key",
            "access_key",
            "access_token",
            "auth_token",
            "bearer_token",
            "refresh_token",
            "credential",
            "credentials",
            "key",
            "keys",
            # AWS
            "AKIA",  # AWS Access Key ID
            "aws_access_key",
            "aws_secret",
            # GitHub
            "ghp_",  # GitHub Personal Access Token
            "github_pat_",  # GitHub Fine-grained PAT
            "gho_",  # GitHub OAuth Token
            "ghu_",  # GitHub User-to-Server Token
            "ghs_",  # GitHub Server-to-Server Token
            "ghr_",  # GitHub Refresh Token
            # Stripe
            "sk_live",
            "sk_test",
            "pk_live",
            "pk_test",
            # Database
            "mysql://",
            "postgresql://",
            "postgres://",
            "mongodb://",
            "redis://",
            # Cloud providers
            "AIza",  # Google API Key
            "ya29.",  # Google OAuth Token
            "1//",  # Google OAuth Refresh Token
            # Other common patterns
            "Bearer",
            "Authorization:",
            "x-api-key",
            "X-API-Key",
            "X-API-KEY",
            "api-token",
            "app_secret",
            "client_secret",
            "consumer_secret",
            "private_key",
            "public_key",
            # Brazilian payment providers
            "APP_USR-",  # Mercado Pago
            "ak_live_",  # Pagar.me
            "ak_test_",  # Pagar.me
            "$aact_",  # Asaas
            "Client_Id_",  # Gerencianet/Efí
        ]
        
        # Search for each term with higher limit
        logger.info(f"Starting search with {len(search_terms)} terms...")
        logger.info(f"Token available: {bool(self.token and len(self.token) > 10)}, Token length: {len(self.token) if self.token else 0}")
        logger.info(f"Patterns loaded: {len(self.patterns)}")
        console.print(f"\n[bold yellow]📊 Starting search with {len(search_terms)} terms...[/bold yellow]")
        console.print(f"[dim]Token available: {bool(self.token and len(self.token) > 10)}[/dim]")
        console.print(f"[dim]Patterns loaded: {len(self.patterns)}[/dim]")
        
        for term_idx, term in enumerate(search_terms):
            logger.info(f"[{term_idx+1}/{len(search_terms)}] Searching for: {term} in {org}")
            console.print(f"[dim]🔎 [{term_idx+1}/{len(search_terms)}] Searching for: {term}[/dim]")
            
            result_count = 0
            processed_files: set[str] = set()  # Track processed files to avoid duplicates
            
            try:
                async for result in self.search_code(term, org=org, max_results=1000):
                    result_count += 1
                    seen_repos.add(result.repository)
                    
                    # Create unique file identifier
                    file_id = f"{result.repository}:{result.file_path}"
                    
                    # Skip if we already processed this file in this search
                    if file_id in processed_files:
                        continue
                    
                    # Try to get full file content for deeper analysis
                    file_content = None
                    if "/" in result.repository:
                        owner, repo_name = result.repository.split("/", 1)
                        try:
                            file_content = await self.get_file_content(owner, repo_name, result.file_path)
                        except Exception:
                            pass  # Fallback to fragment analysis
                    
                    # Use full content if available, otherwise use fragments
                    content_to_analyze = file_content if file_content else " ".join(
                        m.get("fragment", "") for m in result.text_matches
                    )
                    
                    if not content_to_analyze:
                        continue
                    
                    # Analyze with all patterns
                    for pattern in self.patterns:
                        if not pattern._compiled_regex:
                            continue
                        
                        # Search in full content
                        for match in pattern._compiled_regex.finditer(content_to_analyze):
                            matched_text = match.group(0)
                            
                            # Verify it's not a safe reference
                            if self._is_safe_reference(matched_text):
                                continue
                            
                            # Extract line number if we have full content
                            line_num = 0
                            line_content = matched_text
                            
                            if file_content:
                                line_num = file_content[:match.start()].count('\n') + 1
                                lines = file_content.split('\n')
                                if line_num <= len(lines):
                                    line_content = lines[line_num - 1]
                                else:
                                    line_content = matched_text
                            else:
                                # Try to extract from fragment
                                for text_match in result.text_matches:
                                    fragment = text_match.get("fragment", "")
                                    if matched_text in fragment:
                                        # Try to get line number from fragment
                                        line_matches = text_match.get("matches", [])
                                        if line_matches:
                                            line_num = line_matches[0].get("line_number", 0)
                                        line_content = fragment[:200]
                                        break
                            
                            finding = Finding(
                                repository=result.repository,
                                type=FindingType.SECRET,
                                category=pattern.name,
                                severity=pattern.severity,
                                states=[FindingState.ACTIVE],
                                state_details=StateDetails(
                                    is_in_default_branch=True,
                                    is_literal_value=True,
                                ),
                                file_path=result.file_path,
                                line_number=line_num,
                                line_content=line_content[:200],
                                confidence=pattern.confidence * (0.9 if file_content else 0.8),
                                false_positive_likelihood=FalsePositiveLikelihood.MEDIUM,
                                remediation=pattern.remediation,
                                references=pattern.references,
                                rule_id=f"api-scan/{pattern.name}",
                                rule_description=f"[API Scan] {pattern.description}",
                                matched_pattern=pattern.regex,
                                tags=["api-scan"],
                            )
                            findings.append(finding)
                            console.print(f"  [red]🚨 Found: {pattern.name} in {result.file_path}" + 
                                        (f":{line_num}" if line_num > 0 else "") + "[/red]")
                            break  # One finding per pattern per file
                    
                    processed_files.add(file_id)
            
            except Exception as e:
                console.print(f"  [red]❌ Error searching for '{term}': {e}[/red]")
                logger.error(f"Error searching for '{term}': {e}")
            
            if result_count > 0:
                console.print(f"  [dim]Found {result_count} matches for '{term}'[/dim]")
            else:
                console.print(f"  [dim]No matches found for '{term}'[/dim]")
        
        console.print(f"\n[bold]📊 Search completed. Total findings so far: {len(findings)}[/bold]")
        
        # Search config files and analyze their content
        if include_config_files:
            console.print(f"\n[dim]📁 Searching for config files...[/dim]")
            config_patterns = [
                ".env",
                ".env.local",
                ".env.production",
                ".env.development",
                "config.json",
                "config.yaml",
                "config.yml",
                "settings.json",
                "credentials.json",
                "secrets.json",
                "secrets.yaml",
                "secrets.yml",
                "application.properties",
                "application.yml",
                "application.yaml",
                "docker-compose.yml",
                "docker-compose.yaml",
                "Dockerfile",
                ".npmrc",
                ".pypirc",
                ".gitconfig",
                "id_rsa",
                "id_dsa",
                "id_ecdsa",
                "id_ed25519",
                "*.pem",
                "*.key",
                "*.p12",
                "*.pfx",
                "*.jks",
            ]
            
            for pattern in config_patterns:
                try:
                    async for result in self.search_code(
                        f"filename:{pattern}",
                        org=org,
                        max_results=200,  # Increased limit for config files
                    ):
                        seen_repos.add(result.repository)
                        
                        # Try to get full file content for better analysis
                        if "/" in result.repository:
                            owner, repo_name = result.repository.split("/", 1)
                            file_content = await self.get_file_content(
                                owner, repo_name, result.file_path
                            )
                            
                            if file_content:
                                # Analyze full file content with all patterns
                                for pattern_obj in self.patterns:
                                    if not pattern_obj._compiled_regex:
                                        continue
                                    
                                    for match in pattern_obj._compiled_regex.finditer(file_content):
                                        # Check if safe reference
                                        if self._is_safe_reference(match.group(0)):
                                            continue
                                        
                                        # Extract line number from content
                                        line_num = file_content[:match.start()].count('\n') + 1
                                        lines = file_content.split('\n')
                                        line_content = lines[line_num - 1] if line_num <= len(lines) else match.group(0)
                                        
                                        finding = Finding(
                                            repository=result.repository,
                                            type=FindingType.SECRET,
                                            category=pattern_obj.name,
                                            severity=pattern_obj.severity,
                                            states=[FindingState.ACTIVE],
                                            state_details=StateDetails(
                                                is_in_default_branch=True,
                                                is_literal_value=True,
                                            ),
                                            file_path=result.file_path,
                                            line_number=line_num,
                                            line_content=line_content[:200],
                                            confidence=pattern_obj.confidence * 0.9,  # Higher confidence for config files
                                            false_positive_likelihood=FalsePositiveLikelihood.LOW,
                                            remediation=pattern_obj.remediation,
                                            references=pattern_obj.references,
                                            rule_id=f"api-scan/{pattern_obj.name}",
                                            rule_description=f"[API Scan] {pattern_obj.description}",
                                            matched_pattern=pattern_obj.regex,
                                            tags=["api-scan", "config-file"],
                                        )
                                        findings.append(finding)
                                        console.print(f"  [red]🚨 Found: {pattern_obj.name} in {result.file_path}:{line_num}[/red]")
                                        break  # One finding per pattern per file
                        else:
                            # Fallback: flag file for review if we can't analyze
                            finding = Finding(
                                repository=result.repository,
                                type=FindingType.SECRET,
                                category="config_file",
                                severity=Severity.MEDIUM,
                                states=[FindingState.ACTIVE],
                                file_path=result.file_path,
                                line_number=0,
                                line_content="Configuration file detected - review for secrets",
                                confidence=0.5,
                                false_positive_likelihood=FalsePositiveLikelihood.HIGH,
                                remediation="Review configuration file for hardcoded secrets",
                                rule_id="api-scan/config-file",
                                rule_description="Configuration file that may contain secrets",
                                tags=["api-scan", "config-review"],
                            )
                            findings.append(finding)
                except Exception as e:
                    logger.warning(f"Error searching for {pattern}: {e}")
                    continue
        
        # SAST Analysis via API
        if self.enable_sast:
            console.print(f"\n[bold yellow]🔒 Scanning for SAST vulnerabilities...[/bold yellow]")
            sast_findings = await self._scan_sast_patterns(org, repos)
            findings.extend(sast_findings)
            console.print(f"[bold]📊 SAST findings: {len(sast_findings)}[/bold]")
        
        # Additional deep search: Search for specific high-value patterns directly
        console.print(f"\n[dim]🔬 Deep scanning for high-value patterns...[/dim]")
        high_value_patterns = [
            # AWS patterns
            ("AKIA[0-9A-Z]{16}", "aws_access_key_id"),
            # GitHub tokens
            ("ghp_[A-Za-z0-9]{36,}", "github_pat"),
            ("github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}", "github_fine_grained"),
            # Stripe
            ("sk_(live|test)_[A-Za-z0-9]{24,}", "stripe_secret_key"),
            # Database URLs
            ("(mysql|postgresql|postgres|mongodb|redis)://[^:]+:[^@]+@", "database_url"),
            # Private keys
            ("-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----", "private_key"),
            # JWT tokens
            ("eyJ[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+", "jwt_token"),
            # Google API
            ("AIza[0-9A-Za-z_-]{35}", "google_api_key"),
            # SendGrid
            ("SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}", "sendgrid_key"),
        ]
        
        for pattern_regex, pattern_name in high_value_patterns:
            try:
                # Search for the pattern directly
                async for result in self.search_code(
                    pattern_regex,
                    org=org,
                    max_results=500,  # Higher limit for high-value patterns
                ):
                    seen_repos.add(result.repository)
                    
                    # Get full file content if possible
                    file_content = None
                    if "/" in result.repository:
                        owner, repo_name = result.repository.split("/", 1)
                        try:
                            file_content = await self.get_file_content(owner, repo_name, result.file_path)
                        except Exception:
                            pass
                    
                    # Find matching pattern object
                    matching_pattern = None
                    for p in self.patterns:
                        if pattern_name in p.name.lower() or p.name == pattern_name:
                            matching_pattern = p
                            break
                    
                    if not matching_pattern:
                        # Create a generic pattern if not found
                        matching_pattern = SecretPattern(
                            name=pattern_name,
                            regex=pattern_regex,
                            severity=Severity.CRITICAL,
                            description=f"Detected {pattern_name}",
                            remediation="Rotate immediately and use environment variables",
                        )
                        matching_pattern.compile()
                    
                    # Analyze content
                    content = file_content if file_content else " ".join(
                        m.get("fragment", "") for m in result.text_matches
                    )
                    
                    if matching_pattern._compiled_regex:
                        for match in matching_pattern._compiled_regex.finditer(content):
                            if self._is_safe_reference(match.group(0)):
                                continue
                            
                            line_num = 0
                            line_content = match.group(0)
                            if file_content:
                                line_num = file_content[:match.start()].count('\n') + 1
                                lines = file_content.split('\n')
                                if line_num <= len(lines):
                                    line_content = lines[line_num - 1]
                            
                            finding = Finding(
                                repository=result.repository,
                                type=FindingType.SECRET,
                                category=matching_pattern.name,
                                severity=matching_pattern.severity,
                                states=[FindingState.ACTIVE],
                                state_details=StateDetails(
                                    is_in_default_branch=True,
                                    is_literal_value=True,
                                ),
                                file_path=result.file_path,
                                line_number=line_num,
                                line_content=line_content[:200],
                                confidence=matching_pattern.confidence * 0.95,  # High confidence for direct pattern match
                                false_positive_likelihood=FalsePositiveLikelihood.LOW,
                                remediation=matching_pattern.remediation,
                                references=matching_pattern.references,
                                rule_id=f"api-scan-deep/{matching_pattern.name}",
                                rule_description=f"[Deep Scan] {matching_pattern.description}",
                                matched_pattern=matching_pattern.regex,
                                tags=["api-scan", "deep-scan"],
                            )
                            findings.append(finding)
                            console.print(f"  [bold red]🚨 DEEP: {matching_pattern.name} in {result.file_path}" + 
                                        (f":{line_num}" if line_num > 0 else "") + "[/bold red]")
                            break  # One per file
            except Exception as e:
                logger.warning(f"Error in deep scan for {pattern_name}: {e}")
                continue
        
        # Deduplicate findings
        findings = self._deduplicate_findings(findings)
        
        # Update repos scanned to unique repos where we found something
        self.repos_scanned = max(len(repos), len(seen_repos))
        
        console.print(f"\n[bold green]✅ API scan complete![/bold green]")
        console.print(f"   Repositories: {self.repos_scanned}")
        console.print(f"   Findings: {len(findings)}")
        
        logger.info(f"API scan found {len(findings)} potential secrets in {org}")
        return findings
    
    async def scan_repository(
        self,
        repo: str,
    ) -> list[Finding]:
        """
        Scan a single repository for secrets using API.
        
        Args:
            repo: Repository in owner/repo format
            
        Returns:
            List of findings
        """
        findings: list[Finding] = []
        
        # Search for secret patterns
        for pattern in self.patterns:
            if not pattern._compiled_regex:
                continue
            
            # Use a simple search term from the pattern
            search_term = self._extract_search_term(pattern)
            if not search_term:
                continue
            
            async for result in self.search_code(search_term, repo=repo, max_results=50):
                for match in result.text_matches:
                    fragment = match.get("fragment", "")
                    
                    if pattern._compiled_regex.search(fragment):
                        if self._is_safe_reference(fragment):
                            continue
                        
                        finding = Finding(
                            repository=repo,
                            type=FindingType.SECRET,
                            category=pattern.name,
                            severity=pattern.severity,
                            states=[FindingState.ACTIVE],
                            file_path=result.file_path,
                            line_number=0,
                            line_content=fragment[:200],
                            confidence=pattern.confidence * 0.8,
                            false_positive_likelihood=FalsePositiveLikelihood.MEDIUM,
                            remediation=pattern.remediation,
                            rule_id=f"api-scan/{pattern.name}",
                            rule_description=f"[API Scan] {pattern.description}",
                            matched_pattern=pattern.regex,
                            tags=["api-scan"],
                        )
                        findings.append(finding)
        
        return self._deduplicate_findings(findings)
    
    async def get_file_content(
        self,
        owner: str,
        repo: str,
        path: str,
        ref: Optional[str] = None,
    ) -> Optional[str]:
        """
        Get file content from repository without cloning.
        
        Args:
            owner: Repository owner
            repo: Repository name
            path: File path
            ref: Git ref (branch, tag, SHA)
            
        Returns:
            File content or None
        """
        client = await self._get_client()
        
        params = {"ref": ref} if ref else {}
        
        try:
            response = await client.get(
                f"/repos/{owner}/{repo}/contents/{path}",
                params=params,
            )
            response.raise_for_status()
            
            data = response.json()
            if data.get("type") == "file" and data.get("content"):
                return base64.b64decode(data["content"]).decode("utf-8")
        except httpx.HTTPError:
            pass
        
        return None
    
    def _extract_search_term(self, pattern: SecretPattern) -> Optional[str]:
        """Extract a searchable term from a pattern regex."""
        # Map of pattern names to search terms
        search_terms = {
            "aws_access_key": "AKIA",
            "github_token": "ghp_",
            "github_fine_grained": "github_pat_",
            "stripe_secret_key": "sk_live",
            "stripe_publishable_key": "pk_live",
            "slack_token": "xox",
            "sendgrid_key": "SG.",
            "twilio_key": "SK",
            "npm_token": "_authToken",
            "pypi_token": "pypi-",
            "google_api_key": "AIza",
            "database_url": "postgresql://",
        }
        
        return search_terms.get(pattern.name)
    
    def _is_safe_reference(self, content: str) -> bool:
        """Check if content is a safe reference to a secret."""
        for safe_pattern in self._safe_patterns:
            if safe_pattern.search(content):
                return True
        return False
    
    def _deduplicate_findings(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings."""
        seen: dict[str, Finding] = {}
        
        for finding in findings:
            key = f"{finding.repository}:{finding.file_path}:{finding.category}"
            if key not in seen:
                seen[key] = finding
        
        return list(seen.values())
    
    async def _scan_sast_patterns(
        self,
        org: str,
        repos: list[str],
    ) -> list[Finding]:
        """
        Scan for SAST vulnerabilities (XSS, SQLi, etc.) via API.
        
        Args:
            org: Organization name
            repos: List of repository names
            
        Returns:
            List of SAST findings
        """
        findings: list[Finding] = []
        processed_files: set[str] = set()
        
        # Search for each SAST pattern type
        for search_term, vuln_type in SAST_SEARCH_TERMS:
            try:
                console.print(f"  [dim]🔎 Searching for {vuln_type}: {search_term}[/dim]")
                
                async for result in self.search_code(search_term, org=org, max_results=200):
                    file_id = f"{result.repository}:{result.file_path}:{vuln_type}"
                    
                    if file_id in processed_files:
                        continue
                    
                    # Get file content for better analysis
                    file_content = None
                    if "/" in result.repository:
                        owner, repo_name = result.repository.split("/", 1)
                        try:
                            file_content = await self.get_file_content(owner, repo_name, result.file_path)
                        except Exception:
                            pass
                    
                    content = file_content if file_content else " ".join(
                        m.get("fragment", "") for m in result.text_matches
                    )
                    
                    if not content:
                        continue
                    
                    # Find matching SAST rule
                    matching_rule = None
                    for rule in self.sast_rules:
                        if vuln_type in rule.id.lower() and rule._compiled_pattern:
                            if rule._compiled_pattern.search(content):
                                matching_rule = rule
                                break
                    
                    if not matching_rule:
                        # Create a generic finding based on search term
                        matching_rule = self._create_generic_sast_rule(vuln_type, search_term)
                    
                    if matching_rule and matching_rule._compiled_pattern:
                        match = matching_rule._compiled_pattern.search(content)
                        if match:
                            # Extract line info
                            line_num = 0
                            line_content = match.group(0)
                            
                            if file_content:
                                line_num = file_content[:match.start()].count('\n') + 1
                                lines = file_content.split('\n')
                                if line_num <= len(lines):
                                    line_content = lines[line_num - 1]
                            
                            finding = Finding(
                                repository=result.repository,
                                type=FindingType.BUG,
                                category=matching_rule.id.split("/")[-1],
                                severity=matching_rule.severity,
                                states=[FindingState.ACTIVE],
                                state_details=StateDetails(
                                    is_in_default_branch=True,
                                ),
                                file_path=result.file_path,
                                line_number=line_num,
                                line_content=line_content[:200],
                                confidence=matching_rule.confidence,
                                false_positive_likelihood=FalsePositiveLikelihood.MEDIUM,
                                remediation=matching_rule.remediation,
                                references=matching_rule.references,
                                rule_id=f"api-sast/{matching_rule.id}",
                                rule_description=f"[API SAST] {matching_rule.description}",
                                matched_pattern=matching_rule.pattern,
                                cwe_id=matching_rule.cwe_id,
                                tags=["api-scan", "sast", vuln_type],
                            )
                            findings.append(finding)
                            console.print(
                                f"    [yellow]⚠️ {vuln_type.upper()}: {matching_rule.name} "
                                f"in {result.file_path}" + 
                                (f":{line_num}" if line_num > 0 else "") + "[/yellow]"
                            )
                    
                    processed_files.add(file_id)
                    
            except Exception as e:
                logger.warning(f"Error scanning for {vuln_type}: {e}")
                continue
        
        return self._deduplicate_findings(findings)
    
    def _create_generic_sast_rule(self, vuln_type: str, search_term: str) -> SASTRule:
        """Create a generic SAST rule based on vulnerability type."""
        vuln_configs = {
            "sql-injection": {
                "name": "SQL Injection",
                "severity": Severity.CRITICAL,
                "description": "Potential SQL injection vulnerability",
                "remediation": "Use parameterized queries or prepared statements",
                "cwe_id": "CWE-89",
            },
            "xss": {
                "name": "Cross-Site Scripting (XSS)",
                "severity": Severity.HIGH,
                "description": "Potential XSS vulnerability",
                "remediation": "Sanitize user input and use safe DOM methods",
                "cwe_id": "CWE-79",
            },
            "command-injection": {
                "name": "Command Injection",
                "severity": Severity.CRITICAL,
                "description": "Potential command injection vulnerability",
                "remediation": "Avoid shell execution with user input",
                "cwe_id": "CWE-78",
            },
            "deserialization": {
                "name": "Insecure Deserialization",
                "severity": Severity.CRITICAL,
                "description": "Insecure deserialization detected",
                "remediation": "Use safe serialization formats",
                "cwe_id": "CWE-502",
            },
            "path-traversal": {
                "name": "Path Traversal",
                "severity": Severity.HIGH,
                "description": "Potential path traversal vulnerability",
                "remediation": "Validate and sanitize file paths",
                "cwe_id": "CWE-22",
            },
            "ssrf": {
                "name": "Server-Side Request Forgery",
                "severity": Severity.HIGH,
                "description": "Potential SSRF vulnerability",
                "remediation": "Validate and whitelist URLs",
                "cwe_id": "CWE-918",
            },
            "xxe": {
                "name": "XML External Entity",
                "severity": Severity.HIGH,
                "description": "Potential XXE vulnerability",
                "remediation": "Disable external entity processing",
                "cwe_id": "CWE-611",
            },
            "nosql-injection": {
                "name": "NoSQL Injection",
                "severity": Severity.HIGH,
                "description": "Potential NoSQL injection vulnerability",
                "remediation": "Sanitize user input for queries",
                "cwe_id": "CWE-943",
            },
            "weak-crypto": {
                "name": "Weak Cryptography",
                "severity": Severity.MEDIUM,
                "description": "Weak cryptographic algorithm detected",
                "remediation": "Use strong algorithms (AES-256, SHA-256+)",
                "cwe_id": "CWE-327",
            },
            "ssl-verify": {
                "name": "SSL Verification Disabled",
                "severity": Severity.HIGH,
                "description": "SSL certificate verification disabled",
                "remediation": "Enable SSL verification",
                "cwe_id": "CWE-295",
            },
            "jwt-none": {
                "name": "JWT None Algorithm",
                "severity": Severity.CRITICAL,
                "description": "JWT with none algorithm is insecure",
                "remediation": "Use HS256 or RS256 algorithms",
                "cwe_id": "CWE-347",
            },
        }
        
        config = vuln_configs.get(vuln_type, {
            "name": f"Security Issue ({vuln_type})",
            "severity": Severity.MEDIUM,
            "description": f"Potential {vuln_type} vulnerability",
            "remediation": "Review and fix security issue",
            "cwe_id": None,
        })
        
        rule = SASTRule(
            id=f"sast/{vuln_type}",
            name=config["name"],
            pattern=re.escape(search_term),
            severity=config["severity"],
            description=config["description"],
            remediation=config["remediation"],
            cwe_id=config.get("cwe_id"),
        )
        rule.compile()
        return rule


class IncrementalScanner:
    """
    Incremental scanner that only analyzes changed files since last scan.
    
    This is useful for:
    - Continuous integration
    - Regular scheduled scans
    - Reducing scan time for large repositories
    """
    
    def __init__(
        self,
        token: str,
        settings: Settings,
        api_url: str = "https://api.github.com",
    ):
        """
        Initialize incremental scanner.
        
        Args:
            token: GitHub token
            settings: Scanner settings
            api_url: GitHub API URL
        """
        self.token = token
        self.settings = settings
        self.api_url = api_url
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.api_url,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {self.token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=30.0,
            )
        return self._client
    
    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def get_changed_files_since(
        self,
        owner: str,
        repo: str,
        since: datetime,
    ) -> list[dict]:
        """
        Get files changed since a specific date.
        
        Args:
            owner: Repository owner
            repo: Repository name
            since: Date to compare from
            
        Returns:
            List of changed files with metadata
        """
        client = await self._get_client()
        changed_files = []
        
        try:
            # Get commits since date
            response = await client.get(
                f"/repos/{owner}/{repo}/commits",
                params={
                    "since": since.isoformat(),
                    "per_page": 100,
                },
            )
            response.raise_for_status()
            commits = response.json()
            
            # Get files from each commit
            for commit in commits:
                sha = commit.get("sha")
                if not sha:
                    continue
                
                # Get commit details
                commit_response = await client.get(
                    f"/repos/{owner}/{repo}/commits/{sha}",
                )
                commit_response.raise_for_status()
                commit_data = commit_response.json()
                
                for file in commit_data.get("files", []):
                    changed_files.append({
                        "path": file.get("filename"),
                        "status": file.get("status"),  # added, modified, removed
                        "additions": file.get("additions", 0),
                        "deletions": file.get("deletions", 0),
                        "patch": file.get("patch", ""),
                        "commit_sha": sha,
                        "commit_date": commit.get("commit", {}).get("author", {}).get("date"),
                    })
        except httpx.HTTPError as e:
            logger.error(f"Error getting changed files: {e}")
        
        return changed_files
    
    async def get_repositories_with_recent_pushes(
        self,
        org: str,
        since: datetime,
    ) -> list[dict]:
        """
        Get repositories that have been pushed to since a date.
        
        Args:
            org: Organization name
            since: Date to compare from
            
        Returns:
            List of repositories with push info
        """
        client = await self._get_client()
        repos_with_pushes = []
        
        try:
            page = 1
            while True:
                response = await client.get(
                    f"/orgs/{org}/repos",
                    params={
                        "sort": "pushed",
                        "direction": "desc",
                        "per_page": 100,
                        "page": page,
                    },
                )
                response.raise_for_status()
                repos = response.json()
                
                if not repos:
                    break
                
                for repo in repos:
                    pushed_at = repo.get("pushed_at")
                    if pushed_at:
                        push_date = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
                        push_date = push_date.replace(tzinfo=None)
                        
                        if push_date >= since:
                            repos_with_pushes.append({
                                "name": repo.get("name"),
                                "full_name": repo.get("full_name"),
                                "pushed_at": push_date,
                                "default_branch": repo.get("default_branch"),
                            })
                        else:
                            # Repos are sorted by push date, so we can stop
                            return repos_with_pushes
                
                page += 1
        except httpx.HTTPError as e:
            logger.error(f"Error getting repositories: {e}")
        
        return repos_with_pushes
    
    async def analyze_diff_for_secrets(
        self,
        patch: str,
    ) -> list[dict]:
        """
        Analyze a git diff patch for secrets.
        
        Args:
            patch: Git diff patch content
            
        Returns:
            List of detected secrets
        """
        from .secrets import DEFAULT_PATTERNS
        
        detections = []
        
        for line in patch.split("\n"):
            # Only check added lines
            if not line.startswith("+") or line.startswith("+++"):
                continue
            
            content = line[1:]  # Remove + prefix
            
            for pattern in DEFAULT_PATTERNS:
                if not pattern._compiled_regex:
                    pattern.compile()
                
                if pattern._compiled_regex and pattern._compiled_regex.search(content):
                    detections.append({
                        "pattern": pattern.name,
                        "severity": pattern.severity.value,
                        "content": content[:100],
                        "is_addition": True,
                    })
        
        return detections
