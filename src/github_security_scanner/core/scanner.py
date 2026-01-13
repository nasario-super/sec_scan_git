"""
Main security scanner orchestrator.

Coordinates all analyzers, manages repository scanning,
and aggregates results.
"""

import asyncio
import fnmatch
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from ..analyzers import (
    BaseAnalyzer,
    HistoryAnalyzer,
    IaCAnalyzer,
    SASTAnalyzer,
    SecretsAnalyzer,
    VulnerabilityAnalyzer,
)
from ..classifiers import SeverityClassifier, StateClassifier
from ..github import GitHubClient, RepositoryManager
from ..utils.cache import ScanCache
from ..utils.git import GitAnalyzer
from .config import Settings
from .models import (
    Finding,
    Repository,
    ScanMetadata,
    ScanResult,
    ScanStatus,
    Severity,
)

console = Console()


class SecurityScanner:
    """
    Main orchestrator for security scanning.

    Coordinates:
    - GitHub API interactions
    - Repository cloning
    - Running multiple analyzers
    - Result aggregation and classification
    """

    def __init__(self, settings: Settings):
        """
        Initialize security scanner.

        Args:
            settings: Scanner configuration
        """
        self.settings = settings
        self.analyzers: list[BaseAnalyzer] = []
        self.state_classifier = StateClassifier()
        self.severity_classifier = SeverityClassifier(
            min_severity=self._parse_severity_threshold()
        )
        self.cache = ScanCache(
            cache_dir=settings.cache.directory,
            ttl_hours=settings.cache.ttl_hours,
            enabled=settings.cache.enabled,
        )

        # Initialize analyzers based on settings
        self._init_analyzers()

    def _parse_severity_threshold(self) -> Optional[Severity]:
        """Parse severity threshold from settings."""
        threshold = self.settings.analyzers.vulnerabilities_fail_on_severity
        try:
            return Severity(threshold.lower())
        except ValueError:
            return None

    def _init_analyzers(self) -> None:
        """Initialize enabled analyzers."""
        if self.settings.analyzers.secrets_enabled:
            self.analyzers.append(SecretsAnalyzer(self.settings))

        if self.settings.analyzers.vulnerabilities_enabled:
            self.analyzers.append(VulnerabilityAnalyzer(self.settings))

        if self.settings.analyzers.sast_enabled:
            self.analyzers.append(SASTAnalyzer(self.settings))

        if self.settings.analyzers.iac_enabled:
            self.analyzers.append(IaCAnalyzer(self.settings))

        # History analyzer is added separately as it's run conditionally
        if self.settings.scan.analyze_history:
            self.analyzers.append(HistoryAnalyzer(self.settings))

    async def scan_organization(
        self,
        org: str,
        token: str,
        include_archived: bool = False,
        include_forks: bool = False,
    ) -> ScanResult:
        """
        Scan all repositories in a GitHub organization.

        Args:
            org: Organization name
            token: GitHub token
            include_archived: Include archived repositories
            include_forks: Include forked repositories

        Returns:
            Complete scan result
        """
        start_time = datetime.now()
        result = ScanResult()
        result.metadata.organization = org
        result.metadata.scan_date = start_time
        result.metadata.tool_version = "1.0.0"

        console.print(f"\n[bold blue]🔍 Scanning organization: {org}[/bold blue]\n")

        async with GitHubClient(self.settings.github) as client:
            client.settings.token = token

            # Get repositories
            console.print("[blue]Fetching repositories...[/blue]")
            repos = await client.get_organization_repos(
                org,
                include_archived=include_archived,
                include_forks=include_forks,
                languages=self.settings.scan.include_languages or None,
            )

            # Apply repository filters
            repos = self._filter_repos(repos)

            # Add repositories to result
            for repo in repos:
                result.repositories[repo.name] = repo

            result.metadata.repositories_scanned = len(repos)

            # Initialize repository manager
            repo_manager = RepositoryManager(
                settings=self.settings.scan,
                token=token,
            )

            try:
                # Clone repositories
                console.print(f"\n[blue]Cloning {len(repos)} repositories...[/blue]")
                cloned = await repo_manager.clone_repositories(
                    repos,
                    max_parallel=self.settings.scan.parallel_repos,
                )

                # Scan each repository
                console.print("\n[blue]Running security analysis...[/blue]\n")

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    console=console,
                ) as progress:
                    task = progress.add_task(
                        "Analyzing repositories...",
                        total=len(cloned),
                    )

                    for repo_name, repo_path in cloned.items():
                        repo = result.repositories[repo_name]
                        try:
                            findings = await self._scan_repository(
                                repo,
                                repo_path,
                            )

                            for finding in findings:
                                result.add_finding(finding)

                            repo.scan_status = ScanStatus.COMPLETED

                        except Exception as e:
                            repo.scan_status = ScanStatus.FAILED
                            repo.scan_error = str(e)
                            result.metadata.repositories_failed += 1
                            console.print(f"[red]Error scanning {repo_name}: {e}[/red]")

                        progress.advance(task)

            finally:
                # Cleanup cloned repositories
                repo_manager.cleanup_all()

        # Finalize results
        end_time = datetime.now()
        result.metadata.scan_duration_seconds = (end_time - start_time).total_seconds()
        result.calculate_top_repos()

        # Print summary
        self._print_summary(result)

        return result

    async def scan_repository(
        self,
        repo_url: str,
        token: str,
        branch: Optional[str] = None,
    ) -> ScanResult:
        """
        Scan a single repository.

        Args:
            repo_url: Repository URL or owner/repo format
            token: GitHub token
            branch: Specific branch to scan

        Returns:
            Scan result
        """
        start_time = datetime.now()
        result = ScanResult()
        result.metadata.scan_date = start_time
        result.metadata.tool_version = "1.0.0"

        # Parse repo URL
        if "/" in repo_url and not repo_url.startswith("http"):
            owner, repo_name = repo_url.split("/", 1)
        else:
            # Extract from URL
            parts = repo_url.rstrip("/").split("/")
            owner = parts[-2]
            repo_name = parts[-1].replace(".git", "")

        result.metadata.organization = owner

        console.print(f"\n[bold blue]🔍 Scanning repository: {owner}/{repo_name}[/bold blue]\n")

        async with GitHubClient(self.settings.github) as client:
            client.settings.token = token

            # Get repository info
            repo_data = await client.get_repository(owner, repo_name)
            repo = Repository(
                name=repo_data["name"],
                full_name=repo_data["full_name"],
                url=repo_data["html_url"],
                clone_url=repo_data["clone_url"],
                default_branch=branch or repo_data.get("default_branch", "main"),
                visibility="private" if repo_data.get("private") else "public",
            )

            result.repositories[repo.name] = repo
            result.metadata.repositories_scanned = 1

            # Clone repository
            repo_manager = RepositoryManager(
                settings=self.settings.scan,
                token=token,
            )

            try:
                console.print("[blue]Cloning repository...[/blue]")
                repo_path = await repo_manager.clone_repository(repo)

                if repo_path:
                    console.print("[blue]Running security analysis...[/blue]\n")
                    findings = await self._scan_repository(repo, repo_path)

                    for finding in findings:
                        result.add_finding(finding)

                    repo.scan_status = ScanStatus.COMPLETED
                else:
                    repo.scan_status = ScanStatus.FAILED
                    result.metadata.repositories_failed = 1

            finally:
                repo_manager.cleanup_all()

        # Finalize
        end_time = datetime.now()
        result.metadata.scan_duration_seconds = (end_time - start_time).total_seconds()
        result.calculate_top_repos()

        self._print_summary(result)

        return result

    async def _scan_repository(
        self,
        repo: Repository,
        repo_path: Path,
    ) -> list[Finding]:
        """
        Run all analyzers on a repository.

        Args:
            repo: Repository metadata
            repo_path: Path to cloned repository

        Returns:
            List of findings
        """
        all_findings: list[Finding] = []

        # Run analyzers in parallel
        tasks = [
            analyzer.analyze(repo, repo_path)
            for analyzer in self.analyzers
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                console.print(f"[yellow]Analyzer error: {result}[/yellow]")
                continue
            all_findings.extend(result)

        # Classify findings
        git = GitAnalyzer(repo_path)
        all_findings = self.state_classifier.classify_batch(
            all_findings,
            repo_path=repo_path,
            git=git,
        )
        all_findings = self.severity_classifier.classify_batch(all_findings)

        return all_findings

    def _filter_repos(self, repos: list[Repository]) -> list[Repository]:
        """Apply include/exclude filters to repositories."""
        filtered = []

        for repo in repos:
            # Check exclude patterns
            excluded = False
            for pattern in self.settings.scan.exclude_repos:
                if fnmatch.fnmatch(repo.name, pattern):
                    excluded = True
                    break

            if excluded:
                continue

            # Check include patterns (if specified)
            if self.settings.scan.include_repos:
                included = False
                for pattern in self.settings.scan.include_repos:
                    if fnmatch.fnmatch(repo.name, pattern):
                        included = True
                        break
                if not included:
                    continue

            # Check language filter
            if self.settings.scan.exclude_languages:
                if any(
                    lang.lower() in [l.lower() for l in self.settings.scan.exclude_languages]
                    for lang in repo.languages
                ):
                    continue

            filtered.append(repo)

        return filtered

    def _print_summary(self, result: ScanResult) -> None:
        """Print scan summary to console."""
        console.print("\n" + "=" * 60)
        console.print("[bold green]📊 Scan Summary[/bold green]")
        console.print("=" * 60)

        console.print(f"\n[bold]Organization:[/bold] {result.metadata.organization}")
        console.print(f"[bold]Repositories Scanned:[/bold] {result.metadata.repositories_scanned}")
        console.print(f"[bold]Repositories Failed:[/bold] {result.metadata.repositories_failed}")
        console.print(f"[bold]Total Findings:[/bold] {result.metadata.total_findings}")
        console.print(f"[bold]Duration:[/bold] {result.metadata.scan_duration_seconds:.1f}s")

        if result.summary.by_severity:
            console.print("\n[bold]By Severity:[/bold]")
            for sev, count in sorted(result.summary.by_severity.items(), reverse=True):
                color = {
                    "critical": "red bold",
                    "high": "red",
                    "medium": "yellow",
                    "low": "blue",
                    "info": "dim",
                }.get(sev, "white")
                console.print(f"  [{color}]{sev.upper()}:[/{color}] {count}")

        if result.summary.by_type:
            console.print("\n[bold]By Type:[/bold]")
            for ftype, count in result.summary.by_type.items():
                console.print(f"  {ftype}: {count}")

        if result.summary.by_state:
            console.print("\n[bold]By State:[/bold]")
            for state, count in result.summary.by_state.items():
                console.print(f"  {state}: {count}")

        if result.summary.top_affected_repos:
            console.print("\n[bold]Top Affected Repositories:[/bold]")
            for item in result.summary.top_affected_repos[:5]:
                console.print(f"  {item['repo']}: {item['findings']} findings")

        console.print("\n" + "=" * 60 + "\n")


async def scan_org_async(
    org: str,
    token: str,
    settings: Optional[Settings] = None,
) -> ScanResult:
    """
    Convenience function to scan an organization.

    Args:
        org: Organization name
        token: GitHub token
        settings: Optional settings (uses defaults if not provided)

    Returns:
        Scan result
    """
    if settings is None:
        settings = Settings()
    settings.github.token = token

    scanner = SecurityScanner(settings)
    return await scanner.scan_organization(org, token)


async def scan_repo_async(
    repo: str,
    token: str,
    settings: Optional[Settings] = None,
) -> ScanResult:
    """
    Convenience function to scan a repository.

    Args:
        repo: Repository URL or owner/repo
        token: GitHub token
        settings: Optional settings

    Returns:
        Scan result
    """
    if settings is None:
        settings = Settings()
    settings.github.token = token

    scanner = SecurityScanner(settings)
    return await scanner.scan_repository(repo, token)

