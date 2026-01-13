"""
Command-line interface for the GitHub Security Scanner.

Provides commands for scanning organizations and repositories,
generating reports, and managing configuration.
"""

import asyncio
import os
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel

from .core.config import Settings, create_default_config, get_settings
from .core.scanner import SecurityScanner
from .reporters import CSVReporter, HTMLReporter, JSONReporter, SARIFReporter

app = typer.Typer(
    name="github-security-scanner",
    help="🔒 GitHub Organization Security Scanner - Automated security analysis for GitHub repositories",
    add_completion=True,
    no_args_is_help=True,
)

console = Console()


def version_callback(value: bool) -> None:
    """Show version and exit."""
    if value:
        from . import __version__
        console.print(f"GitHub Security Scanner v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option("--version", "-v", callback=version_callback, help="Show version"),
    ] = None,
) -> None:
    """GitHub Organization Security Scanner."""
    pass


@app.command()
def scan(
    org: Annotated[str, typer.Option("--org", "-o", help="GitHub organization name")],
    token: Annotated[
        Optional[str],
        typer.Option("--token", "-t", envvar="GITHUB_TOKEN", help="GitHub token"),
    ] = None,
    config: Annotated[
        Optional[Path],
        typer.Option("--config", "-c", help="Path to config file"),
    ] = None,
    include_historical: Annotated[
        bool,
        typer.Option("--include-historical", help="Include git history analysis"),
    ] = False,
    languages: Annotated[
        Optional[str],
        typer.Option("--languages", "-l", help="Filter by languages (comma-separated)"),
    ] = None,
    exclude_repos: Annotated[
        Optional[str],
        typer.Option("--exclude-repos", help="Exclude repos matching patterns (comma-separated)"),
    ] = None,
    severity_threshold: Annotated[
        str,
        typer.Option("--severity-threshold", "-s", help="Minimum severity to report"),
    ] = "low",
    output_format: Annotated[
        str,
        typer.Option("--output-format", "-f", help="Output formats (comma-separated: json,html,sarif,csv)"),
    ] = "json,html",
    output_dir: Annotated[
        Path,
        typer.Option("--output-dir", "-d", help="Output directory for reports"),
    ] = Path("./reports"),
    parallel: Annotated[
        int,
        typer.Option("--parallel", "-p", help="Number of parallel repository scans"),
    ] = 4,
    include_archived: Annotated[
        bool,
        typer.Option("--include-archived", help="Include archived repositories"),
    ] = False,
    include_forks: Annotated[
        bool,
        typer.Option("--include-forks", help="Include forked repositories"),
    ] = False,
) -> None:
    """
    Scan all repositories in a GitHub organization.

    Example:
        github-security-scanner scan --org myorg --token $GITHUB_TOKEN
    """
    if not token:
        console.print("[red]Error: GitHub token is required. Set GITHUB_TOKEN or use --token[/red]")
        raise typer.Exit(1)

    # Load settings
    settings = get_settings(str(config) if config else None)

    # Apply CLI overrides
    settings.github.token = token
    settings.scan.analyze_history = include_historical
    settings.scan.parallel_repos = parallel
    settings.output.directory = str(output_dir)
    settings.output.formats = output_format.split(",")

    if languages:
        settings.scan.include_languages = [l.strip() for l in languages.split(",")]

    if exclude_repos:
        settings.scan.exclude_repos.extend([r.strip() for r in exclude_repos.split(",")])

    settings.analyzers.vulnerabilities_fail_on_severity = severity_threshold

    # Show configuration
    console.print(Panel.fit(
        f"[bold]Organization:[/bold] {org}\n"
        f"[bold]Historical Analysis:[/bold] {include_historical}\n"
        f"[bold]Parallel Repos:[/bold] {parallel}\n"
        f"[bold]Output Formats:[/bold] {output_format}\n"
        f"[bold]Output Directory:[/bold] {output_dir}",
        title="🔧 Scan Configuration",
    ))

    # Run scan
    scanner = SecurityScanner(settings)

    try:
        result = asyncio.run(scanner.scan_organization(
            org=org,
            token=token,
            include_archived=include_archived,
            include_forks=include_forks,
        ))

        # Save to database
        from .storage.database import Database
        db = Database()
        scan_id = db.save_scan(result)
        console.print(f"[green]✓ Scan saved to database with ID: {scan_id[:8]}[/green]")
        
        # Mark fixed findings
        fixed_count = db.mark_fixed_findings(scan_id)
        if fixed_count > 0:
            console.print(f"[green]✓ {fixed_count} findings marked as fixed[/green]")

        # Generate reports
        _generate_reports(result, settings)

        # Exit with error code if critical/high findings
        critical_high = (
            result.summary.by_severity.get("critical", 0) +
            result.summary.by_severity.get("high", 0)
        )
        if critical_high > 0:
            console.print(f"\n[red]⚠️  Found {critical_high} critical/high severity issues![/red]")
            raise typer.Exit(1)

    except Exception as e:
        console.print(f"[red]Error during scan: {e}[/red]")
        raise typer.Exit(1)


@app.command("scan-repo")
def scan_repo(
    repo: Annotated[str, typer.Option("--repo", "-r", help="Repository (owner/repo or URL)")],
    token: Annotated[
        Optional[str],
        typer.Option("--token", "-t", envvar="GITHUB_TOKEN", help="GitHub token"),
    ] = None,
    config: Annotated[
        Optional[Path],
        typer.Option("--config", "-c", help="Path to config file"),
    ] = None,
    branch: Annotated[
        Optional[str],
        typer.Option("--branch", "-b", help="Specific branch to scan"),
    ] = None,
    full_history: Annotated[
        bool,
        typer.Option("--full-history", help="Analyze full git history"),
    ] = False,
    output_format: Annotated[
        str,
        typer.Option("--output-format", "-f", help="Output formats"),
    ] = "json,html",
    output_dir: Annotated[
        Path,
        typer.Option("--output-dir", "-d", help="Output directory"),
    ] = Path("./reports"),
) -> None:
    """
    Scan a single repository.

    Example:
        github-security-scanner scan-repo --repo owner/repo-name --token $GITHUB_TOKEN
    """
    if not token:
        console.print("[red]Error: GitHub token is required[/red]")
        raise typer.Exit(1)

    settings = get_settings(str(config) if config else None)
    settings.github.token = token
    settings.scan.analyze_history = full_history
    settings.output.directory = str(output_dir)
    settings.output.formats = output_format.split(",")

    if full_history:
        settings.scan.clone_strategy = "full"

    console.print(Panel.fit(
        f"[bold]Repository:[/bold] {repo}\n"
        f"[bold]Branch:[/bold] {branch or 'default'}\n"
        f"[bold]Full History:[/bold] {full_history}",
        title="🔧 Scan Configuration",
    ))

    scanner = SecurityScanner(settings)

    try:
        result = asyncio.run(scanner.scan_repository(
            repo_url=repo,
            token=token,
            branch=branch,
        ))

        # Save to database
        from .storage.database import Database
        db = Database()
        scan_id = db.save_scan(result)
        console.print(f"[green]✓ Scan saved to database with ID: {scan_id[:8]}[/green]")

        _generate_reports(result, settings)

        critical_high = (
            result.summary.by_severity.get("critical", 0) +
            result.summary.by_severity.get("high", 0)
        )
        if critical_high > 0:
            raise typer.Exit(1)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("list-repos")
def list_repos(
    org: Annotated[str, typer.Option("--org", "-o", help="GitHub organization")],
    token: Annotated[
        Optional[str],
        typer.Option("--token", "-t", envvar="GITHUB_TOKEN", help="GitHub token"),
    ] = None,
    include_archived: Annotated[bool, typer.Option("--include-archived")] = False,
    include_forks: Annotated[bool, typer.Option("--include-forks")] = False,
) -> None:
    """
    List repositories in an organization.

    Example:
        github-security-scanner list-repos --org myorg
    """
    if not token:
        console.print("[red]Error: GitHub token is required[/red]")
        raise typer.Exit(1)

    from .github import GitHubClient
    from .core.config import GitHubSettings

    async def _list():
        settings = GitHubSettings(token=token)
        async with GitHubClient(settings) as client:
            repos = await client.get_organization_repos(
                org,
                include_archived=include_archived,
                include_forks=include_forks,
            )

            console.print(f"\n[bold]Repositories in {org}:[/bold]\n")
            for repo in repos:
                visibility = "🔒" if repo.visibility == "private" else "🌍"
                console.print(f"  {visibility} {repo.name}")

            console.print(f"\n[bold]Total:[/bold] {len(repos)} repositories")

    asyncio.run(_list())


@app.command("report")
def report(
    input_file: Annotated[Path, typer.Option("--input", "-i", help="Input JSON scan result")],
    output_format: Annotated[str, typer.Option("--format", "-f", help="Output format")] = "html",
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Output file path"),
    ] = None,
) -> None:
    """
    Generate a report from a previous scan result.

    Example:
        github-security-scanner report --input scan-result.json --format html
    """
    import json
    from .core.models import ScanResult

    if not input_file.exists():
        console.print(f"[red]Error: Input file not found: {input_file}[/red]")
        raise typer.Exit(1)

    try:
        with open(input_file) as f:
            data = json.load(f)

        # Reconstruct ScanResult (simplified)
        from .core.models import Finding, Repository, ScanMetadata, ScanSummary, FindingType, Severity, FindingState

        result = ScanResult()
        result.metadata = ScanMetadata(**data.get("scan_metadata", {}))
        result.summary = ScanSummary(**data.get("summary", {}))

        # This is a simplified reconstruction
        console.print(f"[green]Loaded scan with {len(data.get('findings', []))} findings[/green]")

        settings = Settings()
        settings.output.formats = [output_format]

        if output:
            settings.output.directory = str(output.parent)

        _generate_reports_from_data(data, settings, output)

    except Exception as e:
        console.print(f"[red]Error generating report: {e}[/red]")
        raise typer.Exit(1)


@app.command("config")
def config_cmd(
    init: Annotated[bool, typer.Option("--init", help="Create default config file")] = False,
    show: Annotated[bool, typer.Option("--show", help="Show current configuration")] = False,
    validate: Annotated[bool, typer.Option("--validate", help="Validate configuration")] = False,
    path: Annotated[Path, typer.Option("--path", "-p")] = Path("config.yaml"),
) -> None:
    """
    Manage scanner configuration.

    Example:
        github-security-scanner config --init
    """
    if init:
        if path.exists():
            if not typer.confirm(f"{path} already exists. Overwrite?"):
                raise typer.Exit(0)

        create_default_config(path)
        console.print(f"[green]✓ Created default config at {path}[/green]")

    elif show:
        settings = get_settings(str(path) if path.exists() else None)
        import yaml
        console.print(yaml.dump(settings.model_dump(), default_flow_style=False))

    elif validate:
        try:
            settings = get_settings(str(path))
            console.print("[green]✓ Configuration is valid[/green]")

            # Check for token
            if not settings.github.token and not os.environ.get("GITHUB_TOKEN"):
                console.print("[yellow]⚠ No GitHub token configured[/yellow]")

        except Exception as e:
            console.print(f"[red]✗ Configuration error: {e}[/red]")
            raise typer.Exit(1)
    else:
        console.print("Use --init, --show, or --validate")


@app.command("console")
def console_cmd(
    db_path: Annotated[
        Path,
        typer.Option("--db", "-d", help="Path to database file"),
    ] = Path("security_scans.db"),
    config: Annotated[
        Optional[Path],
        typer.Option("--config", "-c", help="Path to config file"),
    ] = None,
) -> None:
    """
    Start interactive security console.

    Provides an interactive REPL for managing scans, findings, and remediation.

    Example:
        github-security-scanner console
    """
    from .dashboard.console import start_console

    start_console(db_path=str(db_path), config_path=str(config) if config else None)


@app.command("diff")
def diff_cmd(
    baseline: Annotated[str, typer.Argument(help="Baseline scan ID")],
    current: Annotated[str, typer.Argument(help="Current scan ID")],
    db_path: Annotated[
        Path,
        typer.Option("--db", "-d", help="Path to database file"),
    ] = Path("security_scans.db"),
) -> None:
    """
    Compare two scans and show differences.

    Shows new findings, fixed findings, and unchanged findings between two scans.

    Example:
        github-security-scanner diff abc123 def456
    """
    from .storage.database import Database
    from .dashboard.views import ComparisonView

    db = Database(db_path)
    view = ComparisonView(db)
    view.compare(baseline, current)


@app.command("findings")
def findings_cmd(
    status: Annotated[
        Optional[str],
        typer.Option("--status", "-s", help="Filter by status (open, fixed, in_progress)"),
    ] = None,
    severity: Annotated[
        Optional[str],
        typer.Option("--severity", help="Filter by severity (critical, high, medium, low)"),
    ] = None,
    repository: Annotated[
        Optional[str],
        typer.Option("--repo", "-r", help="Filter by repository"),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-l", help="Maximum findings to show"),
    ] = 50,
    db_path: Annotated[
        Path,
        typer.Option("--db", "-d", help="Path to database file"),
    ] = Path("security_scans.db"),
) -> None:
    """
    List findings from the database.

    Example:
        github-security-scanner findings --status open --severity critical
    """
    from .storage.database import Database
    from .dashboard.views import FindingsView

    db = Database(db_path)
    view = FindingsView(db)
    view.list_findings(status=status, severity=severity, repository=repository, limit=limit)


@app.command("update-status")
def update_status_cmd(
    finding_id: Annotated[str, typer.Argument(help="Finding ID")],
    new_status: Annotated[str, typer.Argument(help="New status")],
    comment: Annotated[
        Optional[str],
        typer.Option("--comment", "-m", help="Comment for the status change"),
    ] = None,
    db_path: Annotated[
        Path,
        typer.Option("--db", "-d", help="Path to database file"),
    ] = Path("security_scans.db"),
) -> None:
    """
    Update the status of a finding.

    Status values: open, in_progress, fixed, wont_fix, false_positive, accepted_risk

    Example:
        github-security-scanner update-status abc123 fixed --comment "Fixed in PR #123"
    """
    import os
    from .storage.database import Database
    from .storage.models import RemediationStatus

    db = Database(db_path)

    try:
        status = RemediationStatus(new_status)
    except ValueError:
        console.print(f"[red]Invalid status: {new_status}[/red]")
        console.print("[dim]Valid: open, in_progress, fixed, wont_fix, false_positive, accepted_risk[/dim]")
        raise typer.Exit(1)

    # Find full ID
    findings = db.get_findings(limit=1000)
    full_id = None
    for f in findings:
        if f.id.startswith(finding_id):
            full_id = f.id
            break

    if not full_id:
        console.print(f"[red]Finding not found: {finding_id}[/red]")
        raise typer.Exit(1)

    performed_by = os.environ.get("USER", "cli")

    if db.update_finding_status(full_id, status, performed_by, comment or ""):
        console.print(f"[green]✓ Updated finding {finding_id[:8]} to {status.value}[/green]")
    else:
        console.print("[red]Failed to update finding[/red]")
        raise typer.Exit(1)


@app.command("dashboard")
def dashboard_cmd(
    organization: Annotated[
        Optional[str],
        typer.Option("--org", "-o", help="Filter by organization"),
    ] = None,
    db_path: Annotated[
        Path,
        typer.Option("--db", "-d", help="Path to database file"),
    ] = Path("security_scans.db"),
) -> None:
    """
    Show security dashboard with statistics.

    Example:
        github-security-scanner dashboard --org myorg
    """
    from .storage.database import Database
    from .dashboard.views import DashboardView

    db = Database(db_path)
    view = DashboardView(db)
    view.render(organization)


@app.command("history")
def history_cmd(
    organization: Annotated[
        Optional[str],
        typer.Option("--org", "-o", help="Filter by organization"),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-l", help="Maximum scans to show"),
    ] = 20,
    db_path: Annotated[
        Path,
        typer.Option("--db", "-d", help="Path to database file"),
    ] = Path("security_scans.db"),
) -> None:
    """
    Show scan history.

    Example:
        github-security-scanner history --org myorg
    """
    from .storage.database import Database
    from .dashboard.views import ScansView

    db = Database(db_path)
    view = ScansView(db)
    view.list_scans(organization, limit=limit)


@app.command("trends")
def trends_cmd(
    organization: Annotated[str, typer.Argument(help="Organization name")],
    days: Annotated[
        int,
        typer.Option("--days", "-d", help="Number of days to show"),
    ] = 30,
    db_path: Annotated[
        Path,
        typer.Option("--db", help="Path to database file"),
    ] = Path("security_scans.db"),
) -> None:
    """
    Show security trends over time.

    Example:
        github-security-scanner trends myorg --days 30
    """
    from .storage.database import Database
    from .dashboard.views import TrendsView

    db = Database(db_path)
    view = TrendsView(db)
    view.show_trends(organization, days=days)


def _generate_reports(result, settings: Settings) -> None:
    """Generate reports in configured formats."""
    from .core.models import ScanResult

    output_dir = Path(settings.output.directory)
    output_dir.mkdir(parents=True, exist_ok=True)

    reporters = {
        "json": JSONReporter(settings.output),
        "html": HTMLReporter(settings.output),
        "sarif": SARIFReporter(settings.output),
        "csv": CSVReporter(settings.output),
    }

    for fmt in settings.output.formats:
        fmt = fmt.strip().lower()
        if fmt in reporters:
            reporter = reporters[fmt]
            output_path = reporter.write(result)
            console.print(f"[green]✓ Generated {fmt.upper()} report: {output_path}[/green]")


def _generate_reports_from_data(data: dict, settings: Settings, output: Optional[Path]) -> None:
    """Generate reports from raw scan data."""
    import json

    output_dir = Path(settings.output.directory)
    output_dir.mkdir(parents=True, exist_ok=True)

    for fmt in settings.output.formats:
        fmt = fmt.strip().lower()

        if fmt == "json":
            out_path = output or output_dir / "report.json"
            with open(out_path, "w") as f:
                json.dump(data, f, indent=2)
            console.print(f"[green]✓ Generated JSON report: {out_path}[/green]")

        elif fmt == "html":
            console.print("[yellow]HTML generation from existing data not fully implemented[/yellow]")

        elif fmt == "csv":
            console.print("[yellow]CSV generation from existing data not fully implemented[/yellow]")


if __name__ == "__main__":
    app()

