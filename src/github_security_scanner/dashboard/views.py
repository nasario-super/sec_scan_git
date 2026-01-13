"""
Dashboard views for displaying scan data.

Provides visual components for the interactive console.
"""

from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..storage.database import Database
from ..storage.models import RemediationStatus


console = Console()


class DashboardView:
    """Main dashboard view showing overview statistics."""

    def __init__(self, db: Database):
        """Initialize dashboard view."""
        self.db = db

    def render(self, organization: Optional[str] = None) -> None:
        """Render the main dashboard."""
        stats = self.db.get_statistics(organization)
        scans = self.db.get_scans(organization, limit=5)

        # Header
        console.print()
        console.print(Panel.fit(
            "[bold cyan]🛡️  Security Scanner Dashboard[/bold cyan]",
            border_style="cyan",
        ))
        console.print()

        # Statistics Grid
        self._render_stats_grid(stats)
        console.print()

        # Recent Scans
        self._render_recent_scans(scans)
        console.print()

        # Top Affected Repos
        if stats.get("top_affected_repos"):
            self._render_top_repos(stats["top_affected_repos"])

    def _render_stats_grid(self, stats: dict) -> None:
        """Render statistics grid."""
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("", style="bold")
        table.add_column("")
        table.add_column("", style="bold")
        table.add_column("")
        table.add_column("", style="bold")
        table.add_column("")

        table.add_row(
            "📊 Total Scans:", str(stats.get("total_scans", 0)),
            "🔓 Open Findings:", f"[red]{stats.get('open_findings', 0)}[/red]",
            "✅ Fixed:", f"[green]{stats.get('fixed_findings', 0)}[/green]",
        )

        table.add_row(
            "📈 Avg/Scan:", str(stats.get("average_findings_per_scan", 0)),
            "", "", "", "",
        )

        console.print(Panel(table, title="[bold]Statistics[/bold]", border_style="blue"))

    def _render_recent_scans(self, scans: list) -> None:
        """Render recent scans table."""
        table = Table(title="Recent Scans", show_header=True, header_style="bold magenta")
        table.add_column("Date", style="dim")
        table.add_column("Organization")
        table.add_column("Repos", justify="right")
        table.add_column("Findings", justify="right")
        table.add_column("Critical", justify="right", style="red")
        table.add_column("High", justify="right", style="yellow")
        table.add_column("ID", style="dim")

        for scan in scans:
            table.add_row(
                scan.scan_date.strftime("%Y-%m-%d %H:%M"),
                scan.organization,
                str(scan.repositories_scanned),
                str(scan.total_findings),
                str(scan.critical_count),
                str(scan.high_count),
                scan.id[:8],
            )

        console.print(table)

    def _render_top_repos(self, repos: list) -> None:
        """Render top affected repositories."""
        table = Table(title="Top Affected Repositories", show_header=True)
        table.add_column("Repository")
        table.add_column("Open Findings", justify="right", style="red")

        for repo in repos:
            table.add_row(repo["repo"], str(repo["count"]))

        console.print(table)


class ScansView:
    """View for listing and managing scans."""

    def __init__(self, db: Database):
        """Initialize scans view."""
        self.db = db

    def list_scans(self, organization: Optional[str] = None, limit: int = 20) -> None:
        """List all scans."""
        scans = self.db.get_scans(organization, limit=limit)

        table = Table(title="🔍 Scan History", show_header=True, header_style="bold cyan")
        table.add_column("#", style="dim", width=4)
        table.add_column("ID", width=10)
        table.add_column("Date", width=18)
        table.add_column("Organization", width=20)
        table.add_column("Repos", justify="right", width=6)
        table.add_column("Total", justify="right", width=6)
        table.add_column("🔴", justify="right", width=4)
        table.add_column("🟠", justify="right", width=4)
        table.add_column("🟡", justify="right", width=4)

        for i, scan in enumerate(scans, 1):
            table.add_row(
                str(i),
                scan.id[:8] + "...",
                scan.scan_date.strftime("%Y-%m-%d %H:%M"),
                scan.organization[:18] + ".." if len(scan.organization) > 18 else scan.organization,
                str(scan.repositories_scanned),
                str(scan.total_findings),
                str(scan.critical_count) if scan.critical_count else "-",
                str(scan.high_count) if scan.high_count else "-",
                str(scan.medium_count) if hasattr(scan, 'medium_count') and scan.medium_count else "-",
            )

        console.print(table)

    def show_scan_details(self, scan_id: str) -> None:
        """Show detailed information about a scan."""
        scan = self.db.get_scan(scan_id)
        if not scan:
            # Try partial match
            scans = self.db.get_scans(limit=100)
            for s in scans:
                if s.id.startswith(scan_id):
                    scan = self.db.get_scan(s.id)
                    break

        if not scan:
            console.print(f"[red]Scan not found: {scan_id}[/red]")
            return

        # Header
        console.print(Panel.fit(
            f"[bold]Scan Details: {scan.id[:8]}[/bold]",
            border_style="cyan",
        ))

        # Info table
        table = Table(show_header=False, box=None)
        table.add_column("", style="bold", width=20)
        table.add_column("")

        table.add_row("Organization:", scan.organization)
        table.add_row("Date:", scan.scan_date.strftime("%Y-%m-%d %H:%M:%S"))
        table.add_row("Duration:", f"{scan.duration_seconds:.1f}s")
        table.add_row("Repositories:", str(scan.repositories_scanned))
        table.add_row("Total Findings:", str(scan.total_findings))

        console.print(table)
        console.print()

        # Severity breakdown
        sev_table = Table(title="Severity Breakdown", show_header=True)
        sev_table.add_column("Severity")
        sev_table.add_column("Count", justify="right")

        sev_table.add_row("[red]Critical[/red]", str(scan.critical_count))
        sev_table.add_row("[yellow]High[/yellow]", str(scan.high_count))
        sev_table.add_row("[blue]Medium[/blue]", str(scan.medium_count))
        sev_table.add_row("[dim]Low[/dim]", str(scan.low_count))

        console.print(sev_table)

        # Findings for this scan
        findings = self.db.get_findings(scan_id=scan.id, limit=10)
        if findings:
            console.print()
            console.print("[bold]Top Findings:[/bold]")
            for f in findings[:10]:
                sev_color = {"critical": "red", "high": "yellow", "medium": "blue"}.get(f.severity, "dim")
                console.print(f"  [{sev_color}]●[/{sev_color}] {f.repository}: {f.category} ({f.file_path}:{f.line_number})")


class FindingsView:
    """View for displaying and managing findings."""

    def __init__(self, db: Database):
        """Initialize findings view."""
        self.db = db

    def list_findings(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        repository: Optional[str] = None,
        limit: int = 50,
    ) -> None:
        """List findings with filters."""
        status_filter = None
        if status:
            try:
                status_filter = RemediationStatus(status)
            except ValueError:
                pass

        findings = self.db.get_findings(
            status=status_filter,
            severity=severity,
            repository=repository,
            limit=limit,
        )

        title = "🔍 Findings"
        if status:
            title += f" (Status: {status})"
        if severity:
            title += f" (Severity: {severity})"

        table = Table(title=title, show_header=True, header_style="bold")
        table.add_column("#", style="dim", width=4)
        table.add_column("Sev", width=4)
        table.add_column("Type", width=8)
        table.add_column("Category", width=15)
        table.add_column("Repository", width=20)
        table.add_column("Location", width=30)
        table.add_column("Status", width=10)
        table.add_column("First Seen", width=12)

        for i, finding in enumerate(findings, 1):
            sev_icon = {
                "critical": "[red]🔴[/red]",
                "high": "[yellow]🟠[/yellow]",
                "medium": "[blue]🟡[/blue]",
                "low": "[dim]🔵[/dim]",
            }.get(finding.severity, "⚪")

            status_color = {
                "open": "red",
                "in_progress": "yellow",
                "fixed": "green",
                "wont_fix": "dim",
                "false_positive": "cyan",
            }.get(finding.status.value, "white")

            location = f"{finding.file_path}:{finding.line_number}"
            if len(location) > 28:
                location = "..." + location[-25:]

            table.add_row(
                str(i),
                sev_icon,
                finding.finding_type[:8],
                finding.category[:15],
                finding.repository[:18] + ".." if len(finding.repository) > 18 else finding.repository,
                location,
                f"[{status_color}]{finding.status.value}[/{status_color}]",
                finding.first_seen_date.strftime("%Y-%m-%d"),
            )

        console.print(table)
        console.print(f"\n[dim]Showing {len(findings)} findings[/dim]")

    def show_finding_details(self, finding_id: str) -> None:
        """Show detailed information about a finding."""
        findings = self.db.get_findings(limit=1000)
        finding = None
        for f in findings:
            if f.id.startswith(finding_id):
                finding = f
                break

        if not finding:
            console.print(f"[red]Finding not found: {finding_id}[/red]")
            return

        sev_color = {"critical": "red", "high": "yellow", "medium": "blue"}.get(finding.severity, "dim")

        console.print(Panel.fit(
            f"[bold]Finding: {finding.id[:8]}[/bold]",
            border_style=sev_color,
        ))

        table = Table(show_header=False, box=None)
        table.add_column("", style="bold", width=15)
        table.add_column("")

        table.add_row("Repository:", finding.repository)
        table.add_row("Type:", finding.finding_type)
        table.add_row("Category:", finding.category)
        table.add_row("Severity:", f"[{sev_color}]{finding.severity}[/{sev_color}]")
        table.add_row("Status:", finding.status.value)
        table.add_row("File:", finding.file_path)
        table.add_row("Line:", str(finding.line_number))
        table.add_row("Rule:", finding.rule_id or "-")
        table.add_row("First Seen:", finding.first_seen_date.strftime("%Y-%m-%d %H:%M"))
        table.add_row("Last Seen:", finding.last_seen_date.strftime("%Y-%m-%d %H:%M"))

        console.print(table)


class TrendsView:
    """View for displaying trend data and analytics."""

    def __init__(self, db: Database):
        """Initialize trends view."""
        self.db = db

    def show_trends(self, organization: str, days: int = 30) -> None:
        """Show trend data visualization."""
        trends = self.db.get_trend_data(organization, days=days)

        if not trends:
            console.print(f"[yellow]No trend data available for {organization}[/yellow]")
            return

        console.print(Panel.fit(
            f"[bold]📈 Trends for {organization} (Last {days} days)[/bold]",
            border_style="cyan",
        ))

        # Summary table
        table = Table(show_header=True, header_style="bold")
        table.add_column("Date")
        table.add_column("Total", justify="right")
        table.add_column("Critical", justify="right", style="red")
        table.add_column("High", justify="right", style="yellow")
        table.add_column("Medium", justify="right", style="blue")

        for trend in trends[-10:]:  # Last 10 data points
            table.add_row(
                trend.date.strftime("%Y-%m-%d"),
                str(trend.total_findings),
                str(trend.critical),
                str(trend.high),
                str(trend.medium),
            )

        console.print(table)

        # Simple ASCII chart
        if len(trends) >= 2:
            console.print()
            self._render_ascii_chart(trends)

    def _render_ascii_chart(self, trends: list) -> None:
        """Render a simple ASCII chart of findings over time."""
        if not trends:
            return

        max_val = max(t.total_findings for t in trends) or 1
        height = 10
        width = min(len(trends), 40)

        # Sample data if too many points
        if len(trends) > width:
            step = len(trends) // width
            trends = trends[::step][:width]

        console.print("[bold]Findings Over Time:[/bold]")
        console.print()

        for row in range(height, -1, -1):
            threshold = (row / height) * max_val
            line = ""
            for trend in trends:
                if trend.total_findings >= threshold:
                    line += "█"
                else:
                    line += " "
            if row == height:
                console.print(f" {max_val:4.0f} │{line}")
            elif row == 0:
                console.print(f"    0 │{line}")
                console.print(f"      └{'─' * len(trends)}")
            else:
                console.print(f"      │{line}")


class ComparisonView:
    """View for comparing two scans."""

    def __init__(self, db: Database):
        """Initialize comparison view."""
        self.db = db

    def compare(self, scan_id_1: str, scan_id_2: str) -> None:
        """Compare two scans and show differences."""
        # Resolve partial IDs
        scans = self.db.get_scans(limit=100)
        full_id_1 = None
        full_id_2 = None

        for scan in scans:
            if scan.id.startswith(scan_id_1):
                full_id_1 = scan.id
            if scan.id.startswith(scan_id_2):
                full_id_2 = scan.id

        if not full_id_1 or not full_id_2:
            console.print("[red]One or both scans not found[/red]")
            return

        diff = self.db.compare_scans(full_id_1, full_id_2)

        console.print(Panel.fit(
            "[bold]🔄 Scan Comparison[/bold]",
            border_style="cyan",
        ))

        # Summary
        table = Table(show_header=False, box=None)
        table.add_column("", style="bold", width=20)
        table.add_column("")

        table.add_row("Baseline Scan:", full_id_1[:8])
        table.add_row("Current Scan:", full_id_2[:8])
        table.add_row("", "")
        table.add_row("[green]✅ Fixed:[/green]", f"[green]{diff['fixed_count']}[/green]")
        table.add_row("[red]🆕 New:[/red]", f"[red]{diff['new_count']}[/red]")
        table.add_row("➡️ Unchanged:", str(diff['unchanged_count']))

        console.print(table)

        # New findings
        if diff["new_findings"]:
            console.print()
            console.print("[bold red]New Findings:[/bold red]")
            for f in diff["new_findings"][:10]:
                console.print(f"  🆕 {f['repository']}: {f['category']} ({f['file_path']})")

        # Fixed findings
        if diff["fixed_findings"]:
            console.print()
            console.print("[bold green]Fixed Findings:[/bold green]")
            for f in diff["fixed_findings"][:10]:
                console.print(f"  ✅ {f['repository']}: {f['category']} ({f['file_path']})")

