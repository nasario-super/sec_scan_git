"""
Interactive security console for managing scans and findings.

Provides a REPL-style interface for security management.
"""

import asyncio
import os
import shlex
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from ..core.config import Settings, get_settings
from ..core.scanner import SecurityScanner
from ..storage.database import Database
from ..storage.models import RemediationStatus
from .views import ComparisonView, DashboardView, FindingsView, ScansView, TrendsView


console = Console()


class SecurityConsole:
    """
    Interactive security console.

    Provides commands for:
    - Running scans
    - Viewing results
    - Tracking remediation
    - Generating reports
    - Comparing scans
    """

    COMMANDS = {
        "help": "Show available commands",
        "dashboard": "Show main dashboard",
        "scan": "Run a new scan (scan <org> or scan-repo <repo>)",
        "scans": "List all scans",
        "show": "Show scan details (show <scan_id>)",
        "findings": "List findings (findings [--status open] [--severity critical])",
        "finding": "Show finding details (finding <id>)",
        "status": "Update finding status (status <finding_id> <new_status>)",
        "compare": "Compare two scans (compare <scan1> <scan2>)",
        "trends": "Show trend data (trends <org> [--days 30])",
        "export": "Export report (export <scan_id> [--format json|html|csv])",
        "retest": "Retest to verify fixes (retest <org>)",
        "stats": "Show statistics",
        "clear": "Clear screen",
        "exit": "Exit console",
    }

    def __init__(
        self,
        db_path: str = "security_scans.db",
        config_path: Optional[str] = None,
    ):
        """
        Initialize security console.

        Args:
            db_path: Path to SQLite database
            config_path: Path to config file
        """
        self.db = Database(db_path)
        self.settings = get_settings(config_path)
        self.token: Optional[str] = os.environ.get("GITHUB_TOKEN")

        # Initialize views
        self.dashboard_view = DashboardView(self.db)
        self.scans_view = ScansView(self.db)
        self.findings_view = FindingsView(self.db)
        self.trends_view = TrendsView(self.db)
        self.comparison_view = ComparisonView(self.db)

        # Current context
        self.current_org: Optional[str] = None

    def run(self) -> None:
        """Start the interactive console."""
        self._show_welcome()

        while True:
            try:
                # Show prompt
                prompt = "[bold cyan]security[/bold cyan]"
                if self.current_org:
                    prompt += f"[dim]({self.current_org})[/dim]"
                prompt += "> "

                command = Prompt.ask(prompt)
                if not command.strip():
                    continue

                # Parse and execute command
                self._execute_command(command.strip())

            except KeyboardInterrupt:
                console.print("\n[dim]Use 'exit' to quit[/dim]")
            except EOFError:
                break
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

    def _show_welcome(self) -> None:
        """Show welcome message."""
        console.clear()
        console.print(Panel.fit(
            "[bold cyan]🛡️  GitHub Security Scanner Console[/bold cyan]\n\n"
            "[dim]Interactive security management dashboard[/dim]\n"
            "[dim]Type 'help' for available commands[/dim]",
            border_style="cyan",
        ))
        console.print()

        # Show quick stats
        stats = self.db.get_statistics()
        if stats["total_scans"] > 0:
            console.print(f"[dim]📊 {stats['total_scans']} scans | "
                         f"🔓 {stats['open_findings']} open findings | "
                         f"✅ {stats['fixed_findings']} fixed[/dim]")
            console.print()

    def _execute_command(self, command: str) -> None:
        """Parse and execute a command."""
        try:
            parts = shlex.split(command)
        except ValueError:
            parts = command.split()

        if not parts:
            return

        cmd = parts[0].lower()
        args = parts[1:]

        # Command dispatch
        commands = {
            "help": self._cmd_help,
            "h": self._cmd_help,
            "?": self._cmd_help,
            "dashboard": self._cmd_dashboard,
            "d": self._cmd_dashboard,
            "scan": self._cmd_scan,
            "scans": self._cmd_scans,
            "ls": self._cmd_scans,
            "show": self._cmd_show,
            "findings": self._cmd_findings,
            "f": self._cmd_findings,
            "finding": self._cmd_finding_detail,
            "status": self._cmd_update_status,
            "compare": self._cmd_compare,
            "diff": self._cmd_compare,
            "trends": self._cmd_trends,
            "export": self._cmd_export,
            "retest": self._cmd_retest,
            "stats": self._cmd_stats,
            "org": self._cmd_set_org,
            "clear": lambda _: console.clear(),
            "cls": lambda _: console.clear(),
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "q": self._cmd_exit,
        }

        if cmd in commands:
            commands[cmd](args)
        else:
            console.print(f"[red]Unknown command: {cmd}[/red]")
            console.print("[dim]Type 'help' for available commands[/dim]")

    def _cmd_help(self, args: list) -> None:
        """Show help."""
        table = Table(title="Available Commands", show_header=True, header_style="bold cyan")
        table.add_column("Command", style="cyan")
        table.add_column("Description")

        for cmd, desc in self.COMMANDS.items():
            table.add_row(cmd, desc)

        console.print(table)
        console.print()
        console.print("[dim]Status values: open, in_progress, fixed, wont_fix, false_positive, accepted_risk[/dim]")

    def _cmd_dashboard(self, args: list) -> None:
        """Show dashboard."""
        self.dashboard_view.render(self.current_org)

    def _cmd_scan(self, args: list) -> None:
        """Run a new scan."""
        if not args:
            console.print("[yellow]Usage: scan <organization> or scan-repo <owner/repo>[/yellow]")
            return

        if not self.token:
            self.token = Prompt.ask("GitHub Token", password=True)
            if not self.token:
                console.print("[red]Token required[/red]")
                return

        target = args[0]
        self.settings.github.token = self.token

        scanner = SecurityScanner(self.settings)

        console.print(f"\n[cyan]Starting scan of {target}...[/cyan]\n")

        try:
            if "/" in target:
                # Repository scan
                result = asyncio.run(scanner.scan_repository(target, self.token))
            else:
                # Organization scan
                result = asyncio.run(scanner.scan_organization(target, self.token))
                self.current_org = target

            # Save to database
            scan_id = self.db.save_scan(result)
            console.print(f"[green]✓ Scan saved with ID: {scan_id[:8]}[/green]")

            # Check for fixed findings
            fixed_count = self.db.mark_fixed_findings(scan_id)
            if fixed_count > 0:
                console.print(f"[green]✓ {fixed_count} findings marked as fixed[/green]")

        except Exception as e:
            console.print(f"[red]Scan failed: {e}[/red]")

    def _cmd_scans(self, args: list) -> None:
        """List scans."""
        limit = 20
        if args and args[0].isdigit():
            limit = int(args[0])

        self.scans_view.list_scans(self.current_org, limit=limit)

    def _cmd_show(self, args: list) -> None:
        """Show scan details."""
        if not args:
            console.print("[yellow]Usage: show <scan_id>[/yellow]")
            return

        self.scans_view.show_scan_details(args[0])

    def _cmd_findings(self, args: list) -> None:
        """List findings."""
        status = None
        severity = None
        repository = None
        limit = 50

        # Parse arguments
        i = 0
        while i < len(args):
            if args[i] == "--status" and i + 1 < len(args):
                status = args[i + 1]
                i += 2
            elif args[i] == "--severity" and i + 1 < len(args):
                severity = args[i + 1]
                i += 2
            elif args[i] == "--repo" and i + 1 < len(args):
                repository = args[i + 1]
                i += 2
            elif args[i] == "--limit" and i + 1 < len(args):
                limit = int(args[i + 1])
                i += 2
            elif args[i] in ["open", "fixed", "in_progress"]:
                status = args[i]
                i += 1
            elif args[i] in ["critical", "high", "medium", "low"]:
                severity = args[i]
                i += 1
            else:
                i += 1

        self.findings_view.list_findings(
            status=status,
            severity=severity,
            repository=repository,
            limit=limit,
        )

    def _cmd_finding_detail(self, args: list) -> None:
        """Show finding details."""
        if not args:
            console.print("[yellow]Usage: finding <finding_id>[/yellow]")
            return

        self.findings_view.show_finding_details(args[0])

    def _cmd_update_status(self, args: list) -> None:
        """Update finding status."""
        if len(args) < 2:
            console.print("[yellow]Usage: status <finding_id> <new_status>[/yellow]")
            console.print("[dim]Status: open, in_progress, fixed, wont_fix, false_positive, accepted_risk[/dim]")
            return

        finding_id = args[0]
        new_status_str = args[1]
        comment = " ".join(args[2:]) if len(args) > 2 else ""

        try:
            new_status = RemediationStatus(new_status_str)
        except ValueError:
            console.print(f"[red]Invalid status: {new_status_str}[/red]")
            return

        # Find the full ID
        findings = self.db.get_findings(limit=1000)
        full_id = None
        for f in findings:
            if f.id.startswith(finding_id):
                full_id = f.id
                break

        if not full_id:
            console.print(f"[red]Finding not found: {finding_id}[/red]")
            return

        performed_by = os.environ.get("USER", "console")

        if self.db.update_finding_status(full_id, new_status, performed_by, comment):
            console.print(f"[green]✓ Updated finding {finding_id[:8]} to {new_status.value}[/green]")
        else:
            console.print("[red]Failed to update finding[/red]")

    def _cmd_compare(self, args: list) -> None:
        """Compare two scans."""
        if len(args) < 2:
            console.print("[yellow]Usage: compare <scan_id_1> <scan_id_2>[/yellow]")
            return

        self.comparison_view.compare(args[0], args[1])

    def _cmd_trends(self, args: list) -> None:
        """Show trends."""
        org = args[0] if args else self.current_org
        if not org:
            console.print("[yellow]Usage: trends <organization> [--days 30][/yellow]")
            return

        days = 30
        if "--days" in args:
            idx = args.index("--days")
            if idx + 1 < len(args):
                days = int(args[idx + 1])

        self.trends_view.show_trends(org, days=days)

    def _cmd_export(self, args: list) -> None:
        """Export report."""
        if not args:
            console.print("[yellow]Usage: export <scan_id> [--format json|html|csv|sarif][/yellow]")
            return

        scan_id = args[0]
        output_format = "json"

        if "--format" in args:
            idx = args.index("--format")
            if idx + 1 < len(args):
                output_format = args[idx + 1]

        # Get scan
        scan = self.db.get_scan(scan_id)
        if not scan:
            scans = self.db.get_scans(limit=100)
            for s in scans:
                if s.id.startswith(scan_id):
                    scan = self.db.get_scan(s.id)
                    scan_id = s.id
                    break

        if not scan:
            console.print(f"[red]Scan not found: {scan_id}[/red]")
            return

        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"export-{scan_id[:8]}-{timestamp}.{output_format}"

        # Get findings
        findings = self.db.get_findings(scan_id=scan_id, limit=10000)

        # Export based on format
        if output_format == "json":
            import json
            data = {
                "scan": scan.to_dict(),
                "findings": [f.to_dict() for f in findings],
                "exported_at": datetime.now().isoformat(),
            }
            with open(filename, "w") as f:
                json.dump(data, f, indent=2)
        elif output_format == "csv":
            import csv
            with open(filename, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "Repository", "Type", "Category", "Severity", "Status", "File", "Line"])
                for finding in findings:
                    writer.writerow([
                        finding.id[:8], finding.repository, finding.finding_type,
                        finding.category, finding.severity, finding.status.value,
                        finding.file_path, finding.line_number,
                    ])
        else:
            console.print(f"[yellow]Format {output_format} not fully implemented, using JSON[/yellow]")
            filename = filename.replace(f".{output_format}", ".json")
            import json
            data = {"scan": scan.to_dict(), "findings": [f.to_dict() for f in findings]}
            with open(filename, "w") as f:
                json.dump(data, f, indent=2)

        console.print(f"[green]✓ Exported to {filename}[/green]")

    def _cmd_retest(self, args: list) -> None:
        """Run a retest scan to verify fixes."""
        org = args[0] if args else self.current_org
        if not org:
            console.print("[yellow]Usage: retest <organization>[/yellow]")
            return

        if not self.token:
            self.token = Prompt.ask("GitHub Token", password=True)

        # Get last scan for comparison
        scans = self.db.get_scans(organization=org, limit=1)
        baseline_scan_id = scans[0].id if scans else None

        console.print(f"\n[cyan]Running retest scan of {org}...[/cyan]")
        if baseline_scan_id:
            console.print(f"[dim]Will compare against scan {baseline_scan_id[:8]}[/dim]\n")

        self.settings.github.token = self.token
        scanner = SecurityScanner(self.settings)

        try:
            result = asyncio.run(scanner.scan_organization(org, self.token))
            scan_id = self.db.save_scan(result)

            console.print(f"[green]✓ Retest scan saved: {scan_id[:8]}[/green]")

            # Mark fixed findings
            fixed_count = self.db.mark_fixed_findings(scan_id)
            if fixed_count > 0:
                console.print(f"[green]✓ {fixed_count} findings verified as fixed![/green]")

            # Compare with baseline
            if baseline_scan_id:
                console.print()
                self.comparison_view.compare(baseline_scan_id, scan_id)

        except Exception as e:
            console.print(f"[red]Retest failed: {e}[/red]")

    def _cmd_stats(self, args: list) -> None:
        """Show statistics."""
        stats = self.db.get_statistics(self.current_org)

        table = Table(title="📊 Statistics", show_header=False)
        table.add_column("", style="bold", width=25)
        table.add_column("")

        table.add_row("Total Scans:", str(stats.get("total_scans", 0)))
        table.add_row("Avg Findings/Scan:", str(stats.get("average_findings_per_scan", 0)))
        table.add_row("", "")

        status_counts = stats.get("status_counts", {})
        table.add_row("[red]Open Findings:[/red]", str(status_counts.get("open", 0)))
        table.add_row("[yellow]In Progress:[/yellow]", str(status_counts.get("in_progress", 0)))
        table.add_row("[green]Fixed:[/green]", str(status_counts.get("fixed", 0)))
        table.add_row("[dim]Won't Fix:[/dim]", str(status_counts.get("wont_fix", 0)))
        table.add_row("[cyan]False Positive:[/cyan]", str(status_counts.get("false_positive", 0)))

        console.print(table)

    def _cmd_set_org(self, args: list) -> None:
        """Set current organization context."""
        if not args:
            if self.current_org:
                console.print(f"Current organization: {self.current_org}")
            else:
                console.print("[yellow]Usage: org <organization>[/yellow]")
            return

        self.current_org = args[0]
        console.print(f"[green]✓ Set organization to {self.current_org}[/green]")

    def _cmd_exit(self, args: list) -> None:
        """Exit console."""
        if Confirm.ask("Exit console?", default=True):
            console.print("[dim]Goodbye! 👋[/dim]")
            raise SystemExit(0)


def start_console(db_path: str = "security_scans.db", config_path: Optional[str] = None) -> None:
    """Start the interactive security console."""
    console_app = SecurityConsole(db_path=db_path, config_path=config_path)
    console_app.run()

