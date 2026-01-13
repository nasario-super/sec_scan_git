"""
HTML report generator with modern styling.
"""

from datetime import datetime

from ..core.models import Finding, ScanResult, Severity
from .base import BaseReporter


class HTMLReporter(BaseReporter):
    """Generates HTML format reports with modern styling."""

    format_name = "html"
    file_extension = ".html"

    def generate(self, result: ScanResult) -> str:
        """
        Generate HTML report.

        Args:
            result: Scan result

        Returns:
            HTML string
        """
        return self._render_template(result)

    def _get_severity_class(self, severity: Severity) -> str:
        """Get CSS class for severity."""
        return {
            Severity.CRITICAL: "critical",
            Severity.HIGH: "high",
            Severity.MEDIUM: "medium",
            Severity.LOW: "low",
            Severity.INFO: "info",
        }.get(severity, "info")

    def _render_finding_row(self, finding: Finding) -> str:
        """Render a single finding as HTML table row."""
        severity_class = self._get_severity_class(finding.severity)
        states = ", ".join(s.value for s in finding.states)

        # Sanitize content
        line_content = finding.sanitized_content(self.settings.redact_pattern)
        if len(line_content) > 100:
            line_content = line_content[:97] + "..."

        return f"""
        <tr class="finding-row {severity_class}">
            <td><span class="severity-badge {severity_class}">{finding.severity.value.upper()}</span></td>
            <td>{finding.type.value}</td>
            <td><code>{finding.category}</code></td>
            <td><a href="#{finding.repository}">{finding.repository}</a></td>
            <td><code>{finding.file_path}:{finding.line_number}</code></td>
            <td>{states}</td>
            <td>
                <details>
                    <summary>View Details</summary>
                    <div class="finding-details">
                        <p><strong>Rule:</strong> {finding.rule_id}</p>
                        <p><strong>Description:</strong> {finding.rule_description}</p>
                        <pre><code>{line_content}</code></pre>
                        <p><strong>Remediation:</strong> {finding.remediation}</p>
                    </div>
                </details>
            </td>
        </tr>
        """

    def _render_template(self, result: ScanResult) -> str:
        """Render the complete HTML report."""
        # Generate findings rows
        findings_html = ""
        for finding in sorted(result.findings, key=lambda f: (
            -{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[f.severity.value],
            f.repository,
        )):
            findings_html += self._render_finding_row(finding)

        # Generate repository summary
        repos_html = ""
        for name, repo in result.repositories.items():
            status_class = "success" if repo.scan_status.value == "completed" else "error"
            repos_html += f"""
            <tr id="{name}">
                <td>{name}</td>
                <td>{repo.visibility}</td>
                <td><span class="status-badge {status_class}">{repo.scan_status.value}</span></td>
                <td>{repo.findings_count}</td>
            </tr>
            """

        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {result.metadata.organization}</title>
    <style>
        :root {{
            --color-bg: #0d1117;
            --color-bg-secondary: #161b22;
            --color-border: #30363d;
            --color-text: #c9d1d9;
            --color-text-secondary: #8b949e;
            --color-critical: #f85149;
            --color-high: #db6d28;
            --color-medium: #d29922;
            --color-low: #3fb950;
            --color-info: #58a6ff;
            --color-success: #3fb950;
            --color-error: #f85149;
            --font-mono: 'JetBrains Mono', 'Fira Code', Consolas, monospace;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--color-bg);
            color: var(--color-text);
            line-height: 1.6;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}

        header {{
            background: linear-gradient(135deg, #1a1f35 0%, #0d1117 100%);
            padding: 3rem 0;
            border-bottom: 1px solid var(--color-border);
            margin-bottom: 2rem;
        }}

        header h1 {{
            font-size: 2.5rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }}

        header .meta {{
            color: var(--color-text-secondary);
            font-size: 0.9rem;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .summary-card {{
            background: var(--color-bg-secondary);
            border: 1px solid var(--color-border);
            border-radius: 8px;
            padding: 1.5rem;
        }}

        .summary-card h3 {{
            color: var(--color-text-secondary);
            font-size: 0.875rem;
            font-weight: 500;
            margin-bottom: 0.5rem;
        }}

        .summary-card .value {{
            font-size: 2rem;
            font-weight: 700;
        }}

        .severity-breakdown {{
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
            margin-top: 1rem;
        }}

        .severity-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .severity-badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .severity-badge.critical {{ background: var(--color-critical); color: white; }}
        .severity-badge.high {{ background: var(--color-high); color: white; }}
        .severity-badge.medium {{ background: var(--color-medium); color: black; }}
        .severity-badge.low {{ background: var(--color-low); color: black; }}
        .severity-badge.info {{ background: var(--color-info); color: white; }}

        .status-badge {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
        }}

        .status-badge.success {{ background: rgba(63, 185, 80, 0.2); color: var(--color-success); }}
        .status-badge.error {{ background: rgba(248, 81, 73, 0.2); color: var(--color-error); }}

        section {{
            background: var(--color-bg-secondary);
            border: 1px solid var(--color-border);
            border-radius: 8px;
            margin-bottom: 2rem;
            overflow: hidden;
        }}

        section h2 {{
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--color-border);
            font-size: 1.25rem;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th, td {{
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--color-border);
        }}

        th {{
            background: rgba(0, 0, 0, 0.3);
            font-weight: 600;
            font-size: 0.875rem;
            color: var(--color-text-secondary);
        }}

        tr:hover {{
            background: rgba(255, 255, 255, 0.02);
        }}

        code {{
            font-family: var(--font-mono);
            font-size: 0.875rem;
            background: rgba(0, 0, 0, 0.3);
            padding: 0.125rem 0.375rem;
            border-radius: 4px;
        }}

        pre {{
            background: rgba(0, 0, 0, 0.3);
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            margin: 0.5rem 0;
        }}

        pre code {{
            background: none;
            padding: 0;
        }}

        details {{
            cursor: pointer;
        }}

        summary {{
            color: var(--color-info);
            font-size: 0.875rem;
        }}

        .finding-details {{
            padding: 1rem;
            background: rgba(0, 0, 0, 0.2);
            border-radius: 4px;
            margin-top: 0.5rem;
        }}

        .finding-details p {{
            margin-bottom: 0.5rem;
        }}

        a {{
            color: var(--color-info);
            text-decoration: none;
        }}

        a:hover {{
            text-decoration: underline;
        }}

        .finding-row.critical {{ border-left: 3px solid var(--color-critical); }}
        .finding-row.high {{ border-left: 3px solid var(--color-high); }}
        .finding-row.medium {{ border-left: 3px solid var(--color-medium); }}
        .finding-row.low {{ border-left: 3px solid var(--color-low); }}
        .finding-row.info {{ border-left: 3px solid var(--color-info); }}

        @media (max-width: 768px) {{
            .container {{ padding: 1rem; }}
            .summary-grid {{ grid-template-columns: 1fr 1fr; }}
            table {{ font-size: 0.875rem; }}
            th, td {{ padding: 0.5rem; }}
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🔒 Security Scan Report</h1>
            <p class="meta">
                Organization: <strong>{result.metadata.organization}</strong> |
                Scan Date: <strong>{result.metadata.scan_date.strftime("%Y-%m-%d %H:%M:%S")}</strong> |
                Duration: <strong>{result.metadata.scan_duration_seconds:.1f}s</strong>
            </p>
        </div>
    </header>

    <div class="container">
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="value">{result.metadata.total_findings}</div>
            </div>
            <div class="summary-card">
                <h3>Repositories Scanned</h3>
                <div class="value">{result.metadata.repositories_scanned}</div>
            </div>
            <div class="summary-card">
                <h3>Critical Issues</h3>
                <div class="value" style="color: var(--color-critical)">
                    {result.summary.by_severity.get('critical', 0)}
                </div>
            </div>
            <div class="summary-card">
                <h3>High Issues</h3>
                <div class="value" style="color: var(--color-high)">
                    {result.summary.by_severity.get('high', 0)}
                </div>
            </div>
        </div>

        <div class="summary-grid">
            <div class="summary-card">
                <h3>By Type</h3>
                <div class="severity-breakdown">
                    {"".join(f'<div class="severity-item"><span>{t}:</span> <strong>{c}</strong></div>' for t, c in result.summary.by_type.items())}
                </div>
            </div>
            <div class="summary-card">
                <h3>By State</h3>
                <div class="severity-breakdown">
                    {"".join(f'<div class="severity-item"><span>{s}:</span> <strong>{c}</strong></div>' for s, c in result.summary.by_state.items())}
                </div>
            </div>
        </div>

        <section>
            <h2>📋 Findings ({len(result.findings)})</h2>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Type</th>
                            <th>Category</th>
                            <th>Repository</th>
                            <th>Location</th>
                            <th>State</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {findings_html}
                    </tbody>
                </table>
            </div>
        </section>

        <section>
            <h2>📦 Repositories ({len(result.repositories)})</h2>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Repository</th>
                            <th>Visibility</th>
                            <th>Status</th>
                            <th>Findings</th>
                        </tr>
                    </thead>
                    <tbody>
                        {repos_html}
                    </tbody>
                </table>
            </div>
        </section>

        <footer style="text-align: center; padding: 2rem; color: var(--color-text-secondary);">
            <p>Generated by GitHub Security Scanner v{result.metadata.tool_version} on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </footer>
    </div>
</body>
</html>
"""

