"""
CSV report generator.
"""

import csv
import io

from ..core.models import ScanResult
from .base import BaseReporter


class CSVReporter(BaseReporter):
    """Generates CSV format reports."""

    format_name = "csv"
    file_extension = ".csv"

    def generate(self, result: ScanResult) -> str:
        """
        Generate CSV report.

        Args:
            result: Scan result

        Returns:
            CSV string
        """
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "ID",
            "Repository",
            "Type",
            "Category",
            "Severity",
            "States",
            "File",
            "Line",
            "Content",
            "Rule ID",
            "Description",
            "Remediation",
            "Confidence",
            "CWE",
            "CVSS",
            "Commit SHA",
            "Commit Date",
            "Commit Author",
        ])

        # Data rows
        for finding in result.findings:
            # Sanitize content
            content = finding.sanitized_content(self.settings.redact_pattern)
            if len(content) > 200:
                content = content[:197] + "..."

            writer.writerow([
                finding.id,
                finding.repository,
                finding.type.value,
                finding.category,
                finding.severity.value,
                ";".join(s.value for s in finding.states),
                finding.file_path,
                finding.line_number,
                content,
                finding.rule_id,
                finding.rule_description,
                finding.remediation,
                f"{finding.confidence:.2f}",
                finding.cwe_id or "",
                finding.cvss_score or "",
                finding.commit_sha,
                finding.commit_date.isoformat() if finding.commit_date else "",
                finding.commit_author,
            ])

        return output.getvalue()

