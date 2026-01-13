"""
JSON report generator.
"""

import json
from typing import Any

from ..core.models import ScanResult
from .base import BaseReporter


class JSONReporter(BaseReporter):
    """Generates JSON format reports."""

    format_name = "json"
    file_extension = ".json"

    def generate(self, result: ScanResult) -> str:
        """
        Generate JSON report.

        Args:
            result: Scan result

        Returns:
            JSON string
        """
        report_data = result.to_dict()

        # Sanitize all findings
        if self.settings.redact_secrets:
            report_data["findings"] = [
                self._sanitize_finding(f) for f in report_data["findings"]
            ]

        return json.dumps(report_data, indent=2, default=self._json_serializer)

    def _json_serializer(self, obj: Any) -> Any:
        """Custom JSON serializer for non-serializable objects."""
        if hasattr(obj, "isoformat"):
            return obj.isoformat()
        if hasattr(obj, "value"):
            return obj.value
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        return str(obj)

