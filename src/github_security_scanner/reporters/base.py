"""
Base reporter class for generating scan reports.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..core.config import OutputSettings
from ..core.models import ScanResult
from ..utils.sanitizer import OutputSanitizer


class BaseReporter(ABC):
    """
    Abstract base class for report generators.

    Subclasses implement specific output formats.
    """

    format_name: str = "base"
    file_extension: str = ".txt"

    def __init__(
        self,
        settings: OutputSettings,
        sanitizer: Optional[OutputSanitizer] = None,
    ):
        """
        Initialize reporter.

        Args:
            settings: Output configuration
            sanitizer: Output sanitizer for redacting secrets
        """
        self.settings = settings
        self.sanitizer = sanitizer or OutputSanitizer(
            redact_pattern=settings.redact_pattern,
            redact_secrets=settings.redact_secrets,
        )

    @abstractmethod
    def generate(self, result: ScanResult) -> str:
        """
        Generate report content.

        Args:
            result: Scan result to report

        Returns:
            Report content as string
        """
        pass

    def write(
        self,
        result: ScanResult,
        output_path: Optional[Path] = None,
    ) -> Path:
        """
        Write report to file.

        Args:
            result: Scan result to report
            output_path: Optional specific output path

        Returns:
            Path to written file
        """
        content = self.generate(result)

        if output_path is None:
            output_path = self._get_output_path(result)

        # Ensure directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

        return output_path

    def _get_output_path(self, result: ScanResult) -> Path:
        """Generate output file path based on settings and result."""
        output_dir = Path(self.settings.directory)

        # Format filename
        filename = self.settings.filename_template.format(
            org=result.metadata.organization or "unknown",
            date=datetime.now().strftime("%Y%m%d-%H%M%S"),
        )

        return output_dir / f"{filename}{self.file_extension}"

    def _sanitize_finding(self, finding_dict: dict) -> dict:
        """Sanitize a finding dictionary."""
        return self.sanitizer.sanitize_dict(finding_dict)

