"""
Base analyzer class that all security analyzers inherit from.
"""

import fnmatch
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator

from rich.console import Console

from ..core.config import Settings
from ..core.models import Finding, Repository

console = Console()


class BaseAnalyzer(ABC):
    """
    Abstract base class for all security analyzers.

    Provides common functionality for file iteration,
    path filtering, and finding generation.
    """

    name: str = "base"
    description: str = "Base analyzer"

    def __init__(self, settings: Settings):
        """
        Initialize analyzer.

        Args:
            settings: Scanner settings
        """
        self.settings = settings
        self._exclude_patterns = settings.scan.exclude_paths

    @abstractmethod
    async def analyze(self, repo: Repository, repo_path: Path) -> list[Finding]:
        """
        Analyze a repository for security issues.

        Args:
            repo: Repository metadata
            repo_path: Path to cloned repository

        Returns:
            List of findings
        """
        pass

    def should_skip_path(self, path: Path | str) -> bool:
        """
        Check if a path should be skipped based on exclude patterns.

        Args:
            path: Path to check

        Returns:
            True if path should be skipped
        """
        path_str = str(path)

        for pattern in self._exclude_patterns:
            # Handle directory patterns (ending with /)
            if pattern.endswith("/"):
                if pattern[:-1] in path_str or path_str.startswith(pattern):
                    return True
            # Handle glob patterns
            elif fnmatch.fnmatch(path_str, pattern):
                return True
            elif fnmatch.fnmatch(Path(path_str).name, pattern):
                return True

        return False

    def should_skip_file(self, file_path: Path) -> bool:
        """
        Check if a file should be skipped.

        Args:
            file_path: Path to file

        Returns:
            True if file should be skipped
        """
        # Skip if path matches exclude pattern
        if self.should_skip_path(file_path):
            return True

        # Skip files that are too large
        try:
            size_mb = file_path.stat().st_size / (1024 * 1024)
            if size_mb > self.settings.scan.max_file_size_mb:
                return True
        except OSError:
            return True

        # Skip binary files
        if self._is_binary(file_path):
            return True

        return False

    def _is_binary(self, file_path: Path) -> bool:
        """
        Check if a file is binary.

        Args:
            file_path: Path to file

        Returns:
            True if file appears to be binary
        """
        # Known binary extensions
        binary_extensions = {
            ".exe", ".dll", ".so", ".dylib", ".bin",
            ".pyc", ".pyo", ".class", ".o", ".obj",
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx",
            ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
            ".mp3", ".mp4", ".avi", ".mov", ".wav",
            ".woff", ".woff2", ".ttf", ".eot",
            ".sqlite", ".db",
        }

        if file_path.suffix.lower() in binary_extensions:
            return True

        # Check first bytes for binary content
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(1024)
                # Check for null bytes (common in binary files)
                if b"\x00" in chunk:
                    return True
        except OSError:
            return True

        return False

    def iter_files(
        self,
        repo_path: Path,
        extensions: set[str] | None = None,
    ) -> Iterator[Path]:
        """
        Iterate over files in a repository.

        Args:
            repo_path: Path to repository
            extensions: Optional set of file extensions to include

        Yields:
            Paths to files
        """
        for file_path in repo_path.rglob("*"):
            if not file_path.is_file():
                continue

            if self.should_skip_file(file_path):
                continue

            if extensions and file_path.suffix.lower() not in extensions:
                continue

            yield file_path

    def read_file_lines(self, file_path: Path) -> list[tuple[int, str]]:
        """
        Read file and return numbered lines.

        Args:
            file_path: Path to file

        Returns:
            List of (line_number, line_content) tuples
        """
        try:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                return [(i + 1, line.rstrip("\n\r")) for i, line in enumerate(f)]
        except OSError:
            return []

    def read_file_content(self, file_path: Path) -> str:
        """
        Read entire file content.

        Args:
            file_path: Path to file

        Returns:
            File content as string
        """
        try:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def get_relative_path(self, file_path: Path, repo_path: Path) -> str:
        """
        Get path relative to repository root.

        Args:
            file_path: Absolute file path
            repo_path: Repository root path

        Returns:
            Relative path string
        """
        try:
            return str(file_path.relative_to(repo_path))
        except ValueError:
            return str(file_path)

    def get_context_lines(
        self,
        lines: list[tuple[int, str]],
        line_number: int,
        context: int = 2,
    ) -> tuple[list[str], list[str]]:
        """
        Get context lines before and after a line.

        Args:
            lines: List of (line_number, content) tuples
            line_number: Target line number
            context: Number of context lines

        Returns:
            Tuple of (before_lines, after_lines)
        """
        lines_dict = {num: content for num, content in lines}

        before = []
        for i in range(max(1, line_number - context), line_number):
            if i in lines_dict:
                before.append(lines_dict[i])

        after = []
        for i in range(line_number + 1, line_number + context + 1):
            if i in lines_dict:
                after.append(lines_dict[i])

        return before, after

    def log_info(self, message: str) -> None:
        """Log an info message."""
        console.print(f"[blue][{self.name}][/blue] {message}")

    def log_warning(self, message: str) -> None:
        """Log a warning message."""
        console.print(f"[yellow][{self.name}][/yellow] {message}")

    def log_error(self, message: str) -> None:
        """Log an error message."""
        console.print(f"[red][{self.name}][/red] {message}")

