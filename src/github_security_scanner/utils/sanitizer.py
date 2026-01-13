"""
Output sanitization utilities.

Handles redaction of sensitive data in outputs and logs.
"""

import re
from typing import Any


class OutputSanitizer:
    """
    Sanitizes output to redact sensitive information.
    """

    # Patterns for sensitive data that should always be redacted
    SENSITIVE_PATTERNS = [
        # API Keys and Tokens
        (r"(AKIA[0-9A-Z]{16})", "AWS_ACCESS_KEY"),
        (r"([A-Za-z0-9/+=]{40})", "AWS_SECRET_KEY"),
        (r"(gh[pousr]_[A-Za-z0-9]{36,})", "GITHUB_TOKEN"),
        (r"(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})", "GITHUB_PAT"),
        (r"(sk_(live|test)_[A-Za-z0-9]{24,})", "STRIPE_KEY"),
        (r"(pk_(live|test)_[A-Za-z0-9]{24,})", "STRIPE_PUBKEY"),
        (r"(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})", "SENDGRID_KEY"),
        (r"(xox[baprs]-[A-Za-z0-9-]+)", "SLACK_TOKEN"),

        # Private Keys
        (r"(-----BEGIN [A-Z ]+ PRIVATE KEY-----)", "PRIVATE_KEY_HEADER"),

        # Passwords in connection strings
        (r"(password=)[^\s;&\"']+", "\\1[REDACTED]"),
        (r"(pwd=)[^\s;&\"']+", "\\1[REDACTED]"),
        (r"(passwd=)[^\s;&\"']+", "\\1[REDACTED]"),

        # Database URLs with credentials
        (r"(://[^:]+:)[^@]+(@)", "\\1[REDACTED]\\2"),
    ]

    def __init__(
        self,
        redact_pattern: str = "[REDACTED]",
        redact_secrets: bool = True,
    ):
        """
        Initialize sanitizer.

        Args:
            redact_pattern: Pattern to use for redaction
            redact_secrets: Whether to redact secrets
        """
        self.redact_pattern = redact_pattern
        self.redact_secrets = redact_secrets
        self._compiled_patterns: list[tuple[re.Pattern, str]] = []

        if self.redact_secrets:
            self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile regex patterns for efficiency."""
        for pattern, replacement in self.SENSITIVE_PATTERNS:
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                # If replacement contains groups, keep it; otherwise use redact_pattern
                if "\\" in replacement:
                    self._compiled_patterns.append((compiled, replacement))
                else:
                    self._compiled_patterns.append((compiled, self.redact_pattern))
            except re.error:
                continue

    def sanitize_string(self, text: str) -> str:
        """
        Sanitize a string by redacting sensitive data.

        Args:
            text: Text to sanitize

        Returns:
            Sanitized text
        """
        if not self.redact_secrets or not text:
            return text

        result = text
        for pattern, replacement in self._compiled_patterns:
            result = pattern.sub(replacement, result)

        return result

    def sanitize_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Recursively sanitize a dictionary.

        Args:
            data: Dictionary to sanitize

        Returns:
            Sanitized dictionary
        """
        if not self.redact_secrets:
            return data

        result = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = self.sanitize_string(value)
            elif isinstance(value, dict):
                result[key] = self.sanitize_dict(value)
            elif isinstance(value, list):
                result[key] = self.sanitize_list(value)
            else:
                result[key] = value
        return result

    def sanitize_list(self, data: list[Any]) -> list[Any]:
        """
        Recursively sanitize a list.

        Args:
            data: List to sanitize

        Returns:
            Sanitized list
        """
        if not self.redact_secrets:
            return data

        result = []
        for item in data:
            if isinstance(item, str):
                result.append(self.sanitize_string(item))
            elif isinstance(item, dict):
                result.append(self.sanitize_dict(item))
            elif isinstance(item, list):
                result.append(self.sanitize_list(item))
            else:
                result.append(item)
        return result

    def sanitize_finding_content(
        self,
        content: str,
        matched_pattern: str | None = None,
    ) -> str:
        """
        Sanitize finding line content for display.

        This provides more aggressive redaction for findings,
        showing only context around the match.

        Args:
            content: Line content
            matched_pattern: Pattern that was matched

        Returns:
            Sanitized content showing context but not full secret
        """
        if not content:
            return content

        # First apply standard sanitization
        result = self.sanitize_string(content)

        # If still long, truncate showing start and end
        if len(result) > 100:
            result = result[:40] + f" {self.redact_pattern} " + result[-20:]

        return result

    def sanitize_url(self, url: str) -> str:
        """
        Sanitize a URL by removing credentials.

        Args:
            url: URL to sanitize

        Returns:
            URL without embedded credentials
        """
        if not url:
            return url

        # Remove credentials from URL
        result = re.sub(
            r"(://[^:]+:)[^@]+(@)",
            f"\\1{self.redact_pattern}\\2",
            url,
        )

        # Also remove token query parameters
        result = re.sub(
            r"([?&](?:token|api_key|apikey|key|secret|password|auth)=)[^&]+",
            f"\\1{self.redact_pattern}",
            result,
            flags=re.IGNORECASE,
        )

        return result

    def get_preview(self, text: str, max_length: int = 50) -> str:
        """
        Get a preview of text, redacting if sensitive.

        Args:
            text: Text to preview
            max_length: Maximum length

        Returns:
            Preview text
        """
        sanitized = self.sanitize_string(text)
        if len(sanitized) <= max_length:
            return sanitized
        return sanitized[: max_length - 3] + "..."


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.

    Higher entropy suggests more randomness (potential secret).

    Args:
        text: Text to analyze

    Returns:
        Entropy value (0-8 for ASCII)
    """
    import math
    from collections import Counter

    if not text:
        return 0.0

    # Count character frequencies
    freq = Counter(text)
    length = len(text)

    # Calculate entropy
    entropy = 0.0
    for count in freq.values():
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)

    return entropy


def is_likely_secret(text: str, entropy_threshold: float = 4.5) -> bool:
    """
    Determine if text is likely a secret based on entropy.

    Args:
        text: Text to analyze
        entropy_threshold: Minimum entropy to consider as secret

    Returns:
        True if likely a secret
    """
    # Skip very short strings
    if len(text) < 8:
        return False

    # Skip strings that are mostly non-alphanumeric
    alnum_count = sum(1 for c in text if c.isalnum())
    if alnum_count / len(text) < 0.5:
        return False

    return calculate_entropy(text) >= entropy_threshold

