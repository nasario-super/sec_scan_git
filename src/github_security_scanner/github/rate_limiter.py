"""
Rate limiter for GitHub API requests.

Handles rate limit tracking, waiting, and exponential backoff.
"""

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from rich.console import Console

console = Console()


@dataclass
class RateLimitInfo:
    """Information about current rate limit status."""

    limit: int = 5000
    remaining: int = 5000
    reset_time: datetime = datetime.now()
    used: int = 0


class RateLimiter:
    """
    Rate limiter for GitHub API with exponential backoff.

    Tracks rate limits from response headers and automatically
    waits when approaching limits.
    """

    def __init__(
        self,
        requests_per_second: float = 10.0,
        min_remaining: int = 100,
        backoff_factor: float = 2.0,
        max_backoff: float = 300.0,
    ):
        """
        Initialize rate limiter.

        Args:
            requests_per_second: Maximum requests per second
            min_remaining: Minimum remaining requests before slowing down
            backoff_factor: Exponential backoff multiplier
            max_backoff: Maximum backoff time in seconds
        """
        self.requests_per_second = requests_per_second
        self.min_remaining = min_remaining
        self.backoff_factor = backoff_factor
        self.max_backoff = max_backoff

        self._rate_limit = RateLimitInfo()
        self._last_request_time: float = 0
        self._consecutive_errors: int = 0
        self._lock = asyncio.Lock()

    @property
    def rate_limit(self) -> RateLimitInfo:
        """Get current rate limit info."""
        return self._rate_limit

    def update_from_headers(self, headers: dict[str, str]) -> None:
        """
        Update rate limit info from response headers.

        Args:
            headers: Response headers from GitHub API
        """
        try:
            self._rate_limit.limit = int(headers.get("x-ratelimit-limit", 5000))
            self._rate_limit.remaining = int(headers.get("x-ratelimit-remaining", 5000))
            self._rate_limit.used = int(headers.get("x-ratelimit-used", 0))

            reset_timestamp = int(headers.get("x-ratelimit-reset", 0))
            if reset_timestamp:
                self._rate_limit.reset_time = datetime.fromtimestamp(reset_timestamp)
        except (ValueError, TypeError):
            pass  # Keep existing values if parsing fails

    async def acquire(self) -> None:
        """
        Acquire permission to make a request.

        Waits if necessary to respect rate limits.
        """
        async with self._lock:
            # Basic rate limiting - time between requests
            min_interval = 1.0 / self.requests_per_second
            elapsed = time.time() - self._last_request_time

            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)

            # Check if we're running low on remaining requests
            if self._rate_limit.remaining < self.min_remaining:
                wait_time = self._calculate_wait_time()
                if wait_time > 0:
                    console.print(
                        f"[yellow]Rate limit low ({self._rate_limit.remaining} remaining). "
                        f"Waiting {wait_time:.1f}s until reset...[/yellow]"
                    )
                    await asyncio.sleep(wait_time)

            self._last_request_time = time.time()

    def _calculate_wait_time(self) -> float:
        """Calculate time to wait until rate limit reset."""
        now = datetime.now()
        if self._rate_limit.reset_time > now:
            return (self._rate_limit.reset_time - now).total_seconds()
        return 0

    def get_backoff_time(self, attempt: int) -> float:
        """
        Calculate exponential backoff time for retries.

        Args:
            attempt: Current attempt number (0-indexed)

        Returns:
            Time to wait in seconds
        """
        backoff = min(
            self.backoff_factor ** attempt,
            self.max_backoff,
        )
        # Add jitter to prevent thundering herd
        import random

        jitter = random.uniform(0, backoff * 0.1)  # noqa: S311
        return backoff + jitter

    def record_success(self) -> None:
        """Record a successful request."""
        self._consecutive_errors = 0

    def record_error(self) -> None:
        """Record a failed request."""
        self._consecutive_errors += 1

    @property
    def consecutive_errors(self) -> int:
        """Get number of consecutive errors."""
        return self._consecutive_errors

    def should_retry(self, status_code: int) -> bool:
        """
        Determine if a request should be retried based on status code.

        Args:
            status_code: HTTP status code

        Returns:
            True if request should be retried
        """
        # Retry on rate limit, server errors, and some client errors
        return status_code in {403, 429, 500, 502, 503, 504}

    def get_retry_after(self, headers: dict[str, str]) -> Optional[float]:
        """
        Get retry-after value from headers.

        Args:
            headers: Response headers

        Returns:
            Seconds to wait, or None if not specified
        """
        retry_after = headers.get("retry-after")
        if retry_after:
            try:
                return float(retry_after)
            except ValueError:
                pass
        return None

