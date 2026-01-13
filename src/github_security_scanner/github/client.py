"""
GitHub API client with rate limiting and retry support.

Provides async methods for interacting with the GitHub API,
including organization and repository operations.
"""

import asyncio
from typing import Any, AsyncIterator, Optional

import httpx
from rich.console import Console
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from ..core.config import GitHubSettings
from ..core.models import Repository
from .rate_limiter import RateLimiter

console = Console()


class GitHubAPIError(Exception):
    """Exception raised for GitHub API errors."""

    def __init__(self, message: str, status_code: int = 0, response: Optional[dict] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response or {}


class GitHubClient:
    """
    Async GitHub API client with rate limiting and retry support.

    Handles authentication, pagination, rate limiting, and common
    GitHub API operations.
    """

    def __init__(self, settings: GitHubSettings):
        """
        Initialize GitHub client.

        Args:
            settings: GitHub configuration settings
        """
        self.settings = settings
        self.rate_limiter = RateLimiter()
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "GitHubClient":
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()

    async def connect(self) -> None:
        """Initialize the HTTP client."""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        if self.settings.token:
            headers["Authorization"] = f"Bearer {self.settings.token}"

        self._client = httpx.AsyncClient(
            base_url=self.settings.api_url,
            headers=headers,
            timeout=self.settings.timeout,
            follow_redirects=True,
        )

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        """Get the HTTP client, raising if not connected."""
        if not self._client:
            raise RuntimeError("Client not connected. Use 'async with' or call connect()")
        return self._client

    @retry(
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=30),
    )
    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        json: Optional[dict] = None,
    ) -> dict[str, Any]:
        """
        Make a rate-limited request to the GitHub API.

        Args:
            method: HTTP method
            endpoint: API endpoint (without base URL)
            params: Query parameters
            json: JSON body

        Returns:
            JSON response data

        Raises:
            GitHubAPIError: If the API returns an error
        """
        await self.rate_limiter.acquire()

        response = await self.client.request(
            method,
            endpoint,
            params=params,
            json=json,
        )

        # Update rate limit info from headers
        self.rate_limiter.update_from_headers(dict(response.headers))

        if response.status_code == 204:
            return {}

        if response.status_code >= 400:
            error_data = response.json() if response.content else {}
            message = error_data.get("message", f"HTTP {response.status_code}")

            # Handle rate limiting specially
            if response.status_code == 403 and "rate limit" in message.lower():
                retry_after = self.rate_limiter.get_retry_after(dict(response.headers))
                if retry_after:
                    console.print(f"[yellow]Rate limited. Waiting {retry_after}s...[/yellow]")
                    await asyncio.sleep(retry_after)
                    return await self._request(method, endpoint, params, json)

            self.rate_limiter.record_error()
            raise GitHubAPIError(message, response.status_code, error_data)

        self.rate_limiter.record_success()
        return response.json()

    async def _paginate(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        per_page: int = 100,
    ) -> AsyncIterator[dict[str, Any]]:
        """
        Paginate through GitHub API results.

        Args:
            endpoint: API endpoint
            params: Additional query parameters
            per_page: Results per page (max 100)

        Yields:
            Individual items from paginated results
        """
        params = params or {}
        params["per_page"] = per_page
        page = 1

        while True:
            params["page"] = page
            response = await self._request("GET", endpoint, params=params)

            # Handle both list responses and dict responses with items key
            if isinstance(response, list):
                items = response
            else:
                items = response.get("items", response.get("repositories", []))

            if not items:
                break

            for item in items:
                yield item

            if len(items) < per_page:
                break

            page += 1

    # Organization operations

    async def get_organization(self, org: str) -> dict[str, Any]:
        """
        Get organization information.

        Args:
            org: Organization name

        Returns:
            Organization data
        """
        return await self._request("GET", f"/orgs/{org}")

    async def list_organization_repos(
        self,
        org: str,
        repo_type: str = "all",
        sort: str = "updated",
    ) -> AsyncIterator[dict[str, Any]]:
        """
        List all repositories in an organization.

        Args:
            org: Organization name
            repo_type: Type of repos (all, public, private, forks, sources, member)
            sort: Sort field (created, updated, pushed, full_name)

        Yields:
            Repository data dictionaries
        """
        params = {"type": repo_type, "sort": sort}
        async for repo in self._paginate(f"/orgs/{org}/repos", params):
            yield repo

    async def get_organization_repos(
        self,
        org: str,
        include_archived: bool = False,
        include_forks: bool = False,
        languages: Optional[list[str]] = None,
    ) -> list[Repository]:
        """
        Get all repositories in an organization as Repository objects.

        Args:
            org: Organization name
            include_archived: Include archived repositories
            include_forks: Include forked repositories
            languages: Filter by languages (None = all)

        Returns:
            List of Repository objects
        """
        repos = []
        async for repo_data in self.list_organization_repos(org):
            # Apply filters
            if not include_archived and repo_data.get("archived"):
                continue
            if not include_forks and repo_data.get("fork"):
                continue

            repo = Repository(
                name=repo_data["name"],
                full_name=repo_data["full_name"],
                url=repo_data["html_url"],
                clone_url=repo_data["clone_url"],
                default_branch=repo_data.get("default_branch", "main"),
                languages=[repo_data.get("language")] if repo_data.get("language") else [],
                visibility="private" if repo_data.get("private") else "public",
                size_kb=repo_data.get("size", 0),
                archived=repo_data.get("archived", False),
                fork=repo_data.get("fork", False),
            )

            # Filter by language if specified
            if languages and repo.languages:
                if not any(lang.lower() in [l.lower() for l in languages] for lang in repo.languages):
                    continue

            repos.append(repo)

        console.print(f"[green]Found {len(repos)} repositories in {org}[/green]")
        return repos

    # Repository operations

    async def get_repository(self, owner: str, repo: str) -> dict[str, Any]:
        """
        Get repository information.

        Args:
            owner: Repository owner
            repo: Repository name

        Returns:
            Repository data
        """
        return await self._request("GET", f"/repos/{owner}/{repo}")

    async def get_repo_languages(self, owner: str, repo: str) -> dict[str, int]:
        """
        Get languages used in a repository.

        Args:
            owner: Repository owner
            repo: Repository name

        Returns:
            Dictionary of language -> bytes of code
        """
        return await self._request("GET", f"/repos/{owner}/{repo}/languages")

    async def get_repo_branches(self, owner: str, repo: str) -> list[dict[str, Any]]:
        """
        Get all branches in a repository.

        Args:
            owner: Repository owner
            repo: Repository name

        Returns:
            List of branch data
        """
        branches = []
        async for branch in self._paginate(f"/repos/{owner}/{repo}/branches"):
            branches.append(branch)
        return branches

    async def get_default_branch(self, owner: str, repo: str) -> str:
        """
        Get the default branch of a repository.

        Args:
            owner: Repository owner
            repo: Repository name

        Returns:
            Default branch name
        """
        repo_data = await self.get_repository(owner, repo)
        return repo_data.get("default_branch", "main")

    # User operations

    async def get_authenticated_user(self) -> dict[str, Any]:
        """
        Get the authenticated user.

        Returns:
            User data
        """
        return await self._request("GET", "/user")

    async def get_user_repos(self) -> AsyncIterator[dict[str, Any]]:
        """
        Get repositories for the authenticated user.

        Yields:
            Repository data dictionaries
        """
        async for repo in self._paginate("/user/repos"):
            yield repo

    # Rate limit operations

    async def get_rate_limit(self) -> dict[str, Any]:
        """
        Get current rate limit status.

        Returns:
            Rate limit information
        """
        return await self._request("GET", "/rate_limit")

    async def check_rate_limit(self) -> None:
        """Check and display current rate limit status."""
        rate_limit = await self.get_rate_limit()
        core = rate_limit.get("resources", {}).get("core", {})
        console.print(
            f"[blue]Rate Limit: {core.get('remaining', '?')}/{core.get('limit', '?')} "
            f"(resets at {core.get('reset', '?')})[/blue]"
        )

    # Search operations

    async def search_code(
        self,
        query: str,
        org: Optional[str] = None,
        repo: Optional[str] = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """
        Search for code across repositories.

        Args:
            query: Search query
            org: Limit to organization
            repo: Limit to specific repository

        Yields:
            Search result items
        """
        q = query
        if org:
            q += f" org:{org}"
        if repo:
            q += f" repo:{repo}"

        params = {"q": q}
        async for item in self._paginate("/search/code", params):
            yield item

    # Content operations

    async def get_file_content(
        self,
        owner: str,
        repo: str,
        path: str,
        ref: Optional[str] = None,
    ) -> Optional[str]:
        """
        Get file content from a repository.

        Args:
            owner: Repository owner
            repo: Repository name
            path: File path
            ref: Git ref (branch, tag, or SHA)

        Returns:
            File content as string, or None if not found
        """
        import base64

        params = {"ref": ref} if ref else None
        try:
            response = await self._request(
                "GET",
                f"/repos/{owner}/{repo}/contents/{path}",
                params=params,
            )
            if response.get("type") == "file" and response.get("content"):
                return base64.b64decode(response["content"]).decode("utf-8")
            return None
        except GitHubAPIError as e:
            if e.status_code == 404:
                return None
            raise

