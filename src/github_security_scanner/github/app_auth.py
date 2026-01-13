"""
GitHub App authentication module.

Provides JWT-based authentication for GitHub Apps,
which is the recommended approach for organization-wide access.
"""

import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import httpx
from rich.console import Console

from ..utils.secure_logging import get_secure_logger

# Try to import PyJWT
try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

console = Console()
logger = get_secure_logger(__name__)


@dataclass
class GitHubAppCredentials:
    """Credentials for a GitHub App."""
    
    app_id: int
    private_key: str  # PEM-encoded private key content
    installation_id: Optional[int] = None  # For installation-specific tokens
    
    @classmethod
    def from_file(
        cls,
        app_id: int,
        private_key_path: str | Path,
        installation_id: Optional[int] = None,
    ) -> "GitHubAppCredentials":
        """
        Load credentials from a private key file.
        
        Args:
            app_id: GitHub App ID
            private_key_path: Path to PEM private key file
            installation_id: Optional installation ID
            
        Returns:
            GitHubAppCredentials instance
        """
        path = Path(private_key_path)
        if not path.exists():
            raise FileNotFoundError(f"Private key not found: {path}")
        
        private_key = path.read_text()
        return cls(
            app_id=app_id,
            private_key=private_key,
            installation_id=installation_id,
        )
    
    @classmethod
    def from_env(cls) -> Optional["GitHubAppCredentials"]:
        """
        Load credentials from environment variables.
        
        Environment variables:
        - GITHUB_APP_ID: App ID
        - GITHUB_APP_PRIVATE_KEY: PEM key content (or path)
        - GITHUB_APP_INSTALLATION_ID: Installation ID (optional)
        
        Returns:
            GitHubAppCredentials or None if not configured
        """
        import os
        
        app_id = os.environ.get("GITHUB_APP_ID")
        private_key = os.environ.get("GITHUB_APP_PRIVATE_KEY")
        installation_id = os.environ.get("GITHUB_APP_INSTALLATION_ID")
        
        if not app_id or not private_key:
            return None
        
        # Check if private_key is a file path
        if private_key.startswith("/") or private_key.startswith("~"):
            path = Path(private_key).expanduser()
            if path.exists():
                private_key = path.read_text()
        
        return cls(
            app_id=int(app_id),
            private_key=private_key,
            installation_id=int(installation_id) if installation_id else None,
        )


class GitHubAppAuth:
    """
    GitHub App authentication handler.
    
    Generates JWT tokens for app authentication and exchanges
    them for installation access tokens.
    """
    
    def __init__(
        self,
        credentials: GitHubAppCredentials,
        api_url: str = "https://api.github.com",
    ):
        """
        Initialize GitHub App authentication.
        
        Args:
            credentials: App credentials
            api_url: GitHub API URL
        """
        if not JWT_AVAILABLE:
            raise ImportError(
                "PyJWT is required for GitHub App authentication. "
                "Install it with: pip install PyJWT"
            )
        
        self.credentials = credentials
        self.api_url = api_url
        self._installation_token: Optional[str] = None
        self._token_expires: Optional[datetime] = None
    
    def create_jwt(self, expiration_minutes: int = 10) -> str:
        """
        Create a JWT for authenticating as the GitHub App.
        
        The JWT is used to make API calls as the app itself,
        not as an installation.
        
        Args:
            expiration_minutes: Token validity period (max 10 minutes)
            
        Returns:
            JWT token string
        """
        now = int(time.time())
        
        payload = {
            # Issued at time (60 seconds in the past to account for clock drift)
            "iat": now - 60,
            # JWT expiration time (max 10 minutes)
            "exp": now + (min(expiration_minutes, 10) * 60),
            # GitHub App's identifier
            "iss": self.credentials.app_id,
        }
        
        token = jwt.encode(
            payload,
            self.credentials.private_key,
            algorithm="RS256",
        )
        
        logger.debug(f"Created JWT for GitHub App {self.credentials.app_id}")
        return token
    
    async def get_installation_token(
        self,
        installation_id: Optional[int] = None,
        permissions: Optional[dict[str, str]] = None,
        repositories: Optional[list[str]] = None,
    ) -> str:
        """
        Get an installation access token.
        
        This token has the permissions granted to the app installation
        and can be used to access repositories.
        
        Args:
            installation_id: Installation ID (uses default if not specified)
            permissions: Optional permission overrides
            repositories: Optional list of specific repositories
            
        Returns:
            Installation access token
            
        Raises:
            ValueError: If no installation ID is available
            httpx.HTTPError: If API call fails
        """
        install_id = installation_id or self.credentials.installation_id
        if not install_id:
            raise ValueError(
                "Installation ID required. Provide it in credentials or as argument."
            )
        
        # Check if we have a valid cached token
        if self._installation_token and self._token_expires:
            if datetime.utcnow() < self._token_expires - timedelta(minutes=5):
                return self._installation_token
        
        # Create JWT for app authentication
        app_jwt = self.create_jwt()
        
        # Request installation token
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {app_jwt}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        
        url = f"{self.api_url}/app/installations/{install_id}/access_tokens"
        
        # Build request body
        body = {}
        if permissions:
            body["permissions"] = permissions
        if repositories:
            body["repositories"] = repositories
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=body or None)
            response.raise_for_status()
            
            data = response.json()
        
        self._installation_token = data["token"]
        self._token_expires = datetime.fromisoformat(
            data["expires_at"].replace("Z", "+00:00")
        ).replace(tzinfo=None)
        
        logger.info(f"Obtained installation token for installation {install_id}")
        
        return self._installation_token
    
    async def get_installations(self) -> list[dict]:
        """
        Get all installations of this GitHub App.
        
        Returns:
            List of installation data
        """
        app_jwt = self.create_jwt()
        
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {app_jwt}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        
        url = f"{self.api_url}/app/installations"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            
            return response.json()
    
    async def get_installation_for_org(self, org: str) -> Optional[int]:
        """
        Find the installation ID for a specific organization.
        
        Args:
            org: Organization name
            
        Returns:
            Installation ID or None if not found
        """
        installations = await self.get_installations()
        
        for install in installations:
            if install.get("account", {}).get("login", "").lower() == org.lower():
                return install["id"]
        
        return None
    
    async def get_accessible_repos(
        self,
        installation_id: Optional[int] = None,
    ) -> list[dict]:
        """
        Get repositories accessible by the installation.
        
        Args:
            installation_id: Installation ID
            
        Returns:
            List of repository data
        """
        token = await self.get_installation_token(installation_id)
        
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        
        url = f"{self.api_url}/installation/repositories"
        
        async with httpx.AsyncClient() as client:
            repos = []
            page = 1
            
            while True:
                response = await client.get(
                    url,
                    headers=headers,
                    params={"per_page": 100, "page": page},
                )
                response.raise_for_status()
                
                data = response.json()
                repos.extend(data.get("repositories", []))
                
                if len(data.get("repositories", [])) < 100:
                    break
                
                page += 1
        
        return repos


async def create_app_authenticated_client(
    credentials: Optional[GitHubAppCredentials] = None,
    org: Optional[str] = None,
) -> tuple[str, Optional[int]]:
    """
    Create an authenticated token using GitHub App credentials.
    
    This is a convenience function that:
    1. Loads credentials from env if not provided
    2. Finds the installation ID for the org if needed
    3. Returns an installation token
    
    Args:
        credentials: App credentials (loaded from env if None)
        org: Organization name to find installation for
        
    Returns:
        Tuple of (token, installation_id)
        
    Raises:
        ValueError: If credentials not available
    """
    if credentials is None:
        credentials = GitHubAppCredentials.from_env()
    
    if credentials is None:
        raise ValueError(
            "GitHub App credentials not available. "
            "Set GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY, and optionally "
            "GITHUB_APP_INSTALLATION_ID environment variables."
        )
    
    auth = GitHubAppAuth(credentials)
    
    # Find installation ID if org provided but no installation_id
    installation_id = credentials.installation_id
    if org and not installation_id:
        installation_id = await auth.get_installation_for_org(org)
        if not installation_id:
            raise ValueError(f"No installation found for organization: {org}")
    
    token = await auth.get_installation_token(installation_id)
    
    return token, installation_id


def is_github_app_configured() -> bool:
    """Check if GitHub App authentication is configured."""
    import os
    return bool(
        os.environ.get("GITHUB_APP_ID") and
        os.environ.get("GITHUB_APP_PRIVATE_KEY")
    )
