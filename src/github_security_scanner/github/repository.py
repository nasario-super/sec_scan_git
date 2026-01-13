"""
Repository management for cloning and working with Git repositories.
"""

import asyncio
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from git import Repo
from git.exc import GitCommandError
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..core.config import ScanSettings
from ..core.models import Repository, ScanStatus

console = Console()


class RepositoryManager:
    """
    Manages Git repository operations including cloning,
    checkout, and cleanup.
    """

    def __init__(
        self,
        settings: ScanSettings,
        token: Optional[str] = None,
        work_dir: Optional[Path] = None,
    ):
        """
        Initialize repository manager.

        Args:
            settings: Scan configuration settings
            token: GitHub token for authenticated clones
            work_dir: Working directory for clones (temp dir if None)
        """
        self.settings = settings
        self.token = token
        self._work_dir = work_dir
        self._temp_dir: Optional[tempfile.TemporaryDirectory] = None
        self._cloned_repos: dict[str, Path] = {}

    @property
    def work_dir(self) -> Path:
        """Get the working directory for clones."""
        if self._work_dir:
            return self._work_dir
        if self._temp_dir is None:
            self._temp_dir = tempfile.TemporaryDirectory(prefix="gss-")
        return Path(self._temp_dir.name)

    def _get_authenticated_url(self, clone_url: str) -> str:
        """
        Add authentication to clone URL.

        Args:
            clone_url: Original clone URL

        Returns:
            URL with embedded token
        """
        if not self.token:
            return clone_url

        # Convert HTTPS URL to include token
        if clone_url.startswith("https://github.com/"):
            return clone_url.replace(
                "https://github.com/",
                f"https://{self.token}@github.com/",
            )
        elif clone_url.startswith("https://"):
            # GitHub Enterprise or other
            parts = clone_url.split("://", 1)
            return f"https://{self.token}@{parts[1]}"

        return clone_url

    async def clone_repository(
        self,
        repo: Repository,
        progress: Optional[Progress] = None,
    ) -> Optional[Path]:
        """
        Clone a repository.

        Args:
            repo: Repository to clone
            progress: Optional progress bar

        Returns:
            Path to cloned repository, or None if failed
        """
        repo_path = self.work_dir / repo.name
        auth_url = self._get_authenticated_url(repo.clone_url)

        try:
            clone_args: dict[str, object] = {}

            # Configure clone based on strategy
            if self.settings.clone_strategy == "shallow":
                clone_args["depth"] = 1
            elif self.settings.clone_strategy == "sparse":
                clone_args["depth"] = 1
                clone_args["filter"] = "blob:none"

            # Run clone in thread pool to not block
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: Repo.clone_from(
                    auth_url,
                    str(repo_path),
                    **clone_args,
                ),
            )

            repo.local_path = str(repo_path)
            repo.scan_status = ScanStatus.IN_PROGRESS
            self._cloned_repos[repo.name] = repo_path

            return repo_path

        except GitCommandError as e:
            repo.scan_status = ScanStatus.FAILED
            repo.scan_error = str(e)
            console.print(f"[red]Failed to clone {repo.name}: {e}[/red]")
            return None

    async def clone_repositories(
        self,
        repos: list[Repository],
        max_parallel: Optional[int] = None,
    ) -> dict[str, Path]:
        """
        Clone multiple repositories in parallel.

        Args:
            repos: List of repositories to clone
            max_parallel: Maximum parallel clones

        Returns:
            Dictionary of repo name -> local path
        """
        max_parallel = max_parallel or self.settings.parallel_repos
        semaphore = asyncio.Semaphore(max_parallel)

        async def clone_with_semaphore(repo: Repository) -> tuple[str, Optional[Path]]:
            async with semaphore:
                path = await self.clone_repository(repo)
                return repo.name, path

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Cloning {len(repos)} repositories...", total=len(repos))

            tasks = [clone_with_semaphore(repo) for repo in repos]
            results = {}

            for coro in asyncio.as_completed(tasks):
                name, path = await coro
                if path:
                    results[name] = path
                progress.advance(task)

        console.print(f"[green]Successfully cloned {len(results)}/{len(repos)} repositories[/green]")
        return results

    def get_repo_path(self, repo_name: str) -> Optional[Path]:
        """
        Get local path for a cloned repository.

        Args:
            repo_name: Repository name

        Returns:
            Path to local repository, or None if not cloned
        """
        return self._cloned_repos.get(repo_name)

    def cleanup_repository(self, repo_name: str) -> None:
        """
        Clean up a cloned repository.

        Args:
            repo_name: Repository name to clean up
        """
        path = self._cloned_repos.pop(repo_name, None)
        if path and path.exists():
            shutil.rmtree(path, ignore_errors=True)

    def cleanup_all(self) -> None:
        """Clean up all cloned repositories."""
        for name in list(self._cloned_repos.keys()):
            self.cleanup_repository(name)

        if self._temp_dir:
            self._temp_dir.cleanup()
            self._temp_dir = None

    def __del__(self):
        """Destructor to ensure cleanup."""
        self.cleanup_all()

    # Git operations

    def get_git_repo(self, repo_path: Path) -> Repo:
        """
        Get GitPython Repo object for a cloned repository.

        Args:
            repo_path: Path to repository

        Returns:
            GitPython Repo object
        """
        return Repo(repo_path)

    def checkout_branch(self, repo_path: Path, branch: str) -> bool:
        """
        Checkout a specific branch.

        Args:
            repo_path: Path to repository
            branch: Branch name

        Returns:
            True if successful
        """
        try:
            repo = self.get_git_repo(repo_path)
            repo.git.checkout(branch)
            return True
        except GitCommandError:
            return False

    def fetch_all_history(self, repo_path: Path) -> bool:
        """
        Fetch full history for a shallow clone.

        Args:
            repo_path: Path to repository

        Returns:
            True if successful
        """
        try:
            repo = self.get_git_repo(repo_path)
            repo.git.fetch("--unshallow")
            return True
        except GitCommandError:
            # Already unshallow or error
            return False

    def get_all_branches(self, repo_path: Path) -> list[str]:
        """
        Get all branches in a repository.

        Args:
            repo_path: Path to repository

        Returns:
            List of branch names
        """
        repo = self.get_git_repo(repo_path)
        return [ref.name for ref in repo.references if ref.name.startswith("origin/")]

    def get_commit_history(
        self,
        repo_path: Path,
        max_count: Optional[int] = None,
        since: Optional[str] = None,
    ) -> list[dict]:
        """
        Get commit history for a repository.

        Args:
            repo_path: Path to repository
            max_count: Maximum number of commits
            since: Only commits after this date

        Returns:
            List of commit information dictionaries
        """
        repo = self.get_git_repo(repo_path)
        commits = []

        args = {}
        if max_count:
            args["max_count"] = max_count
        if since:
            args["since"] = since

        for commit in repo.iter_commits(**args):
            commits.append({
                "sha": commit.hexsha,
                "author": commit.author.email if commit.author else "",
                "date": commit.committed_datetime,
                "message": commit.message.strip(),
            })

        return commits

