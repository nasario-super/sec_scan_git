"""
Repository caching utilities for incremental scanning.

Provides file hashing and change detection to speed up repeat scans.
"""

import hashlib
import json
import shutil
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()


class RepositoryCache:
    """
    Cache for cloned repository data to speed up incremental scans.
    
    Stores file hashes and scan results to avoid re-analyzing unchanged files.
    """
    
    def __init__(
        self,
        cache_dir: str | Path = ".scanner-cache/repos",
        enabled: bool = True,
    ):
        """
        Initialize repository cache.
        
        Args:
            cache_dir: Directory to store repository cache
            enabled: Whether caching is enabled
        """
        self.cache_dir = Path(cache_dir)
        self.enabled = enabled
        
        if self.enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_repo_cache_path(self, org: str, repo: str) -> Path:
        """Get the cache directory for a repository."""
        safe_name = f"{org}_{repo}".replace("/", "_").replace("\\", "_")
        return self.cache_dir / safe_name
    
    def get_file_hash(self, org: str, repo: str, file_path: str) -> Optional[str]:
        """
        Get cached hash for a file.
        
        Args:
            org: Organization name
            repo: Repository name
            file_path: Path to file
            
        Returns:
            File hash or None
        """
        if not self.enabled:
            return None
        
        cache_path = self._get_repo_cache_path(org, repo) / "file_hashes.json"
        
        try:
            if cache_path.exists():
                with open(cache_path) as f:
                    hashes = json.load(f)
                return hashes.get(file_path)
        except (json.JSONDecodeError, OSError):
            pass
        
        return None
    
    def set_file_hash(self, org: str, repo: str, file_path: str, file_hash: str) -> bool:
        """
        Cache hash for a file.
        
        Args:
            org: Organization name
            repo: Repository name
            file_path: Path to file
            file_hash: Hash of file content
            
        Returns:
            True if cached successfully
        """
        if not self.enabled:
            return False
        
        repo_cache = self._get_repo_cache_path(org, repo)
        repo_cache.mkdir(parents=True, exist_ok=True)
        cache_path = repo_cache / "file_hashes.json"
        
        try:
            hashes = {}
            if cache_path.exists():
                with open(cache_path) as f:
                    hashes = json.load(f)
            
            hashes[file_path] = file_hash
            
            with open(cache_path, "w") as f:
                json.dump(hashes, f)
            
            return True
        except (json.JSONDecodeError, OSError):
            return False
    
    def update_file_hashes(
        self,
        org: str,
        repo: str,
        hashes: dict[str, str],
    ) -> bool:
        """
        Update multiple file hashes at once.
        
        Args:
            org: Organization name
            repo: Repository name
            hashes: Dictionary of file_path -> hash
            
        Returns:
            True if cached successfully
        """
        if not self.enabled:
            return False
        
        repo_cache = self._get_repo_cache_path(org, repo)
        repo_cache.mkdir(parents=True, exist_ok=True)
        cache_path = repo_cache / "file_hashes.json"
        
        try:
            existing = {}
            if cache_path.exists():
                with open(cache_path) as f:
                    existing = json.load(f)
            
            existing.update(hashes)
            
            with open(cache_path, "w") as f:
                json.dump(existing, f)
            
            return True
        except (json.JSONDecodeError, OSError):
            return False
    
    def get_all_hashes(self, org: str, repo: str) -> dict[str, str]:
        """
        Get all cached file hashes for a repository.
        
        Args:
            org: Organization name
            repo: Repository name
            
        Returns:
            Dictionary of file_path -> hash
        """
        if not self.enabled:
            return {}
        
        cache_path = self._get_repo_cache_path(org, repo) / "file_hashes.json"
        
        try:
            if cache_path.exists():
                with open(cache_path) as f:
                    return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
        
        return {}
    
    def get_changed_files(
        self,
        org: str,
        repo: str,
        current_hashes: dict[str, str],
    ) -> tuple[list[str], list[str], list[str]]:
        """
        Get lists of changed, added, and removed files.
        
        Args:
            org: Organization name
            repo: Repository name
            current_hashes: Current file hashes
            
        Returns:
            Tuple of (changed, added, removed) file lists
        """
        if not self.enabled:
            return list(current_hashes.keys()), [], []
        
        cached_hashes = self.get_all_hashes(org, repo)
        
        current_files = set(current_hashes.keys())
        cached_files = set(cached_hashes.keys())
        
        added = list(current_files - cached_files)
        removed = list(cached_files - current_files)
        
        changed = []
        for file_path in current_files & cached_files:
            if current_hashes[file_path] != cached_hashes.get(file_path):
                changed.append(file_path)
        
        return changed, added, removed
    
    def save_scan_metadata(
        self,
        org: str,
        repo: str,
        commit_sha: str,
        findings_count: int,
    ) -> bool:
        """
        Save metadata about a completed scan.
        
        Args:
            org: Organization name
            repo: Repository name
            commit_sha: Commit SHA that was scanned
            findings_count: Number of findings
            
        Returns:
            True if saved successfully
        """
        if not self.enabled:
            return False
        
        from datetime import datetime
        
        repo_cache = self._get_repo_cache_path(org, repo)
        repo_cache.mkdir(parents=True, exist_ok=True)
        cache_path = repo_cache / "scan_metadata.json"
        
        try:
            metadata = {
                "last_scan_commit": commit_sha,
                "last_scan_date": datetime.now().isoformat(),
                "findings_count": findings_count,
            }
            
            with open(cache_path, "w") as f:
                json.dump(metadata, f)
            
            return True
        except OSError:
            return False
    
    def get_scan_metadata(self, org: str, repo: str) -> Optional[dict]:
        """
        Get metadata about the last scan.
        
        Args:
            org: Organization name
            repo: Repository name
            
        Returns:
            Scan metadata or None
        """
        if not self.enabled:
            return None
        
        cache_path = self._get_repo_cache_path(org, repo) / "scan_metadata.json"
        
        try:
            if cache_path.exists():
                with open(cache_path) as f:
                    return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
        
        return None
    
    def should_rescan(
        self,
        org: str,
        repo: str,
        current_commit: str,
    ) -> bool:
        """
        Check if a repository should be rescanned.
        
        Args:
            org: Organization name
            repo: Repository name
            current_commit: Current commit SHA
            
        Returns:
            True if rescan is needed
        """
        metadata = self.get_scan_metadata(org, repo)
        
        if not metadata:
            return True
        
        return metadata.get("last_scan_commit") != current_commit
    
    def clear_repo_cache(self, org: str, repo: str) -> bool:
        """
        Clear cache for a specific repository.
        
        Args:
            org: Organization name
            repo: Repository name
            
        Returns:
            True if cleared
        """
        repo_cache = self._get_repo_cache_path(org, repo)
        
        try:
            if repo_cache.exists():
                shutil.rmtree(repo_cache)
            return True
        except OSError:
            return False
    
    def clear_all(self) -> int:
        """
        Clear all repository caches.
        
        Returns:
            Number of repos cleared
        """
        count = 0
        
        try:
            for repo_dir in self.cache_dir.iterdir():
                if repo_dir.is_dir():
                    shutil.rmtree(repo_dir)
                    count += 1
        except OSError:
            pass
        
        return count
    
    def get_stats(self) -> dict:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache stats
        """
        if not self.enabled or not self.cache_dir.exists():
            return {"enabled": False}
        
        total_repos = 0
        total_size = 0
        
        for repo_dir in self.cache_dir.iterdir():
            if repo_dir.is_dir():
                total_repos += 1
                for file in repo_dir.rglob("*"):
                    if file.is_file():
                        total_size += file.stat().st_size
        
        return {
            "enabled": True,
            "directory": str(self.cache_dir),
            "cached_repos": total_repos,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
        }


def compute_file_hash(file_path: Path) -> str:
    """
    Compute hash of a file's content.
    
    Args:
        file_path: Path to file
        
    Returns:
        SHA256 hash of file content (first 16 chars)
    """
    hasher = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()[:16]  # Short hash for efficiency
    except OSError:
        return ""


def compute_repo_hashes(
    repo_path: Path,
    extensions: set[str] | None = None,
    skip_dirs: set[str] | None = None,
) -> dict[str, str]:
    """
    Compute hashes for all files in a repository.
    
    Args:
        repo_path: Path to repository
        extensions: File extensions to include (None = all text files)
        skip_dirs: Directories to skip
        
    Returns:
        Dictionary of relative_path -> hash
    """
    if skip_dirs is None:
        skip_dirs = {
            ".git", "node_modules", "vendor", "__pycache__",
            ".venv", "venv", "dist", "build", ".next",
            ".nuxt", "coverage", ".pytest_cache", ".mypy_cache",
        }
    
    hashes = {}
    
    for file_path in repo_path.rglob("*"):
        if not file_path.is_file():
            continue
        
        # Skip directories
        if any(skip in file_path.parts for skip in skip_dirs):
            continue
        
        # Check extension
        if extensions and file_path.suffix.lower() not in extensions:
            continue
        
        # Skip binary files
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
            continue
        
        relative_path = str(file_path.relative_to(repo_path))
        file_hash = compute_file_hash(file_path)
        
        if file_hash:
            hashes[relative_path] = file_hash
    
    return hashes
