"""
Caching utilities for scan results and metadata.
"""

import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from rich.console import Console

console = Console()


class ScanCache:
    """
    Cache for scan results to enable incremental scanning.
    """

    def __init__(
        self,
        cache_dir: str | Path = ".scanner-cache",
        ttl_hours: int = 24,
        enabled: bool = True,
    ):
        """
        Initialize cache.

        Args:
            cache_dir: Directory to store cache files
            ttl_hours: Time-to-live for cache entries in hours
            enabled: Whether caching is enabled
        """
        self.cache_dir = Path(cache_dir)
        self.ttl = timedelta(hours=ttl_hours)
        self.enabled = enabled

        if self.enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_key(self, *args: str) -> str:
        """Generate a cache key from arguments."""
        key_string = ":".join(args)
        return hashlib.sha256(key_string.encode()).hexdigest()[:16]

    def _get_cache_path(self, key: str) -> Path:
        """Get the file path for a cache key."""
        return self.cache_dir / f"{key}.json"

    def _is_valid(self, cache_path: Path) -> bool:
        """Check if a cache entry is still valid."""
        if not cache_path.exists():
            return False

        try:
            with open(cache_path) as f:
                data = json.load(f)

            cached_time = datetime.fromisoformat(data.get("_cached_at", ""))
            return datetime.now() - cached_time < self.ttl
        except (json.JSONDecodeError, ValueError, KeyError):
            return False

    def get(self, *key_parts: str) -> Optional[Any]:
        """
        Get a cached value.

        Args:
            key_parts: Parts to form the cache key

        Returns:
            Cached value or None if not found/expired
        """
        if not self.enabled:
            return None

        key = self._get_cache_key(*key_parts)
        cache_path = self._get_cache_path(key)

        if not self._is_valid(cache_path):
            return None

        try:
            with open(cache_path) as f:
                data = json.load(f)
            return data.get("value")
        except (json.JSONDecodeError, OSError):
            return None

    def set(self, value: Any, *key_parts: str) -> bool:
        """
        Set a cached value.

        Args:
            value: Value to cache
            key_parts: Parts to form the cache key

        Returns:
            True if successfully cached
        """
        if not self.enabled:
            return False

        key = self._get_cache_key(*key_parts)
        cache_path = self._get_cache_path(key)

        try:
            data = {
                "_cached_at": datetime.now().isoformat(),
                "_key_parts": key_parts,
                "value": value,
            }
            with open(cache_path, "w") as f:
                json.dump(data, f)
            return True
        except (TypeError, OSError):
            return False

    def delete(self, *key_parts: str) -> bool:
        """
        Delete a cached value.

        Args:
            key_parts: Parts to form the cache key

        Returns:
            True if deleted
        """
        if not self.enabled:
            return False

        key = self._get_cache_key(*key_parts)
        cache_path = self._get_cache_path(key)

        try:
            cache_path.unlink(missing_ok=True)
            return True
        except OSError:
            return False

    def clear(self) -> int:
        """
        Clear all cached entries.

        Returns:
            Number of entries cleared
        """
        if not self.enabled or not self.cache_dir.exists():
            return 0

        count = 0
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
                count += 1
            except OSError:
                pass
        return count

    def clear_expired(self) -> int:
        """
        Clear expired cache entries.

        Returns:
            Number of entries cleared
        """
        if not self.enabled or not self.cache_dir.exists():
            return 0

        count = 0
        for cache_file in self.cache_dir.glob("*.json"):
            if not self._is_valid(cache_file):
                try:
                    cache_file.unlink()
                    count += 1
                except OSError:
                    pass
        return count

    def get_stats(self) -> dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        if not self.enabled or not self.cache_dir.exists():
            return {"enabled": False}

        total = 0
        valid = 0
        total_size = 0

        for cache_file in self.cache_dir.glob("*.json"):
            total += 1
            total_size += cache_file.stat().st_size
            if self._is_valid(cache_file):
                valid += 1

        return {
            "enabled": True,
            "directory": str(self.cache_dir),
            "total_entries": total,
            "valid_entries": valid,
            "expired_entries": total - valid,
            "total_size_bytes": total_size,
            "ttl_hours": self.ttl.total_seconds() / 3600,
        }

    # Convenience methods for specific cache types

    def get_repo_scan(self, org: str, repo: str, commit_sha: str) -> Optional[dict]:
        """Get cached scan result for a repository."""
        return self.get("repo_scan", org, repo, commit_sha)

    def set_repo_scan(self, result: dict, org: str, repo: str, commit_sha: str) -> bool:
        """Cache scan result for a repository."""
        return self.set(result, "repo_scan", org, repo, commit_sha)

    def get_repo_metadata(self, org: str, repo: str) -> Optional[dict]:
        """Get cached repository metadata."""
        return self.get("repo_metadata", org, repo)

    def set_repo_metadata(self, metadata: dict, org: str, repo: str) -> bool:
        """Cache repository metadata."""
        return self.set(metadata, "repo_metadata", org, repo)

    def get_org_repos(self, org: str) -> Optional[list]:
        """Get cached list of organization repositories."""
        return self.get("org_repos", org)

    def set_org_repos(self, repos: list, org: str) -> bool:
        """Cache list of organization repositories."""
        return self.set(repos, "org_repos", org)

    def get_file_hashes(self, org: str, repo: str) -> Optional[dict]:
        """Get cached file hashes for a repository."""
        return self.get("file_hashes", org, repo)

    def set_file_hashes(self, hashes: dict, org: str, repo: str) -> bool:
        """Cache file hashes for a repository."""
        return self.set(hashes, "file_hashes", org, repo)

    def get_last_scan_commit(self, org: str, repo: str) -> Optional[str]:
        """Get the commit SHA of the last successful scan."""
        data = self.get("last_scan", org, repo)
        return data.get("commit_sha") if data else None

    def set_last_scan_commit(self, commit_sha: str, org: str, repo: str) -> bool:
        """Record the commit SHA of the last successful scan."""
        return self.set({"commit_sha": commit_sha}, "last_scan", org, repo)


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
        safe_name = f"{org}_{repo}".replace("/", "_")
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
        
        cache_path = self._get_repo_cache_path(org, repo) / "file_hashes.json"
        
        try:
            if cache_path.exists():
                with open(cache_path) as f:
                    cached_hashes = json.load(f)
            else:
                cached_hashes = {}
        except (json.JSONDecodeError, OSError):
            cached_hashes = {}
        
        current_files = set(current_hashes.keys())
        cached_files = set(cached_hashes.keys())
        
        added = list(current_files - cached_files)
        removed = list(cached_files - current_files)
        
        changed = []
        for file_path in current_files & cached_files:
            if current_hashes[file_path] != cached_hashes.get(file_path):
                changed.append(file_path)
        
        return changed, added, removed
    
    def clear_repo_cache(self, org: str, repo: str) -> bool:
        """
        Clear cache for a specific repository.
        
        Args:
            org: Organization name
            repo: Repository name
            
        Returns:
            True if cleared
        """
        import shutil
        
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
        import shutil
        
        count = 0
        
        try:
            for repo_dir in self.cache_dir.iterdir():
                if repo_dir.is_dir():
                    shutil.rmtree(repo_dir)
                    count += 1
        except OSError:
            pass
        
        return count


def compute_file_hash(file_path: Path) -> str:
    """
    Compute hash of a file's content.
    
    Args:
        file_path: Path to file
        
    Returns:
        SHA256 hash of file content
    """
    hasher = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()[:16]  # Short hash for efficiency
    except OSError:
        return ""


def compute_repo_hashes(repo_path: Path, extensions: set[str] | None = None) -> dict[str, str]:
    """
    Compute hashes for all files in a repository.
    
    Args:
        repo_path: Path to repository
        extensions: File extensions to include (None = all)
        
    Returns:
        Dictionary of relative_path -> hash
    """
    hashes = {}
    
    skip_dirs = {
        ".git", "node_modules", "vendor", "__pycache__",
        ".venv", "venv", "dist", "build", ".next",
    }
    
    for file_path in repo_path.rglob("*"):
        if not file_path.is_file():
            continue
        
        # Skip directories
        if any(skip in file_path.parts for skip in skip_dirs):
            continue
        
        # Check extension
        if extensions and file_path.suffix.lower() not in extensions:
            continue
        
        relative_path = str(file_path.relative_to(repo_path))
        file_hash = compute_file_hash(file_path)
        
        if file_hash:
            hashes[relative_path] = file_hash
    
    return hashes
