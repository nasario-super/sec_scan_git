"""
Git operations and analysis utilities.

Provides functionality for analyzing git history, finding secrets
in commits, and working with git diffs.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from git import Repo
from git.exc import GitCommandError


@dataclass
class GitMatch:
    """Represents a match found in git history."""

    commit_sha: str
    commit_date: datetime
    commit_author: str
    commit_message: str
    file_path: str
    line_number: int
    line_content: str
    is_addition: bool  # True if added, False if removed
    diff_context: list[str]


@dataclass
class FileBlame:
    """Blame information for a file."""

    file_path: str
    lines: list[dict]  # line_number, commit_sha, author, date, content


class GitAnalyzer:
    """
    Analyzes git repositories for security findings.

    Provides methods for searching through git history,
    analyzing diffs, and extracting blame information.
    Supports multi-branch analysis.
    """

    def __init__(self, repo_path: Path):
        """
        Initialize git analyzer.

        Args:
            repo_path: Path to git repository
        """
        self.repo_path = repo_path
        self._repo: Optional[Repo] = None
        self._all_branches: Optional[list[str]] = None

    @property
    def repo(self) -> Repo:
        """Get GitPython Repo object."""
        if self._repo is None:
            self._repo = Repo(self.repo_path)
        return self._repo

    def is_valid_repo(self) -> bool:
        """Check if path is a valid git repository."""
        try:
            _ = self.repo.head
            return True
        except Exception:
            return False

    def get_all_branches(self) -> list[str]:
        """
        Get all branches (local and remote) in the repository.
        
        Returns:
            List of branch names
        """
        if self._all_branches is not None:
            return self._all_branches
        
        branches = []
        try:
            # Get remote branches
            for ref in self.repo.references:
                ref_name = str(ref)
                if ref_name.startswith("origin/") and not ref_name.endswith("/HEAD"):
                    branches.append(ref_name)
            
            # Get local branches
            for branch in self.repo.branches:
                if branch.name not in branches:
                    branches.append(branch.name)
        except Exception:
            branches = ["HEAD"]
        
        self._all_branches = branches
        return branches

    def fetch_all_branches(self) -> bool:
        """
        Fetch all remote branches for analysis.
        
        Returns:
            True if successful
        """
        try:
            self.repo.git.fetch("--all")
            self._all_branches = None  # Reset cache
            return True
        except GitCommandError:
            return False

    def get_current_branch(self) -> str:
        """Get current branch name."""
        try:
            return self.repo.active_branch.name
        except TypeError:
            # Detached HEAD
            return self.repo.head.commit.hexsha[:8]

    def get_default_branch(self) -> str:
        """Get the default branch name."""
        try:
            # Try to get from remote
            for ref in self.repo.references:
                if "origin/HEAD" in str(ref):
                    return str(ref).split("/")[-1]
        except Exception:
            pass

        # Fall back to common names
        for branch in ["main", "master"]:
            if branch in [b.name for b in self.repo.branches]:
                return branch

        return "main"

    def search_history(
        self,
        pattern: str,
        max_commits: Optional[int] = None,
        file_pattern: Optional[str] = None,
    ) -> Iterator[GitMatch]:
        """
        Search git history for a pattern using git log -S.

        Args:
            pattern: Regex pattern to search for
            max_commits: Maximum commits to search
            file_pattern: Optional file pattern to limit search

        Yields:
            GitMatch objects for each match found
        """
        try:
            # Use git log -p -S for searching
            args = ["-p", "-S", pattern, "--all"]
            if max_commits:
                args.extend(["-n", str(max_commits)])
            if file_pattern:
                args.extend(["--", file_pattern])

            log_output = self.repo.git.log(*args)

            # Parse the log output
            yield from self._parse_log_output(log_output, pattern)

        except GitCommandError:
            return

    def search_history_regex(
        self,
        pattern: str,
        max_commits: Optional[int] = None,
    ) -> Iterator[GitMatch]:
        """
        Search git history using regex with git log -G.

        Args:
            pattern: Regex pattern
            max_commits: Maximum commits to search

        Yields:
            GitMatch objects for each match found
        """
        try:
            args = ["-p", "-G", pattern, "--all"]
            if max_commits:
                args.extend(["-n", str(max_commits)])

            log_output = self.repo.git.log(*args)
            yield from self._parse_log_output(log_output, pattern)

        except GitCommandError:
            return

    def _parse_log_output(
        self,
        log_output: str,
        pattern: str,
    ) -> Iterator[GitMatch]:
        """
        Parse git log output to extract matches.

        Args:
            log_output: Raw git log output
            pattern: Pattern that was searched for

        Yields:
            GitMatch objects
        """
        if not log_output:
            return

        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            # Invalid regex, use literal search
            regex = re.compile(re.escape(pattern), re.IGNORECASE)

        current_commit = None
        current_file = None
        current_line_num = 0
        diff_lines: list[str] = []
        in_diff = False

        for line in log_output.split("\n"):
            # New commit
            if line.startswith("commit "):
                current_commit = {
                    "sha": line.split()[1],
                    "author": "",
                    "date": datetime.now(),
                    "message": "",
                }
                in_diff = False
                continue

            if current_commit is None:
                continue

            # Author line
            if line.startswith("Author:"):
                current_commit["author"] = line[7:].strip()
                continue

            # Date line
            if line.startswith("Date:"):
                try:
                    date_str = line[5:].strip()
                    # Parse git date format
                    current_commit["date"] = datetime.strptime(
                        date_str,
                        "%a %b %d %H:%M:%S %Y %z",
                    ).replace(tzinfo=None)
                except ValueError:
                    pass
                continue

            # Commit message (indented lines after date)
            if line.startswith("    ") and not in_diff:
                current_commit["message"] += line.strip() + " "
                continue

            # Diff file header
            if line.startswith("diff --git"):
                in_diff = True
                # Extract file path
                parts = line.split()
                if len(parts) >= 4:
                    current_file = parts[3][2:]  # Remove b/ prefix
                current_line_num = 0
                diff_lines = []
                continue

            # Line numbers in diff
            if line.startswith("@@") and in_diff:
                # Parse @@ -old,len +new,len @@
                match = re.search(r"\+(\d+)", line)
                if match:
                    current_line_num = int(match.group(1))
                continue

            # Diff content
            if in_diff and current_file:
                diff_lines.append(line)

                # Check for additions/removals that match pattern
                if line.startswith("+") and not line.startswith("+++"):
                    content = line[1:]
                    if regex.search(content):
                        yield GitMatch(
                            commit_sha=current_commit["sha"],
                            commit_date=current_commit["date"],
                            commit_author=current_commit["author"],
                            commit_message=current_commit["message"].strip(),
                            file_path=current_file,
                            line_number=current_line_num,
                            line_content=content,
                            is_addition=True,
                            diff_context=diff_lines[-5:],
                        )
                    current_line_num += 1

                elif line.startswith("-") and not line.startswith("---"):
                    content = line[1:]
                    if regex.search(content):
                        yield GitMatch(
                            commit_sha=current_commit["sha"],
                            commit_date=current_commit["date"],
                            commit_author=current_commit["author"],
                            commit_message=current_commit["message"].strip(),
                            file_path=current_file,
                            line_number=current_line_num,
                            line_content=content,
                            is_addition=False,
                            diff_context=diff_lines[-5:],
                        )

                elif not line.startswith("\\"):  # Skip "\ No newline" lines
                    current_line_num += 1

    def get_file_history(
        self,
        file_path: str,
        max_commits: Optional[int] = None,
    ) -> list[dict]:
        """
        Get commit history for a specific file.

        Args:
            file_path: Path to file within repository
            max_commits: Maximum commits to return

        Returns:
            List of commit information
        """
        try:
            args = ["--follow"]
            if max_commits:
                args.extend(["-n", str(max_commits)])
            args.extend(["--", file_path])

            commits = []
            for commit in self.repo.iter_commits(*args):
                commits.append({
                    "sha": commit.hexsha,
                    "author": commit.author.email if commit.author else "",
                    "date": commit.committed_datetime,
                    "message": commit.message.strip(),
                })
            return commits
        except GitCommandError:
            return []

    def get_blame(self, file_path: str) -> Optional[FileBlame]:
        """
        Get blame information for a file.

        Args:
            file_path: Path to file within repository

        Returns:
            FileBlame object or None if failed
        """
        try:
            blame_data = self.repo.blame("HEAD", file_path)
            lines = []
            line_num = 1

            for commit, line_contents in blame_data:
                for content in line_contents:
                    lines.append({
                        "line_number": line_num,
                        "commit_sha": commit.hexsha,
                        "author": commit.author.email if commit.author else "",
                        "date": commit.committed_datetime,
                        "content": content,
                    })
                    line_num += 1

            return FileBlame(file_path=file_path, lines=lines)
        except GitCommandError:
            return None

    def get_first_commit_date(self) -> Optional[datetime]:
        """Get the date of the first commit in the repository."""
        try:
            first_commit = list(self.repo.iter_commits(reverse=True, max_count=1))[0]
            return first_commit.committed_datetime.replace(tzinfo=None)
        except (IndexError, GitCommandError):
            return None

    def get_last_commit_date(self) -> Optional[datetime]:
        """Get the date of the last commit in the repository."""
        try:
            last_commit = self.repo.head.commit
            return last_commit.committed_datetime.replace(tzinfo=None)
        except GitCommandError:
            return None

    def file_exists_in_commit(self, file_path: str, commit_sha: str) -> bool:
        """
        Check if a file exists in a specific commit.

        Args:
            file_path: Path to file
            commit_sha: Commit SHA

        Returns:
            True if file exists in that commit
        """
        try:
            commit = self.repo.commit(commit_sha)
            commit.tree / file_path
            return True
        except (KeyError, GitCommandError):
            return False

    def get_file_at_commit(
        self,
        file_path: str,
        commit_sha: str,
    ) -> Optional[str]:
        """
        Get file content at a specific commit.

        Args:
            file_path: Path to file
            commit_sha: Commit SHA

        Returns:
            File content or None if not found
        """
        try:
            commit = self.repo.commit(commit_sha)
            blob = commit.tree / file_path
            return blob.data_stream.read().decode("utf-8", errors="replace")
        except (KeyError, GitCommandError):
            return None

    def is_file_in_head(self, file_path: str) -> bool:
        """
        Check if file exists in current HEAD.

        Args:
            file_path: Path to file

        Returns:
            True if file exists
        """
        full_path = self.repo_path / file_path
        return full_path.exists()

    def get_deleted_files(self, since_commits: int = 100) -> list[str]:
        """
        Get list of files that have been deleted.

        Args:
            since_commits: Number of commits to look back

        Returns:
            List of deleted file paths
        """
        deleted = set()
        try:
            for commit in self.repo.iter_commits(max_count=since_commits):
                for diff in commit.diff(commit.parents[0] if commit.parents else None):
                    if diff.deleted_file:
                        deleted.add(diff.a_path)
        except GitCommandError:
            pass
        return list(deleted)

    def search_all_branches(
        self,
        pattern: str,
        max_commits_per_branch: Optional[int] = None,
    ) -> Iterator[GitMatch]:
        """
        Search for a pattern across all branches.
        
        Args:
            pattern: Regex pattern to search for
            max_commits_per_branch: Maximum commits to search per branch
            
        Yields:
            GitMatch objects for each match found
        """
        seen_commits: set[str] = set()
        
        for branch in self.get_all_branches():
            try:
                # Checkout branch temporarily for search
                for match in self.search_history_regex(
                    pattern,
                    max_commits=max_commits_per_branch,
                ):
                    # Deduplicate by commit SHA
                    if match.commit_sha not in seen_commits:
                        seen_commits.add(match.commit_sha)
                        yield match
            except GitCommandError:
                continue

    def get_stale_branches(self, days: int = 90) -> list[dict]:
        """
        Get branches that haven't been updated recently.
        
        Stale branches may contain old secrets that were never properly removed.
        
        Args:
            days: Number of days to consider a branch stale
            
        Returns:
            List of stale branch info
        """
        from datetime import datetime, timedelta
        
        stale = []
        cutoff = datetime.now() - timedelta(days=days)
        
        for branch in self.get_all_branches():
            try:
                # Get latest commit on branch
                commit = self.repo.commit(branch)
                commit_date = commit.committed_datetime.replace(tzinfo=None)
                
                if commit_date < cutoff:
                    stale.append({
                        "branch": branch,
                        "last_commit": commit_date,
                        "days_stale": (datetime.now() - commit_date).days,
                        "author": commit.author.email if commit.author else "",
                    })
            except Exception:
                continue
        
        return sorted(stale, key=lambda x: x["days_stale"], reverse=True)

    def get_branch_diff(
        self,
        branch: str,
        base_branch: str = "main",
    ) -> list[dict]:
        """
        Get files changed in a branch compared to base.
        
        Args:
            branch: Branch to compare
            base_branch: Base branch for comparison
            
        Returns:
            List of changed files with diff info
        """
        changes = []
        try:
            # Get merge base
            merge_base = self.repo.git.merge_base(base_branch, branch)
            
            # Get diff
            diffs = self.repo.commit(branch).diff(merge_base)
            
            for diff in diffs:
                changes.append({
                    "file": diff.b_path or diff.a_path,
                    "change_type": diff.change_type,
                    "insertions": diff.diff.count(b"\n+") if diff.diff else 0,
                    "deletions": diff.diff.count(b"\n-") if diff.diff else 0,
                })
        except GitCommandError:
            pass
        
        return changes

    def get_commits_with_secrets_keywords(
        self,
        max_commits: int = 1000,
    ) -> list[dict]:
        """
        Find commits with suspicious keywords in commit messages.
        
        These commits may have accidentally included secrets.
        
        Args:
            max_commits: Maximum commits to search
            
        Returns:
            List of suspicious commits
        """
        keywords = [
            r"password",
            r"secret",
            r"token",
            r"key",
            r"credential",
            r"api[_-]?key",
            r"remove.*secret",
            r"fix.*leak",
            r"oops",
            r"accidentally",
            r"revert",
            r"rollback",
        ]
        
        pattern = "|".join(keywords)
        regex = re.compile(pattern, re.IGNORECASE)
        
        suspicious = []
        try:
            for commit in self.repo.iter_commits(max_count=max_commits, all=True):
                if regex.search(commit.message):
                    suspicious.append({
                        "sha": commit.hexsha,
                        "message": commit.message.strip()[:100],
                        "author": commit.author.email if commit.author else "",
                        "date": commit.committed_datetime,
                        "keyword_matches": regex.findall(commit.message),
                    })
        except GitCommandError:
            pass
        
        return suspicious

    def analyze_pr_history(
        self,
        max_merges: int = 100,
    ) -> list[dict]:
        """
        Analyze merge commits (PRs) for potential secret introductions.
        
        Args:
            max_merges: Maximum merge commits to analyze
            
        Returns:
            List of merge commit info
        """
        merges = []
        try:
            for commit in self.repo.iter_commits(max_count=max_merges * 10, all=True):
                if len(commit.parents) > 1:  # Merge commit
                    # Get files changed in this merge
                    if commit.parents:
                        diffs = commit.diff(commit.parents[0])
                        files_changed = [d.b_path or d.a_path for d in diffs]
                    else:
                        files_changed = []
                    
                    merges.append({
                        "sha": commit.hexsha,
                        "message": commit.message.strip()[:200],
                        "author": commit.author.email if commit.author else "",
                        "date": commit.committed_datetime,
                        "files_changed": len(files_changed),
                        "sample_files": files_changed[:5],
                    })
                    
                    if len(merges) >= max_merges:
                        break
        except GitCommandError:
            pass
        
        return merges
