"""
Parallel processing utilities for the scanner.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Awaitable, Callable, TypeVar

from rich.console import Console
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn, TimeRemainingColumn

console = Console()

T = TypeVar("T")
R = TypeVar("R")


class ParallelProcessor:
    """
    Handles parallel processing of tasks with progress tracking.
    """

    def __init__(
        self,
        max_workers: int = 4,
        show_progress: bool = True,
    ):
        """
        Initialize parallel processor.

        Args:
            max_workers: Maximum concurrent workers
            show_progress: Show progress bar
        """
        self.max_workers = max_workers
        self.show_progress = show_progress
        self._executor: ThreadPoolExecutor | None = None

    @property
    def executor(self) -> ThreadPoolExecutor:
        """Get or create thread pool executor."""
        if self._executor is None:
            self._executor = ThreadPoolExecutor(max_workers=self.max_workers)
        return self._executor

    def shutdown(self) -> None:
        """Shutdown the executor."""
        if self._executor:
            self._executor.shutdown(wait=True)
            self._executor = None

    async def map_async(
        self,
        func: Callable[[T], Awaitable[R]],
        items: list[T],
        description: str = "Processing",
    ) -> list[R]:
        """
        Apply async function to items in parallel.

        Args:
            func: Async function to apply
            items: Items to process
            description: Progress bar description

        Returns:
            List of results
        """
        if not items:
            return []

        semaphore = asyncio.Semaphore(self.max_workers)

        async def process_item(item: T) -> R:
            async with semaphore:
                return await func(item)

        if self.show_progress:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(description, total=len(items))
                results = []

                tasks = [process_item(item) for item in items]
                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    results.append(result)
                    progress.advance(task)

                return results
        else:
            tasks = [process_item(item) for item in items]
            return await asyncio.gather(*tasks)

    async def map_sync_in_executor(
        self,
        func: Callable[[T], R],
        items: list[T],
        description: str = "Processing",
    ) -> list[R]:
        """
        Apply sync function to items using thread pool.

        Args:
            func: Sync function to apply
            items: Items to process
            description: Progress bar description

        Returns:
            List of results
        """
        if not items:
            return []

        loop = asyncio.get_event_loop()

        if self.show_progress:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(description, total=len(items))
                results = []

                futures = [
                    loop.run_in_executor(self.executor, func, item)
                    for item in items
                ]

                for future in asyncio.as_completed(futures):
                    result = await future
                    results.append(result)
                    progress.advance(task)

                return results
        else:
            futures = [
                loop.run_in_executor(self.executor, func, item)
                for item in items
            ]
            return await asyncio.gather(*futures)

    async def process_batches(
        self,
        items: list[T],
        batch_func: Callable[[list[T]], Awaitable[list[R]]],
        batch_size: int = 10,
        description: str = "Processing batches",
    ) -> list[R]:
        """
        Process items in batches.

        Args:
            items: Items to process
            batch_func: Function that processes a batch
            batch_size: Size of each batch
            description: Progress bar description

        Returns:
            Flattened list of all results
        """
        if not items:
            return []

        # Split into batches
        batches = [
            items[i : i + batch_size]
            for i in range(0, len(items), batch_size)
        ]

        all_results: list[R] = []

        if self.show_progress:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(description, total=len(batches))

                for batch in batches:
                    batch_results = await batch_func(batch)
                    all_results.extend(batch_results)
                    progress.advance(task)
        else:
            for batch in batches:
                batch_results = await batch_func(batch)
                all_results.extend(batch_results)

        return all_results


async def run_with_timeout(
    coro: Awaitable[T],
    timeout: float,
    default: T | None = None,
) -> T | None:
    """
    Run a coroutine with a timeout.

    Args:
        coro: Coroutine to run
        timeout: Timeout in seconds
        default: Default value if timeout

    Returns:
        Result or default if timeout
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        console.print(f"[yellow]Operation timed out after {timeout}s[/yellow]")
        return default


def chunked(items: list[Any], size: int) -> list[list[Any]]:
    """
    Split a list into chunks.

    Args:
        items: Items to split
        size: Chunk size

    Returns:
        List of chunks
    """
    return [items[i : i + size] for i in range(0, len(items), size)]

