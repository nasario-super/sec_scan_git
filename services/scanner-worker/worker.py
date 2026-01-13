"""
Scanner Worker Service

Background worker that processes scan jobs from Redis queue.
Designed for horizontal scaling with multiple workers.
"""

import asyncio
import json
import logging
import os
import signal
import sys
from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

import redis.asyncio as redis

# Add parent paths for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from github_security_scanner.core.config import Settings, get_settings
from github_security_scanner.core.scanner import SecurityScanner
from github_security_scanner.utils.secure_logging import setup_secure_logging

# Setup logging
log_level_str = os.environ.get('LOG_LEVEL', 'INFO').upper()
log_level = getattr(logging, log_level_str, logging.INFO)
setup_secure_logging(
    level=log_level,
    log_file=os.environ.get('LOG_FILE')
)
logger = logging.getLogger(__name__)


class ScanJob:
    """Represents a scan job from the queue."""
    
    def __init__(
        self,
        job_id: str,
        job_type: str,  # 'org' or 'repo'
        target: str,    # org name or repo full name
        token: str,
        options: dict[str, Any] = None,
        created_at: datetime = None,
    ):
        self.job_id = job_id
        self.job_type = job_type
        self.target = target
        self.token = token
        self.options = options or {}
        self.created_at = created_at or datetime.utcnow()
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ScanJob':
        return cls(
            job_id=data['job_id'],
            job_type=data['job_type'],
            target=data['target'],
            token=data['token'],
            options=data.get('options', {}),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None,
        )
    
    def to_dict(self) -> dict:
        return {
            'job_id': self.job_id,
            'job_type': self.job_type,
            'target': self.target,
            'token': self.token,
            'options': self.options,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class ScanWorker:
    """
    Worker that processes scan jobs from Redis queue.
    
    Architecture:
    - Uses Redis LIST for job queue (BRPOP for blocking pop)
    - Uses Redis HASH for job status tracking
    - Supports graceful shutdown
    - Handles concurrent jobs based on WORKER_CONCURRENCY
    """
    
    QUEUE_NAME = 'gss:scan:queue'
    STATUS_PREFIX = 'gss:scan:status:'
    RESULT_PREFIX = 'gss:scan:result:'
    WORKER_PREFIX = 'gss:worker:'
    
    def __init__(
        self,
        redis_url: str = None,
        concurrency: int = None,
        scan_timeout: int = None,
    ):
        self.redis_url = redis_url or os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
        self.concurrency = concurrency or int(os.environ.get('WORKER_CONCURRENCY', '4'))
        self.scan_timeout = scan_timeout or int(os.environ.get('SCAN_TIMEOUT', '3600'))
        
        self.worker_id = f"worker-{uuid4().hex[:8]}"
        self.redis: Optional[redis.Redis] = None
        self.running = False
        self.active_jobs: set[str] = set()
        self.settings = get_settings()
        
        logger.info(f"Worker {self.worker_id} initialized with concurrency={self.concurrency}")
    
    async def connect(self):
        """Connect to Redis."""
        self.redis = redis.from_url(self.redis_url, decode_responses=True)
        await self.redis.ping()
        logger.info(f"Connected to Redis: {self.redis_url}")
        
        # Register worker
        await self.redis.hset(
            f"{self.WORKER_PREFIX}{self.worker_id}",
            mapping={
                'started_at': datetime.utcnow().isoformat(),
                'status': 'running',
                'concurrency': str(self.concurrency),
                'active_jobs': '0',
            }
        )
        await self.redis.expire(f"{self.WORKER_PREFIX}{self.worker_id}", 300)
    
    async def disconnect(self):
        """Disconnect from Redis."""
        if self.redis:
            # Unregister worker
            await self.redis.delete(f"{self.WORKER_PREFIX}{self.worker_id}")
            await self.redis.close()
            logger.info("Disconnected from Redis")
    
    async def update_job_status(
        self,
        job_id: str,
        status: str,
        progress: int = None,
        message: str = None,
        result: dict = None,
    ):
        """Update job status in Redis."""
        status_data = {
            'status': status,
            'updated_at': datetime.utcnow().isoformat(),
            'worker_id': self.worker_id,
        }
        
        if progress is not None:
            status_data['progress'] = str(progress)
        if message:
            status_data['message'] = message
        
        await self.redis.hset(f"{self.STATUS_PREFIX}{job_id}", mapping=status_data)
        
        # Store result if completed
        if result:
            await self.redis.setex(
                f"{self.RESULT_PREFIX}{job_id}",
                86400 * 7,  # Keep results for 7 days
                json.dumps(result)
            )
        
        logger.debug(f"Job {job_id} status updated: {status}")
    
    async def process_job(self, job: ScanJob):
        """Process a single scan job."""
        logger.info(f"Processing job {job.job_id}: {job.job_type} scan for {job.target}")
        
        try:
            await self.update_job_status(job.job_id, 'running', progress=0, message='Initializing scanner')
            
            # Configure settings
            settings = get_settings()
            settings.github.token = job.token
            
            if job.options.get('analyze_history'):
                settings.scan.analyze_history = True
            if job.options.get('clone_strategy'):
                settings.scan.clone_strategy = job.options['clone_strategy']
            
            scanner = SecurityScanner(settings)
            
            # Run scan based on type
            if job.job_type == 'org':
                await self.update_job_status(job.job_id, 'running', progress=10, message='Fetching repositories')
                
                result = await scanner.scan_organization(
                    org=job.target,
                    token=job.token,
                    include_archived=job.options.get('include_archived', False),
                    include_forks=job.options.get('include_forks', False),
                )
            else:  # repo
                await self.update_job_status(job.job_id, 'running', progress=10, message='Cloning repository')
                
                result = await scanner.scan_repository(
                    repo_url=job.target,
                    token=job.token,
                    branch=job.options.get('branch'),
                )
            
            # Prepare result summary
            result_summary = {
                'scan_id': result.metadata.scan_id if result.metadata else None,
                'repositories_scanned': len(result.repositories),
                'total_findings': len(result.findings),
                'findings_by_severity': {
                    'critical': sum(1 for f in result.findings if f.severity.value == 'critical'),
                    'high': sum(1 for f in result.findings if f.severity.value == 'high'),
                    'medium': sum(1 for f in result.findings if f.severity.value == 'medium'),
                    'low': sum(1 for f in result.findings if f.severity.value == 'low'),
                    'info': sum(1 for f in result.findings if f.severity.value == 'info'),
                },
                'completed_at': datetime.utcnow().isoformat(),
            }
            
            await self.update_job_status(
                job.job_id,
                'completed',
                progress=100,
                message=f"Scan completed. Found {result_summary['total_findings']} findings.",
                result=result_summary,
            )
            
            logger.info(f"Job {job.job_id} completed: {result_summary['total_findings']} findings")
            
        except Exception as e:
            logger.exception(f"Job {job.job_id} failed: {e}")
            await self.update_job_status(
                job.job_id,
                'failed',
                message=str(e),
                result={'error': str(e)},
            )
    
    async def worker_loop(self):
        """Main worker loop - fetch and process jobs."""
        while self.running:
            try:
                # Check if we can take more jobs
                if len(self.active_jobs) >= self.concurrency:
                    await asyncio.sleep(1)
                    continue
                
                # Block waiting for a job (with timeout)
                result = await self.redis.brpop(self.QUEUE_NAME, timeout=5)
                
                if result is None:
                    # Timeout, refresh worker heartbeat
                    await self.redis.expire(f"{self.WORKER_PREFIX}{self.worker_id}", 300)
                    continue
                
                _, job_data = result
                job = ScanJob.from_dict(json.loads(job_data))
                
                # Track active job
                self.active_jobs.add(job.job_id)
                
                # Process job in background
                asyncio.create_task(self._run_job(job))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(f"Worker loop error: {e}")
                await asyncio.sleep(5)
    
    async def _run_job(self, job: ScanJob):
        """Run job and cleanup."""
        try:
            await asyncio.wait_for(
                self.process_job(job),
                timeout=self.scan_timeout
            )
        except asyncio.TimeoutError:
            logger.error(f"Job {job.job_id} timed out after {self.scan_timeout}s")
            await self.update_job_status(
                job.job_id,
                'failed',
                message=f"Scan timed out after {self.scan_timeout} seconds",
            )
        except Exception as e:
            logger.exception(f"Job {job.job_id} error: {e}")
        finally:
            self.active_jobs.discard(job.job_id)
            
            # Update worker status
            await self.redis.hset(
                f"{self.WORKER_PREFIX}{self.worker_id}",
                'active_jobs', str(len(self.active_jobs))
            )
    
    async def start(self):
        """Start the worker."""
        await self.connect()
        self.running = True
        
        logger.info(f"Worker {self.worker_id} starting...")
        
        # Handle shutdown signals
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._shutdown)
        
        await self.worker_loop()
        
        # Wait for active jobs to complete
        if self.active_jobs:
            logger.info(f"Waiting for {len(self.active_jobs)} active jobs to complete...")
            for _ in range(60):  # Wait up to 60 seconds
                if not self.active_jobs:
                    break
                await asyncio.sleep(1)
        
        await self.disconnect()
        logger.info(f"Worker {self.worker_id} stopped")
    
    def _shutdown(self):
        """Signal handler for graceful shutdown."""
        logger.info("Shutdown signal received...")
        self.running = False


async def main():
    """Main entry point."""
    worker = ScanWorker()
    await worker.start()


if __name__ == '__main__':
    asyncio.run(main())
