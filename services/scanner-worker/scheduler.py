"""
Scheduler Service

Handles periodic/scheduled scans using Redis-based scheduling.
"""

import asyncio
import json
import logging
import os
import signal
import sys
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

import redis.asyncio as redis

# Add parent paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from github_security_scanner.utils.secure_logging import setup_secure_logging

log_level_str = os.environ.get('LOG_LEVEL', 'INFO').upper()
log_level = getattr(logging, log_level_str, logging.INFO)
setup_secure_logging(level=log_level)
logger = logging.getLogger(__name__)


class ScheduledTask:
    """Represents a scheduled scan task."""
    
    def __init__(
        self,
        task_id: str,
        name: str,
        job_type: str,
        target: str,
        schedule: str,  # cron expression or 'daily', 'weekly', 'hourly'
        token: str,
        options: dict = None,
        enabled: bool = True,
        last_run: datetime = None,
        next_run: datetime = None,
    ):
        self.task_id = task_id
        self.name = name
        self.job_type = job_type
        self.target = target
        self.schedule = schedule
        self.token = token
        self.options = options or {}
        self.enabled = enabled
        self.last_run = last_run
        self.next_run = next_run or self._calculate_next_run()
    
    def _calculate_next_run(self) -> datetime:
        """Calculate next run time based on schedule."""
        now = datetime.utcnow()
        
        if self.schedule == 'hourly':
            return now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        elif self.schedule == 'daily':
            return now.replace(hour=2, minute=0, second=0, microsecond=0) + timedelta(days=1)
        elif self.schedule == 'weekly':
            days_until_monday = (7 - now.weekday()) % 7 or 7
            return now.replace(hour=2, minute=0, second=0, microsecond=0) + timedelta(days=days_until_monday)
        elif self.schedule.startswith('every_'):
            # Format: every_N_hours or every_N_minutes
            parts = self.schedule.split('_')
            if len(parts) == 3:
                interval = int(parts[1])
                unit = parts[2]
                if unit == 'hours':
                    return now + timedelta(hours=interval)
                elif unit == 'minutes':
                    return now + timedelta(minutes=interval)
        
        # Default: next day at 2 AM
        return now.replace(hour=2, minute=0, second=0, microsecond=0) + timedelta(days=1)
    
    def to_dict(self) -> dict:
        return {
            'task_id': self.task_id,
            'name': self.name,
            'job_type': self.job_type,
            'target': self.target,
            'schedule': self.schedule,
            'token': self.token,
            'options': self.options,
            'enabled': self.enabled,
            'last_run': self.last_run.isoformat() if self.last_run else None,
            'next_run': self.next_run.isoformat() if self.next_run else None,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ScheduledTask':
        return cls(
            task_id=data['task_id'],
            name=data['name'],
            job_type=data['job_type'],
            target=data['target'],
            schedule=data['schedule'],
            token=data['token'],
            options=data.get('options', {}),
            enabled=data.get('enabled', True),
            last_run=datetime.fromisoformat(data['last_run']) if data.get('last_run') else None,
            next_run=datetime.fromisoformat(data['next_run']) if data.get('next_run') else None,
        )


class Scheduler:
    """
    Scheduler that manages periodic scans.
    
    Uses Redis for:
    - Storing scheduled tasks
    - Ensuring single scheduler instance (distributed lock)
    - Queuing jobs to worker queue
    """
    
    TASKS_KEY = 'gss:scheduler:tasks'
    LOCK_KEY = 'gss:scheduler:lock'
    QUEUE_NAME = 'gss:scan:queue'
    
    def __init__(self, redis_url: str = None):
        self.redis_url = redis_url or os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
        self.redis: Optional[redis.Redis] = None
        self.running = False
        self.scheduler_id = f"scheduler-{uuid4().hex[:8]}"
        
        logger.info(f"Scheduler {self.scheduler_id} initialized")
    
    async def connect(self):
        """Connect to Redis."""
        self.redis = redis.from_url(self.redis_url, decode_responses=True)
        await self.redis.ping()
        logger.info(f"Connected to Redis: {self.redis_url}")
    
    async def disconnect(self):
        """Disconnect from Redis."""
        if self.redis:
            await self.redis.delete(self.LOCK_KEY)
            await self.redis.close()
            logger.info("Disconnected from Redis")
    
    async def acquire_lock(self) -> bool:
        """Try to acquire scheduler lock (only one scheduler should run)."""
        # SET NX with expiry
        acquired = await self.redis.set(
            self.LOCK_KEY,
            self.scheduler_id,
            nx=True,
            ex=60  # Lock expires in 60 seconds
        )
        return acquired
    
    async def refresh_lock(self):
        """Refresh the scheduler lock."""
        current = await self.redis.get(self.LOCK_KEY)
        if current == self.scheduler_id:
            await self.redis.expire(self.LOCK_KEY, 60)
            return True
        return False
    
    async def get_tasks(self) -> list[ScheduledTask]:
        """Get all scheduled tasks."""
        tasks_data = await self.redis.hgetall(self.TASKS_KEY)
        return [ScheduledTask.from_dict(json.loads(v)) for v in tasks_data.values()]
    
    async def save_task(self, task: ScheduledTask):
        """Save a scheduled task."""
        await self.redis.hset(self.TASKS_KEY, task.task_id, json.dumps(task.to_dict()))
    
    async def delete_task(self, task_id: str):
        """Delete a scheduled task."""
        await self.redis.hdel(self.TASKS_KEY, task_id)
    
    async def queue_job(self, task: ScheduledTask):
        """Queue a scan job for processing."""
        job_data = {
            'job_id': f"scheduled-{task.task_id}-{uuid4().hex[:8]}",
            'job_type': task.job_type,
            'target': task.target,
            'token': task.token,
            'options': task.options,
            'created_at': datetime.utcnow().isoformat(),
            'scheduled_task_id': task.task_id,
        }
        
        await self.redis.lpush(self.QUEUE_NAME, json.dumps(job_data))
        logger.info(f"Queued scheduled job for task {task.name} ({task.task_id})")
    
    async def check_and_run_tasks(self):
        """Check for tasks that need to run."""
        tasks = await self.get_tasks()
        now = datetime.utcnow()
        
        for task in tasks:
            if not task.enabled:
                continue
            
            if task.next_run and task.next_run <= now:
                logger.info(f"Running scheduled task: {task.name}")
                
                # Queue the job
                await self.queue_job(task)
                
                # Update task
                task.last_run = now
                task.next_run = task._calculate_next_run()
                await self.save_task(task)
    
    async def scheduler_loop(self):
        """Main scheduler loop."""
        while self.running:
            try:
                # Try to acquire/refresh lock
                if not await self.refresh_lock():
                    if not await self.acquire_lock():
                        logger.debug("Another scheduler is active, waiting...")
                        await asyncio.sleep(30)
                        continue
                
                # Check for tasks to run
                await self.check_and_run_tasks()
                
                # Sleep before next check
                await asyncio.sleep(60)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(f"Scheduler error: {e}")
                await asyncio.sleep(60)
    
    async def start(self):
        """Start the scheduler."""
        await self.connect()
        self.running = True
        
        logger.info(f"Scheduler {self.scheduler_id} starting...")
        
        # Handle shutdown signals
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._shutdown)
        
        await self.scheduler_loop()
        await self.disconnect()
        
        logger.info(f"Scheduler {self.scheduler_id} stopped")
    
    def _shutdown(self):
        """Signal handler for graceful shutdown."""
        logger.info("Shutdown signal received...")
        self.running = False


async def main():
    """Main entry point."""
    scheduler = Scheduler()
    await scheduler.start()


if __name__ == '__main__':
    asyncio.run(main())
