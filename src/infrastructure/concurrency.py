import threading
import time
import fcntl
import os
from pathlib import Path
from typing import Optional, Dict, Any, Callable
from contextlib import contextmanager
from collections import defaultdict
import hashlib

from src.core.exceptions import InternalServerError, ConflictError
from src.infrastructure.logging import get_logger

logger = get_logger(__name__)


class LockManager:
    """Manages file-based and in-memory locks for concurrent operations"""
    
    def __init__(self, lock_dir: Optional[Path] = None):
        self.lock_dir = lock_dir or Path("/tmp/git2in-locks")
        self.lock_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory locks for fast operations
        self._memory_locks: Dict[str, threading.RLock] = defaultdict(threading.RLock)
        self._lock_counts: Dict[str, int] = defaultdict(int)
        self._global_lock = threading.Lock()
        
        # Lock acquisition metrics
        self._metrics = {
            "acquisitions": 0,
            "releases": 0,
            "timeouts": 0,
            "contentions": 0
        }
    
    def _get_lock_path(self, resource_id: str) -> Path:
        """Get the filesystem path for a lock file"""
        # Hash the resource ID to avoid filesystem issues with special characters
        hash_id = hashlib.sha256(resource_id.encode()).hexdigest()[:16]
        return self.lock_dir / f"{hash_id}.lock"
    
    @contextmanager
    def acquire_lock(
        self,
        resource_id: str,
        timeout: float = 30.0,
        exclusive: bool = True
    ):
        """Acquire a lock for a resource"""
        lock_acquired = False
        memory_lock = None
        file_lock = None
        lock_path = self._get_lock_path(resource_id)
        
        start_time = time.time()
        
        try:
            # First, acquire in-memory lock
            with self._global_lock:
                memory_lock = self._memory_locks[resource_id]
                self._lock_counts[resource_id] += 1
                
                if self._lock_counts[resource_id] > 1:
                    self._metrics["contentions"] += 1
            
            # Try to acquire memory lock with timeout
            if not memory_lock.acquire(timeout=timeout):
                self._metrics["timeouts"] += 1
                raise ConflictError(f"Failed to acquire lock for {resource_id}: timeout")
            
            # Then acquire file-based lock for cross-process synchronization
            lock_path.touch(exist_ok=True)
            file_lock = open(lock_path, 'r+')
            
            # Use fcntl for file locking
            lock_type = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            
            # Try to acquire with timeout
            deadline = start_time + timeout
            while True:
                try:
                    fcntl.flock(file_lock.fileno(), lock_type | fcntl.LOCK_NB)
                    lock_acquired = True
                    break
                except IOError:
                    if time.time() >= deadline:
                        self._metrics["timeouts"] += 1
                        raise ConflictError(f"Failed to acquire file lock for {resource_id}: timeout")
                    time.sleep(0.01)  # Small delay before retry
            
            self._metrics["acquisitions"] += 1
            
            logger.debug(
                "lock_acquired",
                resource_id=resource_id,
                exclusive=exclusive,
                duration=time.time() - start_time
            )
            
            yield
            
        finally:
            # Release file lock
            if file_lock and lock_acquired:
                try:
                    fcntl.flock(file_lock.fileno(), fcntl.LOCK_UN)
                    file_lock.close()
                except Exception as e:
                    logger.warning("file_lock_release_failed", error=str(e))
            
            # Release memory lock
            if memory_lock:
                memory_lock.release()
                
                with self._global_lock:
                    self._lock_counts[resource_id] -= 1
                    if self._lock_counts[resource_id] == 0:
                        # Clean up if no one is using this lock
                        del self._lock_counts[resource_id]
                
                self._metrics["releases"] += 1
            
            logger.debug(
                "lock_released",
                resource_id=resource_id,
                total_duration=time.time() - start_time
            )
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get lock manager metrics"""
        with self._global_lock:
            return {
                **self._metrics,
                "active_locks": len(self._lock_counts),
                "total_contentions": sum(self._lock_counts.values()) - len(self._lock_counts)
            }
    
    def cleanup_stale_locks(self, max_age_seconds: int = 3600) -> int:
        """Clean up stale lock files older than max_age_seconds"""
        cleaned = 0
        current_time = time.time()
        
        for lock_file in self.lock_dir.glob("*.lock"):
            try:
                # Check if file is old enough
                if current_time - lock_file.stat().st_mtime > max_age_seconds:
                    # Try to acquire exclusive lock (non-blocking)
                    with open(lock_file, 'r+') as f:
                        try:
                            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                            # If we got the lock, the file is not in use
                            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                            lock_file.unlink()
                            cleaned += 1
                        except IOError:
                            # Lock is in use, skip
                            pass
            except Exception as e:
                logger.warning(
                    "stale_lock_cleanup_failed",
                    file=str(lock_file),
                    error=str(e)
                )
        
        if cleaned > 0:
            logger.info("stale_locks_cleaned", count=cleaned)
        
        return cleaned


class OperationQueue:
    """Queue for managing conflicting operations"""
    
    def __init__(self, max_queue_size: int = 100):
        self.max_queue_size = max_queue_size
        self._queues: Dict[str, list] = defaultdict(list)
        self._lock = threading.Lock()
        self._conditions: Dict[str, threading.Condition] = defaultdict(
            lambda: threading.Condition(self._lock)
        )
    
    def enqueue(
        self,
        resource_id: str,
        operation: Callable,
        priority: int = 0
    ) -> None:
        """Add an operation to the queue"""
        with self._lock:
            queue = self._queues[resource_id]
            
            if len(queue) >= self.max_queue_size:
                raise ConflictError(f"Operation queue full for {resource_id}")
            
            # Insert based on priority (higher priority first)
            insert_pos = len(queue)
            for i, (_, p) in enumerate(queue):
                if priority > p:
                    insert_pos = i
                    break
            
            queue.insert(insert_pos, (operation, priority))
            self._conditions[resource_id].notify()
            
            logger.debug(
                "operation_enqueued",
                resource_id=resource_id,
                priority=priority,
                queue_size=len(queue)
            )
    
    def dequeue(
        self,
        resource_id: str,
        timeout: Optional[float] = None
    ) -> Optional[Callable]:
        """Get the next operation from the queue"""
        with self._lock:
            condition = self._conditions[resource_id]
            queue = self._queues[resource_id]
            
            # Wait for an operation to be available
            if not queue:
                if not condition.wait(timeout):
                    return None
            
            if queue:
                operation, _ = queue.pop(0)
                
                # Clean up if queue is empty
                if not queue:
                    del self._queues[resource_id]
                    del self._conditions[resource_id]
                
                logger.debug(
                    "operation_dequeued",
                    resource_id=resource_id,
                    remaining=len(queue)
                )
                
                return operation
            
            return None
    
    def get_queue_size(self, resource_id: str) -> int:
        """Get the size of a specific queue"""
        with self._lock:
            return len(self._queues.get(resource_id, []))
    
    def get_all_queue_sizes(self) -> Dict[str, int]:
        """Get sizes of all queues"""
        with self._lock:
            return {rid: len(queue) for rid, queue in self._queues.items()}


class RetryManager:
    """Manages retry logic with exponential backoff"""
    
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        exponential_base: float = 2.0
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
    
    def execute_with_retry(
        self,
        operation: Callable,
        operation_name: str = "operation",
        should_retry: Optional[Callable[[Exception], bool]] = None
    ) -> Any:
        """Execute an operation with retry logic"""
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                result = operation()
                
                if attempt > 0:
                    logger.info(
                        "operation_succeeded_after_retry",
                        operation=operation_name,
                        attempt=attempt
                    )
                
                return result
                
            except Exception as e:
                last_exception = e
                
                # Check if we should retry
                if should_retry and not should_retry(e):
                    raise
                
                if attempt < self.max_retries:
                    # Calculate delay with exponential backoff
                    delay = min(
                        self.base_delay * (self.exponential_base ** attempt),
                        self.max_delay
                    )
                    
                    logger.warning(
                        "operation_retry",
                        operation=operation_name,
                        attempt=attempt + 1,
                        max_retries=self.max_retries,
                        delay=delay,
                        error=str(e)
                    )
                    
                    time.sleep(delay)
                else:
                    logger.error(
                        "operation_failed_after_retries",
                        operation=operation_name,
                        attempts=self.max_retries + 1,
                        error=str(e)
                    )
        
        raise last_exception


class ConcurrentOperationManager:
    """High-level manager for concurrent operations"""
    
    def __init__(self):
        self.lock_manager = LockManager()
        self.operation_queue = OperationQueue()
        self.retry_manager = RetryManager()
    
    @contextmanager
    def execute_exclusive(
        self,
        resource_id: str,
        timeout: float = 30.0
    ):
        """Execute an operation with exclusive access to a resource"""
        with self.lock_manager.acquire_lock(resource_id, timeout=timeout, exclusive=True):
            yield
    
    @contextmanager
    def execute_shared(
        self,
        resource_id: str,
        timeout: float = 30.0
    ):
        """Execute an operation with shared access to a resource"""
        with self.lock_manager.acquire_lock(resource_id, timeout=timeout, exclusive=False):
            yield
    
    def execute_with_retry(
        self,
        operation: Callable,
        operation_name: str = "operation",
        resource_id: Optional[str] = None,
        exclusive: bool = True
    ) -> Any:
        """Execute an operation with retry and optional locking"""
        def wrapped_operation():
            if resource_id:
                if exclusive:
                    with self.execute_exclusive(resource_id):
                        return operation()
                else:
                    with self.execute_shared(resource_id):
                        return operation()
            else:
                return operation()
        
        # Retry on lock conflicts
        def should_retry(e: Exception) -> bool:
            return isinstance(e, ConflictError)
        
        return self.retry_manager.execute_with_retry(
            wrapped_operation,
            operation_name,
            should_retry
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about concurrent operations"""
        return {
            "locks": self.lock_manager.get_metrics(),
            "queues": self.operation_queue.get_all_queue_sizes()
        }


# Global instance for application-wide use
concurrent_ops = ConcurrentOperationManager()