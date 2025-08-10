"""Git operation metrics tracking"""

import time
import os
from typing import Optional, Dict, Any
from pathlib import Path
import asyncio

from src.infrastructure.metrics import (
    git_operations_total,
    git_pack_objects_bytes,
    git_negotiation_rounds,
    repository_size_bytes,
    git_operation_duration_seconds,
    git_ref_advertisement_duration_seconds,
    git_object_enumeration_duration_seconds,
    MetricsContext
)
from src.infrastructure.logging import get_logger

logger = get_logger(__name__)


class GitMetricsTracker:
    """Track metrics for Git operations"""
    
    def __init__(self):
        self.operation_start_times: Dict[str, float] = {}
        self.negotiation_counts: Dict[str, int] = {}
    
    def start_operation(
        self,
        operation_id: str,
        operation_type: str,
        namespace: str,
        repository: str
    ) -> None:
        """Start tracking a Git operation"""
        self.operation_start_times[operation_id] = time.time()
        self.negotiation_counts[operation_id] = 0
        
        logger.info(
            "git_operation_started",
            operation_id=operation_id,
            operation_type=operation_type,
            namespace=namespace,
            repository=repository
        )
    
    def end_operation(
        self,
        operation_id: str,
        operation_type: str,
        namespace: str,
        repository: str,
        success: bool = True,
        pack_size: Optional[int] = None
    ) -> None:
        """End tracking a Git operation"""
        
        # Calculate duration
        start_time = self.operation_start_times.pop(operation_id, None)
        if start_time:
            duration = time.time() - start_time
            git_operation_duration_seconds.labels(
                operation=operation_type,
                namespace=namespace,
                repository=repository
            ).observe(duration)
        
        # Record operation counter
        git_operations_total.labels(
            operation=operation_type,
            namespace=namespace,
            repository=repository,
            status="success" if success else "failure"
        ).inc()
        
        # Record pack size if provided
        if pack_size is not None:
            git_pack_objects_bytes.labels(
                operation=operation_type,
                namespace=namespace,
                repository=repository
            ).observe(pack_size)
        
        # Record negotiation rounds
        negotiation_count = self.negotiation_counts.pop(operation_id, 0)
        if negotiation_count > 0:
            for _ in range(negotiation_count):
                git_negotiation_rounds.labels(
                    operation=operation_type,
                    namespace=namespace,
                    repository=repository
                ).inc()
        
        logger.info(
            "git_operation_completed",
            operation_id=operation_id,
            operation_type=operation_type,
            namespace=namespace,
            repository=repository,
            success=success,
            duration_seconds=duration if start_time else None,
            pack_size=pack_size,
            negotiation_rounds=negotiation_count
        )
    
    def track_negotiation_round(self, operation_id: str) -> None:
        """Track a pack negotiation round"""
        if operation_id in self.negotiation_counts:
            self.negotiation_counts[operation_id] += 1
    
    def track_ref_advertisement(
        self,
        namespace: str,
        repository: str,
        duration: float
    ) -> None:
        """Track ref advertisement duration"""
        git_ref_advertisement_duration_seconds.labels(
            namespace=namespace,
            repository=repository
        ).observe(duration)
    
    def track_object_enumeration(
        self,
        operation_type: str,
        namespace: str,
        repository: str,
        duration: float
    ) -> None:
        """Track object enumeration duration"""
        git_object_enumeration_duration_seconds.labels(
            operation=operation_type,
            namespace=namespace,
            repository=repository
        ).observe(duration)
    
    async def update_repository_size(
        self,
        namespace: str,
        repository: str,
        repo_path: Path
    ) -> None:
        """Update repository size metric"""
        try:
            # Calculate repository size
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(repo_path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total_size += os.path.getsize(filepath)
                    except (OSError, IOError):
                        pass
            
            # Update metric
            repository_size_bytes.labels(
                namespace=namespace,
                repository=repository
            ).set(total_size)
            
            logger.debug(
                "repository_size_updated",
                namespace=namespace,
                repository=repository,
                size_bytes=total_size
            )
            
        except Exception as e:
            logger.error(
                "repository_size_update_failed",
                namespace=namespace,
                repository=repository,
                error=str(e)
            )


# Global tracker instance
git_metrics = GitMetricsTracker()


class GitOperationMetrics:
    """Context manager for tracking Git operation metrics"""
    
    def __init__(
        self,
        operation_type: str,
        namespace: str,
        repository: str,
        operation_id: Optional[str] = None
    ):
        self.operation_type = operation_type
        self.namespace = namespace
        self.repository = repository
        self.operation_id = operation_id or f"{operation_type}_{time.time()}"
        self.success = True
        self.pack_size = None
    
    def __enter__(self):
        git_metrics.start_operation(
            self.operation_id,
            self.operation_type,
            self.namespace,
            self.repository
        )
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Mark as failure if exception occurred
        if exc_type is not None:
            self.success = False
        
        git_metrics.end_operation(
            self.operation_id,
            self.operation_type,
            self.namespace,
            self.repository,
            success=self.success,
            pack_size=self.pack_size
        )
    
    async def __aenter__(self):
        git_metrics.start_operation(
            self.operation_id,
            self.operation_type,
            self.namespace,
            self.repository
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # Mark as failure if exception occurred
        if exc_type is not None:
            self.success = False
        
        git_metrics.end_operation(
            self.operation_id,
            self.operation_type,
            self.namespace,
            self.repository,
            success=self.success,
            pack_size=self.pack_size
        )
    
    def set_pack_size(self, size: int) -> None:
        """Set the pack file size"""
        self.pack_size = size
    
    def track_negotiation(self) -> None:
        """Track a negotiation round"""
        git_metrics.track_negotiation_round(self.operation_id)


class RefAdvertisementMetrics:
    """Context manager for tracking ref advertisement metrics"""
    
    def __init__(self, namespace: str, repository: str):
        self.namespace = namespace
        self.repository = repository
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = time.time() - self.start_time
            git_metrics.track_ref_advertisement(
                self.namespace,
                self.repository,
                duration
            )
    
    async def __aenter__(self):
        self.start_time = time.time()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = time.time() - self.start_time
            git_metrics.track_ref_advertisement(
                self.namespace,
                self.repository,
                duration
            )


class ObjectEnumerationMetrics:
    """Context manager for tracking object enumeration metrics"""
    
    def __init__(
        self,
        operation_type: str,
        namespace: str,
        repository: str
    ):
        self.operation_type = operation_type
        self.namespace = namespace
        self.repository = repository
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = time.time() - self.start_time
            git_metrics.track_object_enumeration(
                self.operation_type,
                self.namespace,
                self.repository,
                duration
            )
    
    async def __aenter__(self):
        self.start_time = time.time()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = time.time() - self.start_time
            git_metrics.track_object_enumeration(
                self.operation_type,
                self.namespace,
                self.repository,
                duration
            )