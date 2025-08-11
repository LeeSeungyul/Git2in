"""Audit log rotation and retention management"""

import asyncio
import gzip
import logging
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.core.config import settings
from src.infrastructure.logging import get_logger

logger = get_logger(__name__)


class LogRotationConfig:
    """Configuration for log rotation and retention"""

    def __init__(
        self,
        retention_days: int = 90,
        compression_enabled: bool = True,
        archive_after_days: int = 30,
        max_size_mb: int = 100,
        max_total_size_gb: int = 10,
    ):
        self.retention_days = retention_days
        self.compression_enabled = compression_enabled
        self.archive_after_days = archive_after_days
        self.max_size_mb = max_size_mb
        self.max_total_size_gb = max_total_size_gb

    @classmethod
    def from_environment(cls) -> "LogRotationConfig":
        """Create config from environment settings"""
        config = cls()

        # Override from settings if available
        if hasattr(settings, "audit_retention_days"):
            config.retention_days = settings.audit_retention_days

        # Different retention for different environments
        if settings.is_production:
            config.retention_days = 365  # 1 year for production
            config.archive_after_days = 90
        elif settings.is_development:
            config.retention_days = 7  # 1 week for development
            config.archive_after_days = 3

        return config


class AuditLogRotationManager:
    """Manages audit log rotation, compression, and cleanup"""

    def __init__(self, config: Optional[LogRotationConfig] = None):
        self.config = config or LogRotationConfig.from_environment()
        self.log_dir = Path("logs/audit")
        self.archive_dir = Path("logs/audit/archive")
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self):
        """Start the rotation manager"""
        if not self._running:
            self._running = True
            self.log_dir.mkdir(parents=True, exist_ok=True)
            self.archive_dir.mkdir(parents=True, exist_ok=True)
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.info("audit_log_rotation_started")

    async def stop(self):
        """Stop the rotation manager"""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            logger.info("audit_log_rotation_stopped")

    async def _cleanup_loop(self):
        """Background task for periodic cleanup"""
        while self._running:
            try:
                # Run cleanup daily at 2 AM
                now = datetime.now()
                next_run = now.replace(hour=2, minute=0, second=0, microsecond=0)
                if next_run <= now:
                    next_run += timedelta(days=1)

                wait_seconds = (next_run - now).total_seconds()
                await asyncio.sleep(wait_seconds)

                if self._running:
                    await self.perform_cleanup()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("audit_log_cleanup_error", error=str(e))
                # Wait an hour before retrying
                await asyncio.sleep(3600)

    async def perform_cleanup(self):
        """Perform log cleanup operations"""
        logger.info("audit_log_cleanup_starting")

        try:
            # Compress old logs
            compressed_count = await self.compress_old_logs()

            # Archive old compressed logs
            archived_count = await self.archive_old_logs()

            # Remove expired logs
            removed_count = await self.remove_expired_logs()

            # Check disk usage
            await self.check_disk_usage()

            logger.info(
                "audit_log_cleanup_completed",
                compressed=compressed_count,
                archived=archived_count,
                removed=removed_count,
            )

        except Exception as e:
            logger.error("audit_log_cleanup_failed", error=str(e))

    async def compress_old_logs(self) -> int:
        """Compress logs older than configured days"""
        if not self.config.compression_enabled:
            return 0

        compressed = 0
        cutoff_date = datetime.now() - timedelta(days=1)  # Compress yesterday's logs

        for log_file in self.log_dir.glob("audit.log.*"):
            # Skip already compressed files
            if log_file.suffix == ".gz":
                continue

            # Check file age
            stat = log_file.stat()
            file_time = datetime.fromtimestamp(stat.st_mtime)

            if file_time < cutoff_date:
                try:
                    # Compress file
                    compressed_path = log_file.with_suffix(log_file.suffix + ".gz")

                    with open(log_file, "rb") as f_in:
                        with gzip.open(compressed_path, "wb", compresslevel=9) as f_out:
                            shutil.copyfileobj(f_in, f_out)

                    # Remove original file
                    log_file.unlink()
                    compressed += 1

                    logger.debug(
                        "audit_log_compressed",
                        file=str(log_file),
                        compressed_file=str(compressed_path),
                    )

                except Exception as e:
                    logger.error(
                        "audit_log_compression_failed", file=str(log_file), error=str(e)
                    )

        return compressed

    async def archive_old_logs(self) -> int:
        """Move old compressed logs to archive directory"""
        if self.config.archive_after_days <= 0:
            return 0

        archived = 0
        cutoff_date = datetime.now() - timedelta(days=self.config.archive_after_days)

        for log_file in self.log_dir.glob("audit.log.*.gz"):
            # Check file age
            stat = log_file.stat()
            file_time = datetime.fromtimestamp(stat.st_mtime)

            if file_time < cutoff_date:
                try:
                    # Create year/month subdirectories in archive
                    year_month = file_time.strftime("%Y/%m")
                    archive_subdir = self.archive_dir / year_month
                    archive_subdir.mkdir(parents=True, exist_ok=True)

                    # Move to archive
                    archive_path = archive_subdir / log_file.name
                    shutil.move(str(log_file), str(archive_path))
                    archived += 1

                    logger.debug(
                        "audit_log_archived",
                        file=str(log_file),
                        archive_path=str(archive_path),
                    )

                except Exception as e:
                    logger.error(
                        "audit_log_archival_failed", file=str(log_file), error=str(e)
                    )

        return archived

    async def remove_expired_logs(self) -> int:
        """Remove logs older than retention period"""
        removed = 0
        cutoff_date = datetime.now() - timedelta(days=self.config.retention_days)

        # Check both main log dir and archive dir
        for base_dir in [self.log_dir, self.archive_dir]:
            for log_file in base_dir.rglob("audit.log.*"):
                # Check file age
                stat = log_file.stat()
                file_time = datetime.fromtimestamp(stat.st_mtime)

                if file_time < cutoff_date:
                    try:
                        log_file.unlink()
                        removed += 1

                        logger.debug(
                            "audit_log_removed",
                            file=str(log_file),
                            age_days=(datetime.now() - file_time).days,
                        )

                    except Exception as e:
                        logger.error(
                            "audit_log_removal_failed", file=str(log_file), error=str(e)
                        )

        return removed

    async def check_disk_usage(self):
        """Check and alert on disk usage"""
        total_size = 0
        file_count = 0

        # Calculate total size
        for base_dir in [self.log_dir, self.archive_dir]:
            for log_file in base_dir.rglob("audit.log.*"):
                stat = log_file.stat()
                total_size += stat.st_size
                file_count += 1

        total_size_gb = total_size / (1024**3)

        # Log current usage
        logger.info(
            "audit_log_disk_usage",
            total_size_gb=round(total_size_gb, 2),
            file_count=file_count,
            max_size_gb=self.config.max_total_size_gb,
        )

        # Alert if approaching limit
        if total_size_gb > self.config.max_total_size_gb * 0.9:
            logger.warning(
                "audit_log_disk_usage_high",
                total_size_gb=round(total_size_gb, 2),
                max_size_gb=self.config.max_total_size_gb,
                usage_percent=round(
                    (total_size_gb / self.config.max_total_size_gb) * 100, 1
                ),
            )

            # Remove oldest archived logs if over limit
            if total_size_gb > self.config.max_total_size_gb:
                await self._emergency_cleanup(
                    total_size_gb - self.config.max_total_size_gb
                )

    async def _emergency_cleanup(self, size_to_free_gb: float):
        """Emergency cleanup when disk usage is too high"""
        logger.warning(
            "audit_log_emergency_cleanup", size_to_free_gb=round(size_to_free_gb, 2)
        )

        # Get all archived files sorted by age
        archived_files = []
        for log_file in self.archive_dir.rglob("audit.log.*"):
            stat = log_file.stat()
            archived_files.append((log_file, stat.st_mtime, stat.st_size))

        # Sort by modification time (oldest first)
        archived_files.sort(key=lambda x: x[1])

        # Remove oldest files until we free enough space
        freed_size = 0
        removed_count = 0

        for log_file, _, size in archived_files:
            try:
                log_file.unlink()
                freed_size += size
                removed_count += 1

                if freed_size >= size_to_free_gb * (1024**3):
                    break

            except Exception as e:
                logger.error(
                    "emergency_cleanup_removal_failed", file=str(log_file), error=str(e)
                )

        logger.info(
            "audit_log_emergency_cleanup_completed",
            removed_count=removed_count,
            freed_size_gb=round(freed_size / (1024**3), 2),
        )

    def get_retention_policy(self) -> Dict[str, Any]:
        """Get current retention policy"""
        return {
            "retention_days": self.config.retention_days,
            "compression_enabled": self.config.compression_enabled,
            "archive_after_days": self.config.archive_after_days,
            "max_size_mb": self.config.max_size_mb,
            "max_total_size_gb": self.config.max_total_size_gb,
            "environment": settings.environment,
        }


# Global rotation manager instance
audit_rotation_manager = AuditLogRotationManager()
