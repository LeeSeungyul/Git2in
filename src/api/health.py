"""Health and readiness check endpoints"""

import os
import time
import subprocess
import psutil
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime
from fastapi import APIRouter, HTTPException, status

from src.core.config import settings
from src.infrastructure.logging import get_logger
from src.infrastructure.metrics import health_check_status

logger = get_logger(__name__)

router = APIRouter(tags=["health"])


class HealthChecker:
    """Service health checking utilities"""
    
    def __init__(self):
        self.start_time = time.time()
    
    def check_filesystem(self) -> tuple[bool, str]:
        """Check filesystem access"""
        try:
            # Check if repository base path exists and is writable
            base_path = Path(settings.repository_base_path)
            if not base_path.exists():
                return False, "Repository base path does not exist"
            
            # Try to create a test file
            test_file = base_path / f".health_check_{os.getpid()}"
            try:
                test_file.touch()
                test_file.unlink()
                return True, "Filesystem is accessible"
            except Exception as e:
                return False, f"Cannot write to filesystem: {str(e)}"
                
        except Exception as e:
            return False, f"Filesystem check failed: {str(e)}"
    
    def check_git_binary(self) -> tuple[bool, str]:
        """Check if git binary is available"""
        try:
            result = subprocess.run(
                ["git", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                return True, version
            else:
                return False, "Git binary returned non-zero exit code"
        except FileNotFoundError:
            return False, "Git binary not found"
        except subprocess.TimeoutExpired:
            return False, "Git binary check timed out"
        except Exception as e:
            return False, f"Git binary check failed: {str(e)}"
    
    def check_disk_space(self, min_free_gb: float = 1.0) -> tuple[bool, str]:
        """Check available disk space"""
        try:
            base_path = Path(settings.repository_base_path)
            stat = os.statvfs(base_path)
            
            # Calculate free space in GB
            free_gb = (stat.f_bavail * stat.f_frsize) / (1024 ** 3)
            
            if free_gb < min_free_gb:
                return False, f"Low disk space: {free_gb:.2f} GB free"
            
            return True, f"Disk space OK: {free_gb:.2f} GB free"
            
        except Exception as e:
            return False, f"Disk space check failed: {str(e)}"
    
    def check_memory(self, max_usage_percent: float = 90.0) -> tuple[bool, str]:
        """Check memory usage"""
        try:
            memory = psutil.virtual_memory()
            
            if memory.percent > max_usage_percent:
                return False, f"High memory usage: {memory.percent:.1f}%"
            
            return True, f"Memory OK: {memory.percent:.1f}% used"
            
        except Exception as e:
            return False, f"Memory check failed: {str(e)}"
    
    def get_uptime(self) -> float:
        """Get service uptime in seconds"""
        return time.time() - self.start_time


# Global health checker instance
health_checker = HealthChecker()


@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """
    Basic health check endpoint
    
    Returns 200 if service is alive, regardless of dependency status
    """
    response_time_start = time.time()
    
    response = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "git2in",
        "version": settings.app_version,
        "environment": settings.environment,
        "uptime_seconds": health_checker.get_uptime(),
        "response_time_ms": round((time.time() - response_time_start) * 1000, 2)
    }
    
    # Update metric
    health_check_status.labels(check_type="liveness").set(1)
    
    logger.debug("health_check", **response)
    
    return response


@router.get("/ready")
async def readiness_check() -> Dict[str, Any]:
    """
    Readiness check endpoint
    
    Checks if all critical dependencies are available.
    Returns 503 if any critical check fails.
    """
    response_time_start = time.time()
    
    checks = {}
    all_healthy = True
    
    # Check filesystem
    fs_healthy, fs_message = health_checker.check_filesystem()
    checks["filesystem"] = {
        "healthy": fs_healthy,
        "message": fs_message
    }
    if not fs_healthy:
        all_healthy = False
    
    # Check git binary
    git_healthy, git_message = health_checker.check_git_binary()
    checks["git_binary"] = {
        "healthy": git_healthy,
        "message": git_message
    }
    if not git_healthy:
        all_healthy = False
    
    # Check disk space (warning only, not critical)
    disk_healthy, disk_message = health_checker.check_disk_space()
    checks["disk_space"] = {
        "healthy": disk_healthy,
        "message": disk_message,
        "warning": not disk_healthy
    }
    
    # Check memory (warning only, not critical)
    mem_healthy, mem_message = health_checker.check_memory()
    checks["memory"] = {
        "healthy": mem_healthy,
        "message": mem_message,
        "warning": not mem_healthy
    }
    
    response = {
        "status": "ready" if all_healthy else "not_ready",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "git2in",
        "version": settings.app_version,
        "environment": settings.environment,
        "uptime_seconds": health_checker.get_uptime(),
        "checks": checks,
        "response_time_ms": round((time.time() - response_time_start) * 1000, 2)
    }
    
    # Update metric
    health_check_status.labels(check_type="readiness").set(1 if all_healthy else 0)
    
    if not all_healthy:
        logger.warning("readiness_check_failed", **response)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=response
        )
    
    logger.debug("readiness_check", **response)
    
    return response


@router.get("/health/detailed")
async def detailed_health_check() -> Dict[str, Any]:
    """
    Detailed health check with all system information
    
    This endpoint provides comprehensive system status.
    Should be protected in production.
    """
    response_time_start = time.time()
    
    # Get all checks
    checks = {}
    
    # Filesystem check
    fs_healthy, fs_message = health_checker.check_filesystem()
    checks["filesystem"] = {
        "healthy": fs_healthy,
        "message": fs_message
    }
    
    # Git binary check
    git_healthy, git_message = health_checker.check_git_binary()
    checks["git_binary"] = {
        "healthy": git_healthy,
        "message": git_message
    }
    
    # Disk space check
    disk_healthy, disk_message = health_checker.check_disk_space()
    checks["disk_space"] = {
        "healthy": disk_healthy,
        "message": disk_message
    }
    
    # Memory check
    mem_healthy, mem_message = health_checker.check_memory()
    checks["memory"] = {
        "healthy": mem_healthy,
        "message": mem_message
    }
    
    # System information
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage(settings.repository_base_path)
        
        system_info = {
            "cpu": {
                "count": psutil.cpu_count(),
                "usage_percent": cpu_percent
            },
            "memory": {
                "total_gb": round(memory.total / (1024 ** 3), 2),
                "available_gb": round(memory.available / (1024 ** 3), 2),
                "used_gb": round(memory.used / (1024 ** 3), 2),
                "percent": memory.percent
            },
            "disk": {
                "total_gb": round(disk.total / (1024 ** 3), 2),
                "free_gb": round(disk.free / (1024 ** 3), 2),
                "used_gb": round(disk.used / (1024 ** 3), 2),
                "percent": disk.percent
            },
            "process": {
                "pid": os.getpid(),
                "threads": psutil.Process().num_threads(),
                "connections": len(psutil.Process().connections())
            }
        }
    except Exception as e:
        system_info = {"error": str(e)}
    
    # Configuration info (non-sensitive)
    config_info = {
        "environment": settings.environment,
        "log_level": settings.log_level,
        "log_format": settings.log_format,
        "repository_base_path": str(settings.repository_base_path),
        "cors_enabled": bool(settings.cors_allow_origins)
    }
    
    response = {
        "status": "healthy" if all(c.get("healthy", False) for c in checks.values() if not c.get("warning")) else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "git2in",
        "version": settings.app_version,
        "uptime_seconds": health_checker.get_uptime(),
        "checks": checks,
        "system": system_info,
        "configuration": config_info,
        "response_time_ms": round((time.time() - response_time_start) * 1000, 2)
    }
    
    logger.debug("detailed_health_check", **response)
    
    return response