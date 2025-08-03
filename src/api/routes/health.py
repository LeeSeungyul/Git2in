"""Health check endpoints."""

from datetime import datetime
import time
import subprocess
from typing import Dict, Any

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import structlog

from src.api.dependencies import get_db, get_settings_dep
from src.api.models.common_models import HealthResponse, ReadinessResponse, HealthStatus
from src.config.settings import Settings

logger = structlog.get_logger()
router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Basic health check endpoint that returns service status and version",
    tags=["health"]
)
async def health_check(settings: Settings = Depends(get_settings_dep)) -> HealthResponse:
    """Basic health check endpoint."""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.utcnow(),
        version="1.0.0"
    )


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Readiness check",
    description="Check if service is ready to handle requests by verifying all dependencies",
    tags=["health"],
    responses={
        200: {"description": "Service is ready"},
        503: {"description": "Service is not ready"}
    }
)
async def readiness_check(
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings_dep)
) -> ReadinessResponse:
    """Readiness check including all service dependencies."""
    checks = {}
    all_ready = True
    
    # Check database connectivity
    db_start = time.time()
    try:
        await db.execute(text("SELECT 1"))
        db_time = int((time.time() - db_start) * 1000)
        checks["database"] = HealthStatus(
            status="healthy",
            response_time_ms=db_time
        )
    except Exception as e:
        logger.error("Database check failed", error=str(e))
        checks["database"] = HealthStatus(
            status="unhealthy",
            details={"error": str(e)}
        )
        all_ready = False
    
    # Check filesystem access
    fs_start = time.time()
    try:
        repos_path = settings.repos_path
        if not repos_path.exists():
            repos_path.mkdir(parents=True, exist_ok=True)
        
        # Try to write a test file
        test_file = repos_path / ".health_check"
        test_file.write_text("OK")
        test_file.unlink()
        
        fs_time = int((time.time() - fs_start) * 1000)
        checks["filesystem"] = HealthStatus(
            status="healthy",
            response_time_ms=fs_time,
            details={"repos_path": str(repos_path)}
        )
    except Exception as e:
        logger.error("Filesystem check failed", error=str(e))
        checks["filesystem"] = HealthStatus(
            status="unhealthy",
            details={"error": str(e)}
        )
        all_ready = False
    
    # Check Git binary availability
    git_start = time.time()
    try:
        result = subprocess.run(
            [settings.git_binary_path, "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            git_version = result.stdout.strip()
            git_time = int((time.time() - git_start) * 1000)
            checks["git"] = HealthStatus(
                status="healthy",
                response_time_ms=git_time,
                details={"version": git_version}
            )
        else:
            checks["git"] = HealthStatus(
                status="unhealthy",
                details={"error": result.stderr}
            )
            all_ready = False
    except Exception as e:
        logger.error("Git check failed", error=str(e))
        checks["git"] = HealthStatus(
            status="unhealthy",
            details={"error": str(e)}
        )
        all_ready = False
    
    # Build response
    response = HealthResponse(
        status="healthy" if all_ready else "unhealthy",
        timestamp=datetime.utcnow(),
        version="1.0.0",
        checks=checks
    )
    
    # Return appropriate status code
    if not all_ready:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=response.model_dump()
        )
    
    return response


@router.get(
    "/alive",
    status_code=status.HTTP_200_OK,
    summary="Liveness check",
    description="Simple liveness probe that returns 200 OK if the service is running",
    tags=["health"],
    response_description="Service is alive"
)
async def liveness_check():
    """Simple liveness probe endpoint."""
    return {"status": "alive"}