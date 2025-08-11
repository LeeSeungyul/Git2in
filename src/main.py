from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException as StarletteHTTPException

from src.api import health, metrics_endpoint
from src.api.exception_handlers import (base_api_exception_handler,
                                        general_exception_handler,
                                        http_exception_handler,
                                        validation_exception_handler)
from src.api.router import api_router
from src.api.v1.middleware.rate_limit import limiter
from src.api.v1.router import get_openapi_config
from src.core.auth.revocation import revocation_manager
from src.core.auth.storage import token_storage
from src.core.config import settings
from src.core.exceptions import BaseAPIException
from src.infrastructure.audit.logger import audit_logger
from src.infrastructure.audit.rotation import audit_rotation_manager
from src.infrastructure.logging import get_logger, setup_logging
from src.infrastructure.middleware.correlation import CorrelationIDMiddleware
from src.infrastructure.middleware.ip_filter import IPFilterMiddleware
from src.infrastructure.middleware.logging import LoggingMiddleware
from src.infrastructure.middleware.metrics import MetricsMiddleware

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    logger.info(
        "application_startup",
        app_name=settings.app_name,
        environment=settings.environment,
        repository_base_path=str(settings.repository_base_path),
    )

    # Start background cleanup tasks
    await revocation_manager.start_cleanup_task()
    await token_storage.start_cleanup_task()
    await audit_logger.start()
    await audit_rotation_manager.start()

    yield

    # Stop cleanup tasks on shutdown
    await revocation_manager.stop_cleanup_task()
    await token_storage.stop_cleanup_task()
    await audit_logger.stop()
    await audit_rotation_manager.stop()

    logger.info("application_shutdown", app_name=settings.app_name)


# Get OpenAPI configuration
openapi_config = get_openapi_config()

app = FastAPI(
    title=openapi_config["title"],
    description=openapi_config["description"],
    version=openapi_config["version"],
    contact=openapi_config.get("contact"),
    license_info=openapi_config.get("license"),
    servers=openapi_config.get("servers"),
    lifespan=lifespan,
)

# Add rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(LoggingMiddleware)
app.add_middleware(MetricsMiddleware)
app.add_middleware(CorrelationIDMiddleware)
app.add_middleware(IPFilterMiddleware, enabled=settings.is_production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_exception_handler(BaseAPIException, base_api_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(Exception, general_exception_handler)


@app.get("/", response_model=Dict[str, Any])
async def root():
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "description": "Self-hosted Git repository manager",
        "status": "running",
        "environment": settings.environment,
        "endpoints": {
            "api": settings.api_prefix,
            "docs": "/docs",
            "redoc": "/redoc",
            "health": "/health",
            "metrics": "/metrics",
        },
    }


# Include health endpoints at root level (no prefix)
app.include_router(health.router)

# Include metrics endpoints at root level (no prefix)
app.include_router(metrics_endpoint.router)

# Include API routes with prefix
app.include_router(api_router, prefix=settings.api_prefix)
