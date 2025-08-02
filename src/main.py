"""Git2in - A minimal Git repository backend service.

This module provides the main FastAPI application for Git2in, a minimal
Git repository backend service with HTTP support.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator, Dict

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import structlog

from src.config.settings import settings

# Configure structured logging
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.make_filtering_bound_logger(settings.log_level),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application lifespan events.
    
    This context manager handles startup and shutdown events for the
    FastAPI application, replacing the deprecated @app.on_event decorators.
    
    Args:
        app: The FastAPI application instance.
        
    Yields:
        None: Control back to FastAPI during application runtime.
    """
    # Startup
    logger.info(
        "Starting Git2in application", 
        app_name=settings.app_name,
        debug=settings.debug,
        log_level=settings.log_level
    )
    
    # Ensure repository directory exists
    settings.repos_path.mkdir(parents=True, exist_ok=True)
    logger.info("Repository directory initialized", path=str(settings.repos_path))
    
    yield
    
    # Shutdown
    logger.info("Shutting down Git2in application")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    description="A minimal Git repository backend service",
    version="0.1.0",
    debug=settings.debug,
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root() -> Dict[str, str]:
    """Root endpoint providing basic service information.
    
    Returns:
        Dict[str, str]: A dictionary containing service information including
            message, version, and status.
    """
    return {
        "message": "Welcome to Git2in",
        "version": "0.1.0",
        "status": "running"
    }


@app.get("/health")
async def health_check() -> Dict[str, str]:
    """Health check endpoint for monitoring service status.
    
    This endpoint is typically used by load balancers and monitoring
    systems to verify the service is responsive.
    
    Returns:
        Dict[str, str]: A dictionary containing the health status and
            service name.
    """
    return {
        "status": "healthy",
        "service": settings.app_name
    }


if __name__ == "__main__":
    import uvicorn
    
    # Convert log level to string for uvicorn
    # Note: uvicorn expects lowercase log level names
    log_level_name = {
        10: "debug",
        20: "info",
        30: "warning",
        40: "error",
        50: "critical"
    }.get(settings.log_level, "info")
    
    uvicorn.run(
        "src.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=log_level_name
    )