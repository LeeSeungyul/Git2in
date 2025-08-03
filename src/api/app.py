"""FastAPI application setup and configuration."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import structlog

from src.api.routes import health, auth, users, repositories, git_http
from src.api.middleware.error_handler import ErrorHandlerMiddleware
from src.api.middleware.logging import LoggingMiddleware
from src.api.middleware.auth import AuthenticationMiddleware
from src.api.middleware.rate_limit import RateLimitMiddleware
from src.api.models.common_models import ErrorResponse
from src.config.settings import Settings
from src.infrastructure.database import DatabaseConnection

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Application lifespan manager."""
    # Startup
    logger.info("Starting Git2in API server")
    
    # Initialize database
    from src.config.settings import settings
    db_connection = DatabaseConnection(settings.database_url)
    
    # Create tables if needed
    try:
        async with db_connection.get_engine().begin() as conn:
            from src.infrastructure.database.models import Base
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database initialized")
    except Exception as e:
        logger.error("Failed to initialize database", error=str(e))
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down Git2in API server")
    
    # Close database connections
    await db_connection.close()


def create_app(settings: Settings) -> FastAPI:
    """Create and configure FastAPI application."""
    # Create FastAPI app
    app = FastAPI(
        title="Git2in API",
        description="A Git server implementation with user management and repository hosting",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan
    )
    
    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure based on your needs
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=[
            "X-Request-Id",
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining", 
            "X-RateLimit-Reset"
        ]
    )
    
    # Add custom middleware in reverse order (last added = first executed)
    app.add_middleware(ErrorHandlerMiddleware)
    app.add_middleware(RateLimitMiddleware, settings=settings)
    app.add_middleware(AuthenticationMiddleware, settings=settings)
    app.add_middleware(LoggingMiddleware)
    
    # Include routers
    app.include_router(
        health.router,
        prefix="/api/v1",
        tags=["health"]
    )
    
    app.include_router(
        auth.router,
        prefix="/api/v1",
        tags=["authentication"]
    )
    
    app.include_router(
        users.router,
        prefix="/api/v1",
        tags=["users"]
    )
    
    app.include_router(
        repositories.router,
        prefix="/api/v1",
        tags=["repositories"]
    )
    
    # Git HTTP routes don't use /api/v1 prefix
    app.include_router(
        git_http.router,
        tags=["git"]
    )
    
    # Root endpoint
    @app.get("/", include_in_schema=False)
    async def root():
        """Root endpoint."""
        return {
            "name": "Git2in",
            "version": "1.0.0",
            "description": "Git server with user management",
            "docs": "/docs"
        }
    
    # Custom 404 handler
    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc):
        """Handle 404 errors."""
        return JSONResponse(
            status_code=404,
            content=ErrorResponse(
                error="NOT_FOUND",
                message=f"The requested URL {request.url.path} was not found",
                request_id=getattr(request.state, 'request_id', None)
            ).model_dump()
        )
    
    # Custom 405 handler
    @app.exception_handler(405)
    async def method_not_allowed_handler(request: Request, exc):
        """Handle 405 errors."""
        return JSONResponse(
            status_code=405,
            content=ErrorResponse(
                error="METHOD_NOT_ALLOWED",
                message=f"Method {request.method} not allowed for {request.url.path}",
                request_id=getattr(request.state, 'request_id', None)
            ).model_dump()
        )
    
    return app


# Create app instance
from src.config.settings import settings
app = create_app(settings)