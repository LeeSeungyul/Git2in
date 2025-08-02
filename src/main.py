"""Git2in - A minimal Git repository backend service"""

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

# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    description="A minimal Git repository backend service",
    version="0.1.0",
    debug=settings.debug,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    logger.info("Starting Git2in application", 
                app_name=settings.app_name,
                debug=settings.debug,
                log_level=settings.log_level)
    
    # Ensure repository directory exists
    settings.repos_path.mkdir(parents=True, exist_ok=True)
    logger.info("Repository directory initialized", path=str(settings.repos_path))

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on application shutdown"""
    logger.info("Shutting down Git2in application")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Welcome to Git2in",
        "version": "0.1.0",
        "status": "running"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": settings.app_name
    }

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "src.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )