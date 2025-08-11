"""API v1 router with OpenAPI configuration"""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from src.api.v1.middleware.rate_limit import (limiter,
                                              rate_limit_exceeded_handler)
from src.api.v1.routes import (namespaces_router, repositories_router,
                               tokens_router, users_router)

# Create v1 API router with OpenAPI tags
api_v1_router = APIRouter(
    prefix="",
    responses={
        400: {
            "description": "Bad Request",
            "content": {
                "application/json": {
                    "example": {
                        "success": False,
                        "error": "BAD_REQUEST",
                        "message": "Invalid request parameters",
                        "correlation_id": "abc123",
                    }
                }
            },
        },
        401: {
            "description": "Unauthorized",
            "content": {
                "application/json": {
                    "example": {
                        "success": False,
                        "error": "UNAUTHORIZED",
                        "message": "Authentication required",
                        "correlation_id": "abc123",
                    }
                }
            },
        },
        403: {
            "description": "Forbidden",
            "content": {
                "application/json": {
                    "example": {
                        "success": False,
                        "error": "FORBIDDEN",
                        "message": "Access denied",
                        "correlation_id": "abc123",
                    }
                }
            },
        },
        404: {
            "description": "Not Found",
            "content": {
                "application/json": {
                    "example": {
                        "success": False,
                        "error": "NOT_FOUND",
                        "message": "Resource not found",
                        "correlation_id": "abc123",
                    }
                }
            },
        },
        429: {
            "description": "Too Many Requests",
            "content": {
                "application/json": {
                    "example": {
                        "success": False,
                        "error": "RATE_LIMIT_EXCEEDED",
                        "message": "Rate limit exceeded. Retry after 60 seconds",
                        "correlation_id": "abc123",
                    }
                }
            },
        },
        500: {
            "description": "Internal Server Error",
            "content": {
                "application/json": {
                    "example": {
                        "success": False,
                        "error": "INTERNAL_ERROR",
                        "message": "An internal error occurred",
                        "correlation_id": "abc123",
                    }
                }
            },
        },
    },
)

# Include route modules
api_v1_router.include_router(namespaces_router)
api_v1_router.include_router(repositories_router)
api_v1_router.include_router(users_router)
api_v1_router.include_router(tokens_router)


@api_v1_router.get(
    "/",
    summary="API v1 Root",
    description="Get API v1 information and available endpoints",
    tags=["api"],
)
async def api_v1_root():
    """Get API v1 information"""
    return {
        "version": "1.0.0",
        "description": "Git2in Management REST API",
        "endpoints": {
            "namespaces": "/api/v1/namespaces",
            "repositories": "/api/v1/namespaces/{namespace}/repos",
            "users": "/api/v1/users",
            "tokens": "/api/v1/tokens",
            "auth": "/api/v1/auth",
        },
        "documentation": {"openapi": "/docs", "redoc": "/redoc"},
        "rate_limits": {
            "default": "1000 requests per hour",
            "authenticated": "5000 requests per hour",
            "description": "Rate limits are per user for authenticated requests, per IP for anonymous",
        },
    }


# OpenAPI metadata configuration
def get_openapi_config():
    """Get OpenAPI configuration for FastAPI app"""
    # Import settings locally to avoid circular imports
    try:
        from src.core.config import settings

        server_url = f"http://{settings.api_host}:{settings.api_port}"
    except Exception:
        # Fallback if settings fail to load
        server_url = "http://localhost:8000"

    return {
        "title": "Git2in API",
        "description": """
# Git2in Management REST API

Self-hosted Git repository manager with comprehensive REST API for managing namespaces, repositories, users, and access tokens.

## Features

- **Namespace Management**: Create and manage namespaces for organizing repositories
- **Repository CRUD**: Full repository lifecycle management with Git backend integration
- **User Management**: User registration, authentication, and profile management
- **Token Management**: API token creation, rotation, and revocation
- **Rate Limiting**: Configurable rate limits per endpoint and user role
- **Pagination**: Consistent pagination across all list endpoints
- **Error Handling**: Standardized error responses with correlation IDs

## Authentication

The API uses bearer token authentication. Include your API token in the Authorization header:

```
Authorization: Bearer <your-token>
```

## Rate Limiting

Rate limits are enforced per endpoint and user role:
- Anonymous: 1000 requests/hour
- Authenticated: 5000 requests/hour
- Admin: 10000 requests/hour

Rate limit headers are included in responses:
- `X-RateLimit-Limit`: Maximum requests allowed
- `X-RateLimit-Remaining`: Requests remaining
- `X-RateLimit-Reset`: Unix timestamp when limit resets
- `Retry-After`: Seconds to wait (on 429 responses)

## Pagination

List endpoints support pagination with these parameters:
- `page`: Page number (default: 1)
- `per_page`: Items per page (default: 20, max: 100)

Pagination metadata is returned in response and headers:
- `X-Total-Count`: Total number of items
- `X-Page`: Current page
- `X-Per-Page`: Items per page
- `Link`: RFC 5988 Link header with first, last, prev, next

## Error Responses

All errors follow a consistent format:

```json
{
  "success": false,
  "error": "ERROR_CODE",
  "message": "Human-readable error message",
  "details": [...],
  "correlation_id": "unique-request-id",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## API Versioning

The API is versioned via URL path. Current version: v1

Future versions will be available at `/api/v2`, `/api/v3`, etc.
        """,
        "version": "1.0.0",
        "contact": {"name": "Git2in Support", "email": "support@git2in.example.com"},
        "license": {"name": "MIT", "url": "https://opensource.org/licenses/MIT"},
        "servers": [{"url": server_url, "description": "Local development server"}],
        "tags": [
            {"name": "namespaces", "description": "Namespace management operations"},
            {"name": "repositories", "description": "Repository management operations"},
            {"name": "users", "description": "User management operations"},
            {"name": "tokens", "description": "API token management operations"},
            {"name": "authentication", "description": "Authentication operations"},
            {"name": "health", "description": "Health check endpoints"},
            {"name": "metrics", "description": "Metrics and monitoring"},
        ],
    }
