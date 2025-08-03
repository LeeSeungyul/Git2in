"""Global error handling middleware."""

from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException
import structlog
from datetime import datetime

from src.application.exceptions.service_exceptions import (
    ServiceError, ValidationError, NotFoundError,
    ConflictError, AuthenticationError, AuthorizationError,
    RateLimitError, ServiceUnavailableError
)
from src.api.models.common_models import ErrorResponse

logger = structlog.get_logger()


async def error_handler_middleware(request: Request, call_next):
    """Handle all exceptions and return consistent error responses."""
    try:
        response = await call_next(request)
        return response
    
    except RequestValidationError as e:
        # FastAPI validation errors
        request_id = getattr(request.state, 'request_id', None)
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error="VALIDATION_ERROR",
                message="Request validation failed",
                details={"errors": e.errors()},
                request_id=request_id
            ).model_dump()
        )
    
    except HTTPException as e:
        # FastAPI HTTP exceptions
        request_id = getattr(request.state, 'request_id', None)
        return JSONResponse(
            status_code=e.status_code,
            content=ErrorResponse(
                error="HTTP_ERROR",
                message=e.detail,
                request_id=request_id
            ).model_dump()
        )
    
    except ValidationError as e:
        # Application validation errors
        request_id = getattr(request.state, 'request_id', None)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                error="VALIDATION_ERROR",
                message=str(e),
                details={"errors": e.errors},
                request_id=request_id
            ).model_dump()
        )
    
    except NotFoundError as e:
        request_id = getattr(request.state, 'request_id', None)
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(
                error="NOT_FOUND",
                message=str(e),
                details=e.details,
                request_id=request_id
            ).model_dump()
        )
    
    except ConflictError as e:
        request_id = getattr(request.state, 'request_id', None)
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content=ErrorResponse(
                error="CONFLICT",
                message=str(e),
                details=e.details,
                request_id=request_id
            ).model_dump()
        )
    
    except AuthenticationError as e:
        request_id = getattr(request.state, 'request_id', None)
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=ErrorResponse(
                error="AUTHENTICATION_ERROR",
                message=str(e),
                request_id=request_id
            ).model_dump(),
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    except AuthorizationError as e:
        request_id = getattr(request.state, 'request_id', None)
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=ErrorResponse(
                error="AUTHORIZATION_ERROR",
                message=str(e),
                details=e.details,
                request_id=request_id
            ).model_dump()
        )
    
    except RateLimitError as e:
        request_id = getattr(request.state, 'request_id', None)
        headers = {}
        if e.retry_after:
            headers["Retry-After"] = str(e.retry_after)
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content=ErrorResponse(
                error="RATE_LIMITED",
                message=str(e),
                details={"retry_after": e.retry_after} if e.retry_after else None,
                request_id=request_id
            ).model_dump(),
            headers=headers
        )
    
    except ServiceUnavailableError as e:
        request_id = getattr(request.state, 'request_id', None)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=ErrorResponse(
                error="SERVICE_UNAVAILABLE",
                message=str(e),
                details=e.details,
                request_id=request_id
            ).model_dump()
        )
    
    except ServiceError as e:
        # General service errors
        request_id = getattr(request.state, 'request_id', None)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                error=e.error_code.value,
                message=str(e),
                details=e.details,
                request_id=request_id
            ).model_dump()
        )
    
    except Exception as e:
        # Unexpected errors
        request_id = getattr(request.state, 'request_id', None)
        logger.error(
            "Unhandled exception",
            error=str(e),
            request_id=request_id,
            exc_info=True
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                error="INTERNAL_ERROR",
                message="An unexpected error occurred",
                request_id=request_id
            ).model_dump()
        )