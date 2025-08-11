import structlog
from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from src.core.exceptions import (BaseAPIException, InternalServerError,
                                 ValidationError)
from src.infrastructure.middleware.correlation import get_correlation_id

logger = structlog.get_logger(__name__)


async def base_api_exception_handler(
    request: Request, exc: BaseAPIException
) -> JSONResponse:
    correlation_id = get_correlation_id()

    logger.error(
        "api_exception",
        code=exc.code,
        message=exc.message,
        status_code=exc.status_code,
        details=exc.details,
        correlation_id=correlation_id,
        path=request.url.path,
    )

    error_response = exc.to_error_response(correlation_id=correlation_id)

    return JSONResponse(
        status_code=exc.status_code,
        content=error_response.model_dump(exclude_none=True),
        headers={"X-Correlation-ID": correlation_id} if correlation_id else {},
    )


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    correlation_id = get_correlation_id()

    errors = []
    for error in exc.errors():
        errors.append(
            {
                "field": ".".join(str(loc) for loc in error["loc"]),
                "message": error["msg"],
                "type": error["type"],
            }
        )

    validation_error = ValidationError(
        message="Request validation failed", details={"errors": errors}
    )

    logger.error(
        "validation_error",
        errors=errors,
        correlation_id=correlation_id,
        path=request.url.path,
    )

    error_response = validation_error.to_error_response(correlation_id=correlation_id)

    return JSONResponse(
        status_code=validation_error.status_code,
        content=error_response.model_dump(exclude_none=True),
        headers={"X-Correlation-ID": correlation_id} if correlation_id else {},
    )


async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    correlation_id = get_correlation_id()

    logger.error(
        "http_exception",
        status_code=exc.status_code,
        detail=exc.detail,
        correlation_id=correlation_id,
        path=request.url.path,
    )

    code_mapping = {
        400: "G2IN-400",
        401: "G2IN-401",
        403: "G2IN-403",
        404: "G2IN-404",
        409: "G2IN-409",
        413: "G2IN-413",
        429: "G2IN-429",
        500: "G2IN-500",
    }

    error_code = code_mapping.get(exc.status_code, "G2IN-500")

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "code": error_code,
            "message": str(exc.detail),
            "correlation_id": correlation_id,
        },
        headers={"X-Correlation-ID": correlation_id} if correlation_id else {},
    )


async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    correlation_id = get_correlation_id()

    logger.error(
        "unhandled_exception",
        error=str(exc),
        error_type=type(exc).__name__,
        correlation_id=correlation_id,
        path=request.url.path,
        exc_info=True,
    )

    internal_error = InternalServerError(
        message="An unexpected error occurred",
        details=(
            {"error_type": type(exc).__name__}
            if not getattr(request.app.state, "is_production", True)
            else None
        ),
    )

    error_response = internal_error.to_error_response(correlation_id=correlation_id)

    return JSONResponse(
        status_code=internal_error.status_code,
        content=error_response.model_dump(exclude_none=True),
        headers={"X-Correlation-ID": correlation_id} if correlation_id else {},
    )
