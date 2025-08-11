"""Token management API endpoints"""

from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID

from fastapi import (APIRouter, Depends, HTTPException, Query, Request,
                     Response, status)

from src.api.auth.dependencies import get_current_token
from src.api.v1.models.common import (ResourceCreatedResponse,
                                      ResourceDeletedResponse)
from src.api.v1.models.errors import ErrorResponse
from src.api.v1.models.pagination import (PaginatedResponse, PaginationParams,
                                          create_link_header,
                                          get_pagination_params)
from src.api.v1.models.token import (TokenCreateRequest, TokenListResponse,
                                     TokenResponse, TokenRotateRequest,
                                     TokenStatistics)
from src.core.auth.models import (TokenClaims, TokenRequest, TokenScope,
                                  TokenType)
from src.core.auth.revocation import revocation_manager
from src.core.auth.service import token_service
from src.core.auth.storage import token_storage
from src.infrastructure.logging import get_logger
from src.infrastructure.middleware.correlation import get_correlation_id

logger = get_logger(__name__)
router = APIRouter(prefix="/tokens", tags=["tokens"])


@router.get(
    "",
    response_model=PaginatedResponse[TokenListResponse],
    summary="List tokens",
    description="List all tokens for the current user",
)
async def list_tokens(
    request: Request,
    response: Response,
    pagination: PaginationParams = Depends(get_pagination_params),
    include_expired: bool = Query(False, description="Include expired tokens"),
    include_revoked: bool = Query(False, description="Include revoked tokens"),
    current_token: TokenClaims = Depends(get_current_token),
):
    """List all tokens for the current user"""

    correlation_id = get_correlation_id()

    try:
        # Get all sessions for user
        sessions = await token_storage.list_user_sessions(current_token.sub)

        # Convert to token list responses
        token_responses = []
        for session in sessions:
            # Check if expired
            is_expired = session.expires_at < datetime.utcnow()

            # Check if revoked
            is_revoked = await revocation_manager.is_revoked(session.token_id)

            # Filter based on parameters
            if not include_expired and is_expired:
                continue
            if not include_revoked and is_revoked:
                continue

            token_responses.append(
                TokenListResponse(
                    id=session.token_id,
                    name=f"Token {session.token_id[:8]}",  # Short ID as name
                    scopes=[],  # Would need to decode token to get scopes
                    namespace=None,
                    repository=None,
                    created_at=session.created_at,
                    expires_at=session.expires_at,
                    last_used_at=session.last_used,
                    usage_count=0,  # Would track in production
                    is_expired=is_expired,
                    is_revoked=is_revoked,
                )
            )

        # Apply pagination
        total = len(token_responses)
        start = pagination.get_offset()
        end = start + pagination.get_limit()
        token_responses = token_responses[start:end]

        # Create paginated response
        paginated = PaginatedResponse.create(
            items=token_responses,
            total=total,
            page=pagination.page,
            per_page=pagination.per_page,
        )

        # Add pagination headers
        response.headers["X-Total-Count"] = str(total)
        response.headers["X-Page"] = str(pagination.page)
        response.headers["X-Per-Page"] = str(pagination.per_page)
        response.headers["Link"] = create_link_header(
            request, pagination.page, paginated.pages, pagination.per_page
        )

        logger.info(
            "tokens_listed",
            user_id=current_token.sub,
            count=len(token_responses),
            total=total,
            correlation_id=correlation_id,
        )

        return paginated

    except Exception as e:
        logger.error(
            "token_list_failed",
            error=str(e),
            user_id=current_token.sub,
            correlation_id=correlation_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to list tokens", correlation_id=correlation_id
            ).model_dump(),
        )


@router.post(
    "",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create token",
    description="Create a new API token",
)
async def create_token(
    request: TokenCreateRequest, current_token: TokenClaims = Depends(get_current_token)
):
    """Create a new API token"""

    correlation_id = get_correlation_id()

    try:
        # Parse scopes
        try:
            scopes = [TokenScope(s) for s in request.scopes]
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorResponse.validation_error(
                    errors=[
                        {
                            "loc": ["body", "scopes"],
                            "msg": f"Invalid scope: {str(e)}",
                            "type": "value_error",
                        }
                    ],
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Create token request
        token_req = TokenRequest(
            user_id=UUID(current_token.sub),
            username=current_token.username or "unknown",
            email=current_token.email or "unknown@example.com",
            scopes=scopes,
            token_type=TokenType.API_KEY,
            ttl_seconds=request.expires_in_days * 86400,
            namespace=request.namespace,
            repository=request.repository,
            extra_claims={"token_name": request.name},
        )

        # Generate token
        api_token = token_service.generate_token(token_req)

        # Get token claims
        claims = token_service.decode_token(api_token)

        if claims:
            # Store token
            await token_storage.store_token(claims)

            logger.info(
                "api_token_created",
                user_id=current_token.sub,
                token_id=claims.jti,
                token_name=request.name,
                scopes=request.scopes,
                correlation_id=correlation_id,
            )

            return TokenResponse(
                id=claims.jti,
                name=request.name,
                token=api_token,  # Only show token value on creation
                scopes=request.scopes,
                namespace=request.namespace,
                repository=request.repository,
                created_at=datetime.fromtimestamp(claims.iat),
                expires_at=datetime.fromtimestamp(claims.exp),
                last_used_at=None,
                usage_count=0,
            )
        else:
            raise ValueError("Failed to generate token")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "token_create_failed",
            error=str(e),
            user_id=current_token.sub,
            correlation_id=correlation_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to create token", correlation_id=correlation_id
            ).model_dump(),
        )


@router.get(
    "/{token_id}",
    response_model=TokenListResponse,
    summary="Get token details",
    description="Get details for a specific token",
)
async def get_token(
    token_id: str, current_token: TokenClaims = Depends(get_current_token)
):
    """Get details for a specific token"""

    correlation_id = get_correlation_id()

    try:
        # Get token from storage
        token_claims = await token_storage.get_token(token_id)

        if not token_claims:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse.not_found(
                    resource="Token",
                    resource_id=token_id,
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Check ownership
        if token_claims.sub != current_token.sub:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=ErrorResponse.forbidden(
                    message="You don't have access to this token",
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Check if revoked
        is_revoked = await revocation_manager.is_revoked(token_id)

        # Get session info
        sessions = await token_storage.list_user_sessions(current_token.sub)
        session = next((s for s in sessions if s.token_id == token_id), None)

        return TokenListResponse(
            id=token_id,
            name=token_claims.extra_claims.get("token_name", f"Token {token_id[:8]}"),
            scopes=[s.value for s in token_claims.scopes],
            namespace=token_claims.namespace,
            repository=token_claims.repository,
            created_at=datetime.fromtimestamp(token_claims.iat),
            expires_at=datetime.fromtimestamp(token_claims.exp),
            last_used_at=session.last_used if session else None,
            usage_count=0,  # Would track in production
            is_expired=token_claims.exp < datetime.utcnow().timestamp(),
            is_revoked=is_revoked,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "token_get_failed",
            error=str(e),
            token_id=token_id,
            correlation_id=correlation_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to get token", correlation_id=correlation_id
            ).model_dump(),
        )


@router.post(
    "/{token_id}/revoke",
    response_model=ResourceDeletedResponse,
    summary="Revoke token",
    description="Revoke a token",
)
async def revoke_token(
    token_id: str,
    reason: Optional[str] = Query(None, description="Reason for revocation"),
    current_token: TokenClaims = Depends(get_current_token),
):
    """Revoke a token"""

    correlation_id = get_correlation_id()

    try:
        # Get token from storage
        token_claims = await token_storage.get_token(token_id)

        if not token_claims:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse.not_found(
                    resource="Token",
                    resource_id=token_id,
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Check ownership
        if token_claims.sub != current_token.sub and not current_token.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=ErrorResponse.forbidden(
                    message="You don't have permission to revoke this token",
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Revoke token
        await revocation_manager.revoke_token(
            jti=token_id,
            token_exp=token_claims.exp,
            reason=reason,
            revoked_by=current_token.username or current_token.sub,
        )

        # Remove from storage
        await token_storage.delete_token(token_id)

        logger.info(
            "token_revoked",
            token_id=token_id,
            revoked_by=current_token.sub,
            reason=reason,
            correlation_id=correlation_id,
        )

        return ResourceDeletedResponse(
            id=token_id,
            deleted_at=datetime.utcnow(),
            message=f"Token revoked successfully",
            correlation_id=correlation_id,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "token_revoke_failed",
            error=str(e),
            token_id=token_id,
            correlation_id=correlation_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to revoke token", correlation_id=correlation_id
            ).model_dump(),
        )


@router.post(
    "/{token_id}/rotate",
    response_model=TokenResponse,
    summary="Rotate token",
    description="Rotate a token (revoke old, create new)",
)
async def rotate_token(
    token_id: str,
    request: TokenRotateRequest,
    current_token: TokenClaims = Depends(get_current_token),
):
    """Rotate a token (revoke old, create new)"""

    correlation_id = get_correlation_id()

    try:
        # Get existing token
        old_token_claims = await token_storage.get_token(token_id)

        if not old_token_claims:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse.not_found(
                    resource="Token",
                    resource_id=token_id,
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Check ownership
        if old_token_claims.sub != current_token.sub:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=ErrorResponse.forbidden(
                    message="You don't have permission to rotate this token",
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Revoke old token
        await revocation_manager.revoke_token(
            jti=token_id,
            token_exp=old_token_claims.exp,
            reason="Token rotation",
            revoked_by=current_token.username or current_token.sub,
        )
        await token_storage.delete_token(token_id)

        # Create new token with same scopes and restrictions
        token_req = TokenRequest(
            user_id=UUID(old_token_claims.sub),
            username=old_token_claims.username or "unknown",
            email=old_token_claims.email or "unknown@example.com",
            scopes=old_token_claims.scopes,
            token_type=old_token_claims.token_type,
            ttl_seconds=request.expires_in_days * 86400,
            namespace=old_token_claims.namespace,
            repository=old_token_claims.repository,
            extra_claims=old_token_claims.extra_claims,
        )

        # Generate new token
        new_token = token_service.generate_token(token_req)
        new_claims = token_service.decode_token(new_token)

        if new_claims:
            # Store new token
            await token_storage.store_token(new_claims)

            logger.info(
                "token_rotated",
                old_token_id=token_id,
                new_token_id=new_claims.jti,
                user_id=current_token.sub,
                correlation_id=correlation_id,
            )

            return TokenResponse(
                id=new_claims.jti,
                name=old_token_claims.extra_claims.get(
                    "token_name", f"Token {new_claims.jti[:8]}"
                ),
                token=new_token,  # Show new token value
                scopes=[s.value for s in new_claims.scopes],
                namespace=new_claims.namespace,
                repository=new_claims.repository,
                created_at=datetime.fromtimestamp(new_claims.iat),
                expires_at=datetime.fromtimestamp(new_claims.exp),
                last_used_at=None,
                usage_count=0,
            )
        else:
            raise ValueError("Failed to generate new token")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "token_rotate_failed",
            error=str(e),
            token_id=token_id,
            correlation_id=correlation_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to rotate token", correlation_id=correlation_id
            ).model_dump(),
        )
