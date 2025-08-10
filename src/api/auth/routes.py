"""Authentication API routes"""

from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field

from src.core.auth.models import TokenScope, TokenType, TokenRequest
from src.core.auth.service import token_service
from src.core.auth.revocation import revocation_manager
from src.core.auth.storage import token_storage
from src.api.auth.dependencies import (
    CurrentToken, AdminToken, require_token_create, require_token_revoke,
    get_current_token, require_admin
)
from src.infrastructure.logging import get_logger
from src.infrastructure.middleware.correlation import get_correlation_id

logger = get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["authentication"])


# Request/Response models
class TokenCreateRequest(BaseModel):
    """Request to create a new token"""
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)  # Would validate against user service
    scopes: List[str] = Field(default_factory=list)
    token_type: str = Field(default="access")


class RefreshTokenRequest(BaseModel):
    """Request to refresh an access token"""
    refresh_token: str = Field(..., description="Refresh token")
    ttl_seconds: Optional[int] = Field(None, gt=0, le=31536000)
    namespace: Optional[str] = None
    repository: Optional[str] = None


class TokenResponse(BaseModel):
    """Token response"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    scopes: List[str]


class TokenIntrospectResponse(BaseModel):
    """Token introspection response"""
    active: bool
    token_id: Optional[str] = None
    user_id: Optional[str] = None
    username: Optional[str] = None
    scopes: Optional[List[str]] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    token_type: Optional[str] = None


class TokenRevokeRequest(BaseModel):
    """Request to revoke a token"""
    token_id: str
    reason: Optional[str] = None


class ApiKeyCreateRequest(BaseModel):
    """Request to create an API key"""
    name: str = Field(..., min_length=1)
    scopes: List[str]
    namespace: Optional[str] = None
    repository: Optional[str] = None
    ttl_days: int = Field(default=365, gt=0, le=365)


@router.post("/token", response_model=TokenResponse)
async def create_token(
    request: Request,
    token_request: TokenCreateRequest
):
    """Create a new authentication token"""
    
    # TODO: Validate username/password against user service
    # For now, using hardcoded test user
    if token_request.username != "administrator" or token_request.password != "admin":
        logger.warning(
            "auth_login_failed",
            username=token_request.username,
            ip_address=request.client.host if request.client else None
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # Parse scopes
    try:
        scopes = [TokenScope(s) for s in token_request.scopes]
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scope: {str(e)}"
        )
    
    # Parse token type
    try:
        token_type = TokenType(token_request.token_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid token type: {token_request.token_type}"
        )
    
    # Create token request
    req = TokenRequest(
        user_id=UUID("00000000-0000-0000-0000-000000000000"),  # Test user ID
        username=token_request.username,
        email="admin@example.com",  # Would come from user service
        scopes=scopes,
        token_type=token_type,
        ttl_seconds=token_request.ttl_seconds,
        namespace=token_request.namespace,
        repository=token_request.repository,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    # Generate tokens
    access_token = token_service.generate_token(req)
    
    # Get token claims for response
    claims = token_service.decode_token(access_token)
    
    response = TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=claims.exp - claims.iat if claims else 3600,
        scopes=[s.value for s in claims.scopes] if claims else []
    )
    
    # Generate refresh token if access token
    if token_type == TokenType.ACCESS:
        refresh_token = token_service.create_refresh_token(
            user_id=req.user_id,
            username=req.username,
            email=req.email,
            ip_address=req.ip_address,
            user_agent=req.user_agent
        )
        response.refresh_token = refresh_token
    
    # Store tokens
    if claims:
        await token_storage.store_token(claims)
    
    logger.info(
        "token_created",
        username=token_request.username,
        token_type=token_type.value,
        scopes=[s.value for s in scopes],
        correlation_id=get_correlation_id()
    )
    
    return response


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    refresh_request: RefreshTokenRequest
):
    """Refresh an access token using a refresh token"""
    
    # Validate and refresh
    access_token = token_service.refresh_access_token(refresh_request.refresh_token)
    
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    
    # Get token claims
    claims = token_service.decode_token(access_token)
    
    if not claims:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate new access token"
        )
    
    # Store new token
    await token_storage.store_token(claims)
    
    logger.info(
        "token_refreshed",
        user_id=claims.sub,
        correlation_id=get_correlation_id()
    )
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=claims.exp - claims.iat,
        scopes=[s.value for s in claims.scopes]
    )


@router.post("/revoke")
async def revoke_token(
    revoke_request: TokenRevokeRequest,
    current_token: CurrentToken
):
    """Revoke a token"""
    
    # Check permission
    if not current_token.has_scope(TokenScope.TOKEN_REVOKE):
        # Can only revoke own tokens
        token_claims = await token_storage.get_token(revoke_request.token_id)
        if not token_claims or token_claims.sub != current_token.sub:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot revoke tokens for other users"
            )
    
    # Get token to revoke
    token_claims = await token_storage.get_token(revoke_request.token_id)
    
    if not token_claims:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found"
        )
    
    # Revoke token
    await revocation_manager.revoke_token(
        jti=revoke_request.token_id,
        token_exp=token_claims.exp,
        reason=revoke_request.reason,
        revoked_by=current_token.username or current_token.sub
    )
    
    # Remove from storage
    await token_storage.delete_token(revoke_request.token_id)
    
    logger.info(
        "token_revoked_by_api",
        token_id=revoke_request.token_id,
        revoked_by=current_token.sub,
        reason=revoke_request.reason
    )
    
    return {"status": "revoked", "token_id": revoke_request.token_id}


class TokenIntrospectRequest(BaseModel):
    """Request to introspect a token"""
    token: str = Field(..., description="Token to introspect")


@router.post("/introspect", response_model=TokenIntrospectResponse)
async def introspect_token(
    request: TokenIntrospectRequest,
    current_token: Optional[CurrentToken] = None
):
    """Introspect a token to get its details"""
    
    # Validate token
    result = token_service.validate_token(request.token)
    
    if not result.valid or not result.claims:
        return TokenIntrospectResponse(active=False)
    
    # Check if revoked
    if await revocation_manager.is_revoked(result.claims.jti):
        return TokenIntrospectResponse(active=False)
    
    # Return token details
    return TokenIntrospectResponse(
        active=True,
        token_id=result.claims.jti,
        user_id=result.claims.sub,
        username=result.claims.username,
        scopes=[s.value for s in result.claims.scopes],
        exp=result.claims.exp,
        iat=result.claims.iat,
        token_type=result.claims.token_type.value
    )


@router.get("/sessions")
async def list_sessions(
    current_token: CurrentToken
):
    """List all active sessions for the current user"""
    
    sessions = await token_storage.list_user_sessions(current_token.sub)
    
    return {
        "sessions": [
            {
                "token_id": s.token_id,
                "created_at": s.created_at.isoformat(),
                "expires_at": s.expires_at.isoformat(),
                "token_type": s.token_type,
                "ip_address": s.ip_address,
                "user_agent": s.user_agent,
                "last_used": s.last_used.isoformat() if s.last_used else None
            }
            for s in sessions
        ]
    }


@router.delete("/sessions")
async def terminate_all_sessions(
    current_token: CurrentToken
):
    """Terminate all sessions for the current user"""
    
    # Get all user tokens
    sessions = await token_storage.list_user_sessions(current_token.sub)
    
    # Revoke all tokens
    for session in sessions:
        await revocation_manager.revoke_token(
            jti=session.token_id,
            token_exp=int(session.expires_at.timestamp()),
            reason="User terminated all sessions",
            revoked_by=current_token.username or current_token.sub
        )
    
    # Delete from storage
    count = await token_storage.terminate_user_sessions(current_token.sub)
    
    logger.info(
        "all_sessions_terminated",
        user_id=current_token.sub,
        count=count
    )
    
    return {"terminated": count}


@router.post("/api-key", response_model=TokenResponse)
async def create_api_key(
    request: Request,
    api_key_request: ApiKeyCreateRequest,
    _: None = Depends(require_token_create)
):
    """Create a long-lived API key"""
    
    # Parse scopes
    try:
        scopes = [TokenScope(s) for s in api_key_request.scopes]
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scope: {str(e)}"
        )
    
    # Create API key
    api_key = token_service.create_api_key(
        user_id=UUID(current_token.sub) if current_token.user_id else UUID("00000000-0000-0000-0000-000000000000"),
        username=current_token.username or current_token.sub,
        scopes=scopes,
        ttl_seconds=api_key_request.ttl_days * 86400,
        namespace=api_key_request.namespace,
        repository=api_key_request.repository,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        extra_claims={"api_key_name": api_key_request.name}
    )
    
    # Get token claims
    claims = token_service.decode_token(api_key)
    
    if claims:
        await token_storage.store_token(claims)
    
    logger.info(
        "api_key_created",
        user_id=current_token.sub,
        api_key_name=api_key_request.name,
        scopes=[s.value for s in scopes]
    )
    
    return TokenResponse(
        access_token=api_key,
        token_type="bearer",
        expires_in=api_key_request.ttl_days * 86400,
        scopes=[s.value for s in scopes]
    )


@router.get("/jwks")
async def get_jwks():
    """Get JSON Web Key Set for token verification"""
    
    keys = token_service.signer.key_manager.export_public_keys()
    
    return {
        "keys": [
            {
                "kid": key_id,
                "kty": "oct",  # Symmetric key
                "use": "sig",
                "alg": info["alg"],
                "created_at": info["created_at"],
                "expires_at": info["expires_at"],
                "is_active": info["is_active"]
            }
            for key_id, info in keys.items()
        ]
    }


@router.post("/rotate-key", dependencies=[Depends(require_admin)])
async def rotate_signing_key():
    """Rotate the signing key (admin only)"""
    
    token_service.rotate_signing_key()
    
    logger.info("signing_key_rotated_by_api")
    
    return {"status": "rotated"}