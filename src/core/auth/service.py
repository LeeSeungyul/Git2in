"""Token generation and validation service"""

import time
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from uuid import UUID

from src.core.auth.models import (
    Token, TokenClaims, TokenHeader, TokenType, TokenScope,
    TokenRequest, TokenValidationResult
)
from src.core.auth.signing import token_signer
from src.core.config import settings
from src.core.exceptions import AuthenticationError, ValidationError
from src.infrastructure.logging import get_logger

logger = get_logger(__name__)


class TokenService:
    """Service for token generation and validation"""
    
    # Default TTL values in seconds
    DEFAULT_ACCESS_TOKEN_TTL = 3600  # 1 hour
    DEFAULT_REFRESH_TOKEN_TTL = 86400 * 7  # 7 days
    DEFAULT_API_KEY_TTL = 86400 * 365  # 1 year
    DEFAULT_TEMPORARY_TOKEN_TTL = 300  # 5 minutes
    
    def __init__(self):
        self.signer = token_signer
        
        # Override TTLs from settings if available
        if hasattr(settings, "access_token_ttl"):
            self.DEFAULT_ACCESS_TOKEN_TTL = settings.access_token_ttl
        if hasattr(settings, "refresh_token_ttl"):
            self.DEFAULT_REFRESH_TOKEN_TTL = settings.refresh_token_ttl
        if hasattr(settings, "api_key_ttl"):
            self.DEFAULT_API_KEY_TTL = settings.api_key_ttl
    
    def get_default_ttl(self, token_type: TokenType) -> int:
        """Get default TTL for a token type"""
        ttl_map = {
            TokenType.ACCESS: self.DEFAULT_ACCESS_TOKEN_TTL,
            TokenType.REFRESH: self.DEFAULT_REFRESH_TOKEN_TTL,
            TokenType.API_KEY: self.DEFAULT_API_KEY_TTL,
            TokenType.TEMPORARY: self.DEFAULT_TEMPORARY_TOKEN_TTL,
        }
        return ttl_map.get(token_type, self.DEFAULT_ACCESS_TOKEN_TTL)
    
    def generate_token(self, request: TokenRequest) -> str:
        """Generate a new token from request"""
        
        # Determine TTL
        ttl_seconds = request.ttl_seconds
        if ttl_seconds is None:
            ttl_seconds = self.get_default_ttl(request.token_type)
        
        # Create claims
        current_time = int(time.time())
        claims = TokenClaims(
            sub=str(request.user_id),
            iat=current_time,
            exp=current_time + ttl_seconds,
            token_type=request.token_type,
            scopes=request.scopes,
            namespace=request.namespace,
            repository=request.repository,
            user_id=request.user_id,
            username=request.username,
            email=request.email,
            ip_address=request.ip_address,
            user_agent=request.user_agent,
            extra=request.extra_claims
        )
        
        # Create header
        header = TokenHeader()
        
        # Create token
        token = Token(header=header, claims=claims)
        
        # Sign and encode token
        token_string = self.signer.sign_token(
            header.to_dict(),
            claims.to_dict()
        )
        
        logger.info(
            "token_generated",
            token_id=claims.jti,
            user_id=str(request.user_id),
            token_type=request.token_type.value,
            scopes=[s.value for s in request.scopes],
            ttl_seconds=ttl_seconds
        )
        
        return token_string
    
    def validate_token(self, token_string: str) -> TokenValidationResult:
        """Validate a token string"""
        
        # Verify signature and decode
        is_valid, header, payload = self.signer.verify_token(token_string)
        
        if not is_valid:
            logger.warning("token_validation_failed", reason="invalid_signature")
            return TokenValidationResult.failure(
                "Invalid token signature",
                "INVALID_SIGNATURE"
            )
        
        if not header or not payload:
            logger.warning("token_validation_failed", reason="decode_error")
            return TokenValidationResult.failure(
                "Failed to decode token",
                "DECODE_ERROR"
            )
        
        try:
            # Parse claims
            claims = TokenClaims.from_dict(payload)
            
            # Check expiration
            if claims.is_expired():
                logger.warning(
                    "token_validation_failed",
                    reason="expired",
                    token_id=claims.jti
                )
                return TokenValidationResult.failure(
                    "Token has expired",
                    "TOKEN_EXPIRED"
                )
            
            # Additional validation can be added here
            # (e.g., check against revocation list)
            
            logger.debug(
                "token_validated",
                token_id=claims.jti,
                user_id=claims.sub
            )
            
            return TokenValidationResult.success(claims)
            
        except Exception as e:
            logger.error(
                "token_validation_error",
                error=str(e)
            )
            return TokenValidationResult.failure(
                "Invalid token claims",
                "INVALID_CLAIMS"
            )
    
    def create_access_token(
        self,
        user_id: UUID,
        username: str,
        scopes: List[TokenScope],
        **kwargs
    ) -> str:
        """Create an access token"""
        request = TokenRequest(
            user_id=user_id,
            username=username,
            scopes=scopes,
            token_type=TokenType.ACCESS,
            **kwargs
        )
        return self.generate_token(request)
    
    def create_refresh_token(
        self,
        user_id: UUID,
        username: str,
        **kwargs
    ) -> str:
        """Create a refresh token"""
        request = TokenRequest(
            user_id=user_id,
            username=username,
            scopes=[],  # Refresh tokens don't need scopes
            token_type=TokenType.REFRESH,
            **kwargs
        )
        return self.generate_token(request)
    
    def create_api_key(
        self,
        user_id: UUID,
        username: str,
        scopes: List[TokenScope],
        **kwargs
    ) -> str:
        """Create a long-lived API key"""
        request = TokenRequest(
            user_id=user_id,
            username=username,
            scopes=scopes,
            token_type=TokenType.API_KEY,
            **kwargs
        )
        return self.generate_token(request)
    
    def create_temporary_token(
        self,
        user_id: UUID,
        username: str,
        scopes: List[TokenScope],
        ttl_seconds: int = 300,
        **kwargs
    ) -> str:
        """Create a temporary token with short TTL"""
        request = TokenRequest(
            user_id=user_id,
            username=username,
            scopes=scopes,
            token_type=TokenType.TEMPORARY,
            ttl_seconds=ttl_seconds,
            **kwargs
        )
        return self.generate_token(request)
    
    def refresh_access_token(self, refresh_token_string: str) -> Optional[str]:
        """Generate a new access token from a refresh token"""
        
        # Validate refresh token
        result = self.validate_token(refresh_token_string)
        
        if not result.valid or not result.claims:
            logger.warning("refresh_token_invalid")
            return None
        
        # Check token type
        if result.claims.token_type != TokenType.REFRESH:
            logger.warning(
                "refresh_token_wrong_type",
                token_type=result.claims.token_type.value
            )
            return None
        
        # Generate new access token
        # Note: In a real system, you'd fetch fresh user data and scopes
        return self.create_access_token(
            user_id=result.claims.user_id or UUID(result.claims.sub),
            username=result.claims.username or result.claims.sub,
            scopes=[],  # Would fetch actual scopes from user service
            email=result.claims.email,
            ip_address=result.claims.ip_address,
            user_agent=result.claims.user_agent
        )
    
    def decode_token(self, token_string: str) -> Optional[TokenClaims]:
        """Decode a token without full validation (for debugging)"""
        try:
            parts = token_string.split(".")
            if len(parts) != 3:
                return None
            
            import base64
            import json
            
            # Decode payload
            payload_b64 = parts[1]
            payload_padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))
            
            return TokenClaims.from_dict(payload)
            
        except Exception as e:
            logger.error("token_decode_error", error=str(e))
            return None
    
    def rotate_signing_key(self) -> None:
        """Rotate the signing key"""
        self.signer.rotate_key()
        logger.info("signing_key_rotated")


# Global token service instance
token_service = TokenService()