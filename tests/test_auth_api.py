"""Tests for authentication API endpoints"""

import pytest
import time
from uuid import uuid4
from unittest.mock import patch, AsyncMock

from fastapi import status
from httpx import AsyncClient

from src.core.auth.models import TokenScope, TokenType, TokenClaims
from src.core.auth.service import token_service
from src.core.auth.storage import token_storage
from src.core.auth.revocation import revocation_manager


class TestAuthenticationAPI:
    """Test authentication API endpoints"""
    
    @pytest.mark.asyncio
    async def test_create_token_success(self, async_client: AsyncClient):
        """Test successful token creation"""
        response = await async_client.post(
            "/api/v1/auth/token",
            json={
                "username": "admin",
                "password": "admin",
                "scopes": ["repo:read", "repo:write"],
                "token_type": "access"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data
        assert "refresh_token" in data
        assert "repo:read" in data["scopes"]
        assert "repo:write" in data["scopes"]
    
    @pytest.mark.asyncio
    async def test_create_token_invalid_credentials(self, async_client: AsyncClient):
        """Test token creation with invalid credentials"""
        response = await async_client.post(
            "/api/v1/auth/token",
            json={
                "username": "wrong",
                "password": "wrong",
                "scopes": []
            }
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid username or password" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_create_token_invalid_scope(self, async_client: AsyncClient):
        """Test token creation with invalid scope"""
        response = await async_client.post(
            "/api/v1/auth/token",
            json={
                "username": "admin",
                "password": "admin",
                "scopes": ["invalid:scope"]
            }
        )
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Invalid scope" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_refresh_token(self, async_client: AsyncClient):
        """Test refreshing access token"""
        # First create tokens
        response = await async_client.post(
            "/api/v1/auth/token",
            json={
                "username": "admin",
                "password": "admin",
                "scopes": ["repo:read"]
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        refresh_token = response.json()["refresh_token"]
        
        # Now refresh
        response = await async_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
    
    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, async_client: AsyncClient):
        """Test refreshing with invalid token"""
        response = await async_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "invalid.refresh.token"}
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid or expired refresh token" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_introspect_token(self, async_client: AsyncClient):
        """Test token introspection"""
        # Create a token
        token = token_service.create_access_token(
            user_id=uuid4(),
            username="testuser",
            scopes=[TokenScope.REPO_READ]
        )
        
        response = await async_client.post(
            "/api/v1/auth/introspect",
            json={"token": token}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        assert data["active"] is True
        assert data["username"] == "testuser"
        assert "repo:read" in data["scopes"]
    
    @pytest.mark.asyncio
    async def test_introspect_invalid_token(self, async_client: AsyncClient):
        """Test introspecting invalid token"""
        response = await async_client.post(
            "/api/v1/auth/introspect",
            json={"token": "invalid.token.here"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["active"] is False
    
    @pytest.mark.asyncio
    async def test_revoke_token(self, async_client: AsyncClient):
        """Test token revocation"""
        # Create tokens for testing
        user_id = uuid4()
        access_token = token_service.create_access_token(
            user_id=user_id,
            username="testuser",
            scopes=[TokenScope.TOKEN_REVOKE]
        )
        
        # Store token
        claims = token_service.decode_token(access_token)
        await token_storage.store_token(claims)
        
        # Revoke the token
        response = await async_client.post(
            "/api/v1/auth/revoke",
            json={
                "token_id": claims.jti,
                "reason": "Test revocation"
            },
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["status"] == "revoked"
        
        # Verify token is revoked
        assert await revocation_manager.is_revoked(claims.jti)
    
    @pytest.mark.asyncio
    async def test_list_sessions(self, async_client: AsyncClient):
        """Test listing user sessions"""
        # Create a token
        user_id = uuid4()
        access_token = token_service.create_access_token(
            user_id=user_id,
            username="testuser",
            scopes=[TokenScope.USER_READ]
        )
        
        # Store token
        claims = token_service.decode_token(access_token)
        await token_storage.store_token(claims)
        
        # List sessions
        response = await async_client.get(
            "/api/v1/auth/sessions",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "sessions" in data
        assert len(data["sessions"]) >= 1
    
    @pytest.mark.asyncio
    async def test_terminate_all_sessions(self, async_client: AsyncClient):
        """Test terminating all user sessions"""
        # Create multiple tokens
        user_id = uuid4()
        tokens = []
        
        for i in range(3):
            token = token_service.create_access_token(
                user_id=user_id,
                username="testuser",
                scopes=[TokenScope.USER_WRITE]
            )
            claims = token_service.decode_token(token)
            await token_storage.store_token(claims)
            tokens.append(token)
        
        # Terminate all sessions using first token
        response = await async_client.delete(
            "/api/v1/auth/sessions",
            headers={"Authorization": f"Bearer {tokens[0]}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["terminated"] == 3
    
    @pytest.mark.asyncio
    async def test_create_api_key(self, async_client: AsyncClient):
        """Test creating API key"""
        # Create admin token
        admin_token = token_service.create_access_token(
            user_id=uuid4(),
            username="admin",
            scopes=[TokenScope.TOKEN_CREATE]
        )
        
        response = await async_client.post(
            "/api/v1/auth/api-key",
            json={
                "name": "Test API Key",
                "scopes": ["repo:read"],
                "ttl_days": 30
            },
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        assert "access_token" in data
        assert data["expires_in"] == 30 * 86400
        assert "repo:read" in data["scopes"]
    
    @pytest.mark.asyncio
    async def test_get_jwks(self, async_client: AsyncClient):
        """Test getting JWKS endpoint"""
        response = await async_client.get("/api/v1/auth/jwks")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        assert "keys" in data
        assert len(data["keys"]) > 0
        
        # Check key structure
        key = data["keys"][0]
        assert "kid" in key
        assert key["kty"] == "oct"
        assert key["use"] == "sig"
        assert key["alg"] == "HS256"


class TestAuthenticationMiddleware:
    """Test authentication middleware and dependencies"""
    
    @pytest.mark.asyncio
    async def test_protected_endpoint_without_token(self, async_client: AsyncClient):
        """Test accessing protected endpoint without token"""
        # Try to push without authentication
        response = await async_client.post(
            "/api/v1/git/test-namespace/test-repo/git-receive-pack",
            content=b"test data"
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.asyncio
    async def test_protected_endpoint_with_valid_token(self, async_client: AsyncClient):
        """Test accessing protected endpoint with valid token"""
        # Create token with write permission
        token = token_service.create_access_token(
            user_id=uuid4(),
            username="testuser",
            scopes=[TokenScope.REPO_WRITE],
            namespace="test-namespace",
            repository="test-repo"
        )
        
        # Mock repository existence
        with patch("src.api.git_http.FilesystemManager") as mock_fs:
            mock_fs.return_value.get_repository_path.return_value.exists.return_value = True
            
            response = await async_client.post(
                "/api/v1/git/test-namespace/test-repo/git-receive-pack",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/x-git-receive-pack-request"
                },
                content=b"0000"
            )
            
            # Should not be 401/403
            assert response.status_code != status.HTTP_401_UNAUTHORIZED
            assert response.status_code != status.HTTP_403_FORBIDDEN
    
    @pytest.mark.asyncio
    async def test_scope_validation(self, async_client: AsyncClient):
        """Test scope-based access control"""
        # Create token with only read permission
        token = token_service.create_access_token(
            user_id=uuid4(),
            username="testuser",
            scopes=[TokenScope.REPO_READ],  # Only read, not write
            namespace="test-namespace",
            repository="test-repo"
        )
        
        # Try to push (requires write)
        response = await async_client.post(
            "/api/v1/git/test-namespace/test-repo/git-receive-pack",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/x-git-receive-pack-request"
            },
            content=b"0000"
        )
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    @pytest.mark.asyncio
    async def test_namespace_scoped_access(self, async_client: AsyncClient):
        """Test namespace-scoped token access"""
        # Create token scoped to specific namespace
        token = token_service.create_access_token(
            user_id=uuid4(),
            username="testuser",
            scopes=[TokenScope.REPO_WRITE],
            namespace="allowed-namespace"
        )
        
        # Try to access different namespace
        response = await async_client.post(
            "/api/v1/git/different-namespace/some-repo/git-receive-pack",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/x-git-receive-pack-request"
            },
            content=b"0000"
        )
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    @pytest.mark.asyncio
    async def test_expired_token(self, async_client: AsyncClient):
        """Test using expired token"""
        # Create expired token
        with patch("time.time", return_value=time.time() - 7200):
            token = token_service.create_access_token(
                user_id=uuid4(),
                username="testuser",
                scopes=[TokenScope.REPO_READ],
                ttl_seconds=3600  # Already expired
            )
        
        response = await async_client.get(
            "/api/v1/auth/sessions",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "expired" in response.json()["detail"].lower()
    
    @pytest.mark.asyncio
    async def test_revoked_token(self, async_client: AsyncClient):
        """Test using revoked token"""
        # Create token
        token = token_service.create_access_token(
            user_id=uuid4(),
            username="testuser",
            scopes=[TokenScope.USER_READ]
        )
        
        claims = token_service.decode_token(token)
        
        # Revoke it
        await revocation_manager.revoke_token(
            jti=claims.jti,
            token_exp=claims.exp,
            reason="Test"
        )
        
        response = await async_client.get(
            "/api/v1/auth/sessions",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "revoked" in response.json()["detail"].lower()