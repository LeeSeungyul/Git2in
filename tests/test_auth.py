"""Tests for authentication system"""

import base64
import json
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from uuid import UUID, uuid4

import pytest

from src.core.auth.models import (Token, TokenClaims, TokenHeader,
                                  TokenRequest, TokenRevocation, TokenScope,
                                  TokenType, TokenValidationResult)
from src.core.auth.revocation import InMemoryRevocationStore, RevocationManager
from src.core.auth.service import TokenService
from src.core.auth.signing import KeyManager, SigningKey, TokenSigner
from src.core.auth.storage import (InMemoryTokenStore, TokenMetadata,
                                   TokenStorageManager)


class TestTokenModels:
    """Test token model classes"""

    def test_token_scope_implies(self):
        """Test scope implication logic"""
        assert TokenScope.ADMIN.implies(TokenScope.REPO_READ)
        assert TokenScope.ADMIN.implies(TokenScope.NAMESPACE_WRITE)
        assert TokenScope.NAMESPACE_WRITE.implies(TokenScope.NAMESPACE_READ)
        assert TokenScope.REPO_WRITE.implies(TokenScope.REPO_READ)
        assert not TokenScope.REPO_READ.implies(TokenScope.REPO_WRITE)
        assert TokenScope.NAMESPACE_ADMIN.implies(TokenScope.NAMESPACE_READ)
        assert TokenScope.NAMESPACE_ADMIN.implies(TokenScope.NAMESPACE_WRITE)

    def test_token_claims_creation(self):
        """Test creating token claims"""
        claims = TokenClaims(
            sub="user123",
            exp=int(time.time()) + 3600,
            scopes=[TokenScope.REPO_READ, TokenScope.REPO_WRITE],
            namespace="test-namespace",
            repository="test-repo",
        )

        assert claims.sub == "user123"
        assert not claims.is_expired()
        assert claims.has_scope(TokenScope.REPO_READ)
        assert claims.has_scope(TokenScope.REPO_WRITE)
        assert claims.has_all_scopes([TokenScope.REPO_READ, TokenScope.REPO_WRITE])

    def test_token_claims_expiration(self):
        """Test token expiration checking"""
        # Create expired token
        claims = TokenClaims(
            sub="user123",
            iat=int(time.time()) - 7200,
            exp=int(time.time()) - 3600,
            scopes=[],
        )

        assert claims.is_expired()
        assert claims.remaining_lifetime().total_seconds() == 0

    def test_token_claims_serialization(self):
        """Test claims serialization/deserialization"""
        original = TokenClaims(
            sub="user123",
            exp=int(time.time()) + 3600,
            scopes=[TokenScope.REPO_READ],
            user_id=uuid4(),
            username="testuser",
            extra={"custom": "value"},
        )

        # Serialize to dict
        data = original.to_dict()
        assert data["sub"] == "user123"
        assert data["username"] == "testuser"
        assert data["custom"] == "value"

        # Deserialize from dict
        restored = TokenClaims.from_dict(data)
        assert restored.sub == original.sub
        assert restored.username == original.username
        assert restored.extra["custom"] == "value"

    def test_token_validation_result(self):
        """Test token validation result helpers"""
        claims = Mock()

        success = TokenValidationResult.success(claims)
        assert success.valid
        assert success.claims == claims
        assert success.error is None

        failure = TokenValidationResult.failure("Invalid token", "INVALID")
        assert not failure.valid
        assert failure.claims is None
        assert failure.error == "Invalid token"
        assert failure.error_code == "INVALID"


class TestTokenSigning:
    """Test token signing and key management"""

    def test_signing_key(self):
        """Test signing key functionality"""
        key = SigningKey(
            key_id="test-key",
            key_bytes=b"secret-key-bytes",
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=30),
        )

        assert key.is_valid()

        # Test signing
        message = "test message"
        signature = key.sign(message)
        assert signature
        assert key.verify(message, signature)
        assert not key.verify("wrong message", signature)

    def test_key_manager(self):
        """Test key manager functionality"""
        manager = KeyManager(key_rotation_days=30, key_overlap_days=7, max_keys=3)

        # Should have default key
        active_key = manager.get_active_key()
        assert active_key
        assert active_key.is_valid()

        # Test signing and verification
        message = "test message"
        signature, key_id = manager.sign(message)
        assert manager.verify(message, signature, key_id)
        assert manager.verify(message, signature)  # Without key_id

        # Test key rotation
        new_key = manager.rotate_key()
        assert new_key.key_id != active_key.key_id
        assert manager.get_active_key().key_id == new_key.key_id

    def test_token_signer(self):
        """Test token signer"""
        signer = TokenSigner()

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "user123",
            "exp": int(time.time()) + 3600,
            "scopes": ["repo:read"],
        }

        # Sign token
        token = signer.sign_token(header, payload)
        assert token
        assert len(token.split(".")) == 3

        # Verify token
        is_valid, decoded_header, decoded_payload = signer.verify_token(token)
        assert is_valid
        assert decoded_header["alg"] == "HS256"
        assert decoded_payload["sub"] == "user123"

        # Test invalid token
        is_valid, _, _ = signer.verify_token("invalid.token.here")
        assert not is_valid


class TestTokenService:
    """Test token generation and validation service"""

    def test_generate_access_token(self):
        """Test generating access token"""
        service = TokenService()

        request = TokenRequest(
            user_id=uuid4(),
            username="testuser",
            email="test@example.com",
            scopes=[TokenScope.REPO_READ],
            token_type=TokenType.ACCESS,
            ttl_seconds=3600,
        )

        token = service.generate_token(request)
        assert token

        # Validate generated token
        result = service.validate_token(token)
        assert result.valid
        assert result.claims
        assert result.claims.username == "testuser"
        assert result.claims.token_type == TokenType.ACCESS

    def test_token_validation(self):
        """Test token validation"""
        service = TokenService()

        # Create valid token
        token = service.create_access_token(
            user_id=uuid4(), username="testuser", scopes=[TokenScope.REPO_READ]
        )

        # Validate valid token
        result = service.validate_token(token)
        assert result.valid
        assert result.claims.username == "testuser"

        # Test invalid token
        result = service.validate_token("invalid.token.string")
        assert not result.valid
        assert result.error_code == "INVALID_SIGNATURE"

        # Test expired token
        with patch("time.time", return_value=time.time() + 7200):
            result = service.validate_token(token)
            assert not result.valid
            assert result.error_code == "TOKEN_EXPIRED"

    def test_refresh_token_flow(self):
        """Test refresh token flow"""
        service = TokenService()
        user_id = uuid4()

        # Create refresh token
        refresh_token = service.create_refresh_token(
            user_id=user_id, username="testuser"
        )

        # Validate it's a refresh token
        result = service.validate_token(refresh_token)
        assert result.valid
        assert result.claims.token_type == TokenType.REFRESH

        # Use refresh token to get new access token
        new_access_token = service.refresh_access_token(refresh_token)
        assert new_access_token

        # Validate new access token
        result = service.validate_token(new_access_token)
        assert result.valid
        assert result.claims.token_type == TokenType.ACCESS


class TestTokenRevocation:
    """Test token revocation management"""

    @pytest.mark.asyncio
    async def test_revocation_store(self):
        """Test in-memory revocation store"""
        store = InMemoryRevocationStore()

        # Add revocation
        jti = "test-token-id"
        expires_at = datetime.utcnow() + timedelta(hours=1)
        await store.add(jti, expires_at, "Test reason", "admin")

        # Check if revoked
        assert await store.is_revoked(jti)
        assert not await store.is_revoked("other-token-id")

        # List revocations
        revocations = await store.list_all()
        assert len(revocations) == 1
        assert revocations[0].jti == jti

        # Remove revocation
        await store.remove(jti)
        assert not await store.is_revoked(jti)

    @pytest.mark.asyncio
    async def test_revocation_manager(self):
        """Test revocation manager"""
        manager = RevocationManager()

        # Revoke token
        jti = "test-token-id"
        token_exp = int(time.time()) + 3600
        await manager.revoke_token(jti, token_exp, "Security reason", "admin")

        # Check if revoked
        assert await manager.is_revoked(jti)

        # Get statistics
        stats = await manager.get_statistics()
        assert stats["total_revoked"] == 1
        assert "Security reason" in stats["by_reason"]

    @pytest.mark.asyncio
    async def test_expired_revocation_cleanup(self):
        """Test cleanup of expired revocations"""
        store = InMemoryRevocationStore()

        # Add expired revocation
        jti = "expired-token"
        expires_at = datetime.utcnow() - timedelta(hours=1)
        await store.add(jti, expires_at)

        # Should not be considered revoked (expired)
        assert not await store.is_revoked(jti)

        # Cleanup should remove it
        count = await store.cleanup_expired()
        assert count == 0  # Already removed by is_revoked check


class TestTokenStorage:
    """Test token storage management"""

    @pytest.mark.asyncio
    async def test_token_store(self):
        """Test in-memory token store"""
        store = InMemoryTokenStore()

        # Create claims
        claims = TokenClaims(
            sub="user123",
            jti="token123",
            iat=int(time.time()),
            exp=int(time.time()) + 3600,
            scopes=[TokenScope.REPO_READ],
        )

        # Store token
        await store.set("token123", claims, 3600)

        # Retrieve token
        retrieved = await store.get("token123")
        assert retrieved
        assert retrieved.sub == "user123"

        # Check existence
        assert await store.exists("token123")
        assert not await store.exists("nonexistent")

        # Delete token
        assert await store.delete("token123")
        assert not await store.exists("token123")

    @pytest.mark.asyncio
    async def test_user_token_management(self):
        """Test managing tokens by user"""
        store = InMemoryTokenStore()

        # Store multiple tokens for a user
        user_id = "user123"
        for i in range(3):
            claims = TokenClaims(
                sub=user_id,
                jti=f"token{i}",
                iat=int(time.time()),
                exp=int(time.time()) + 3600,
                scopes=[],
            )
            await store.set(f"token{i}", claims)

        # List user tokens
        metadata_list = await store.list_by_user(user_id)
        assert len(metadata_list) == 3

        # Delete all user tokens
        count = await store.delete_by_user(user_id)
        assert count == 3

        # Verify all deleted
        metadata_list = await store.list_by_user(user_id)
        assert len(metadata_list) == 0

    @pytest.mark.asyncio
    async def test_token_metadata(self):
        """Test token metadata tracking"""
        store = InMemoryTokenStore()

        claims = TokenClaims(
            sub="user123",
            jti="token123",
            iat=int(time.time()),
            exp=int(time.time()) + 3600,
            token_type=TokenType.ACCESS,
            ip_address="192.168.1.1",
            user_agent="TestClient/1.0",
            scopes=[],
        )

        await store.set("token123", claims)

        # Get metadata
        metadata = await store.get_metadata("token123")
        assert metadata
        assert metadata.token_id == "token123"
        assert metadata.user_id == "user123"
        assert metadata.ip_address == "192.168.1.1"
        assert metadata.user_agent == "TestClient/1.0"

        # Update last used
        await store.update_last_used("token123")
        metadata = await store.get_metadata("token123")
        assert metadata.last_used > metadata.created_at
