"""Token storage layer with in-memory and Redis support"""

import asyncio
from typing import Dict, Optional, Set, List, Any
from datetime import datetime, timedelta
from threading import Lock
from abc import ABC, abstractmethod
import json

from src.core.auth.models import TokenClaims, Token
from src.infrastructure.logging import get_logger

logger = get_logger(__name__)


class TokenMetadata:
    """Metadata about a stored token"""
    
    def __init__(
        self,
        token_id: str,
        user_id: str,
        created_at: datetime,
        expires_at: datetime,
        token_type: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        last_used: Optional[datetime] = None
    ):
        self.token_id = token_id
        self.user_id = user_id
        self.created_at = created_at
        self.expires_at = expires_at
        self.token_type = token_type
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.last_used = last_used or created_at
    
    def is_expired(self) -> bool:
        """Check if token is expired"""
        return datetime.utcnow() >= self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "token_id": self.token_id,
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "token_type": self.token_type,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "last_used": self.last_used.isoformat() if self.last_used else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenMetadata":
        """Create from dictionary"""
        return cls(
            token_id=data["token_id"],
            user_id=data["user_id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            token_type=data["token_type"],
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent"),
            last_used=datetime.fromisoformat(data["last_used"]) if data.get("last_used") else None
        )


class TokenStore(ABC):
    """Abstract base class for token storage"""
    
    @abstractmethod
    async def set(
        self,
        token_id: str,
        claims: TokenClaims,
        ttl_seconds: Optional[int] = None
    ) -> None:
        """Store a token with optional TTL"""
        pass
    
    @abstractmethod
    async def get(self, token_id: str) -> Optional[TokenClaims]:
        """Retrieve a token by ID"""
        pass
    
    @abstractmethod
    async def delete(self, token_id: str) -> bool:
        """Delete a token, return True if deleted"""
        pass
    
    @abstractmethod
    async def exists(self, token_id: str) -> bool:
        """Check if a token exists"""
        pass
    
    @abstractmethod
    async def list_by_user(self, user_id: str) -> List[TokenMetadata]:
        """List all tokens for a user"""
        pass
    
    @abstractmethod
    async def delete_by_user(self, user_id: str) -> int:
        """Delete all tokens for a user, return count deleted"""
        pass
    
    @abstractmethod
    async def cleanup_expired(self) -> int:
        """Remove expired tokens, return count removed"""
        pass
    
    @abstractmethod
    async def get_metadata(self, token_id: str) -> Optional[TokenMetadata]:
        """Get token metadata"""
        pass
    
    @abstractmethod
    async def update_last_used(self, token_id: str) -> None:
        """Update last used timestamp"""
        pass


class InMemoryTokenStore(TokenStore):
    """In-memory token storage implementation"""
    
    def __init__(self):
        self._tokens: Dict[str, TokenClaims] = {}
        self._metadata: Dict[str, TokenMetadata] = {}
        self._user_tokens: Dict[str, Set[str]] = {}  # user_id -> token_ids
        self._lock = Lock()
    
    async def set(
        self,
        token_id: str,
        claims: TokenClaims,
        ttl_seconds: Optional[int] = None
    ) -> None:
        """Store a token with optional TTL"""
        with self._lock:
            # Store claims
            self._tokens[token_id] = claims
            
            # Create metadata
            created_at = datetime.utcfromtimestamp(claims.iat)
            expires_at = datetime.utcfromtimestamp(claims.exp)
            
            metadata = TokenMetadata(
                token_id=token_id,
                user_id=claims.sub,
                created_at=created_at,
                expires_at=expires_at,
                token_type=claims.token_type.value,
                ip_address=claims.ip_address,
                user_agent=claims.user_agent
            )
            self._metadata[token_id] = metadata
            
            # Track by user
            if claims.sub not in self._user_tokens:
                self._user_tokens[claims.sub] = set()
            self._user_tokens[claims.sub].add(token_id)
            
            logger.debug(
                "token_stored",
                token_id=token_id,
                user_id=claims.sub,
                expires_at=expires_at.isoformat()
            )
    
    async def get(self, token_id: str) -> Optional[TokenClaims]:
        """Retrieve a token by ID"""
        with self._lock:
            claims = self._tokens.get(token_id)
            
            if claims and claims.is_expired():
                # Remove expired token
                await self._remove_token(token_id)
                return None
            
            return claims
    
    async def delete(self, token_id: str) -> bool:
        """Delete a token"""
        with self._lock:
            return await self._remove_token(token_id)
    
    async def _remove_token(self, token_id: str) -> bool:
        """Internal method to remove a token"""
        if token_id not in self._tokens:
            return False
        
        claims = self._tokens[token_id]
        
        # Remove from tokens
        del self._tokens[token_id]
        
        # Remove metadata
        if token_id in self._metadata:
            del self._metadata[token_id]
        
        # Remove from user tracking
        if claims.sub in self._user_tokens:
            self._user_tokens[claims.sub].discard(token_id)
            if not self._user_tokens[claims.sub]:
                del self._user_tokens[claims.sub]
        
        logger.debug("token_removed", token_id=token_id)
        return True
    
    async def exists(self, token_id: str) -> bool:
        """Check if a token exists"""
        with self._lock:
            if token_id not in self._tokens:
                return False
            
            claims = self._tokens[token_id]
            if claims.is_expired():
                await self._remove_token(token_id)
                return False
            
            return True
    
    async def list_by_user(self, user_id: str) -> List[TokenMetadata]:
        """List all tokens for a user"""
        with self._lock:
            token_ids = self._user_tokens.get(user_id, set()).copy()
            
            metadata_list = []
            for token_id in token_ids:
                metadata = self._metadata.get(token_id)
                if metadata and not metadata.is_expired():
                    metadata_list.append(metadata)
                elif metadata:
                    # Remove expired token
                    await self._remove_token(token_id)
            
            return metadata_list
    
    async def delete_by_user(self, user_id: str) -> int:
        """Delete all tokens for a user"""
        with self._lock:
            token_ids = self._user_tokens.get(user_id, set()).copy()
            
            count = 0
            for token_id in token_ids:
                if await self._remove_token(token_id):
                    count += 1
            
            logger.info(
                "user_tokens_deleted",
                user_id=user_id,
                count=count
            )
            
            return count
    
    async def cleanup_expired(self) -> int:
        """Remove expired tokens"""
        with self._lock:
            expired_ids = []
            
            for token_id, claims in self._tokens.items():
                if claims.is_expired():
                    expired_ids.append(token_id)
            
            count = 0
            for token_id in expired_ids:
                if await self._remove_token(token_id):
                    count += 1
            
            if count > 0:
                logger.info("expired_tokens_cleaned", count=count)
            
            return count
    
    async def get_metadata(self, token_id: str) -> Optional[TokenMetadata]:
        """Get token metadata"""
        with self._lock:
            metadata = self._metadata.get(token_id)
            
            if metadata and metadata.is_expired():
                await self._remove_token(token_id)
                return None
            
            return metadata
    
    async def update_last_used(self, token_id: str) -> None:
        """Update last used timestamp"""
        with self._lock:
            if token_id in self._metadata:
                self._metadata[token_id].last_used = datetime.utcnow()


class RedisTokenStore(TokenStore):
    """Redis-backed token storage (placeholder for future implementation)"""
    
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        logger.info("redis_token_store_initialized", url=redis_url)
    
    async def set(
        self,
        token_id: str,
        claims: TokenClaims,
        ttl_seconds: Optional[int] = None
    ) -> None:
        """Store a token in Redis with TTL"""
        # Would use Redis SET with EXPIREAT
        raise NotImplementedError("Redis token store not yet implemented")
    
    async def get(self, token_id: str) -> Optional[TokenClaims]:
        """Retrieve a token from Redis"""
        # Would use Redis GET
        raise NotImplementedError("Redis token store not yet implemented")
    
    async def delete(self, token_id: str) -> bool:
        """Delete a token from Redis"""
        # Would use Redis DEL
        raise NotImplementedError("Redis token store not yet implemented")
    
    async def exists(self, token_id: str) -> bool:
        """Check if a token exists in Redis"""
        # Would use Redis EXISTS
        raise NotImplementedError("Redis token store not yet implemented")
    
    async def list_by_user(self, user_id: str) -> List[TokenMetadata]:
        """List all tokens for a user from Redis"""
        # Would use Redis SCAN with pattern
        raise NotImplementedError("Redis token store not yet implemented")
    
    async def delete_by_user(self, user_id: str) -> int:
        """Delete all tokens for a user from Redis"""
        # Would use Redis SCAN and DEL
        raise NotImplementedError("Redis token store not yet implemented")
    
    async def cleanup_expired(self) -> int:
        """Redis handles expiration automatically"""
        return 0
    
    async def get_metadata(self, token_id: str) -> Optional[TokenMetadata]:
        """Get token metadata from Redis"""
        # Would use Redis HGETALL
        raise NotImplementedError("Redis token store not yet implemented")
    
    async def update_last_used(self, token_id: str) -> None:
        """Update last used timestamp in Redis"""
        # Would use Redis HSET
        raise NotImplementedError("Redis token store not yet implemented")


class TokenStorageManager:
    """High-level token storage management"""
    
    def __init__(self, store: Optional[TokenStore] = None):
        self.store = store or InMemoryTokenStore()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._cleanup_interval = 3600  # 1 hour
    
    async def store_token(self, claims: TokenClaims) -> None:
        """Store a token"""
        ttl_seconds = claims.exp - claims.iat
        await self.store.set(claims.jti, claims, ttl_seconds)
    
    async def get_token(self, token_id: str) -> Optional[TokenClaims]:
        """Get a token by ID"""
        claims = await self.store.get(token_id)
        
        if claims:
            # Update last used
            await self.store.update_last_used(token_id)
        
        return claims
    
    async def delete_token(self, token_id: str) -> bool:
        """Delete a token"""
        return await self.store.delete(token_id)
    
    async def list_user_sessions(self, user_id: str) -> List[TokenMetadata]:
        """List all active sessions for a user"""
        return await self.store.list_by_user(user_id)
    
    async def terminate_user_sessions(self, user_id: str) -> int:
        """Terminate all sessions for a user"""
        return await self.store.delete_by_user(user_id)
    
    async def start_cleanup_task(self) -> None:
        """Start background cleanup task"""
        if self._cleanup_task and not self._cleanup_task.done():
            return
        
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("storage_cleanup_task_started")
    
    async def stop_cleanup_task(self) -> None:
        """Stop background cleanup task"""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            logger.info("storage_cleanup_task_stopped")
    
    async def _cleanup_loop(self) -> None:
        """Background task to clean up expired tokens"""
        while True:
            try:
                await asyncio.sleep(self._cleanup_interval)
                count = await self.store.cleanup_expired()
                if count > 0:
                    logger.info("storage_cleanup_completed", removed=count)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("storage_cleanup_error", error=str(e))
    
    async def get_statistics(self) -> Dict:
        """Get storage statistics"""
        # This would need to be implemented per store type
        # For now, return basic stats
        return {
            "store_type": self.store.__class__.__name__,
            "cleanup_interval": self._cleanup_interval
        }


# Global token storage manager
token_storage = TokenStorageManager()