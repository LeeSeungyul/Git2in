"""Token revocation list management"""

import asyncio
from typing import Dict, Optional, Set, List
from datetime import datetime, timedelta
from threading import Lock
import time

from src.core.auth.models import TokenRevocation
from src.infrastructure.logging import get_logger

logger = get_logger(__name__)


class RevocationStore:
    """Abstract base for revocation storage"""
    
    async def add(self, jti: str, expires_at: datetime, reason: Optional[str] = None) -> None:
        """Add a token to revocation list"""
        raise NotImplementedError
    
    async def remove(self, jti: str) -> None:
        """Remove a token from revocation list"""
        raise NotImplementedError
    
    async def is_revoked(self, jti: str) -> bool:
        """Check if a token is revoked"""
        raise NotImplementedError
    
    async def cleanup_expired(self) -> int:
        """Remove expired revocation entries, return count removed"""
        raise NotImplementedError
    
    async def list_all(self) -> List[TokenRevocation]:
        """List all revoked tokens"""
        raise NotImplementedError
    
    async def clear(self) -> None:
        """Clear all revocations"""
        raise NotImplementedError


class InMemoryRevocationStore(RevocationStore):
    """In-memory revocation store implementation"""
    
    def __init__(self):
        self._revocations: Dict[str, TokenRevocation] = {}
        self._lock = Lock()
    
    async def add(
        self,
        jti: str,
        expires_at: datetime,
        reason: Optional[str] = None,
        revoked_by: Optional[str] = None
    ) -> None:
        """Add a token to revocation list"""
        with self._lock:
            revocation = TokenRevocation(
                jti=jti,
                expires_at=expires_at,
                reason=reason,
                revoked_by=revoked_by
            )
            self._revocations[jti] = revocation
            
            logger.info(
                "token_revoked",
                jti=jti,
                reason=reason,
                revoked_by=revoked_by
            )
    
    async def remove(self, jti: str) -> None:
        """Remove a token from revocation list"""
        with self._lock:
            if jti in self._revocations:
                del self._revocations[jti]
                logger.debug("revocation_removed", jti=jti)
    
    async def is_revoked(self, jti: str) -> bool:
        """Check if a token is revoked"""
        with self._lock:
            if jti not in self._revocations:
                return False
            
            revocation = self._revocations[jti]
            
            # Check if revocation record expired
            if revocation.is_expired():
                del self._revocations[jti]
                return False
            
            return True
    
    async def cleanup_expired(self) -> int:
        """Remove expired revocation entries"""
        with self._lock:
            expired_jtis = [
                jti for jti, rev in self._revocations.items()
                if rev.is_expired()
            ]
            
            for jti in expired_jtis:
                del self._revocations[jti]
            
            if expired_jtis:
                logger.info(
                    "expired_revocations_cleaned",
                    count=len(expired_jtis)
                )
            
            return len(expired_jtis)
    
    async def list_all(self) -> List[TokenRevocation]:
        """List all revoked tokens"""
        with self._lock:
            # Filter out expired entries
            active_revocations = [
                rev for rev in self._revocations.values()
                if not rev.is_expired()
            ]
            return active_revocations
    
    async def clear(self) -> None:
        """Clear all revocations"""
        with self._lock:
            count = len(self._revocations)
            self._revocations.clear()
            logger.info("revocations_cleared", count=count)


class RedisRevocationStore(RevocationStore):
    """Redis-backed revocation store (placeholder for future implementation)"""
    
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        # Would initialize Redis client here
        logger.info("redis_revocation_store_initialized", url=redis_url)
    
    async def add(
        self,
        jti: str,
        expires_at: datetime,
        reason: Optional[str] = None,
        revoked_by: Optional[str] = None
    ) -> None:
        """Add a token to revocation list in Redis"""
        # Implementation would use Redis SET with EXPIREAT
        raise NotImplementedError("Redis revocation store not yet implemented")
    
    async def remove(self, jti: str) -> None:
        """Remove a token from revocation list in Redis"""
        # Implementation would use Redis DEL
        raise NotImplementedError("Redis revocation store not yet implemented")
    
    async def is_revoked(self, jti: str) -> bool:
        """Check if a token is revoked in Redis"""
        # Implementation would use Redis EXISTS
        raise NotImplementedError("Redis revocation store not yet implemented")
    
    async def cleanup_expired(self) -> int:
        """Redis handles expiration automatically"""
        return 0
    
    async def list_all(self) -> List[TokenRevocation]:
        """List all revoked tokens from Redis"""
        # Implementation would use Redis SCAN
        raise NotImplementedError("Redis revocation store not yet implemented")
    
    async def clear(self) -> None:
        """Clear all revocations from Redis"""
        # Implementation would use Redis FLUSHDB or pattern delete
        raise NotImplementedError("Redis revocation store not yet implemented")


class RevocationManager:
    """High-level revocation management"""
    
    def __init__(self, store: Optional[RevocationStore] = None):
        self.store = store or InMemoryRevocationStore()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._cleanup_interval = 3600  # 1 hour
    
    async def revoke_token(
        self,
        jti: str,
        token_exp: int,
        reason: Optional[str] = None,
        revoked_by: Optional[str] = None
    ) -> None:
        """Revoke a token"""
        # Convert Unix timestamp to datetime
        expires_at = datetime.utcfromtimestamp(token_exp)
        
        await self.store.add(jti, expires_at, reason, revoked_by)
    
    async def revoke_tokens_by_user(
        self,
        user_id: str,
        token_ids: List[str],
        reason: str = "User tokens revoked"
    ) -> int:
        """Revoke multiple tokens for a user"""
        count = 0
        for jti in token_ids:
            # In a real system, would look up token expiration
            # For now, use a default expiration
            expires_at = datetime.utcnow() + timedelta(days=7)
            await self.store.add(jti, expires_at, reason, f"user:{user_id}")
            count += 1
        
        logger.info(
            "user_tokens_revoked",
            user_id=user_id,
            count=count,
            reason=reason
        )
        
        return count
    
    async def is_revoked(self, jti: str) -> bool:
        """Check if a token is revoked"""
        return await self.store.is_revoked(jti)
    
    async def list_revoked(self) -> List[TokenRevocation]:
        """List all revoked tokens"""
        return await self.store.list_all()
    
    async def clear_all(self) -> None:
        """Clear all revocations (dangerous!)"""
        await self.store.clear()
    
    async def start_cleanup_task(self) -> None:
        """Start background cleanup task"""
        if self._cleanup_task and not self._cleanup_task.done():
            return
        
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("revocation_cleanup_task_started")
    
    async def stop_cleanup_task(self) -> None:
        """Stop background cleanup task"""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            logger.info("revocation_cleanup_task_stopped")
    
    async def _cleanup_loop(self) -> None:
        """Background task to clean up expired revocations"""
        while True:
            try:
                await asyncio.sleep(self._cleanup_interval)
                count = await self.store.cleanup_expired()
                if count > 0:
                    logger.info("revocation_cleanup_completed", removed=count)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("revocation_cleanup_error", error=str(e))
    
    async def get_statistics(self) -> Dict:
        """Get revocation statistics"""
        revocations = await self.store.list_all()
        
        now = datetime.utcnow()
        stats = {
            "total_revoked": len(revocations),
            "revoked_last_hour": sum(
                1 for r in revocations
                if (now - r.revoked_at).total_seconds() < 3600
            ),
            "revoked_last_day": sum(
                1 for r in revocations
                if (now - r.revoked_at).total_seconds() < 86400
            ),
            "by_reason": {}
        }
        
        # Count by reason
        for rev in revocations:
            reason = rev.reason or "unknown"
            stats["by_reason"][reason] = stats["by_reason"].get(reason, 0) + 1
        
        return stats


# Global revocation manager instance
revocation_manager = RevocationManager()