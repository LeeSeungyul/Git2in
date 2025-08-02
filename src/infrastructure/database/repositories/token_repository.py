"""Token data access repository."""
from typing import Optional, List
from uuid import UUID
from datetime import datetime
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession

from src.infrastructure.database.models.personal_access_token import PersonalAccessTokenModel
from src.infrastructure.database.repositories.base import BaseRepository


class TokenRepository(BaseRepository[PersonalAccessTokenModel]):
    """Token data access only."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, PersonalAccessTokenModel)
    
    async def find_by_token_hash(self, token_hash: str) -> Optional[PersonalAccessTokenModel]:
        """Find token by hash."""
        stmt = select(PersonalAccessTokenModel).where(
            PersonalAccessTokenModel.token_hash == token_hash
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def find_by_user(self, user_id: UUID) -> List[PersonalAccessTokenModel]:
        """Find all tokens for a user."""
        stmt = (
            select(PersonalAccessTokenModel)
            .where(PersonalAccessTokenModel.user_id == user_id)
            .order_by(PersonalAccessTokenModel.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
    
    async def delete_expired(self) -> int:
        """Delete all expired tokens."""
        stmt = delete(PersonalAccessTokenModel).where(
            PersonalAccessTokenModel.expires_at < datetime.utcnow()
        )
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount
    
    async def update_last_used(self, id: UUID, timestamp: datetime) -> bool:
        """Update token last used timestamp."""
        stmt = (
            update(PersonalAccessTokenModel)
            .where(PersonalAccessTokenModel.id == id)
            .values(last_used_at=timestamp)
        )
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount > 0