"""Repository data access for Git repositories."""
from typing import Optional, List
from uuid import UUID
from datetime import datetime
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.infrastructure.database.models.repository import RepositoryModel
from src.infrastructure.database.repositories.base import BaseRepository


class RepositoryRepository(BaseRepository[RepositoryModel]):
    """Repository data access only."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, RepositoryModel)
    
    async def find_by_owner_and_name(
        self, 
        owner_id: UUID, 
        name: str
    ) -> Optional[RepositoryModel]:
        """Find repository by owner and name."""
        stmt = select(RepositoryModel).where(
            RepositoryModel.owner_id == owner_id,
            RepositoryModel.name == name
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def find_by_owner(
        self, 
        owner_id: UUID, 
        offset: int = 0, 
        limit: int = 100
    ) -> List[RepositoryModel]:
        """Find repositories by owner with pagination."""
        stmt = (
            select(RepositoryModel)
            .where(RepositoryModel.owner_id == owner_id)
            .offset(offset)
            .limit(limit)
            .order_by(RepositoryModel.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
    
    async def update_size(self, id: UUID, size_bytes: int) -> bool:
        """Update repository size."""
        stmt = (
            update(RepositoryModel)
            .where(RepositoryModel.id == id)
            .values(size_bytes=size_bytes)
        )
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount > 0
    
    async def update_last_push(self, id: UUID, timestamp: datetime) -> bool:
        """Update repository last push timestamp."""
        stmt = (
            update(RepositoryModel)
            .where(RepositoryModel.id == id)
            .values(last_push_at=timestamp)
        )
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount > 0