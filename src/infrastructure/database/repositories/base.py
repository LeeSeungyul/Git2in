"""Base repository implementation with common CRUD operations."""
from abc import ABC, abstractmethod
from typing import Optional, List, TypeVar, Generic, Type
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, exists
from sqlalchemy.exc import IntegrityError

T = TypeVar('T')


class BaseRepository(ABC, Generic[T]):
    """Base repository implementation with common CRUD operations."""
    
    def __init__(self, session: AsyncSession, model_class: Type[T]):
        self.session = session
        self.model_class = model_class
    
    async def find_by_id(self, id: UUID) -> Optional[T]:
        """Find entity by ID."""
        result = await self.session.get(self.model_class, id)
        return result
    
    async def find_all(self, offset: int = 0, limit: int = 100) -> List[T]:
        """Find all entities with pagination."""
        stmt = select(self.model_class).offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
    
    async def save(self, entity: T) -> T:
        """Save entity (create or update)."""
        try:
            self.session.add(entity)
            await self.session.flush()
            return entity
        except IntegrityError as e:
            await self.session.rollback()
            raise RepositoryError(f"Failed to save entity: {str(e)}")
    
    async def delete(self, id: UUID) -> bool:
        """Delete entity by ID."""
        entity = await self.find_by_id(id)
        if entity:
            await self.session.delete(entity)
            await self.session.flush()
            return True
        return False
    
    async def exists(self, id: UUID) -> bool:
        """Check if entity exists."""
        stmt = exists(self.model_class).where(self.model_class.id == id)
        result = await self.session.execute(select(stmt))
        return result.scalar()


class RepositoryError(Exception):
    """Repository operation error."""
    pass