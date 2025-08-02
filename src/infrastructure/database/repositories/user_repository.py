"""User data access repository."""
from typing import Optional
from uuid import UUID
from sqlalchemy import select, exists
from sqlalchemy.ext.asyncio import AsyncSession

from src.infrastructure.database.models.user import UserModel
from src.infrastructure.database.repositories.base import BaseRepository


class UserRepository(BaseRepository[UserModel]):
    """User data access only."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, UserModel)
    
    async def find_by_username(self, username: str) -> Optional[UserModel]:
        """Find user by username."""
        stmt = select(UserModel).where(UserModel.username == username)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def find_by_email(self, email: str) -> Optional[UserModel]:
        """Find user by email."""
        stmt = select(UserModel).where(UserModel.email == email)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def exists_by_username(self, username: str) -> bool:
        """Check if username exists."""
        stmt = select(exists().where(UserModel.username == username))
        result = await self.session.execute(stmt)
        return result.scalar()
    
    async def exists_by_email(self, email: str) -> bool:
        """Check if email exists."""
        stmt = select(exists().where(UserModel.email == email))
        result = await self.session.execute(stmt)
        return result.scalar()