"""SSH key data access repository."""
from typing import Optional, List
from uuid import UUID
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.infrastructure.database.models.ssh_key import SSHKeyModel
from src.infrastructure.database.repositories.base import BaseRepository


class SSHKeyRepository(BaseRepository[SSHKeyModel]):
    """SSH key data access only."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, SSHKeyModel)
    
    async def find_by_fingerprint(self, fingerprint: str) -> Optional[SSHKeyModel]:
        """Find SSH key by fingerprint."""
        stmt = select(SSHKeyModel).where(
            SSHKeyModel.fingerprint == fingerprint
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def find_by_user(self, user_id: UUID) -> List[SSHKeyModel]:
        """Find all SSH keys for a user."""
        stmt = (
            select(SSHKeyModel)
            .where(SSHKeyModel.user_id == user_id)
            .order_by(SSHKeyModel.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())