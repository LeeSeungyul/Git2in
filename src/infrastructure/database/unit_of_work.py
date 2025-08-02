"""Unit of Work pattern for transaction management."""
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from .repositories.user_repository import UserRepository
from .repositories.repository_repository import RepositoryRepository
from .repositories.token_repository import TokenRepository
from .repositories.ssh_key_repository import SSHKeyRepository


class UnitOfWork:
    """Unit of Work pattern for transaction management."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self._users: Optional[UserRepository] = None
        self._repositories: Optional[RepositoryRepository] = None
        self._tokens: Optional[TokenRepository] = None
        self._ssh_keys: Optional[SSHKeyRepository] = None
    
    @property
    def users(self) -> UserRepository:
        """Get user repository."""
        if self._users is None:
            self._users = UserRepository(self.session)
        return self._users
    
    @property
    def repositories(self) -> RepositoryRepository:
        """Get repository repository."""
        if self._repositories is None:
            self._repositories = RepositoryRepository(self.session)
        return self._repositories
    
    @property
    def tokens(self) -> TokenRepository:
        """Get token repository."""
        if self._tokens is None:
            self._tokens = TokenRepository(self.session)
        return self._tokens
    
    @property
    def ssh_keys(self) -> SSHKeyRepository:
        """Get SSH key repository."""
        if self._ssh_keys is None:
            self._ssh_keys = SSHKeyRepository(self.session)
        return self._ssh_keys
    
    async def commit(self) -> None:
        """Commit transaction."""
        await self.session.commit()
    
    async def rollback(self) -> None:
        """Rollback transaction."""
        await self.session.rollback()
    
    async def __aenter__(self):
        """Enter transaction context."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit transaction context."""
        if exc_type is not None:
            await self.rollback()
        else:
            await self.commit()