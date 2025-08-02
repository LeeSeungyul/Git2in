"""Database connection management module."""
from typing import Optional
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    create_async_engine,
    async_sessionmaker
)
from sqlalchemy.pool import NullPool, QueuePool
import logging

logger = logging.getLogger(__name__)


class DatabaseConnection:
    """Manages database connections only."""
    
    def __init__(
        self,
        database_url: str,
        pool_size: int = 20,
        max_overflow: int = 40,
        pool_timeout: int = 30,
        echo: bool = False
    ):
        self._engine: Optional[AsyncEngine] = None
        self._sessionmaker: Optional[async_sessionmaker] = None
        self.database_url = self._convert_to_async_url(database_url)
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.pool_timeout = pool_timeout
        self.echo = echo
    
    def _convert_to_async_url(self, url: str) -> str:
        """Convert sync database URL to async."""
        if url.startswith("sqlite"):
            return url.replace("sqlite://", "sqlite+aiosqlite://")
        elif url.startswith("postgresql://"):
            return url.replace("postgresql://", "postgresql+asyncpg://")
        return url
    
    async def connect(self) -> None:
        """Initialize database connection."""
        if self._engine is not None:
            return
        
        # Choose pool class based on database type
        if "sqlite" in self.database_url:
            poolclass = NullPool
        else:
            poolclass = QueuePool
        
        self._engine = create_async_engine(
            self.database_url,
            echo=self.echo,
            poolclass=poolclass,
            pool_size=self.pool_size,
            max_overflow=self.max_overflow,
            pool_timeout=self.pool_timeout,
            pool_pre_ping=True,  # Verify connections before use
        )
        
        self._sessionmaker = async_sessionmaker(
            self._engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        logger.info("Database connection established")
    
    async def disconnect(self) -> None:
        """Close database connection."""
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._sessionmaker = None
            logger.info("Database connection closed")
    
    @asynccontextmanager
    async def get_session(self):
        """Get database session."""
        if self._sessionmaker is None:
            raise RuntimeError("Database not connected")
        
        async with self._sessionmaker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()
    
    @property
    def engine(self) -> AsyncEngine:
        """Get database engine."""
        if self._engine is None:
            raise RuntimeError("Database not connected")
        return self._engine