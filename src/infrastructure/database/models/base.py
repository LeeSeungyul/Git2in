"""Base model classes for database entities."""
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import DateTime, func
from datetime import datetime
from uuid import UUID, uuid4


class Base(DeclarativeBase):
    """Base model class for all database models."""
    pass


class TimestampedModel(Base):
    """Base model with timestamps."""
    __abstract__ = True
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )


class UUIDModel(TimestampedModel):
    """Base model with UUID primary key and timestamps."""
    __abstract__ = True
    
    id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=uuid4
    )