"""Repository database model."""
from sqlalchemy import String, Boolean, CheckConstraint, ForeignKey, BigInteger, DateTime, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from uuid import UUID
from datetime import datetime
from typing import Optional, TYPE_CHECKING
from .base import UUIDModel

if TYPE_CHECKING:
    from .user import UserModel


class RepositoryModel(UUIDModel):
    """Repository database model."""
    __tablename__ = "repositories"
    
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True
    )
    owner_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )
    description: Mapped[Optional[str]] = mapped_column(
        String,
        nullable=True
    )
    is_private: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True
    )
    default_branch: Mapped[str] = mapped_column(
        String(255),
        default="main",
        nullable=False
    )
    size_bytes: Mapped[int] = mapped_column(
        BigInteger,
        default=0,
        nullable=False
    )
    last_push_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    
    # Relationships
    owner: Mapped["UserModel"] = relationship(
        back_populates="repositories"
    )
    
    __table_args__ = (
        CheckConstraint(
            "name ~ '^[a-zA-Z0-9][a-zA-Z0-9-_.]*$'",
            name="repo_name_format"
        ),
        CheckConstraint(
            "LENGTH(name) >= 1 AND LENGTH(name) <= 255",
            name="repo_name_length"
        ),
        UniqueConstraint("owner_id", "name", name="unique_owner_repo_name"),
    )