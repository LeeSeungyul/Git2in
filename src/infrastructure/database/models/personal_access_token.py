"""Personal access token database model."""
from sqlalchemy import String, ForeignKey, DateTime, CheckConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from uuid import UUID
from datetime import datetime
from typing import Optional, TYPE_CHECKING
from .base import UUIDModel

if TYPE_CHECKING:
    from .user import UserModel


class PersonalAccessTokenModel(UUIDModel):
    """Personal access token database model."""
    __tablename__ = "personal_access_tokens"
    
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )
    token_hash: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True
    )
    
    # Relationships
    user: Mapped["UserModel"] = relationship(
        back_populates="access_tokens"
    )
    
    __table_args__ = (
        CheckConstraint(
            "LENGTH(name) >= 1 AND LENGTH(name) <= 255",
            name="token_name_length"
        ),
    )