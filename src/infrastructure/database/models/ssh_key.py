"""SSH key database model."""
from sqlalchemy import String, ForeignKey, CheckConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from uuid import UUID
from typing import TYPE_CHECKING
from .base import UUIDModel

if TYPE_CHECKING:
    from .user import UserModel


class SSHKeyModel(UUIDModel):
    """SSH key database model."""
    __tablename__ = "ssh_keys"
    
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )
    public_key: Mapped[str] = mapped_column(
        String,
        nullable=False
    )
    fingerprint: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )
    
    # Relationships
    user: Mapped["UserModel"] = relationship(
        back_populates="ssh_keys"
    )
    
    __table_args__ = (
        CheckConstraint(
            "LENGTH(name) >= 1 AND LENGTH(name) <= 255",
            name="key_name_length"
        ),
    )