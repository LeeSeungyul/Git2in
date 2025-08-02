"""User database model."""
from sqlalchemy import String, Boolean, CheckConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import List, TYPE_CHECKING
from .base import UUIDModel

if TYPE_CHECKING:
    from .repository import RepositoryModel
    from .personal_access_token import PersonalAccessTokenModel
    from .ssh_key import SSHKeyModel


class UserModel(UUIDModel):
    """User database model."""
    __tablename__ = "users"
    
    username: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False
    )
    is_admin: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )
    
    # Relationships
    repositories: Mapped[List["RepositoryModel"]] = relationship(
        back_populates="owner",
        cascade="all, delete-orphan"
    )
    access_tokens: Mapped[List["PersonalAccessTokenModel"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan"
    )
    ssh_keys: Mapped[List["SSHKeyModel"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan"
    )
    
    __table_args__ = (
        CheckConstraint(
            "username ~ '^[a-zA-Z0-9_-]{3,32}$'",
            name="username_format"
        ),
        CheckConstraint(
            "email ~ '^[^@]+@[^@]+\.[^@]+$'",
            name="email_format"
        ),
    )