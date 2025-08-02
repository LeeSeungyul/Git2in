"""Common type definitions for Git2in"""

from typing import NewType, TypeVar, Protocol
from uuid import UUID
from datetime import datetime

# Type aliases
UserId = NewType("UserId", UUID)
RepositoryId = NewType("RepositoryId", UUID)
TokenId = NewType("TokenId", UUID)

# Generic types
EntityT = TypeVar("EntityT")

# Protocols
class Identifiable(Protocol):
    """Protocol for entities with an ID"""
    id: UUID

class Timestamped(Protocol):
    """Protocol for entities with timestamps"""
    created_at: datetime
    updated_at: datetime