"""Base DTO classes for the application layer.

This module provides base classes and protocols for Data Transfer Objects (DTOs)
used in the application layer.
"""

from abc import ABC
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable, Any, Dict, Type, TypeVar
from uuid import UUID

T = TypeVar('T')


@runtime_checkable
class DTOProtocol(Protocol):
    """Protocol for all DTOs in the application layer."""
    
    @classmethod
    def from_model(cls: Type[T], model: Any) -> T:
        """Create DTO instance from a database model.
        
        Args:
            model: Database model instance
            
        Returns:
            DTO instance
        """
        ...
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert DTO to dictionary representation.
        
        Returns:
            Dictionary representation of the DTO
        """
        ...


@dataclass
class BaseDTO(ABC):
    """Abstract base class for DTOs with common functionality."""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert DTO to dictionary representation.
        
        Returns:
            Dictionary representation of the DTO
        """
        from dataclasses import asdict
        return asdict(self)


@dataclass
class TimestampedDTO(BaseDTO):
    """Base DTO for entities with timestamps."""
    created_at: datetime
    updated_at: datetime


@dataclass 
class IdentifiableDTO(BaseDTO):
    """Base DTO for entities with UUID identifiers."""
    id: UUID