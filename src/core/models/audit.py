from datetime import datetime
from typing import Optional, Dict, Any
from uuid import UUID, uuid4
from enum import Enum
import ipaddress

from pydantic import BaseModel, Field, field_validator, ConfigDict

from src.infrastructure.logging import get_logger

logger = get_logger(__name__)


class AuditAction(str, Enum):
    """Enumeration of audit actions"""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    CLONE = "clone"
    PUSH = "push"
    PULL = "pull"
    FETCH = "fetch"
    LOGIN = "login"
    LOGOUT = "logout"
    TOKEN_CREATE = "token_create"
    TOKEN_REVOKE = "token_revoke"
    PERMISSION_GRANT = "permission_grant"
    PERMISSION_REVOKE = "permission_revoke"


class ResourceType(str, Enum):
    """Enumeration of resource types"""
    NAMESPACE = "namespace"
    REPOSITORY = "repository"
    USER = "user"
    TOKEN = "token"
    SYSTEM = "system"


class AuditStatus(str, Enum):
    """Enumeration of audit statuses"""
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"


class AuditEntry(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        json_encoders={
            datetime: lambda v: v.isoformat(),
            UUID: lambda v: str(v)
        },
        use_enum_values=True
    )
    
    id: UUID = Field(
        default_factory=uuid4,
        description="Unique audit entry identifier"
    )
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the action occurred"
    )
    user_id: Optional[UUID] = Field(
        None,
        description="User who performed the action"
    )
    username: Optional[str] = Field(
        None,
        description="Username for reference"
    )
    action: AuditAction = Field(
        ...,
        description="Action that was performed"
    )
    resource_type: ResourceType = Field(
        ...,
        description="Type of resource affected"
    )
    resource_id: str = Field(
        ...,
        description="Identifier of the affected resource"
    )
    resource_name: Optional[str] = Field(
        None,
        description="Human-readable name of the resource"
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional action details"
    )
    ip_address: Optional[str] = Field(
        None,
        description="IP address of the client"
    )
    user_agent: Optional[str] = Field(
        None,
        max_length=512,
        description="User agent string"
    )
    correlation_id: Optional[str] = Field(
        None,
        description="Request correlation ID for tracing"
    )
    status: AuditStatus = Field(
        ...,
        description="Status of the action"
    )
    error_message: Optional[str] = Field(
        None,
        description="Error message if action failed"
    )
    duration_ms: Optional[int] = Field(
        None,
        ge=0,
        description="Duration of the operation in milliseconds"
    )
    
    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        
        try:
            # Validate IP address format
            ipaddress.ip_address(v)
            return v
        except ValueError:
            # If it's not a valid IP, might be a proxy identifier
            if v in ["unknown", "localhost"]:
                return v
            raise ValueError(f"Invalid IP address: {v}")
    
    @field_validator("details")
    @classmethod
    def validate_details(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        # Ensure details don't contain sensitive information
        sensitive_keys = {"password", "token", "secret", "key", "credential"}
        
        for key in v.keys():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                raise ValueError(f"Details cannot contain sensitive information: {key}")
        
        return v
    
    def log_to_structured(self) -> None:
        """Log the audit entry to structured logging"""
        log_data = {
            "audit_id": str(self.id),
            "user_id": str(self.user_id) if self.user_id else None,
            "username": self.username,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "status": self.status,
            "ip_address": self.ip_address,
            "correlation_id": self.correlation_id,
            "duration_ms": self.duration_ms,
        }
        
        if self.status == AuditStatus.SUCCESS:
            logger.info("audit_event", **log_data, details=self.details)
        else:
            logger.warning(
                "audit_event_failed",
                **log_data,
                error_message=self.error_message,
                details=self.details
            )
    
    @classmethod
    def create_success(
        cls,
        action: AuditAction,
        resource_type: ResourceType,
        resource_id: str,
        user_id: Optional[UUID] = None,
        **kwargs
    ) -> "AuditEntry":
        """Create a successful audit entry"""
        return cls(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            user_id=user_id,
            status=AuditStatus.SUCCESS,
            **kwargs
        )
    
    @classmethod
    def create_failure(
        cls,
        action: AuditAction,
        resource_type: ResourceType,
        resource_id: str,
        error_message: str,
        user_id: Optional[UUID] = None,
        **kwargs
    ) -> "AuditEntry":
        """Create a failed audit entry"""
        return cls(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            user_id=user_id,
            status=AuditStatus.FAILURE,
            error_message=error_message,
            **kwargs
        )
    
    def to_dict(self) -> dict:
        """Convert model to dictionary for serialization"""
        return self.model_dump(mode="json")
    
    def __str__(self) -> str:
        return f"AuditEntry({self.action} on {self.resource_type}:{self.resource_id})"
    
    def __repr__(self) -> str:
        return (
            f"<AuditEntry id='{self.id}' action='{self.action}' "
            f"resource='{self.resource_type}:{self.resource_id}' status='{self.status}'>"
        )