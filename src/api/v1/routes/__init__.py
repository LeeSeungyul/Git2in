"""API v1 routes"""

from .namespaces import router as namespaces_router
from .repositories import router as repositories_router
from .users import router as users_router
from .tokens import router as tokens_router

__all__ = [
    "namespaces_router",
    "repositories_router", 
    "users_router",
    "tokens_router"
]