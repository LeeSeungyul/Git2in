from fastapi import APIRouter

from src.api import git_http
from src.api.auth import routes as auth_routes
from src.api.v1.router import api_v1_router

api_router = APIRouter()

# Include authentication routes
api_router.include_router(auth_routes.router)

# Include Git HTTP routes
api_router.include_router(git_http.router)

# Include v1 API routes
api_router.include_router(api_v1_router)


@api_router.get("/version")
async def get_version():
    return {"version": "0.1.0", "api_version": "v1"}