"""Git HTTP protocol routes."""

from typing import Optional

from fastapi import APIRouter, Depends, Request, Response, HTTPException, status, Query, Path
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import structlog

from src.api.dependencies import (
    get_git_service,
    get_repository_service,
    get_git_credentials,
    get_current_user_optional
)
from src.api.models.common_models import ErrorResponse
from src.application.services.git_service import GitService
from src.application.services.repository_service import RepositoryService
from src.application.dto.user_dto import UserDTO
from src.application.dto.git_dto import GitOperationType

logger = structlog.get_logger()
router = APIRouter(tags=["git"])

# Basic auth for Git clients
basic_auth = HTTPBasic(auto_error=False)


@router.get(
    "/{owner}/{name}.git/info/refs",
    summary="Git info/refs",
    description="Git service discovery endpoint",
    response_class=Response,
    responses={
        200: {"description": "Git refs information"},
        401: {"description": "Authentication required"},
        403: {"description": "Access denied"},
        404: {"description": "Repository not found"}
    }
)
async def git_info_refs(
    request: Request,
    owner: str = Path(..., description="Repository owner"),
    name: str = Path(..., description="Repository name"),
    service: Optional[str] = Query(None, regex="^git-(upload|receive)-pack$"),
    credentials: Optional[HTTPBasicCredentials] = Depends(basic_auth),
    git_service: GitService = Depends(get_git_service),
    repository_service: RepositoryService = Depends(get_repository_service)
) -> Response:
    """Handle Git info/refs requests."""
    # Determine operation type
    if service == "git-upload-pack":
        operation = GitOperationType.CLONE
    elif service == "git-receive-pack":
        operation = GitOperationType.PUSH
    else:
        # Smart HTTP requires service parameter
        return Response(
            content="Service parameter required",
            status_code=status.HTTP_400_BAD_REQUEST
        )
    
    # Get authenticated user from credentials
    user = None
    if credentials:
        user = await get_git_credentials(credentials, git_service.auth_service)
    
    # Check repository exists and user has access
    repo_result = await repository_service.get_repository(
        owner_username=owner,
        repository_name=name,
        current_user_id=user.id if user else None
    )
    
    if not repo_result.success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )
    
    repository = repo_result.value
    
    # Check access permissions
    if operation == GitOperationType.PUSH:
        # Push requires authentication
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Basic realm=\"Git\""}
            )
        # Check write access
        if repository.owner.id != user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Write access denied"
            )
    else:
        # Clone/pull - check read access
        if repository.is_private and not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Basic realm=\"Git\""}
            )
        if repository.is_private and repository.owner.id != user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
    
    # Get refs
    result = await git_service.handle_info_refs(
        repository_id=repository.id,
        service=service,
        user_id=user.id if user else None
    )
    
    if not result.success:
        logger.error(
            "Failed to get refs",
            error=result.error,
            repo=f"{owner}/{name}",
            service=service
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve repository information"
        )
    
    git_response = result.value
    
    # Set appropriate headers
    headers = {
        "Content-Type": f"application/x-{service}-advertisement",
        "Cache-Control": "no-cache"
    }
    
    return Response(
        content=git_response.content,
        headers=headers,
        media_type=f"application/x-{service}-advertisement"
    )


@router.post(
    "/{owner}/{name}.git/git-upload-pack",
    summary="Git upload pack",
    description="Handle git clone/pull operations",
    response_class=StreamingResponse,
    responses={
        200: {"description": "Git pack data"},
        401: {"description": "Authentication required"},
        403: {"description": "Access denied"},
        404: {"description": "Repository not found"}
    }
)
async def git_upload_pack(
    request: Request,
    owner: str = Path(..., description="Repository owner"),
    name: str = Path(..., description="Repository name"),
    credentials: Optional[HTTPBasicCredentials] = Depends(basic_auth),
    git_service: GitService = Depends(get_git_service),
    repository_service: RepositoryService = Depends(get_repository_service)
) -> StreamingResponse:
    """Handle Git upload-pack (clone/pull) requests."""
    # Get authenticated user from credentials
    user = None
    if credentials:
        user = await get_git_credentials(credentials, git_service.auth_service)
    
    # Check repository exists and user has access
    repo_result = await repository_service.get_repository(
        owner_username=owner,
        repository_name=name,
        current_user_id=user.id if user else None
    )
    
    if not repo_result.success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )
    
    repository = repo_result.value
    
    # Check read access
    if repository.is_private and not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Basic realm=\"Git\""}
        )
    if repository.is_private and repository.owner.id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Read request body
    body = await request.body()
    
    # Handle upload-pack
    result = await git_service.handle_upload_pack(
        repository_id=repository.id,
        data=body,
        user_id=user.id if user else None
    )
    
    if not result.success:
        logger.error(
            "Upload pack failed",
            error=result.error,
            repo=f"{owner}/{name}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Git operation failed"
        )
    
    git_response = result.value
    
    # Return streaming response
    return StreamingResponse(
        iter([git_response.content]),
        media_type="application/x-git-upload-pack-result",
        headers={
            "Cache-Control": "no-cache"
        }
    )


@router.post(
    "/{owner}/{name}.git/git-receive-pack",
    summary="Git receive pack",
    description="Handle git push operations",
    response_class=StreamingResponse,
    responses={
        200: {"description": "Git pack result"},
        401: {"description": "Authentication required"},
        403: {"description": "Access denied"},
        404: {"description": "Repository not found"}
    }
)
async def git_receive_pack(
    request: Request,
    owner: str = Path(..., description="Repository owner"),
    name: str = Path(..., description="Repository name"),
    credentials: Optional[HTTPBasicCredentials] = Depends(basic_auth),
    git_service: GitService = Depends(get_git_service),
    repository_service: RepositoryService = Depends(get_repository_service)
) -> StreamingResponse:
    """Handle Git receive-pack (push) requests."""
    # Push requires authentication
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Basic realm=\"Git\""}
        )
    
    # Get authenticated user
    user = await get_git_credentials(credentials, git_service.auth_service)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic realm=\"Git\""}
        )
    
    # Check repository exists
    repo_result = await repository_service.get_repository(
        owner_username=owner,
        repository_name=name,
        current_user_id=user.id
    )
    
    if not repo_result.success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )
    
    repository = repo_result.value
    
    # Check write access
    if repository.owner.id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write access denied"
        )
    
    # Read request body
    body = await request.body()
    
    # Handle receive-pack
    result = await git_service.handle_receive_pack(
        repository_id=repository.id,
        data=body,
        user_id=user.id
    )
    
    if not result.success:
        logger.error(
            "Receive pack failed",
            error=result.error,
            repo=f"{owner}/{name}",
            user=user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Git operation failed"
        )
    
    git_response = result.value
    
    # Log successful push
    logger.info(
        "Git push completed",
        repo=f"{owner}/{name}",
        user=user.username
    )
    
    # Return streaming response
    return StreamingResponse(
        iter([git_response.content]),
        media_type="application/x-git-receive-pack-result",
        headers={
            "Cache-Control": "no-cache"
        }
    )


# Additional Git endpoints that some clients may use

@router.head(
    "/{owner}/{name}.git/info/refs",
    summary="Git info/refs HEAD",
    description="HEAD request for Git service discovery",
    response_class=Response,
    include_in_schema=False
)
async def git_info_refs_head(
    owner: str = Path(..., description="Repository owner"),
    name: str = Path(..., description="Repository name"),
    repository_service: RepositoryService = Depends(get_repository_service)
) -> Response:
    """Handle HEAD requests for info/refs."""
    # Check if repository exists
    repo_result = await repository_service.get_repository(
        owner_username=owner,
        repository_name=name,
        current_user_id=None
    )
    
    if not repo_result.success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND
        )
    
    return Response(
        status_code=status.HTTP_200_OK,
        headers={
            "Content-Type": "text/plain"
        }
    )


@router.get(
    "/{owner}/{name}.git/HEAD",
    summary="Get default branch",
    description="Get repository default branch reference",
    response_class=Response,
    include_in_schema=False
)
async def git_head(
    owner: str = Path(..., description="Repository owner"),
    name: str = Path(..., description="Repository name"),
    credentials: Optional[HTTPBasicCredentials] = Depends(basic_auth),
    git_service: GitService = Depends(get_git_service),
    repository_service: RepositoryService = Depends(get_repository_service)
) -> Response:
    """Get repository HEAD reference."""
    # Get authenticated user if credentials provided
    user = None
    if credentials:
        user = await get_git_credentials(credentials, git_service.auth_service)
    
    # Check repository exists and user has access
    repo_result = await repository_service.get_repository(
        owner_username=owner,
        repository_name=name,
        current_user_id=user.id if user else None
    )
    
    if not repo_result.success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND
        )
    
    repository = repo_result.value
    
    # Check access for private repos
    if repository.is_private and not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Basic realm=\"Git\""}
        )
    
    # Return default branch ref
    return Response(
        content=f"ref: refs/heads/{repository.default_branch}\n",
        media_type="text/plain"
    )