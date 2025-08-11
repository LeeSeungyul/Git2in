"""FastAPI routes for Git Smart HTTP Protocol"""

import asyncio
from pathlib import Path
from typing import AsyncIterator, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse

from src.api.auth.dependencies import OptionalToken
from src.api.authorization.dependencies import (RequireRepositoryPermission,
                                                require_repo_read,
                                                require_repo_write)
from src.core.authorization.models import Action
from src.core.exceptions import AuthorizationError, NotFoundError
from src.core.models import Repository
from src.infrastructure.audit.logger import (AuditAction, AuditResult,
                                             audit_logger)
from src.infrastructure.filesystem import FilesystemManager
from src.infrastructure.git_protocol import (GitContentType, GitHeaders,
                                             GitProtocolValidator, GitService,
                                             PktLineParser)
from src.infrastructure.git_subprocess import (GitBackendProcess,
                                               GitBackendStreamProcessor)
from src.infrastructure.hooks import HookContext, HookEvent, hook_manager
from src.infrastructure.logging import get_logger
from src.infrastructure.middleware.correlation import get_correlation_id

logger = get_logger(__name__)

router = APIRouter(prefix="/git", tags=["git"])


# Dependency to get filesystem manager
def get_filesystem_manager() -> FilesystemManager:
    return FilesystemManager()


@router.get("/{namespace}/{repo_name}/info/refs")
async def get_info_refs(
    namespace: str,
    repo_name: str,
    service: Optional[str] = Query(None),
    request: Request = None,
    fs_manager: FilesystemManager = Depends(get_filesystem_manager),
    token: OptionalToken = None,
):
    """Handle Git info/refs endpoint for service discovery"""

    # Clean repo name (remove .git suffix if present)
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]

    # Get repository path
    repo_path = fs_manager.get_repository_path(namespace, f"{repo_name}.git")

    # Check if repository exists
    if not repo_path.exists():
        logger.warning("git_info_refs_not_found", namespace=namespace, repo=repo_name)
        raise HTTPException(status_code=404, detail="Repository not found")

    # Validate repository structure
    if not fs_manager.verify_repository_structure(namespace, repo_name):
        logger.error("git_info_refs_invalid_repo", namespace=namespace, repo=repo_name)
        raise HTTPException(status_code=500, detail="Invalid repository structure")

    # Parse service parameter
    git_service = None
    if service:
        try:
            git_service = GitProtocolValidator.validate_service(service)
        except Exception:
            raise HTTPException(status_code=400, detail=f"Invalid service: {service}")

    # Check if this is a smart HTTP request
    is_smart = git_service is not None and GitHeaders.is_smart_request(
        dict(request.headers)
    )

    if not is_smart:
        # Dumb HTTP protocol - return plain text refs
        logger.info("git_info_refs_dumb", namespace=namespace, repo=repo_name)
        # For dumb protocol, we would need to read the actual refs
        # This is rarely used anymore
        raise HTTPException(status_code=403, detail="Dumb HTTP protocol not supported")

    # Smart HTTP protocol
    logger.info(
        "git_info_refs_smart", namespace=namespace, repo=repo_name, service=service
    )

    # Log to audit
    audit_logger.log_success(
        action=AuditAction.FETCH,
        user_id=token.sub if token else None,
        resource=f"{namespace}/{repo_name}",
        resource_type="repository",
        client_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        details={"operation": "info_refs", "service": service},
    )

    # Execute git-http-backend
    async def stream_response():
        # First, send service advertisement
        yield GitHeaders.format_service_advertisement(git_service)

        # Then proxy to git-http-backend
        backend = GitBackendProcess(repo_path, timeout=30.0)

        async with backend.execute(
            method="GET",
            path_info=f"/{namespace}/{repo_name}.git/info/refs",
            query_string=f"service={service}",
            remote_addr=request.client.host if request.client else "",
            http_headers=dict(request.headers),
        ):
            # Read and stream output
            async for chunk in backend.read_output():
                yield chunk

            # Check for errors
            stderr = await backend.read_stderr()
            if stderr:
                logger.warning("git_backend_stderr", stderr=stderr)

            return_code = await backend.wait()
            if return_code != 0:
                logger.error(
                    "git_backend_error", return_code=return_code, stderr=stderr
                )

    # Return streaming response
    return StreamingResponse(
        stream_response(),
        media_type=GitContentType.for_service_advertisement(git_service),
        headers={
            "Cache-Control": "no-cache",
            "Expires": "Fri, 01 Jan 1980 00:00:00 GMT",
            "Pragma": "no-cache",
        },
    )


@router.post("/{namespace}/{repo_name}/git-upload-pack")
async def post_upload_pack(
    namespace: str,
    repo_name: str,
    request: Request,
    fs_manager: FilesystemManager = Depends(get_filesystem_manager),
    token: OptionalToken = None,
):
    """Handle git-upload-pack for fetch/clone operations"""

    # Clean repo name
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]

    # Get repository path
    repo_path = fs_manager.get_repository_path(namespace, f"{repo_name}.git")

    # Check if repository exists
    if not repo_path.exists():
        raise HTTPException(status_code=404, detail="Repository not found")

    # Validate content type
    content_type = request.headers.get("content-type", "")
    if not GitHeaders.validate_content_type(
        content_type, GitContentType.UPLOAD_PACK_REQUEST
    ):
        logger.warning("git_upload_pack_bad_content_type", content_type=content_type)

    logger.info(
        "git_upload_pack",
        namespace=namespace,
        repo=repo_name,
        content_length=request.headers.get("content-length"),
    )

    # Create repository object for hooks
    repo = Repository(
        name=repo_name,
        namespace_name=namespace,
        owner_id="00000000-0000-0000-0000-000000000000",  # TODO: Get from auth
    )

    # Execute pre-upload hooks
    hook_context = HookContext(
        event=HookEvent.PRE_UPLOAD,
        repository=repo,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        correlation_id=get_correlation_id(),
    )

    hook_context = await hook_manager.execute_hooks(
        HookEvent.PRE_UPLOAD, hook_context, stop_on_error=True
    )

    if hook_context.has_errors():
        logger.warning("git_upload_pack_blocked_by_hook", errors=hook_context.errors)
        raise HTTPException(status_code=403, detail="Access denied by hook")

    # Log audit event
    audit_logger.log_success(
        action=AuditAction.FETCH,
        user_id=token.sub if token else None,
        resource=f"{namespace}/{repo_name}",
        resource_type="repository",
        client_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        details={"operation": "upload_pack"},
    )

    # Stream request body to git-http-backend and stream response back
    async def stream_response():
        backend = GitBackendProcess(
            repo_path,
            timeout=300.0,  # 5 minutes for large repos
            max_memory_mb=1024,  # 1GB for pack operations
        )

        async with backend.execute(
            method="POST",
            path_info=f"/{namespace}/{repo_name}.git/git-upload-pack",
            content_type=content_type,
            content_length=int(request.headers.get("content-length", 0)),
            remote_addr=request.client.host if request.client else "",
            http_headers=dict(request.headers),
        ):
            # Stream request body to backend
            async def forward_input():
                async for chunk in request.stream():
                    await backend.write_input(chunk)
                await backend.close_input()

            # Start forwarding input in background
            input_task = asyncio.create_task(forward_input())

            try:
                # Parse CGI headers from output
                output_stream = backend.read_output()
                headers, body_stream = (
                    await GitBackendStreamProcessor.parse_cgi_headers(output_stream)
                )

                # Stream body
                async for chunk in body_stream:
                    yield chunk

            finally:
                # Ensure input task completes
                await input_task

            # Check for errors
            stderr = await backend.read_stderr()
            if stderr:
                logger.warning("git_upload_pack_stderr", stderr=stderr)

            return_code = await backend.wait()
            if return_code != 0:
                logger.error(
                    "git_upload_pack_error", return_code=return_code, stderr=stderr
                )

            # Execute post-upload hooks
            post_hook_context = HookContext(
                event=HookEvent.POST_UPLOAD,
                repository=repo,
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                correlation_id=get_correlation_id(),
                return_code=return_code,
            )

            await hook_manager.execute_hooks(HookEvent.POST_UPLOAD, post_hook_context)

    return StreamingResponse(
        stream_response(),
        media_type=GitContentType.UPLOAD_PACK_RESULT,
        headers={"Cache-Control": "no-cache"},
    )


@router.post("/{namespace}/{repo_name}/git-receive-pack")
async def post_receive_pack(
    namespace: str,
    repo_name: str,
    request: Request,
    fs_manager: FilesystemManager = Depends(get_filesystem_manager),
    _: None = Depends(require_repo_write),  # Require write permission for push
):
    """Handle git-receive-pack for push operations"""

    # Clean repo name
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]

    # Get repository path
    repo_path = fs_manager.get_repository_path(namespace, f"{repo_name}.git")

    # Check if repository exists
    if not repo_path.exists():
        raise HTTPException(status_code=404, detail="Repository not found")

    # Validate content type
    content_type = request.headers.get("content-type", "")
    if not GitHeaders.validate_content_type(
        content_type, GitContentType.RECEIVE_PACK_REQUEST
    ):
        logger.warning("git_receive_pack_bad_content_type", content_type=content_type)

    logger.info(
        "git_receive_pack",
        namespace=namespace,
        repo=repo_name,
        content_length=request.headers.get("content-length"),
    )

    # Log audit event
    audit_logger.log_success(
        action=AuditAction.PUSH,
        user_id="system",  # Will be updated when token auth is integrated
        resource=f"{namespace}/{repo_name}",
        resource_type="repository",
        client_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        details={"operation": "receive_pack"},
    )

    # Stream request body to git-http-backend and stream response back
    async def stream_response():
        backend = GitBackendProcess(
            repo_path,
            timeout=300.0,  # 5 minutes for large pushes
            max_memory_mb=1024,  # 1GB for pack operations
        )

        async with backend.execute(
            method="POST",
            path_info=f"/{namespace}/{repo_name}.git/git-receive-pack",
            content_type=content_type,
            content_length=int(request.headers.get("content-length", 0)),
            remote_addr=request.client.host if request.client else "",
            http_headers=dict(request.headers),
        ):
            # Stream request body to backend
            async def forward_input():
                async for chunk in request.stream():
                    await backend.write_input(chunk)
                await backend.close_input()

            # Start forwarding input in background
            input_task = asyncio.create_task(forward_input())

            try:
                # Parse CGI headers from output
                output_stream = backend.read_output()
                headers, body_stream = (
                    await GitBackendStreamProcessor.parse_cgi_headers(output_stream)
                )

                # Stream body
                async for chunk in body_stream:
                    yield chunk

            finally:
                # Ensure input task completes
                await input_task

            # Check for errors
            stderr = await backend.read_stderr()
            if stderr:
                logger.warning("git_receive_pack_stderr", stderr=stderr)

            return_code = await backend.wait()
            if return_code != 0:
                logger.error(
                    "git_receive_pack_error", return_code=return_code, stderr=stderr
                )

    return StreamingResponse(
        stream_response(),
        media_type=GitContentType.RECEIVE_PACK_RESULT,
        headers={"Cache-Control": "no-cache"},
    )
