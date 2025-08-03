"""Git protocol operations service.

This service handles Git protocol operations including clone, pull, and push
by orchestrating Core Git components with authentication and repository services.
"""

from typing import AsyncIterator, Optional, Callable, Tuple
from pathlib import Path
from uuid import UUID
import structlog

from src.core.git.upload_pack_service import GitUploadPackService
from src.core.git.receive_pack_service import GitReceivePackService
from src.core.git.command_executor import GitCommandExecutor
from src.core.git.git_types import GitService as GitServiceEnum
from src.core.repository.path_resolver import RepositoryPathResolver
from src.infrastructure.database.unit_of_work import UnitOfWork
from src.infrastructure.http.request_parser import GitHttpRequestParser
from src.application.services.base import ServiceBase
from src.application.services.auth_service import AuthService
from src.application.services.repository_service import RepositoryService
from src.application.dto.common_dto import Result, ErrorCode
from src.application.dto.repository_dto import GitServiceType, GitOperationRequest
from src.application.exceptions.service_exceptions import (
    AuthenticationError,
    AuthorizationError,
    NotFoundError
)

logger = structlog.get_logger()


class GitService(ServiceBase):
    """Service for Git protocol operations.
    
    Handles Git HTTP protocol operations including info/refs, upload-pack,
    and receive-pack by coordinating authentication, permissions, and Git commands.
    """
    
    def __init__(
        self,
        auth_service: AuthService,
        repository_service: RepositoryService,
        upload_pack_service: GitUploadPackService,
        receive_pack_service: GitReceivePackService,
        path_resolver: RepositoryPathResolver,
        request_parser: GitHttpRequestParser,
        unit_of_work_factory: Callable[[], UnitOfWork]
    ):
        """Initialize git service.
        
        Args:
            auth_service: Authentication service
            repository_service: Repository management service
            upload_pack_service: Git upload-pack service (clone/pull)
            receive_pack_service: Git receive-pack service (push)
            path_resolver: Repository path resolver
            request_parser: Git HTTP request parser
            unit_of_work_factory: Factory for creating unit of work instances
        """
        super().__init__()
        self.auth_service = auth_service
        self.repository_service = repository_service
        self.upload_pack_service = upload_pack_service
        self.receive_pack_service = receive_pack_service
        self.path_resolver = path_resolver
        self.request_parser = request_parser
        self.unit_of_work_factory = unit_of_work_factory
    
    async def initialize(self) -> None:
        """Initialize service resources."""
        self.logger.info("GitService initialized")
    
    async def cleanup(self) -> None:
        """Cleanup service resources."""
        self.logger.info("GitService cleanup")
    
    async def handle_info_refs(
        self,
        repo_path: str,
        service: GitServiceType,
        auth_header: Optional[str] = None
    ) -> Result[bytes]:
        """Handle git info/refs request.
        
        Args:
            repo_path: Repository path from URL (e.g., "owner/repo.git")
            service: Git service type (upload-pack or receive-pack)
            auth_header: Optional authorization header
            
        Returns:
            Result containing refs advertisement or error
        """
        try:
            # Parse repository path
            parsed = self.request_parser.parse_repository_path(repo_path)
            if not parsed:
                return Result.fail(
                    "Invalid repository path",
                    ErrorCode.NOT_FOUND
                )
            
            owner, repo_name = parsed
            repo_name = repo_name.replace('.git', '')
            
            # Get repository
            repo_result = await self.repository_service.get_repository(
                owner,
                repo_name,
                await self._get_user_id_from_auth(auth_header)
            )
            
            if not repo_result.success:
                return repo_result
            
            repo = repo_result.value
            
            # Check access permissions
            access_result = await self._check_repository_access(
                repo.id,
                service == GitServiceType.RECEIVE_PACK,
                auth_header
            )
            
            if not access_result.success:
                return access_result
            
            # Get repository filesystem path
            fs_path = self.path_resolver.get_repository_path(
                repo.owner.username,
                repo.name
            )
            
            # Generate refs advertisement
            if service == GitServiceType.UPLOAD_PACK:
                refs_data = await self.upload_pack_service.advertise_refs(fs_path)
            else:
                refs_data = await self.receive_pack_service.advertise_refs(fs_path)
            
            # Format response with service capabilities
            response = self._format_info_refs_response(refs_data, service)
            
            self.logger.info(
                "Handled info/refs",
                repo=f"{owner}/{repo_name}",
                service=service.value
            )
            
            return Result.ok(response)
            
        except Exception as e:
            self.logger.error(
                "Failed to handle info/refs",
                error=str(e),
                repo_path=repo_path,
                service=service.value
            )
            return Result.fail(
                "Failed to handle request",
                ErrorCode.INTERNAL_ERROR
            )
    
    async def handle_upload_pack(
        self,
        repo_path: str,
        input_stream: AsyncIterator[bytes],
        auth_header: Optional[str] = None
    ) -> AsyncIterator[bytes]:
        """Handle git-upload-pack (clone/pull).
        
        Args:
            repo_path: Repository path from URL
            input_stream: Client request data stream
            auth_header: Optional authorization header
            
        Yields:
            Response data chunks
        """
        try:
            # Parse repository path
            parsed = self.request_parser.parse_repository_path(repo_path)
            if not parsed:
                yield b"ERR Invalid repository path\n"
                return
            
            owner, repo_name = parsed
            repo_name = repo_name.replace('.git', '')
            
            # Get repository and check read access
            repo_result = await self.repository_service.get_repository(
                owner,
                repo_name,
                await self._get_user_id_from_auth(auth_header)
            )
            
            if not repo_result.success:
                yield f"ERR {repo_result.error}\n".encode()
                return
            
            repo = repo_result.value
            
            # Check read access
            access_result = await self._check_repository_access(
                repo.id,
                False,  # Read access
                auth_header
            )
            
            if not access_result.success:
                yield f"ERR {access_result.error}\n".encode()
                return
            
            # Get repository filesystem path
            fs_path = self.path_resolver.get_repository_path(
                repo.owner.username,
                repo.name
            )
            
            # Stream to git process and back
            async for chunk in self.upload_pack_service.handle_upload_pack(
                fs_path,
                input_stream
            ):
                yield chunk
            
            # Update access statistics
            await self._log_repository_access(
                repo.id,
                await self._get_user_id_from_auth(auth_header),
                'clone',
                True
            )
            
        except Exception as e:
            self.logger.error(
                "Failed to handle upload-pack",
                error=str(e),
                repo_path=repo_path
            )
            yield b"ERR Internal server error\n"
    
    async def handle_receive_pack(
        self,
        repo_path: str,
        input_stream: AsyncIterator[bytes],
        auth_header: Optional[str] = None
    ) -> AsyncIterator[bytes]:
        """Handle git-receive-pack (push).
        
        Args:
            repo_path: Repository path from URL
            input_stream: Client request data stream
            auth_header: Optional authorization header
            
        Yields:
            Response data chunks
        """
        try:
            # Parse repository path
            parsed = self.request_parser.parse_repository_path(repo_path)
            if not parsed:
                yield b"ERR Invalid repository path\n"
                return
            
            owner, repo_name = parsed
            repo_name = repo_name.replace('.git', '')
            
            # Authentication is required for push
            if not auth_header:
                yield b"ERR Authentication required\n"
                return
            
            user_id = await self._get_user_id_from_auth(auth_header)
            if not user_id:
                yield b"ERR Invalid authentication\n"
                return
            
            # Get repository
            repo_result = await self.repository_service.get_repository(
                owner,
                repo_name,
                user_id
            )
            
            if not repo_result.success:
                yield f"ERR {repo_result.error}\n".encode()
                return
            
            repo = repo_result.value
            
            # Check write access
            access_result = await self._check_repository_access(
                repo.id,
                True,  # Write access
                auth_header
            )
            
            if not access_result.success:
                yield f"ERR {access_result.error}\n".encode()
                return
            
            # Get repository filesystem path
            fs_path = self.path_resolver.get_repository_path(
                repo.owner.username,
                repo.name
            )
            
            # Stream to git process and back
            success = True
            async for chunk in self.receive_pack_service.handle_receive_pack(
                fs_path,
                input_stream
            ):
                # Check for errors in response
                if b'error' in chunk.lower() or b'fatal' in chunk.lower():
                    success = False
                yield chunk
            
            # Update repository metadata
            if success:
                await self._update_repository_after_push(repo.id)
            
            # Log access
            await self._log_repository_access(
                repo.id,
                user_id,
                'push',
                success
            )
            
        except Exception as e:
            self.logger.error(
                "Failed to handle receive-pack",
                error=str(e),
                repo_path=repo_path
            )
            yield b"ERR Internal server error\n"
    
    async def _get_user_id_from_auth(self, auth_header: Optional[str]) -> Optional[UUID]:
        """Extract user ID from authorization header.
        
        Args:
            auth_header: Authorization header
            
        Returns:
            User ID if authenticated, None otherwise
        """
        if not auth_header:
            return None
        
        parsed = self.request_parser.parse_auth_header(auth_header)
        if not parsed or parsed['type'] != 'bearer':
            return None
        
        result = await self.auth_service.validate_token(parsed['token'])
        if result.success:
            return result.value.user_id
        
        return None
    
    async def _check_repository_access(
        self,
        repo_id: UUID,
        write_access: bool,
        auth_header: Optional[str]
    ) -> Result[bool]:
        """Check if user has required repository access.
        
        Args:
            repo_id: Repository ID
            write_access: Whether write access is required
            auth_header: Authorization header
            
        Returns:
            Result indicating access granted or denied
        """
        async with self.unit_of_work_factory() as uow:
            repo = await uow.repositories.find_by_id(repo_id)
            
            if not repo:
                return Result.fail(
                    "Repository not found",
                    ErrorCode.NOT_FOUND
                )
            
            # Public repositories allow read without auth
            if not write_access and not repo.is_private:
                return Result.ok(True)
            
            # All other cases require authentication
            if not auth_header:
                return Result.fail(
                    "Authentication required",
                    ErrorCode.UNAUTHORIZED
                )
            
            user_id = await self._get_user_id_from_auth(auth_header)
            if not user_id:
                return Result.fail(
                    "Invalid authentication",
                    ErrorCode.UNAUTHORIZED
                )
            
            # Owner always has access
            if repo.owner_id == user_id:
                return Result.ok(True)
            
            # Check permissions
            perm = await uow.permissions.get_user_permission(user_id, repo_id)
            
            if write_access:
                if not perm or perm.permission not in ['write', 'admin']:
                    return Result.fail(
                        "Write access denied",
                        ErrorCode.FORBIDDEN
                    )
            else:
                if repo.is_private and not perm:
                    return Result.fail(
                        "Read access denied",
                        ErrorCode.FORBIDDEN
                    )
            
            return Result.ok(True)
    
    async def _update_repository_after_push(self, repo_id: UUID) -> None:
        """Update repository metadata after successful push.
        
        Args:
            repo_id: Repository ID
        """
        try:
            async with self.unit_of_work_factory() as uow:
                repo = await uow.repositories.find_by_id(repo_id)
                if repo:
                    # Update last push timestamp
                    from datetime import datetime, timezone
                    await uow.repositories.update_last_push(
                        repo_id,
                        datetime.now(timezone.utc)
                    )
                    
                    # TODO: Update repository size
                    # TODO: Update search indexes
                    
                    await uow.commit()
                    
        except Exception as e:
            self.logger.error(
                "Failed to update repository after push",
                error=str(e),
                repo_id=str(repo_id)
            )
    
    async def _log_repository_access(
        self,
        repo_id: UUID,
        user_id: Optional[UUID],
        operation: str,
        success: bool
    ) -> None:
        """Log repository access.
        
        Args:
            repo_id: Repository ID
            user_id: User ID (if authenticated)
            operation: Operation type (clone, fetch, push)
            success: Whether operation succeeded
        """
        try:
            # TODO: Implement access logging
            self.logger.info(
                "Repository accessed",
                repo_id=str(repo_id),
                user_id=str(user_id) if user_id else "anonymous",
                operation=operation,
                success=success
            )
        except Exception as e:
            self.logger.error(
                "Failed to log repository access",
                error=str(e)
            )
    
    def _format_info_refs_response(
        self,
        refs_data: bytes,
        service: GitServiceType
    ) -> bytes:
        """Format info/refs response with service advertisement.
        
        Args:
            refs_data: Raw refs data from git
            service: Git service type
            
        Returns:
            Formatted response with service capabilities
        """
        # Add service advertisement header
        service_line = f"# service={service.value}\n"
        pkt_line = f"{len(service_line) + 4:04x}{service_line}"
        
        # Add flush packet
        response = pkt_line.encode() + b"0000"
        
        # Add refs data
        response += refs_data
        
        return response