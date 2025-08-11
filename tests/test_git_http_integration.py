"""Integration tests for Git HTTP endpoints"""

import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import status
from httpx import AsyncClient

from src.core.models import Repository
from src.infrastructure.hooks import Hook, HookContext, HookEvent, HookManager


class TestGitHTTPEndpoints:
    """Test Git HTTP Smart Protocol endpoints"""

    @pytest.mark.asyncio
    async def test_info_refs_endpoint_not_found(self, async_client: AsyncClient):
        """Test info/refs endpoint with non-existent repository"""
        response = await async_client.get(
            "/git/nonexistent/nonexistent/info/refs?service=git-upload-pack",
            headers={"User-Agent": "git/2.39.0"},
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "Repository not found" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_info_refs_endpoint_invalid_service(
        self, async_client: AsyncClient, test_repository_path: Path
    ):
        """Test info/refs endpoint with invalid service"""
        response = await async_client.get(
            "/git/test-namespace/test-repo/info/refs?service=invalid-service",
            headers={"User-Agent": "git/2.39.0"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Invalid service" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_info_refs_endpoint_dumb_protocol(
        self, async_client: AsyncClient, test_repository_path: Path
    ):
        """Test info/refs endpoint with dumb HTTP protocol"""
        response = await async_client.get(
            "/git/test-namespace/test-repo/info/refs",
            headers={"User-Agent": "curl/7.0"},  # Not a Git client
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "Dumb HTTP protocol not supported" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_info_refs_endpoint_with_mock(
        self,
        async_client: AsyncClient,
        test_repository_path: Path,
        mock_git_http_backend,
    ):
        """Test info/refs endpoint with mocked git-http-backend"""
        response = await async_client.get(
            "/git/test-namespace/test-repo/info/refs?service=git-upload-pack",
            headers={"User-Agent": "git/2.39.0"},
        )

        assert response.status_code == status.HTTP_200_OK
        assert (
            response.headers["content-type"]
            == "application/x-git-upload-pack-advertisement"
        )

        # Check response contains service advertisement
        content = response.content
        assert b"# service=git-upload-pack" in content

    @pytest.mark.asyncio
    async def test_upload_pack_endpoint_not_found(self, async_client: AsyncClient):
        """Test upload-pack endpoint with non-existent repository"""
        response = await async_client.post(
            "/git/nonexistent/nonexistent/git-upload-pack",
            headers={
                "User-Agent": "git/2.39.0",
                "Content-Type": "application/x-git-upload-pack-request",
            },
            content=b"0000",
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.asyncio
    async def test_upload_pack_endpoint_with_mock(
        self,
        async_client: AsyncClient,
        test_repository_path: Path,
        mock_git_http_backend,
    ):
        """Test upload-pack endpoint with mocked backend"""
        response = await async_client.post(
            "/git/test-namespace/test-repo/git-upload-pack",
            headers={
                "User-Agent": "git/2.39.0",
                "Content-Type": "application/x-git-upload-pack-request",
            },
            content=b"0000",
        )

        assert response.status_code == status.HTTP_200_OK
        assert (
            response.headers["content-type"] == "application/x-git-upload-pack-result"
        )

    @pytest.mark.asyncio
    async def test_receive_pack_endpoint_not_found(self, async_client: AsyncClient):
        """Test receive-pack endpoint with non-existent repository"""
        response = await async_client.post(
            "/git/nonexistent/nonexistent/git-receive-pack",
            headers={
                "User-Agent": "git/2.39.0",
                "Content-Type": "application/x-git-receive-pack-request",
            },
            content=b"0000",
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.asyncio
    async def test_git_url_with_dot_git_suffix(
        self,
        async_client: AsyncClient,
        test_repository_path: Path,
        mock_git_http_backend,
    ):
        """Test handling of .git suffix in repository name"""
        response = await async_client.get(
            "/git/test-namespace/test-repo.git/info/refs?service=git-upload-pack",
            headers={"User-Agent": "git/2.39.0"},
        )

        assert response.status_code == status.HTTP_200_OK


class TestGitHTTPHooks:
    """Test hook integration with Git HTTP endpoints"""

    @pytest.mark.asyncio
    async def test_upload_pack_with_pre_hook_blocking(
        self,
        async_client: AsyncClient,
        test_repository_path: Path,
        mock_git_http_backend,
    ):
        """Test upload-pack blocked by pre-upload hook"""

        # Create a blocking hook
        class BlockingHook(Hook):
            async def execute(self, context: HookContext):
                context.add_error("Blocked by test hook")

        # Register the hook
        from src.api.git_http import hook_manager

        blocking_hook = BlockingHook("test_blocker", enabled=True)
        hook_manager.register_hook(HookEvent.PRE_UPLOAD, blocking_hook)

        try:
            response = await async_client.post(
                "/git/test-namespace/test-repo/git-upload-pack",
                headers={
                    "User-Agent": "git/2.39.0",
                    "Content-Type": "application/x-git-upload-pack-request",
                },
                content=b"0000",
            )

            assert response.status_code == status.HTTP_403_FORBIDDEN
            assert "Access denied by hook" in response.json()["detail"]

        finally:
            # Cleanup: unregister the hook
            hook_manager.unregister_hook(HookEvent.PRE_UPLOAD, blocking_hook)

    @pytest.mark.asyncio
    async def test_upload_pack_with_hooks_success(
        self,
        async_client: AsyncClient,
        test_repository_path: Path,
        mock_git_http_backend,
    ):
        """Test upload-pack with successful hook execution"""

        # Track hook execution
        hook_executed = {"pre": False, "post": False}

        class TrackingHook(Hook):
            def __init__(self, name: str, track_key: str):
                super().__init__(name, enabled=True)
                self.track_key = track_key

            async def execute(self, context: HookContext):
                hook_executed[self.track_key] = True
                context.add_result(f"{self.track_key}_executed", True)

        # Register hooks
        from src.api.git_http import hook_manager

        pre_hook = TrackingHook("test_pre", "pre")
        post_hook = TrackingHook("test_post", "post")

        hook_manager.register_hook(HookEvent.PRE_UPLOAD, pre_hook)
        hook_manager.register_hook(HookEvent.POST_UPLOAD, post_hook)

        try:
            response = await async_client.post(
                "/git/test-namespace/test-repo/git-upload-pack",
                headers={
                    "User-Agent": "git/2.39.0",
                    "Content-Type": "application/x-git-upload-pack-request",
                },
                content=b"0000",
            )

            assert response.status_code == status.HTTP_200_OK
            assert hook_executed["pre"] is True
            assert hook_executed["post"] is True

        finally:
            # Cleanup
            hook_manager.unregister_hook(HookEvent.PRE_UPLOAD, pre_hook)
            hook_manager.unregister_hook(HookEvent.POST_UPLOAD, post_hook)


class TestGitOperationsE2E:
    """End-to-end tests for Git operations (requires git-http-backend)"""

    @pytest.mark.skipif(
        not shutil.which("git-http-backend"), reason="git-http-backend not available"
    )
    @pytest.mark.asyncio
    async def test_git_clone_operation(
        self, async_client: AsyncClient, initialized_repo: Path
    ):
        """Test actual Git clone operation through HTTP"""

        # Start the FastAPI server in test mode
        # This would need actual server running or special test setup

        # Create temporary directory for clone
        with tempfile.TemporaryDirectory() as temp_dir:
            clone_path = Path(temp_dir) / "cloned-repo"

            # Attempt to clone (would need server running)
            # This is more of a structure example since it requires
            # a running server

            # result = subprocess.run(
            #     ["git", "clone",
            #      "http://localhost:8000/git/test-namespace/test-repo.git",
            #      str(clone_path)],
            #     capture_output=True,
            #     text=True
            # )

            # assert result.returncode == 0
            # assert clone_path.exists()
            # assert (clone_path / ".git").exists()

            pass  # Placeholder for actual implementation

    @pytest.mark.skipif(
        not shutil.which("git-http-backend"), reason="git-http-backend not available"
    )
    def test_git_http_backend_availability(self):
        """Test that git-http-backend is available and working"""
        result = subprocess.run(
            ["git-http-backend"],
            env={"REQUEST_METHOD": "GET", "PATH_INFO": "/"},
            capture_output=True,
            text=True,
        )

        # git-http-backend should exit with an error when called directly
        # but should be available
        assert result.returncode != 127  # 127 = command not found


class TestStreamProcessing:
    """Test streaming and chunked processing"""

    @pytest.mark.asyncio
    async def test_large_upload_streaming(
        self,
        async_client: AsyncClient,
        test_repository_path: Path,
        mock_git_http_backend,
    ):
        """Test streaming large upload data"""

        # Create large test data (simulate pack file)
        large_data = b"PACK" + b"x" * 10000 + b"0000"

        response = await async_client.post(
            "/git/test-namespace/test-repo/git-upload-pack",
            headers={
                "User-Agent": "git/2.39.0",
                "Content-Type": "application/x-git-upload-pack-request",
                "Content-Length": str(len(large_data)),
            },
            content=large_data,
        )

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_receive_pack_streaming(
        self,
        async_client: AsyncClient,
        test_repository_path: Path,
        mock_git_http_backend,
    ):
        """Test streaming receive-pack data"""

        # Create test push data
        push_data = b"0000"

        response = await async_client.post(
            "/git/test-namespace/test-repo/git-receive-pack",
            headers={
                "User-Agent": "git/2.39.0",
                "Content-Type": "application/x-git-receive-pack-request",
                "Content-Length": str(len(push_data)),
            },
            content=push_data,
        )

        assert response.status_code == status.HTTP_200_OK
        assert (
            response.headers["content-type"] == "application/x-git-receive-pack-result"
        )
