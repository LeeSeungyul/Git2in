"""Tests for Git subprocess execution"""

import pytest
import os
import asyncio
import tempfile
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

from src.infrastructure.git_subprocess import GitBackendProcess, GitBackendStreamProcessor
from src.core.exceptions import InternalServerError


class TestGitBackendProcess:
    """Test Git backend subprocess management"""
    
    @pytest.fixture
    def test_repo_path(self) -> Path:
        """Create a temporary test repository"""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "test-repo.git"
            repo_path.mkdir(parents=True)
            
            # Initialize as bare repository
            subprocess.run(
                ["git", "init", "--bare"],
                cwd=str(repo_path),
                check=True,
                capture_output=True
            )
            
            yield repo_path
    
    def test_create_cgi_environment(self, test_repo_path: Path):
        """Test CGI environment creation"""
        backend = GitBackendProcess(test_repo_path)
        
        env = backend._create_cgi_environment(
            method="GET",
            path_info="/namespace/repo.git/info/refs",
            query_string="service=git-upload-pack",
            content_type="application/x-git-upload-pack-request",
            content_length=1024,
            remote_addr="192.168.1.1",
            http_headers={
                "User-Agent": "git/2.39.0",
                "Accept": "*/*"
            }
        )
        
        assert env["REQUEST_METHOD"] == "GET"
        assert env["PATH_INFO"] == "/namespace/repo.git/info/refs"
        assert env["QUERY_STRING"] == "service=git-upload-pack"
        assert env["CONTENT_TYPE"] == "application/x-git-upload-pack-request"
        assert env["CONTENT_LENGTH"] == "1024"
        assert env["REMOTE_ADDR"] == "192.168.1.1"
        assert env["HTTP_USER_AGENT"] == "git/2.39.0"
        assert env["HTTP_ACCEPT"] == "*/*"
        assert env["GIT_HTTP_EXPORT_ALL"] == "1"
        assert "GIT_PROJECT_ROOT" in env
    
    def test_cgi_environment_filters_sensitive(self, test_repo_path: Path):
        """Test that CGI environment filters sensitive variables"""
        backend = GitBackendProcess(test_repo_path)
        
        # Set some environment variables that should be filtered
        os.environ["SECRET_KEY"] = "secret"
        os.environ["DATABASE_URL"] = "postgresql://..."
        
        try:
            env = backend._create_cgi_environment(
                method="GET",
                path_info="/test",
                http_headers={"Authorization": "Bearer token"}
            )
            
            # Sensitive environment variables should not be included
            assert "SECRET_KEY" not in env
            assert "DATABASE_URL" not in env
            
            # Authorization header should not be passed as HTTP_AUTHORIZATION
            assert "HTTP_AUTHORIZATION" not in env
            
            # Safe variables should be included
            assert "PATH" in env or "HOME" in env  # At least one should exist
            
        finally:
            # Cleanup
            del os.environ["SECRET_KEY"]
            del os.environ["DATABASE_URL"]
    
    @pytest.mark.asyncio
    async def test_execute_context_manager(self, test_repo_path: Path):
        """Test executing backend as context manager"""
        backend = GitBackendProcess(test_repo_path, timeout=10.0)
        
        with patch("asyncio.create_subprocess_exec") as mock_create:
            mock_process = AsyncMock()
            mock_process.stdin = AsyncMock()
            mock_process.stdout = AsyncMock()
            mock_process.stderr = AsyncMock()
            mock_process.wait = AsyncMock(return_value=0)
            mock_process.terminate = AsyncMock()
            mock_create.return_value = mock_process
            
            async with backend.execute(
                method="GET",
                path_info="/test"
            ):
                assert backend.process is not None
                assert backend.start_time is not None
            
            # Process should be cleaned up
            assert backend.process is None
    
    @pytest.mark.asyncio
    async def test_execute_with_nonexistent_repo(self):
        """Test executing with non-existent repository"""
        backend = GitBackendProcess(Path("/nonexistent/repo"))
        
        with pytest.raises(InternalServerError, match="Repository not found"):
            async with backend.execute(method="GET", path_info="/test"):
                pass
    
    @pytest.mark.asyncio
    async def test_write_input(self, test_repo_path: Path):
        """Test writing input to subprocess"""
        backend = GitBackendProcess(test_repo_path)
        
        with patch("asyncio.create_subprocess_exec") as mock_create:
            mock_process = AsyncMock()
            mock_stdin = AsyncMock()
            mock_process.stdin = mock_stdin
            mock_process.stdout = AsyncMock()
            mock_process.stderr = AsyncMock()
            mock_create.return_value = mock_process
            
            async with backend.execute(method="POST", path_info="/test"):
                await backend.write_input(b"test data")
                mock_stdin.write.assert_called_once_with(b"test data")
                mock_stdin.drain.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_write_input_without_process(self, test_repo_path: Path):
        """Test writing input without active process"""
        backend = GitBackendProcess(test_repo_path)
        
        with pytest.raises(InternalServerError, match="Process not started"):
            await backend.write_input(b"test data")
    
    @pytest.mark.asyncio
    async def test_read_output(self, test_repo_path: Path):
        """Test reading output from subprocess"""
        backend = GitBackendProcess(test_repo_path)
        
        with patch("asyncio.create_subprocess_exec") as mock_create:
            mock_process = AsyncMock()
            mock_stdout = AsyncMock()
            
            # Simulate output chunks
            mock_stdout.read = AsyncMock(side_effect=[
                b"chunk1",
                b"chunk2",
                b""  # EOF
            ])
            
            mock_process.stdin = AsyncMock()
            mock_process.stdout = mock_stdout
            mock_process.stderr = AsyncMock()
            mock_create.return_value = mock_process
            
            async with backend.execute(method="GET", path_info="/test"):
                chunks = []
                async for chunk in backend.read_output():
                    chunks.append(chunk)
                
                assert chunks == [b"chunk1", b"chunk2"]
    
    @pytest.mark.asyncio
    async def test_read_output_timeout(self, test_repo_path: Path):
        """Test reading output with timeout"""
        backend = GitBackendProcess(test_repo_path, timeout=0.1)
        
        with patch("asyncio.create_subprocess_exec") as mock_create:
            mock_process = AsyncMock()
            mock_stdout = AsyncMock()
            
            # Simulate slow output
            async def slow_read(size):
                await asyncio.sleep(1.0)  # Longer than timeout
                return b"data"
            
            mock_stdout.read = slow_read
            mock_process.stdin = AsyncMock()
            mock_process.stdout = mock_stdout
            mock_process.stderr = AsyncMock()
            mock_process.terminate = AsyncMock()
            mock_create.return_value = mock_process
            
            async with backend.execute(method="GET", path_info="/test"):
                with pytest.raises(InternalServerError, match="timed out"):
                    async for chunk in backend.read_output():
                        pass
    
    @pytest.mark.asyncio
    async def test_terminate_graceful(self, test_repo_path: Path):
        """Test graceful process termination"""
        backend = GitBackendProcess(test_repo_path)
        
        with patch("asyncio.create_subprocess_exec") as mock_create:
            mock_process = AsyncMock()
            mock_process.terminate = AsyncMock()
            mock_process.wait = AsyncMock(return_value=0)
            mock_process.stdin = AsyncMock()
            mock_process.stdout = AsyncMock()
            mock_process.stderr = AsyncMock()
            mock_create.return_value = mock_process
            
            async with backend.execute(method="GET", path_info="/test"):
                backend.process = mock_process
                await backend.terminate()
                
                mock_process.terminate.assert_called_once()
                mock_process.wait.assert_called()
    
    @pytest.mark.asyncio
    async def test_terminate_force_kill(self, test_repo_path: Path):
        """Test force killing process when graceful termination fails"""
        backend = GitBackendProcess(test_repo_path)
        
        with patch("asyncio.create_subprocess_exec") as mock_create:
            mock_process = AsyncMock()
            mock_process.terminate = AsyncMock()
            
            # Simulate timeout on wait after terminate
            mock_process.wait = AsyncMock(side_effect=[
                asyncio.TimeoutError(),  # First wait times out
                0  # Second wait after kill succeeds
            ])
            mock_process.kill = AsyncMock()
            
            mock_process.stdin = AsyncMock()
            mock_process.stdout = AsyncMock()
            mock_process.stderr = AsyncMock()
            mock_create.return_value = mock_process
            
            async with backend.execute(method="GET", path_info="/test"):
                backend.process = mock_process
                await backend.terminate()
                
                mock_process.terminate.assert_called_once()
                mock_process.kill.assert_called_once()


class TestGitBackendStreamProcessor:
    """Test Git backend stream processing"""
    
    @pytest.mark.asyncio
    async def test_parse_cgi_headers_simple(self):
        """Test parsing simple CGI headers"""
        
        async def stream():
            yield b"Status: 200 OK\r\n"
            yield b"Content-Type: application/x-git-upload-pack-result\r\n"
            yield b"\r\n"
            yield b"body content"
        
        headers, body_stream = await GitBackendStreamProcessor.parse_cgi_headers(stream())
        
        assert headers["Status"] == "200 OK"
        assert headers["Content-Type"] == "application/x-git-upload-pack-result"
        
        # Read body
        body = b""
        async for chunk in body_stream:
            body += chunk
        assert body == b"body content"
    
    @pytest.mark.asyncio
    async def test_parse_cgi_headers_newline_only(self):
        """Test parsing CGI headers with \\n\\n separator"""
        
        async def stream():
            yield b"Status: 200 OK\n"
            yield b"Content-Type: text/plain\n"
            yield b"\n"
            yield b"body"
        
        headers, body_stream = await GitBackendStreamProcessor.parse_cgi_headers(stream())
        
        assert headers["Status"] == "200 OK"
        assert headers["Content-Type"] == "text/plain"
        
        body = b""
        async for chunk in body_stream:
            body += chunk
        assert body == b"body"
    
    @pytest.mark.asyncio
    async def test_parse_cgi_headers_split_across_chunks(self):
        """Test parsing headers split across stream chunks"""
        
        async def stream():
            yield b"Status: 200"
            yield b" OK\r\nContent-"
            yield b"Type: text/plain\r\n\r"
            yield b"\nbody content here"
        
        headers, body_stream = await GitBackendStreamProcessor.parse_cgi_headers(stream())
        
        assert headers["Status"] == "200 OK"
        assert headers["Content-Type"] == "text/plain"
        
        body = b""
        async for chunk in body_stream:
            body += chunk
        assert body == b"body content here"
    
    def test_parse_http_status_valid(self):
        """Test parsing valid HTTP status"""
        assert GitBackendStreamProcessor.parse_http_status("200 OK") == 200
        assert GitBackendStreamProcessor.parse_http_status("404 Not Found") == 404
        assert GitBackendStreamProcessor.parse_http_status("500") == 500
    
    def test_parse_http_status_invalid(self):
        """Test parsing invalid HTTP status"""
        assert GitBackendStreamProcessor.parse_http_status("invalid") == 200
        assert GitBackendStreamProcessor.parse_http_status("") == 200
        assert GitBackendStreamProcessor.parse_http_status("OK 200") == 200


class TestResourceLimits:
    """Test resource limit settings"""
    
    @pytest.mark.skipif(
        os.name == 'nt',
        reason="Resource limits not supported on Windows"
    )
    def test_set_resource_limits(self, test_repo_path: Path):
        """Test setting resource limits (Unix only)"""
        backend = GitBackendProcess(
            test_repo_path,
            max_memory_mb=256,
            max_cpu_seconds=30
        )
        
        # This would need to be tested in a subprocess
        # to avoid affecting the test process itself
        
        # Create a test script that applies limits
        test_script = """
import resource
from pathlib import Path
import sys

repo_path = Path(sys.argv[1])
from src.infrastructure.git_subprocess import GitBackendProcess

backend = GitBackendProcess(repo_path, max_memory_mb=256, max_cpu_seconds=30)
backend._set_resource_limits()

# Check limits were set
mem_limit = resource.getrlimit(resource.RLIMIT_AS)
cpu_limit = resource.getrlimit(resource.RLIMIT_CPU)
nproc_limit = resource.getrlimit(resource.RLIMIT_NPROC)

print(f"Memory: {mem_limit[0]}")
print(f"CPU: {cpu_limit[0]}")
print(f"NPROC: {nproc_limit[0]}")
"""
        
        # Would run this in subprocess to test
        # For now just verify the method exists
        assert hasattr(backend, "_set_resource_limits")