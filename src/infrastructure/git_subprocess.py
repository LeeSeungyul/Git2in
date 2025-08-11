"""Secure subprocess wrapper for git-http-backend execution"""

import asyncio
import os
import resource
import signal
import subprocess
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Optional, Tuple

from src.core.config import settings
from src.core.exceptions import InternalServerError
from src.infrastructure.logging import get_logger

logger = get_logger(__name__)


class GitBackendProcess:
    """Manages git-http-backend subprocess execution with security controls"""

    def __init__(
        self,
        repository_path: Path,
        timeout: float = 300.0,  # 5 minutes default
        max_memory_mb: int = 512,
        max_cpu_seconds: int = 60,
    ):
        self.repository_path = repository_path
        self.timeout = timeout
        self.max_memory_mb = max_memory_mb
        self.max_cpu_seconds = max_cpu_seconds
        self.process: Optional[asyncio.subprocess.Process] = None
        self.start_time: Optional[float] = None

        # Path to git-http-backend
        self.git_http_backend = settings.git_http_backend_path

    def _create_cgi_environment(
        self,
        method: str,
        path_info: str,
        query_string: str = "",
        content_type: str = "",
        content_length: int = 0,
        remote_addr: str = "",
        http_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """Create CGI environment variables for git-http-backend"""

        # Base environment (filter sensitive variables)
        env = {
            k: v
            for k, v in os.environ.items()
            if k.startswith(("PATH", "HOME", "USER", "LANG", "LC_"))
        }

        # Git-specific environment
        env.update(
            {
                "GIT_PROJECT_ROOT": str(
                    self.repository_path.parent.parent
                ),  # Base repositories path
                "GIT_HTTP_EXPORT_ALL": "1",  # Allow access (we handle auth separately)
                "PATH_INFO": path_info,
                "QUERY_STRING": query_string,
                "REQUEST_METHOD": method,
                "SERVER_PROTOCOL": "HTTP/1.1",
                "GATEWAY_INTERFACE": "CGI/1.1",
                "REMOTE_ADDR": remote_addr or "127.0.0.1",
                "REMOTE_HOST": remote_addr or "localhost",
                "SERVER_SOFTWARE": f"Git2in/{settings.app_version}",
                "SERVER_NAME": "localhost",
                "SERVER_PORT": str(settings.api_port),
            }
        )

        # Add content type and length for POST requests
        if content_type:
            env["CONTENT_TYPE"] = content_type
        if content_length > 0:
            env["CONTENT_LENGTH"] = str(content_length)

        # Add HTTP headers as CGI variables
        if http_headers:
            for header, value in http_headers.items():
                # Convert to CGI format: HTTP_HEADER_NAME
                cgi_name = f"HTTP_{header.upper().replace('-', '_')}"
                # Skip certain headers that shouldn't be passed
                if cgi_name not in [
                    "HTTP_CONTENT_TYPE",
                    "HTTP_CONTENT_LENGTH",
                    "HTTP_AUTHORIZATION",
                ]:
                    env[cgi_name] = value

        return env

    def _set_resource_limits(self):
        """Set resource limits for the subprocess (called in subprocess)"""
        # Memory limit (in bytes)
        if self.max_memory_mb > 0:
            memory_bytes = self.max_memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))

        # CPU time limit (in seconds)
        if self.max_cpu_seconds > 0:
            resource.setrlimit(
                resource.RLIMIT_CPU, (self.max_cpu_seconds, self.max_cpu_seconds)
            )

        # Limit number of processes (prevent fork bombs)
        resource.setrlimit(resource.RLIMIT_NPROC, (10, 10))

        # Limit file size (prevent disk filling)
        max_file_size = 100 * 1024 * 1024  # 100MB
        resource.setrlimit(resource.RLIMIT_FSIZE, (max_file_size, max_file_size))

    @asynccontextmanager
    async def execute(
        self,
        method: str,
        path_info: str,
        query_string: str = "",
        content_type: str = "",
        content_length: int = 0,
        remote_addr: str = "",
        http_headers: Optional[Dict[str, str]] = None,
    ):
        """Execute git-http-backend as a context manager"""

        # Validate repository path
        if not self.repository_path.exists():
            raise InternalServerError(f"Repository not found: {self.repository_path}")

        # Create CGI environment
        env = self._create_cgi_environment(
            method,
            path_info,
            query_string,
            content_type,
            content_length,
            remote_addr,
            http_headers,
        )

        logger.info(
            "git_backend_starting",
            method=method,
            path_info=path_info,
            query_string=query_string,
            repository=str(self.repository_path),
        )

        self.start_time = time.time()

        try:
            # Start the subprocess
            self.process = await asyncio.create_subprocess_exec(
                self.git_http_backend,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=str(self.repository_path),
                preexec_fn=self._set_resource_limits if os.name != "nt" else None,
                start_new_session=True,  # Create new process group for cleanup
            )

            yield self

        finally:
            await self.cleanup()

    async def write_input(self, data: bytes) -> None:
        """Write data to subprocess stdin"""
        if not self.process or not self.process.stdin:
            raise InternalServerError("Process not started or stdin not available")

        try:
            self.process.stdin.write(data)
            await self.process.stdin.drain()
        except Exception as e:
            logger.error("git_backend_write_error", error=str(e))
            raise InternalServerError(f"Failed to write to git-http-backend: {str(e)}")

    async def close_input(self) -> None:
        """Close subprocess stdin to signal end of input"""
        if self.process and self.process.stdin:
            self.process.stdin.close()
            await self.process.stdin.wait_closed()

    async def read_output(self, chunk_size: int = 8192) -> AsyncIterator[bytes]:
        """Read output from subprocess stdout as async iterator"""
        if not self.process or not self.process.stdout:
            raise InternalServerError("Process not started or stdout not available")

        try:
            while True:
                # Check timeout
                if self.start_time and (time.time() - self.start_time) > self.timeout:
                    await self.terminate()
                    raise InternalServerError("Git operation timed out")

                # Read chunk with timeout
                try:
                    chunk = await asyncio.wait_for(
                        self.process.stdout.read(chunk_size),
                        timeout=min(
                            10.0, self.timeout - (time.time() - self.start_time)
                        ),
                    )
                except asyncio.TimeoutError:
                    continue

                if not chunk:
                    break

                yield chunk

        except Exception as e:
            logger.error("git_backend_read_error", error=str(e))
            raise InternalServerError(f"Failed to read from git-http-backend: {str(e)}")

    async def read_stderr(self) -> str:
        """Read all stderr output"""
        if not self.process or not self.process.stderr:
            return ""

        try:
            stderr_data = await self.process.stderr.read()
            return stderr_data.decode("utf-8", errors="replace")
        except Exception:
            return ""

    async def wait(self) -> int:
        """Wait for process to complete and return exit code"""
        if not self.process:
            return -1

        try:
            return_code = await asyncio.wait_for(
                self.process.wait(), timeout=self.timeout
            )

            # Log completion
            duration = time.time() - self.start_time if self.start_time else 0
            logger.info(
                "git_backend_completed", return_code=return_code, duration=duration
            )

            return return_code

        except asyncio.TimeoutError:
            await self.terminate()
            raise InternalServerError("Git operation timed out")

    async def terminate(self) -> None:
        """Terminate the subprocess gracefully"""
        if not self.process:
            return

        try:
            # Try graceful termination first
            self.process.terminate()

            # Wait a bit for graceful shutdown
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                # Force kill if graceful termination failed
                try:
                    self.process.kill()
                    await self.process.wait()
                except ProcessLookupError:
                    pass  # Process already dead

            logger.info("git_backend_terminated")

        except Exception as e:
            logger.error("git_backend_termination_error", error=str(e))

    async def cleanup(self) -> None:
        """Clean up subprocess resources"""
        if self.process:
            # Ensure process is terminated
            await self.terminate()

            # Close streams
            if self.process.stdin and not self.process.stdin.is_closing():
                self.process.stdin.close()

            self.process = None

            # Log final metrics
            if self.start_time:
                duration = time.time() - self.start_time
                logger.info("git_backend_cleanup", duration=duration)


class GitBackendStreamProcessor:
    """Process git-http-backend output stream with CGI header parsing"""

    @staticmethod
    async def parse_cgi_headers(
        stream: AsyncIterator[bytes],
    ) -> Tuple[Dict[str, str], AsyncIterator[bytes]]:
        """
        Parse CGI headers from stream and return headers dict and body stream.
        CGI headers are terminated by a blank line.
        """
        headers = {}
        header_buffer = b""
        header_complete = False

        async def body_stream():
            nonlocal header_buffer, header_complete

            # First, yield any remaining data after headers
            if header_complete and header_buffer:
                yield header_buffer
                header_buffer = b""

            # Then yield the rest of the stream
            async for chunk in stream:
                yield chunk

        # Read and parse headers
        async for chunk in stream:
            header_buffer += chunk

            # Look for end of headers (blank line)
            if b"\r\n\r\n" in header_buffer:
                header_part, body_part = header_buffer.split(b"\r\n\r\n", 1)
                header_complete = True
                header_buffer = body_part
            elif b"\n\n" in header_buffer:
                header_part, body_part = header_buffer.split(b"\n\n", 1)
                header_complete = True
                header_buffer = body_part
            else:
                continue

            # Parse headers
            for line in header_part.split(b"\n"):
                line = line.strip()
                if not line:
                    continue

                if b":" in line:
                    key, value = line.split(b":", 1)
                    headers[key.decode("utf-8").strip()] = value.decode("utf-8").strip()

            break

        return headers, body_stream()

    @staticmethod
    def parse_http_status(status_line: str) -> int:
        """Parse HTTP status from CGI Status header"""
        # Format: "Status: 200 OK" or just "200"
        parts = status_line.split(None, 1)
        if parts:
            try:
                return int(parts[0])
            except ValueError:
                pass
        return 200  # Default to 200 if not specified
