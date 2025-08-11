"""Sandbox environment for secure plugin execution with resource limits."""

import asyncio
import os
import resource
import signal
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Union

import structlog

from src.plugins.base import PluginRuntimeError, PluginTimeoutError

logger = structlog.get_logger(__name__)


class ResourceLimits:
    """Resource limit configuration for sandboxed execution."""

    def __init__(
        self,
        cpu_time: Optional[int] = 10,  # CPU seconds
        memory: Optional[int] = 256 * 1024 * 1024,  # 256 MB
        file_size: Optional[int] = 10 * 1024 * 1024,  # 10 MB
        file_descriptors: Optional[int] = 100,
        processes: Optional[int] = 10,
        timeout: Optional[float] = 30.0,  # Wall clock timeout
    ):
        """
        Initialize resource limits.

        Args:
            cpu_time: CPU time limit in seconds
            memory: Memory limit in bytes
            file_size: Maximum file size in bytes
            file_descriptors: Maximum number of open file descriptors
            processes: Maximum number of processes
            timeout: Wall clock timeout in seconds
        """
        self.cpu_time = cpu_time
        self.memory = memory
        self.file_size = file_size
        self.file_descriptors = file_descriptors
        self.processes = processes
        self.timeout = timeout


class PluginSandbox:
    """Sandbox for secure plugin execution."""

    def __init__(
        self,
        limits: Optional[ResourceLimits] = None,
        work_dir: Optional[Path] = None,
        network_enabled: bool = False,
        readonly_paths: Optional[list] = None,
        writable_paths: Optional[list] = None,
    ):
        """
        Initialize sandbox.

        Args:
            limits: Resource limits configuration
            work_dir: Working directory for sandboxed process
            network_enabled: Whether to allow network access
            readonly_paths: List of paths to mount as read-only
            writable_paths: List of paths to mount as writable
        """
        self.limits = limits or ResourceLimits()
        self.work_dir = work_dir
        self.network_enabled = network_enabled
        self.readonly_paths = readonly_paths or []
        self.writable_paths = writable_paths or []
        self._temp_dir: Optional[tempfile.TemporaryDirectory] = None

    def _apply_resource_limits(self):
        """Apply resource limits to the current process."""
        if not sys.platform.startswith("linux") and not sys.platform == "darwin":
            logger.warning("Resource limits not supported on this platform")
            return

        try:
            # CPU time limit
            if self.limits.cpu_time is not None:
                resource.setrlimit(
                    resource.RLIMIT_CPU,
                    (self.limits.cpu_time, self.limits.cpu_time),
                )

            # Memory limit (RSS)
            if self.limits.memory is not None:
                if hasattr(resource, "RLIMIT_RSS"):
                    resource.setrlimit(
                        resource.RLIMIT_RSS,
                        (self.limits.memory, self.limits.memory),
                    )
                elif hasattr(resource, "RLIMIT_AS"):
                    # Address space limit as fallback
                    resource.setrlimit(
                        resource.RLIMIT_AS,
                        (self.limits.memory, self.limits.memory),
                    )

            # File size limit
            if self.limits.file_size is not None:
                resource.setrlimit(
                    resource.RLIMIT_FSIZE,
                    (self.limits.file_size, self.limits.file_size),
                )

            # File descriptor limit
            if self.limits.file_descriptors is not None:
                resource.setrlimit(
                    resource.RLIMIT_NOFILE,
                    (self.limits.file_descriptors, self.limits.file_descriptors),
                )

            # Process limit
            if self.limits.processes is not None and hasattr(resource, "RLIMIT_NPROC"):
                resource.setrlimit(
                    resource.RLIMIT_NPROC,
                    (self.limits.processes, self.limits.processes),
                )

            logger.debug("Applied resource limits")

        except Exception as e:
            logger.warning(f"Failed to apply resource limits: {e}")

    def _setup_filesystem_isolation(self):
        """Setup filesystem isolation (basic implementation)."""
        # Note: Full filesystem isolation requires OS-specific features like:
        # - Linux: chroot, namespaces, seccomp
        # - macOS: sandbox-exec profiles
        # This is a basic implementation that changes working directory

        if self.work_dir:
            os.chdir(self.work_dir)
            logger.debug(f"Changed working directory to {self.work_dir}")

    def _disable_network(self):
        """Disable network access (requires root on most systems)."""
        # Note: Proper network isolation requires:
        # - Linux: network namespaces or iptables rules
        # - macOS: pfctl rules
        # This is a placeholder for the concept

        if not self.network_enabled:
            # Set environment variable as a signal to well-behaved plugins
            os.environ["GIT2IN_NETWORK_DISABLED"] = "1"
            logger.debug("Network access disabled (environment flag set)")

    async def execute(
        self,
        command: Union[str, list],
        input_data: Optional[bytes] = None,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[Path] = None,
    ) -> tuple[bytes, bytes, int]:
        """
        Execute a command in the sandbox.

        Args:
            command: Command to execute (string or list)
            input_data: Input to send to stdin
            env: Environment variables
            cwd: Working directory

        Returns:
            Tuple of (stdout, stderr, return_code)

        Raises:
            PluginTimeoutError: If execution times out
            PluginRuntimeError: If execution fails
        """
        # Prepare command
        if isinstance(command, str):
            command = command.split()

        # Prepare environment
        sandbox_env = os.environ.copy()
        if env:
            sandbox_env.update(env)

        # Add sandbox indicators
        sandbox_env["GIT2IN_SANDBOXED"] = "1"
        sandbox_env["GIT2IN_SANDBOX_LIMITS"] = "1"

        # Create temporary directory if needed
        if not self.work_dir:
            self._temp_dir = tempfile.TemporaryDirectory(prefix="git2in_sandbox_")
            work_dir = Path(self._temp_dir.name)
        else:
            work_dir = self.work_dir

        try:
            # Create subprocess with preexec_fn for resource limits
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=sandbox_env,
                cwd=cwd or work_dir,
                preexec_fn=(
                    self._apply_resource_limits if sys.platform != "win32" else None
                ),
            )

            # Execute with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(input_data),
                    timeout=self.limits.timeout,
                )

                return stdout, stderr, process.returncode or 0

            except asyncio.TimeoutError:
                # Kill the process
                process.kill()
                await process.wait()

                raise PluginTimeoutError(
                    f"Command timed out after {self.limits.timeout} seconds"
                )

        except Exception as e:
            if isinstance(e, PluginTimeoutError):
                raise
            raise PluginRuntimeError(f"Sandbox execution failed: {e}")

        finally:
            # Cleanup temporary directory
            if self._temp_dir:
                self._temp_dir.cleanup()
                self._temp_dir = None

    async def execute_python(
        self,
        code: str,
        globals_dict: Optional[Dict[str, Any]] = None,
        locals_dict: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """
        Execute Python code in a sandboxed environment.

        Args:
            code: Python code to execute
            globals_dict: Global variables for execution
            locals_dict: Local variables for execution

        Returns:
            Result of code execution

        Raises:
            PluginRuntimeError: If execution fails
        """
        # Create isolated Python script
        script = f"""
import sys
import resource
import signal

# Apply resource limits
def apply_limits():
    {self._generate_limit_code()}

# Timeout handler
def timeout_handler(signum, frame):
    raise TimeoutError("Execution timed out")

# Apply limits
apply_limits()

# Set timeout alarm
signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm({int(self.limits.timeout or 30)})

# Execute user code
try:
    {code}
except Exception as e:
    print(f"ERROR: {{e}}", file=sys.stderr)
    sys.exit(1)
finally:
    signal.alarm(0)  # Cancel alarm
"""

        # Execute in subprocess
        try:
            stdout, stderr, returncode = await self.execute(
                [sys.executable, "-c", script],
                env={"PYTHONPATH": ""},
            )

            if returncode != 0:
                raise PluginRuntimeError(f"Python execution failed: {stderr.decode()}")

            return stdout.decode()

        except Exception as e:
            raise PluginRuntimeError(f"Failed to execute Python code: {e}")

    def _generate_limit_code(self) -> str:
        """Generate Python code for applying resource limits."""
        code_lines = []

        if self.limits.cpu_time is not None:
            code_lines.append(
                f"resource.setrlimit(resource.RLIMIT_CPU, ({self.limits.cpu_time}, {self.limits.cpu_time}))"
            )

        if self.limits.memory is not None:
            if sys.platform == "darwin":
                code_lines.append(
                    f"resource.setrlimit(resource.RLIMIT_AS, ({self.limits.memory}, {self.limits.memory}))"
                )
            else:
                code_lines.append(
                    f"resource.setrlimit(resource.RLIMIT_RSS, ({self.limits.memory}, {self.limits.memory}))"
                )

        if self.limits.file_size is not None:
            code_lines.append(
                f"resource.setrlimit(resource.RLIMIT_FSIZE, ({self.limits.file_size}, {self.limits.file_size}))"
            )

        if self.limits.file_descriptors is not None:
            code_lines.append(
                f"resource.setrlimit(resource.RLIMIT_NOFILE, ({self.limits.file_descriptors}, {self.limits.file_descriptors}))"
            )

        return "\n    ".join(code_lines) if code_lines else "pass"


class CGroupsSandbox(PluginSandbox):
    """
    Advanced sandbox using Linux cgroups v2 for better resource isolation.

    Note: This requires root privileges or proper cgroup delegation.
    """

    def __init__(self, *args, cgroup_name: Optional[str] = None, **kwargs):
        """
        Initialize cgroups sandbox.

        Args:
            cgroup_name: Name for the cgroup (auto-generated if not provided)
            *args, **kwargs: Passed to parent class
        """
        super().__init__(*args, **kwargs)
        self.cgroup_name = cgroup_name or f"git2in_plugin_{os.getpid()}"
        self.cgroup_path = Path(f"/sys/fs/cgroup/{self.cgroup_name}")

    def _setup_cgroup(self):
        """Setup cgroup v2 for resource isolation."""
        if not sys.platform.startswith("linux"):
            logger.warning("Cgroups are only available on Linux")
            return

        try:
            # Check if cgroups v2 is available
            if not Path("/sys/fs/cgroup/cgroup.controllers").exists():
                logger.warning("Cgroups v2 not available")
                return

            # Create cgroup
            self.cgroup_path.mkdir(exist_ok=True)

            # Set memory limit
            if self.limits.memory:
                (self.cgroup_path / "memory.max").write_text(str(self.limits.memory))

            # Set CPU limit (in microseconds per second)
            if self.limits.cpu_time:
                cpu_quota = self.limits.cpu_time * 1000000  # Convert to microseconds
                (self.cgroup_path / "cpu.max").write_text(f"{cpu_quota} 1000000")

            # Set process limit
            if self.limits.processes:
                (self.cgroup_path / "pids.max").write_text(str(self.limits.processes))

            logger.info(f"Created cgroup: {self.cgroup_name}")

        except PermissionError:
            logger.warning("Insufficient privileges to create cgroups")
        except Exception as e:
            logger.warning(f"Failed to setup cgroup: {e}")

    def _cleanup_cgroup(self):
        """Remove the cgroup."""
        if self.cgroup_path.exists():
            try:
                # Move processes back to parent cgroup
                (Path("/sys/fs/cgroup") / "cgroup.procs").write_text(str(os.getpid()))
                # Remove cgroup
                self.cgroup_path.rmdir()
                logger.info(f"Removed cgroup: {self.cgroup_name}")
            except Exception as e:
                logger.warning(f"Failed to cleanup cgroup: {e}")

    async def execute(self, *args, **kwargs):
        """Execute with cgroup isolation."""
        self._setup_cgroup()
        try:
            # Add current process to cgroup
            if self.cgroup_path.exists():
                (self.cgroup_path / "cgroup.procs").write_text(str(os.getpid()))

            return await super().execute(*args, **kwargs)
        finally:
            self._cleanup_cgroup()
