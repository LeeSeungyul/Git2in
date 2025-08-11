"""External executable plugin support with IPC communication."""

import asyncio
import json
import os
import shutil
import signal
from pathlib import Path
from typing import Any, Dict, Optional, Union

import structlog

from src.plugins.base import (Plugin, PluginContext, PluginMetadata,
                              PluginPriority, PluginResult, PluginRuntimeError,
                              PluginStatus, PluginTimeoutError)

logger = structlog.get_logger(__name__)


class ExternalPlugin(Plugin):
    """Plugin wrapper for external executables."""

    def __init__(
        self,
        executable_path: Union[str, Path],
        config: Optional[Dict[str, Any]] = None,
        timeout: float = 30.0,
        env: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize external plugin.

        Args:
            executable_path: Path to the executable
            config: Plugin configuration
            timeout: Execution timeout in seconds
            env: Additional environment variables
        """
        super().__init__(config)
        self.executable_path = Path(executable_path)
        self.timeout = timeout
        self.env = env or {}
        self._process: Optional[asyncio.subprocess.Process] = None
        self._metadata_cache: Optional[PluginMetadata] = None

        if not self.executable_path.exists():
            raise ValueError(f"Executable not found: {executable_path}")

        if not os.access(self.executable_path, os.X_OK):
            raise ValueError(f"File is not executable: {executable_path}")

    @property
    def metadata(self) -> PluginMetadata:
        """Get plugin metadata from external executable."""
        if self._metadata_cache:
            return self._metadata_cache

        # Query metadata from external plugin
        try:
            result = asyncio.run(self._execute_command({"command": "metadata"}))

            self._metadata_cache = PluginMetadata(
                name=result.get("name", self.executable_path.stem),
                version=result.get("version", "1.0.0"),
                author=result.get("author", "Unknown"),
                description=result.get("description", "External plugin"),
                priority=PluginPriority[result.get("priority", "NORMAL")],
                enabled=result.get("enabled", True),
                tags=result.get("tags", []),
                dependencies=result.get("dependencies", []),
                homepage=result.get("homepage"),
                license=result.get("license"),
            )

            return self._metadata_cache

        except Exception as e:
            logger.warning(
                "Failed to get metadata from external plugin",
                executable=str(self.executable_path),
                error=str(e),
            )

            # Return default metadata
            return PluginMetadata(
                name=self.executable_path.stem,
                version="1.0.0",
                author="Unknown",
                description=f"External plugin: {self.executable_path.name}",
            )

    async def _execute_command(
        self,
        data: Dict[str, Any],
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Execute a command in the external plugin.

        Args:
            data: Command data to send to plugin
            timeout: Command timeout (uses self.timeout if not specified)

        Returns:
            Response from the plugin

        Raises:
            PluginTimeoutError: If execution times out
            PluginRuntimeError: If execution fails
        """
        timeout = timeout or self.timeout

        # Prepare environment
        env = os.environ.copy()
        env.update(self.env)
        env["GIT2IN_PLUGIN_MODE"] = "true"

        # Serialize input data
        input_json = json.dumps(data)

        try:
            # Start the process
            process = await asyncio.create_subprocess_exec(
                str(self.executable_path),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            # Send input and wait for output
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input_json.encode()),
                timeout=timeout,
            )

            # Check return code
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                raise PluginRuntimeError(
                    f"External plugin failed with code {process.returncode}: {error_msg}"
                )

            # Parse output
            try:
                result = json.loads(stdout.decode())
                return result
            except json.JSONDecodeError as e:
                raise PluginRuntimeError(f"Invalid JSON response from plugin: {e}")

        except asyncio.TimeoutError:
            # Kill the process if it's still running
            if process and process.returncode is None:
                process.kill()
                await process.wait()

            raise PluginTimeoutError(
                f"External plugin timed out after {timeout} seconds"
            )

        except Exception as e:
            raise PluginRuntimeError(f"Failed to execute external plugin: {e}")

    async def initialize(self) -> None:
        """Initialize the external plugin."""
        try:
            await self._execute_command(
                {
                    "command": "initialize",
                    "config": self.config,
                }
            )
            logger.info(
                "Initialized external plugin",
                executable=str(self.executable_path),
            )
        except Exception as e:
            logger.error(
                "Failed to initialize external plugin",
                executable=str(self.executable_path),
                error=str(e),
            )
            raise

    async def shutdown(self) -> None:
        """Shutdown the external plugin."""
        try:
            await self._execute_command(
                {
                    "command": "shutdown",
                }
            )
            logger.info(
                "Shutdown external plugin",
                executable=str(self.executable_path),
            )
        except Exception as e:
            logger.warning(
                "Error during external plugin shutdown",
                executable=str(self.executable_path),
                error=str(e),
            )

    async def validate_config(self) -> bool:
        """Validate plugin configuration."""
        try:
            result = await self._execute_command(
                {
                    "command": "validate_config",
                    "config": self.config,
                }
            )
            return result.get("valid", False)
        except Exception:
            return False

    async def _execute_hook(
        self, hook_name: str, context: PluginContext
    ) -> PluginResult:
        """
        Execute a hook in the external plugin.

        Args:
            hook_name: Name of the hook to execute
            context: Plugin context

        Returns:
            Plugin result
        """
        try:
            # Execute the hook command
            result = await self._execute_command(
                {
                    "command": hook_name,
                    "context": context.to_dict(),
                    "config": self.config,
                }
            )

            # Parse result
            return PluginResult(
                status=PluginStatus[result.get("status", "SUCCESS")],
                allowed=result.get("allowed", True),
                message=result.get("message"),
                data=result.get("data"),
                execution_time_ms=result.get("execution_time_ms"),
            )

        except PluginTimeoutError:
            return PluginResult(
                status=PluginStatus.TIMEOUT,
                allowed=False,
                message=f"Hook {hook_name} timed out",
            )

        except Exception as e:
            logger.error(
                "External plugin hook failed",
                hook=hook_name,
                executable=str(self.executable_path),
                error=str(e),
            )
            return PluginResult(
                status=PluginStatus.ERROR,
                allowed=False,
                message=f"Hook {hook_name} failed: {e}",
            )

    async def pre_receive(self, context: PluginContext) -> PluginResult:
        """Execute pre_receive hook."""
        return await self._execute_hook("pre_receive", context)

    async def post_receive(self, context: PluginContext) -> PluginResult:
        """Execute post_receive hook."""
        return await self._execute_hook("post_receive", context)

    async def pre_upload(self, context: PluginContext) -> PluginResult:
        """Execute pre_upload hook."""
        return await self._execute_hook("pre_upload", context)

    async def post_upload(self, context: PluginContext) -> PluginResult:
        """Execute post_upload hook."""
        return await self._execute_hook("post_upload", context)

    async def custom_hook(self, hook_name: str, context: PluginContext) -> PluginResult:
        """Execute custom hook."""
        return await self._execute_hook(f"custom_{hook_name}", context)


class ExternalPluginProtocol:
    """
    Protocol definition for external plugin communication.

    External plugins should implement this protocol for IPC communication.
    Input is received as JSON on stdin, output is sent as JSON on stdout.

    Request format:
    {
        "command": "hook_name",
        "context": {...},
        "config": {...}
    }

    Response format:
    {
        "status": "SUCCESS|FAILURE|ERROR|TIMEOUT|SKIPPED",
        "allowed": true|false,
        "message": "optional message",
        "data": {...},
        "execution_time_ms": 123
    }

    Metadata response format:
    {
        "name": "plugin_name",
        "version": "1.0.0",
        "author": "Author Name",
        "description": "Plugin description",
        "priority": "NORMAL",
        "tags": ["tag1", "tag2"],
        "dependencies": ["dep1", "dep2"]
    }
    """

    @staticmethod
    def create_example_script(output_path: Path, language: str = "python") -> None:
        """
        Create an example external plugin script.

        Args:
            output_path: Path where to create the script
            language: Language for the example (python, bash)
        """
        if language == "python":
            script_content = '''#!/usr/bin/env python3
"""Example external Git2in plugin."""

import json
import sys

def handle_metadata():
    """Return plugin metadata."""
    return {
        "name": "example_plugin",
        "version": "1.0.0",
        "author": "Example Author",
        "description": "Example external plugin",
        "priority": "NORMAL",
        "tags": ["example"],
        "dependencies": []
    }

def handle_initialize(config):
    """Initialize plugin."""
    # Perform initialization
    return {"status": "SUCCESS"}

def handle_pre_receive(context, config):
    """Handle pre_receive hook."""
    # Check if push is allowed
    repo = context.get("repository", {})
    user = context.get("user", {})
    
    # Example: Block pushes to main branch by non-admins
    if context.get("operation", {}).get("ref") == "refs/heads/main":
        if user.get("role") != "admin":
            return {
                "status": "FAILURE",
                "allowed": False,
                "message": "Only admins can push to main branch"
            }
    
    return {
        "status": "SUCCESS",
        "allowed": True,
        "message": "Push allowed"
    }

def main():
    """Main entry point."""
    # Read input from stdin
    input_data = json.loads(sys.stdin.read())
    
    command = input_data.get("command")
    context = input_data.get("context", {})
    config = input_data.get("config", {})
    
    # Handle commands
    if command == "metadata":
        result = handle_metadata()
    elif command == "initialize":
        result = handle_initialize(config)
    elif command == "pre_receive":
        result = handle_pre_receive(context, config)
    else:
        result = {
            "status": "SKIPPED",
            "allowed": True,
            "message": f"Command not implemented: {command}"
        }
    
    # Write output to stdout
    json.dump(result, sys.stdout)

if __name__ == "__main__":
    main()
'''

        elif language == "bash":
            script_content = """#!/bin/bash
# Example external Git2in plugin

# Read input from stdin
INPUT=$(cat)

# Parse command using jq (must be installed)
COMMAND=$(echo "$INPUT" | jq -r '.command')

case "$COMMAND" in
    metadata)
        cat <<EOF
{
    "name": "bash_example",
    "version": "1.0.0",
    "author": "Example Author",
    "description": "Bash external plugin example",
    "priority": "NORMAL",
    "tags": ["bash", "example"],
    "dependencies": []
}
EOF
        ;;
    
    initialize)
        echo '{"status": "SUCCESS"}'
        ;;
    
    pre_receive)
        # Parse context
        REF=$(echo "$INPUT" | jq -r '.context.operation.ref')
        USER_ROLE=$(echo "$INPUT" | jq -r '.context.user.role')
        
        # Example: Check branch protection
        if [[ "$REF" == "refs/heads/main" ]] && [[ "$USER_ROLE" != "admin" ]]; then
            cat <<EOF
{
    "status": "FAILURE",
    "allowed": false,
    "message": "Only admins can push to main branch"
}
EOF
        else
            cat <<EOF
{
    "status": "SUCCESS",
    "allowed": true,
    "message": "Push allowed"
}
EOF
        fi
        ;;
    
    *)
        cat <<EOF
{
    "status": "SKIPPED",
    "allowed": true,
    "message": "Command not implemented: $COMMAND"
}
EOF
        ;;
esac
"""

        else:
            raise ValueError(f"Unsupported language: {language}")

        # Write script
        output_path.write_text(script_content)

        # Make executable
        output_path.chmod(0o755)

        logger.info(
            "Created example external plugin",
            path=str(output_path),
            language=language,
        )
