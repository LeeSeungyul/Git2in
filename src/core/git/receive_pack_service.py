"""git-receive-pack handling only (for push)"""
from pathlib import Path
from typing import AsyncIterator, List, Optional
import re

from .command_executor import GitCommandExecutor
from .command_builder import GitCommandBuilder
from .git_types import RefUpdate, GitProtocolError


class GitReceivePackService:
    """Handles git-receive-pack operations only"""
    
    REF_UPDATE_PATTERN = re.compile(
        r'^([0-9a-f]{40}) ([0-9a-f]{40}) (.+)$'
    )
    
    def __init__(self, command_executor: GitCommandExecutor):
        """
        Initialize service
        
        Args:
            command_executor: Git command executor
        """
        self.executor = command_executor
        self.builder = GitCommandBuilder()
    
    async def advertise_refs(self, repo_path: Path) -> bytes:
        """
        Generate refs advertisement for receive-pack
        
        Args:
            repo_path: Repository path
            
        Returns:
            Refs advertisement in pkt-line format
        """
        # Get refs from repository
        cmd = self.builder.for_each_ref(
            format_string='%(objectname) %(refname)'
        )
        
        result = await self.executor.execute(cmd, cwd=repo_path)
        
        lines = []
        
        # Service advertisement
        service_line = "# service=git-receive-pack\n"
        lines.append(self._encode_pkt_line(service_line))
        lines.append(b'0000')  # Flush packet
        
        refs = result.stdout.decode().strip().split('\n')
        
        if refs and refs[0]:
            first_ref = refs[0]
            capabilities = self._get_receive_pack_capabilities()
            
            first_line = f"{first_ref}\0{' '.join(capabilities)}\n"
            lines.append(self._encode_pkt_line(first_line))
            
            for ref in refs[1:]:
                if ref:
                    lines.append(self._encode_pkt_line(f"{ref}\n"))
        else:
            # No refs, send capabilities with zero ID
            capabilities = self._get_receive_pack_capabilities()
            zero_id = '0' * 40
            capabilities_line = f"{zero_id} capabilities^{{}}\0{' '.join(capabilities)}\n"
            lines.append(self._encode_pkt_line(capabilities_line))
        
        lines.append(b'0000')
        return b''.join(lines)
    
    async def process_receive_pack(
        self,
        repo_path: Path,
        input_stream: AsyncIterator[bytes]
    ) -> AsyncIterator[bytes]:
        """
        Process receive-pack request
        
        Args:
            repo_path: Repository path
            input_stream: Client push data
            
        Yields:
            Response chunks
        """
        # Build receive-pack command
        cmd = self.builder.receive_pack(
            repo_path,
            stateless_rpc=True
        )
        
        # Stream to git-receive-pack
        async for chunk in self.executor.stream_command(
            cmd,
            cwd=repo_path,
            input_stream=input_stream
        ):
            yield chunk
    
    async def parse_ref_updates(
        self,
        pkt_lines: List[bytes]
    ) -> List[RefUpdate]:
        """
        Parse reference updates from pkt-line format
        
        Args:
            pkt_lines: List of pkt-line encoded data
            
        Returns:
            List of ref updates
        """
        updates = []
        
        for pkt_line in pkt_lines:
            if not pkt_line or pkt_line == b'0000':
                continue
            
            # Decode pkt-line
            line_data = self._decode_pkt_line(pkt_line)
            if not line_data:
                continue
            
            line = line_data.decode('utf-8').strip()
            
            # Parse ref update
            match = self.REF_UPDATE_PATTERN.match(line)
            if match:
                updates.append(RefUpdate(
                    ref_name=match.group(3),
                    old_sha=match.group(1),
                    new_sha=match.group(2)
                ))
        
        return updates
    
    async def validate_ref_update(
        self,
        repo_path: Path,
        update: RefUpdate
    ) -> None:
        """
        Validate a reference update
        
        Args:
            repo_path: Repository path
            update: Ref update to validate
            
        Raises:
            GitProtocolError: If update is invalid
        """
        # Check if ref exists for non-create operations
        if not update.is_create:
            cmd = self.builder.rev_parse(update.ref_name, verify=True)
            result = await self.executor.execute(cmd, cwd=repo_path)
            
            if not result.success:
                raise GitProtocolError(f"Reference not found: {update.ref_name}")
            
            current_sha = result.stdout.decode().strip()
            if current_sha != update.old_sha:
                raise GitProtocolError(
                    f"Reference {update.ref_name} has changed "
                    f"(expected {update.old_sha}, got {current_sha})"
                )
        
        # Validate new SHA exists (for non-delete)
        if not update.is_delete:
            cmd = self.builder.cat_file(sha=update.new_sha, check_exists=True)
            result = await self.executor.execute(cmd, cwd=repo_path)
            
            if not result.success:
                raise GitProtocolError(f"Object not found: {update.new_sha}")
    
    def _get_receive_pack_capabilities(self) -> List[str]:
        """Get receive-pack capabilities"""
        return [
            'report-status',
            'side-band-64k',
            'quiet',
            'atomic',
            'ofs-delta',
            'push-options',
            'object-format=sha1'
        ]
    
    def _encode_pkt_line(self, data: str) -> bytes:
        """Encode data in pkt-line format"""
        encoded = data.encode('utf-8')
        length = len(encoded) + 4
        return f"{length:04x}".encode('ascii') + encoded
    
    def _decode_pkt_line(self, data: bytes) -> Optional[bytes]:
        """
        Decode pkt-line format
        
        Args:
            data: Encoded pkt-line
            
        Returns:
            Decoded data or None for flush packet
        """
        if len(data) < 4:
            return None
        
        length_hex = data[:4]
        try:
            length = int(length_hex, 16)
        except ValueError:
            return None
        
        if length == 0:
            return None  # Flush packet
        
        if length < 4:
            return None
        
        return data[4:length]