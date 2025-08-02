"""git-upload-pack handling only (for clone/pull)"""
from pathlib import Path
from typing import AsyncIterator, Optional, List

from .command_executor import GitCommandExecutor
from .command_builder import GitCommandBuilder
from .git_types import GitProtocolError


class GitUploadPackService:
    """Handles git-upload-pack operations only"""
    
    PKT_LINE_DATA_MAX = 65516
    
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
        Generate refs advertisement for upload-pack
        
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
        
        # Build advertisement
        lines = []
        
        # Service advertisement
        service_line = "# service=git-upload-pack\n"
        lines.append(self._encode_pkt_line(service_line))
        lines.append(b'0000')  # Flush packet
        
        # First line includes capabilities
        refs = result.stdout.decode().strip().split('\n')
        if refs and refs[0]:
            first_ref = refs[0]
            capabilities = self._get_upload_pack_capabilities()
            
            first_line = f"{first_ref}\0{' '.join(capabilities)}\n"
            lines.append(self._encode_pkt_line(first_line))
            
            # Additional refs
            for ref in refs[1:]:
                if ref:
                    lines.append(self._encode_pkt_line(f"{ref}\n"))
        else:
            # No refs, send capabilities with zero ID
            capabilities = self._get_upload_pack_capabilities()
            zero_id = '0' * 40
            capabilities_line = f"{zero_id} capabilities^{{}}\0{' '.join(capabilities)}\n"
            lines.append(self._encode_pkt_line(capabilities_line))
        
        # End with flush packet
        lines.append(b'0000')
        
        return b''.join(lines)
    
    async def process_upload_pack(
        self,
        repo_path: Path,
        input_stream: AsyncIterator[bytes]
    ) -> AsyncIterator[bytes]:
        """
        Process upload-pack request
        
        Args:
            repo_path: Repository path
            input_stream: Client request stream
            
        Yields:
            Response chunks
        """
        # Build upload-pack command
        cmd = self.builder.upload_pack(
            repo_path,
            stateless_rpc=True,
            advertise_refs=False
        )
        
        # Stream directly to git-upload-pack
        async for chunk in self.executor.stream_command(
            cmd,
            cwd=repo_path,
            input_stream=input_stream
        ):
            yield chunk
    
    def _get_upload_pack_capabilities(self) -> List[str]:
        """Get upload-pack capabilities"""
        return [
            'multi_ack_detailed',
            'no-done',
            'side-band-64k',
            'thin-pack',
            'ofs-delta',
            'shallow',
            'deepen-since',
            'deepen-not',
            'deepen-relative',
            'no-progress',
            'include-tag',
            'allow-tip-sha1-in-want',
            'allow-reachable-sha1-in-want',
            'filter',
            'symref=HEAD:refs/heads/main'
        ]
    
    def _encode_pkt_line(self, data: str) -> bytes:
        """
        Encode data in pkt-line format
        
        Args:
            data: String to encode
            
        Returns:
            Encoded pkt-line
        """
        encoded = data.encode('utf-8')
        length = len(encoded) + 4
        
        if length > self.PKT_LINE_DATA_MAX + 4:
            raise ValueError("Data too large for pkt-line")
        
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
            raise ValueError("Invalid pkt-line")
        
        length_hex = data[:4]
        try:
            length = int(length_hex, 16)
        except ValueError:
            raise ValueError("Invalid pkt-line length")
        
        if length == 0:
            return None  # Flush packet
        
        if length < 4 or length > self.PKT_LINE_DATA_MAX + 4:
            raise ValueError(f"Invalid pkt-line length: {length}")
        
        return data[4:length]