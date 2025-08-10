"""Git Smart HTTP Protocol utilities and parsers"""

import re
from typing import Optional, List, Tuple, AsyncIterator, Union
from enum import Enum

from src.core.exceptions import ValidationError
from src.infrastructure.logging import get_logger

logger = get_logger(__name__)


class GitService(str, Enum):
    """Git services supported by the smart HTTP protocol"""
    UPLOAD_PACK = "git-upload-pack"
    RECEIVE_PACK = "git-receive-pack"


class GitContentType:
    """Git protocol content types"""
    # Advertisement
    UPLOAD_PACK_ADVERTISEMENT = "application/x-git-upload-pack-advertisement"
    RECEIVE_PACK_ADVERTISEMENT = "application/x-git-receive-pack-advertisement"
    
    # Request
    UPLOAD_PACK_REQUEST = "application/x-git-upload-pack-request"
    RECEIVE_PACK_REQUEST = "application/x-git-receive-pack-request"
    
    # Result
    UPLOAD_PACK_RESULT = "application/x-git-upload-pack-result"
    RECEIVE_PACK_RESULT = "application/x-git-receive-pack-result"
    
    @classmethod
    def for_service_advertisement(cls, service: GitService) -> str:
        """Get content type for service advertisement"""
        if service == GitService.UPLOAD_PACK:
            return cls.UPLOAD_PACK_ADVERTISEMENT
        elif service == GitService.RECEIVE_PACK:
            return cls.RECEIVE_PACK_ADVERTISEMENT
        else:
            raise ValueError(f"Unknown service: {service}")
    
    @classmethod
    def for_service_request(cls, service: GitService) -> str:
        """Get content type for service request"""
        if service == GitService.UPLOAD_PACK:
            return cls.UPLOAD_PACK_REQUEST
        elif service == GitService.RECEIVE_PACK:
            return cls.RECEIVE_PACK_REQUEST
        else:
            raise ValueError(f"Unknown service: {service}")
    
    @classmethod
    def for_service_result(cls, service: GitService) -> str:
        """Get content type for service result"""
        if service == GitService.UPLOAD_PACK:
            return cls.UPLOAD_PACK_RESULT
        elif service == GitService.RECEIVE_PACK:
            return cls.RECEIVE_PACK_RESULT
        else:
            raise ValueError(f"Unknown service: {service}")


class PktLineParser:
    """Parser for Git packet-line format"""
    
    FLUSH_PKT = b"0000"
    MAX_PKT_DATA_LEN = 65520  # Max data length (65524 - 4 for length prefix)
    
    @staticmethod
    def encode_line(data: Union[str, bytes]) -> bytes:
        """Encode data as a pkt-line"""
        if isinstance(data, str):
            data = data.encode("utf-8")
        
        if len(data) > PktLineParser.MAX_PKT_DATA_LEN:
            raise ValueError(f"Data too long for pkt-line: {len(data)} bytes")
        
        # Length includes the 4-byte length prefix
        length = len(data) + 4
        length_hex = f"{length:04x}".encode("ascii")
        
        return length_hex + data
    
    @staticmethod
    def encode_flush() -> bytes:
        """Encode a flush packet"""
        return PktLineParser.FLUSH_PKT
    
    @staticmethod
    def encode_lines(lines: List[Union[str, bytes]]) -> bytes:
        """Encode multiple lines with a flush packet at the end"""
        result = b""
        for line in lines:
            result += PktLineParser.encode_line(line)
        result += PktLineParser.encode_flush()
        return result
    
    @staticmethod
    def decode_line(data: bytes) -> Tuple[Optional[bytes], int]:
        """
        Decode a single pkt-line from data.
        Returns (line_data, bytes_consumed).
        line_data is None for flush packets.
        """
        if len(data) < 4:
            raise ValueError("Insufficient data for pkt-line length")
        
        length_hex = data[:4]
        
        # Check for flush packet
        if length_hex == PktLineParser.FLUSH_PKT:
            return None, 4
        
        try:
            length = int(length_hex, 16)
        except ValueError:
            raise ValueError(f"Invalid pkt-line length: {length_hex}")
        
        if length < 4:
            raise ValueError(f"Invalid pkt-line length: {length}")
        
        if length > 65524:
            raise ValueError(f"pkt-line too long: {length}")
        
        if len(data) < length:
            raise ValueError(f"Insufficient data for pkt-line: need {length}, have {len(data)}")
        
        # Extract the data (excluding the 4-byte length prefix)
        line_data = data[4:length]
        
        return line_data, length
    
    @staticmethod
    def decode_lines(data: bytes) -> List[Optional[bytes]]:
        """Decode all pkt-lines from data"""
        lines = []
        offset = 0
        
        while offset < len(data):
            line, consumed = PktLineParser.decode_line(data[offset:])
            lines.append(line)
            offset += consumed
            
            # Stop at flush packet
            if line is None:
                break
        
        return lines
    
    @staticmethod
    async def decode_stream(stream: AsyncIterator[bytes]) -> AsyncIterator[Optional[bytes]]:
        """Decode pkt-lines from an async stream"""
        buffer = b""
        
        async for chunk in stream:
            buffer += chunk
            
            while len(buffer) >= 4:
                # Try to decode a line
                try:
                    line, consumed = PktLineParser.decode_line(buffer)
                    buffer = buffer[consumed:]
                    yield line
                    
                    # Stop at flush packet
                    if line is None:
                        break
                except ValueError as e:
                    # Need more data
                    if "Insufficient data" in str(e):
                        break
                    else:
                        raise


class GitProtocolValidator:
    """Validator for Git protocol elements"""
    
    # Valid ref name pattern (simplified)
    REF_PATTERN = re.compile(r"^refs/(heads|tags|remotes)/[A-Za-z0-9._/-]+$")
    
    # Object ID pattern (SHA-1 or SHA-256)
    SHA1_PATTERN = re.compile(r"^[0-9a-f]{40}$")
    SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
    
    @classmethod
    def validate_service(cls, service: str) -> GitService:
        """Validate and return a Git service"""
        try:
            return GitService(service)
        except ValueError:
            raise ValidationError(f"Invalid Git service: {service}")
    
    @classmethod
    def validate_ref_name(cls, ref: str) -> bool:
        """Validate a Git reference name"""
        if not ref:
            return False
        
        # Special cases
        if ref in ["HEAD", "FETCH_HEAD", "ORIG_HEAD", "MERGE_HEAD"]:
            return True
        
        return bool(cls.REF_PATTERN.match(ref))
    
    @classmethod
    def validate_object_id(cls, obj_id: str) -> bool:
        """Validate a Git object ID (SHA-1 or SHA-256)"""
        if not obj_id:
            return False
        
        return bool(cls.SHA1_PATTERN.match(obj_id) or cls.SHA256_PATTERN.match(obj_id))
    
    @classmethod
    def validate_capability(cls, capability: str) -> bool:
        """Validate a Git capability string"""
        # List of known capabilities
        known_capabilities = {
            "multi_ack", "multi_ack_detailed", "thin-pack", "side-band",
            "side-band-64k", "ofs-delta", "shallow", "no-progress",
            "include-tag", "allow-tip-sha1-in-want", "allow-reachable-sha1-in-want",
            "no-done", "filter", "object-format", "agent"
        }
        
        # Check if it's a known capability or has a value (capability=value)
        if "=" in capability:
            cap_name = capability.split("=")[0]
            return cap_name in known_capabilities or cap_name == "agent" or cap_name == "object-format"
        
        return capability in known_capabilities
    
    @classmethod
    def parse_capabilities(cls, line: bytes) -> Tuple[bytes, List[str]]:
        """Parse capabilities from a pkt-line"""
        parts = line.split(b"\0", 1)
        
        if len(parts) == 1:
            return line, []
        
        ref_part = parts[0]
        capabilities = parts[1].decode("utf-8").split()
        
        return ref_part, capabilities


class GitHeaders:
    """Git protocol HTTP headers"""
    
    @staticmethod
    def validate_content_type(content_type: str, expected: str) -> bool:
        """Validate that content type matches expected"""
        if not content_type:
            return False
        
        # Handle charset suffix
        content_type = content_type.split(";")[0].strip()
        
        return content_type == expected
    
    @staticmethod
    def extract_service(query_string: str) -> Optional[GitService]:
        """Extract service from query string"""
        if not query_string:
            return None
        
        # Parse query parameters
        params = {}
        for param in query_string.split("&"):
            if "=" in param:
                key, value = param.split("=", 1)
                params[key] = value
        
        service = params.get("service")
        if service:
            try:
                return GitProtocolValidator.validate_service(service)
            except ValidationError:
                return None
        
        return None
    
    @staticmethod
    def format_service_advertisement(service: GitService) -> bytes:
        """Format the service advertisement header"""
        service_line = f"# service={service.value}\n"
        return PktLineParser.encode_lines([service_line])
    
    @staticmethod
    def is_smart_request(headers: dict) -> bool:
        """Check if request is for smart HTTP protocol"""
        user_agent = headers.get("user-agent", "").lower()
        
        # Git clients include "git/" in their user agent
        return "git/" in user_agent