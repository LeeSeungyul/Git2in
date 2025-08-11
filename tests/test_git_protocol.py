"""Tests for Git protocol utilities"""

from typing import List

import pytest

from src.core.exceptions import ValidationError
from src.infrastructure.git_protocol import (GitContentType, GitHeaders,
                                             GitProtocolValidator, GitService,
                                             PktLineParser)


class TestPktLineParser:
    """Test Git packet-line format parsing"""

    def test_encode_simple_line(self):
        """Test encoding a simple line"""
        data = b"hello world"
        encoded = PktLineParser.encode_line(data)

        # Length should be 4 (prefix) + 11 (data) = 15 = 0x000f
        assert encoded == b"000fhello world"

    def test_encode_string_line(self):
        """Test encoding a string"""
        data = "hello world"
        encoded = PktLineParser.encode_line(data)
        assert encoded == b"000fhello world"

    def test_encode_flush_packet(self):
        """Test encoding a flush packet"""
        flush = PktLineParser.encode_flush()
        assert flush == b"0000"

    def test_encode_multiple_lines(self):
        """Test encoding multiple lines with flush"""
        lines = ["line1", "line2", "line3"]
        encoded = PktLineParser.encode_lines(lines)

        expected = b"0009line1" + b"0009line2" + b"0009line3" + b"0000"
        assert encoded == expected

    def test_decode_simple_line(self):
        """Test decoding a simple line"""
        data = b"000fhello world"
        line, consumed = PktLineParser.decode_line(data)

        assert line == b"hello world"
        assert consumed == 15

    def test_decode_flush_packet(self):
        """Test decoding a flush packet"""
        data = b"0000"
        line, consumed = PktLineParser.decode_line(data)

        assert line is None
        assert consumed == 4

    def test_decode_multiple_lines(self):
        """Test decoding multiple lines"""
        data = b"0009line1" + b"0009line2" + b"0009line3" + b"0000"
        lines = PktLineParser.decode_lines(data)

        assert len(lines) == 4
        assert lines[0] == b"line1"
        assert lines[1] == b"line2"
        assert lines[2] == b"line3"
        assert lines[3] is None  # Flush packet

    def test_encode_line_too_long(self):
        """Test encoding data that's too long"""
        data = b"x" * (PktLineParser.MAX_PKT_DATA_LEN + 1)

        with pytest.raises(ValueError, match="Data too long"):
            PktLineParser.encode_line(data)

    def test_decode_invalid_length(self):
        """Test decoding with invalid length prefix"""
        data = b"XXXX"

        with pytest.raises(ValueError, match="Invalid pkt-line length"):
            PktLineParser.decode_line(data)

    def test_decode_insufficient_data(self):
        """Test decoding with insufficient data"""
        data = b"000f"  # Says 15 bytes but no data follows

        with pytest.raises(ValueError, match="Insufficient data"):
            PktLineParser.decode_line(data)

    @pytest.mark.asyncio
    async def test_decode_stream(self):
        """Test decoding from async stream"""

        async def stream_generator():
            yield b"0009line1"
            yield b"0009line2"
            yield b"0000"

        lines = []
        async for line in PktLineParser.decode_stream(stream_generator()):
            lines.append(line)
            if line is None:
                break

        assert len(lines) == 3
        assert lines[0] == b"line1"
        assert lines[1] == b"line2"
        assert lines[2] is None


class TestGitProtocolValidator:
    """Test Git protocol validation"""

    def test_validate_service_valid(self):
        """Test validating valid Git services"""
        assert (
            GitProtocolValidator.validate_service("git-upload-pack")
            == GitService.UPLOAD_PACK
        )
        assert (
            GitProtocolValidator.validate_service("git-receive-pack")
            == GitService.RECEIVE_PACK
        )

    def test_validate_service_invalid(self):
        """Test validating invalid Git service"""
        with pytest.raises(ValidationError, match="Invalid Git service"):
            GitProtocolValidator.validate_service("git-invalid-service")

    def test_validate_ref_name_valid(self):
        """Test validating valid ref names"""
        assert GitProtocolValidator.validate_ref_name("refs/heads/main") is True
        assert GitProtocolValidator.validate_ref_name("refs/tags/v1.0.0") is True
        assert (
            GitProtocolValidator.validate_ref_name("refs/remotes/origin/main") is True
        )
        assert GitProtocolValidator.validate_ref_name("HEAD") is True
        assert GitProtocolValidator.validate_ref_name("FETCH_HEAD") is True

    def test_validate_ref_name_invalid(self):
        """Test validating invalid ref names"""
        assert GitProtocolValidator.validate_ref_name("") is False
        assert GitProtocolValidator.validate_ref_name("invalid-ref") is False
        assert GitProtocolValidator.validate_ref_name("refs/invalid/ref") is False

    def test_validate_object_id_valid(self):
        """Test validating valid object IDs"""
        # SHA-1
        assert GitProtocolValidator.validate_object_id("a" * 40) is True
        assert (
            GitProtocolValidator.validate_object_id("0123456789abcdef" * 2 + "01234567")
            is True
        )

        # SHA-256
        assert GitProtocolValidator.validate_object_id("a" * 64) is True

    def test_validate_object_id_invalid(self):
        """Test validating invalid object IDs"""
        assert GitProtocolValidator.validate_object_id("") is False
        assert GitProtocolValidator.validate_object_id("not-a-hash") is False
        assert GitProtocolValidator.validate_object_id("a" * 39) is False  # Too short
        assert (
            GitProtocolValidator.validate_object_id("a" * 41) is False
        )  # Wrong length
        assert (
            GitProtocolValidator.validate_object_id("g" * 40) is False
        )  # Invalid chars

    def test_validate_capability_valid(self):
        """Test validating valid capabilities"""
        assert GitProtocolValidator.validate_capability("multi_ack") is True
        assert GitProtocolValidator.validate_capability("thin-pack") is True
        assert GitProtocolValidator.validate_capability("side-band-64k") is True
        assert GitProtocolValidator.validate_capability("agent=git/2.39.0") is True
        assert GitProtocolValidator.validate_capability("object-format=sha256") is True

    def test_validate_capability_invalid(self):
        """Test validating invalid capabilities"""
        assert GitProtocolValidator.validate_capability("unknown-cap") is False
        assert GitProtocolValidator.validate_capability("invalid=value") is False

    def test_parse_capabilities(self):
        """Test parsing capabilities from pkt-line"""
        line = b"a" * 40 + b" HEAD\x00multi_ack thin-pack side-band"
        ref_part, capabilities = GitProtocolValidator.parse_capabilities(line)

        assert ref_part == b"a" * 40 + b" HEAD"
        assert capabilities == ["multi_ack", "thin-pack", "side-band"]

    def test_parse_capabilities_no_caps(self):
        """Test parsing line without capabilities"""
        line = b"a" * 40 + b" refs/heads/main"
        ref_part, capabilities = GitProtocolValidator.parse_capabilities(line)

        assert ref_part == line
        assert capabilities == []


class TestGitHeaders:
    """Test Git protocol HTTP headers"""

    def test_validate_content_type_valid(self):
        """Test validating valid content types"""
        assert (
            GitHeaders.validate_content_type(
                "application/x-git-upload-pack-request",
                GitContentType.UPLOAD_PACK_REQUEST,
            )
            is True
        )

        assert (
            GitHeaders.validate_content_type(
                "application/x-git-upload-pack-request; charset=utf-8",
                GitContentType.UPLOAD_PACK_REQUEST,
            )
            is True
        )

    def test_validate_content_type_invalid(self):
        """Test validating invalid content types"""
        assert (
            GitHeaders.validate_content_type(
                "application/json", GitContentType.UPLOAD_PACK_REQUEST
            )
            is False
        )

        assert (
            GitHeaders.validate_content_type("", GitContentType.UPLOAD_PACK_REQUEST)
            is False
        )

    def test_extract_service_valid(self):
        """Test extracting service from query string"""
        assert (
            GitHeaders.extract_service("service=git-upload-pack")
            == GitService.UPLOAD_PACK
        )
        assert (
            GitHeaders.extract_service("service=git-receive-pack")
            == GitService.RECEIVE_PACK
        )
        assert (
            GitHeaders.extract_service("foo=bar&service=git-upload-pack&baz=qux")
            == GitService.UPLOAD_PACK
        )

    def test_extract_service_invalid(self):
        """Test extracting invalid service from query string"""
        assert GitHeaders.extract_service("") is None
        assert GitHeaders.extract_service("foo=bar") is None
        assert GitHeaders.extract_service("service=invalid") is None

    def test_format_service_advertisement(self):
        """Test formatting service advertisement"""
        adv = GitHeaders.format_service_advertisement(GitService.UPLOAD_PACK)

        # Should be pkt-line encoded
        lines = PktLineParser.decode_lines(adv)
        assert len(lines) == 2
        assert lines[0] == b"# service=git-upload-pack\n"
        assert lines[1] is None  # Flush

    def test_is_smart_request(self):
        """Test detecting smart HTTP requests"""
        assert GitHeaders.is_smart_request({"user-agent": "git/2.39.0"}) is True
        assert GitHeaders.is_smart_request({"user-agent": "Git/2.39.0"}) is True
        assert GitHeaders.is_smart_request({"user-agent": "JGit/1.0"}) is False
        assert GitHeaders.is_smart_request({"user-agent": "curl/7.0"}) is False
        assert GitHeaders.is_smart_request({}) is False


class TestGitContentType:
    """Test Git content type helpers"""

    def test_for_service_advertisement(self):
        """Test getting content type for service advertisement"""
        assert (
            GitContentType.for_service_advertisement(GitService.UPLOAD_PACK)
            == "application/x-git-upload-pack-advertisement"
        )
        assert (
            GitContentType.for_service_advertisement(GitService.RECEIVE_PACK)
            == "application/x-git-receive-pack-advertisement"
        )

    def test_for_service_request(self):
        """Test getting content type for service request"""
        assert (
            GitContentType.for_service_request(GitService.UPLOAD_PACK)
            == "application/x-git-upload-pack-request"
        )
        assert (
            GitContentType.for_service_request(GitService.RECEIVE_PACK)
            == "application/x-git-receive-pack-request"
        )

    def test_for_service_result(self):
        """Test getting content type for service result"""
        assert (
            GitContentType.for_service_result(GitService.UPLOAD_PACK)
            == "application/x-git-upload-pack-result"
        )
        assert (
            GitContentType.for_service_result(GitService.RECEIVE_PACK)
            == "application/x-git-receive-pack-result"
        )
