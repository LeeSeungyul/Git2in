"""Commit validation plugin for Git2in."""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern
import structlog

from src.plugins.base import (
    Plugin,
    PluginContext,
    PluginMetadata,
    PluginPriority,
    PluginResult,
)

logger = structlog.get_logger(__name__)


class CommitValidationPlugin(Plugin):
    """Plugin for validating commit messages and file content."""
    
    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return PluginMetadata(
            name="commit_validation",
            version="1.0.0",
            author="Git2in Team",
            description="Validates commit messages and file constraints",
            priority=PluginPriority.HIGH,
            tags=["validation", "commit", "security", "builtin"],
        )
    
    async def initialize(self) -> None:
        """Initialize plugin with configuration."""
        # Commit message validation
        self.message_patterns = self._compile_message_patterns()
        self.require_issue_reference = self.config.get("require_issue_reference", False)
        self.issue_pattern = self.config.get("issue_pattern", r"#\d+|[A-Z]+-\d+")
        
        # File validation
        self.max_file_size = self.config.get("max_file_size", 10 * 1024 * 1024)  # 10MB default
        self.file_size_exceptions = self.config.get("file_size_exceptions", [])
        self.forbidden_files = self._compile_forbidden_patterns()
        self.sensitive_patterns = self._compile_sensitive_patterns()
        
        # Author validation
        self.allowed_email_domains = self.config.get("allowed_email_domains", [])
        self.blocked_authors = self.config.get("blocked_authors", [])
        
        # Commit validation
        self.max_commits_per_push = self.config.get("max_commits_per_push", 100)
        self.require_signed_commits = self.config.get("require_signed_commits", False)
        
        logger.info(
            "Initialized commit validation",
            message_patterns=len(self.message_patterns),
            forbidden_files=len(self.forbidden_files),
            sensitive_patterns=len(self.sensitive_patterns),
        )
    
    def _compile_message_patterns(self) -> List[Pattern]:
        """Compile commit message patterns."""
        patterns = []
        
        # Default patterns
        default_patterns = [
            # Conventional commits
            r"^(feat|fix|docs|style|refactor|test|chore|perf|ci|build|revert)(\(.+\))?: .+",
            # Simple format
            r"^[A-Z].{10,}",  # At least 10 chars, starts with capital
        ]
        
        configured = self.config.get("message_patterns", [])
        pattern_strings = configured if configured else default_patterns
        
        for pattern_str in pattern_strings:
            try:
                patterns.append(re.compile(pattern_str))
            except re.error as e:
                logger.warning(f"Invalid message pattern '{pattern_str}': {e}")
        
        return patterns
    
    def _compile_forbidden_patterns(self) -> List[Pattern]:
        """Compile forbidden file patterns."""
        patterns = []
        
        # Default forbidden files
        default_forbidden = [
            r"\.env$",
            r"\.env\.",
            r"\.pem$",
            r"\.key$",
            r"\.p12$",
            r"\.pfx$",
            r"id_rsa",
            r"id_dsa",
            r"\.aws/credentials",
            r"\.ssh/",
            r"\.gnupg/",
        ]
        
        configured = self.config.get("forbidden_files", [])
        pattern_strings = configured if configured else default_forbidden
        
        for pattern_str in pattern_strings:
            try:
                patterns.append(re.compile(pattern_str))
            except re.error as e:
                logger.warning(f"Invalid forbidden pattern '{pattern_str}': {e}")
        
        return patterns
    
    def _compile_sensitive_patterns(self) -> List[tuple[Pattern, str]]:
        """Compile patterns for detecting sensitive content."""
        patterns = []
        
        # Default sensitive content patterns
        default_sensitive = [
            (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}", "API key"),
            (r"(?i)(secret[_-]?key|secret)\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}", "Secret key"),
            (r"(?i)password\s*[:=]\s*['\"]?[^\s\"']{8,}", "Password"),
            (r"(?i)token\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}", "Token"),
            (r"(?i)aws_access_key_id\s*[:=]\s*['\"]?[A-Z0-9]{20}", "AWS access key"),
            (r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[a-zA-Z0-9/+=]{40}", "AWS secret key"),
            (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private key"),
            (r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*", "Bearer token"),
            (r"(?i)basic\s+[a-zA-Z0-9\-._~+/]+=*", "Basic auth"),
            (r"mongodb(\+srv)?://[^\s]+", "MongoDB connection string"),
            (r"postgres(ql)?://[^\s]+", "PostgreSQL connection string"),
            (r"mysql://[^\s]+", "MySQL connection string"),
            (r"redis://[^\s]+", "Redis connection string"),
        ]
        
        configured = self.config.get("sensitive_patterns", [])
        pattern_tuples = configured if configured else default_sensitive
        
        for pattern_data in pattern_tuples:
            if isinstance(pattern_data, (list, tuple)):
                pattern_str, description = pattern_data
            else:
                pattern_str, description = pattern_data, "Sensitive content"
            
            try:
                patterns.append((re.compile(pattern_str), description))
            except re.error as e:
                logger.warning(f"Invalid sensitive pattern '{pattern_str}': {e}")
        
        return patterns
    
    def _validate_commit_message(self, commit: Dict[str, Any]) -> Optional[str]:
        """
        Validate a commit message.
        
        Args:
            commit: Commit data
            
        Returns:
            Error message if validation fails, None otherwise
        """
        message = commit.get("message", "")
        
        if not message:
            return "Empty commit message"
        
        # Check message patterns
        if self.message_patterns:
            matches_pattern = any(p.match(message) for p in self.message_patterns)
            if not matches_pattern:
                return f"Commit message does not match required format"
        
        # Check for issue reference
        if self.require_issue_reference:
            if not re.search(self.issue_pattern, message):
                return f"Commit message must reference an issue (pattern: {self.issue_pattern})"
        
        # Check message length
        lines = message.split("\n")
        if lines:
            # Check first line (subject)
            subject = lines[0]
            if len(subject) > 72:
                return "Commit subject line should be <= 72 characters"
            if len(subject) < 10:
                return "Commit subject line too short (minimum 10 characters)"
            
            # Check body line length
            for i, line in enumerate(lines[2:], start=3):  # Skip subject and blank line
                if len(line) > 100:
                    return f"Commit message body line {i} exceeds 100 characters"
        
        return None
    
    def _validate_author(self, commit: Dict[str, Any]) -> Optional[str]:
        """
        Validate commit author.
        
        Args:
            commit: Commit data
            
        Returns:
            Error message if validation fails, None otherwise
        """
        author_email = commit.get("author_email", "")
        author_name = commit.get("author_name", "")
        
        # Check blocked authors
        if author_email in self.blocked_authors or author_name in self.blocked_authors:
            return f"Author {author_name} <{author_email}> is blocked"
        
        # Check email domain
        if self.allowed_email_domains:
            domain = author_email.split("@")[-1] if "@" in author_email else ""
            if not domain or domain not in self.allowed_email_domains:
                return f"Author email domain '{domain}' not in allowed domains: {self.allowed_email_domains}"
        
        # Check for valid email format
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_pattern, author_email):
            return f"Invalid author email format: {author_email}"
        
        return None
    
    def _validate_files(self, context: PluginContext) -> List[str]:
        """
        Validate changed files.
        
        Args:
            context: Plugin context
            
        Returns:
            List of validation errors
        """
        errors = []
        
        for file_path in context.operation.files_changed:
            # Check forbidden files
            for pattern in self.forbidden_files:
                if pattern.search(file_path):
                    errors.append(f"Forbidden file: {file_path}")
                    break
            
            # Check file size (would need actual file content in real implementation)
            file_size = context.operation.metadata.get("file_sizes", {}).get(file_path, 0)
            if file_size > self.max_file_size:
                # Check exceptions
                is_exception = any(
                    file_path.endswith(ext) for ext in self.file_size_exceptions
                )
                if not is_exception:
                    size_mb = file_size / (1024 * 1024)
                    max_mb = self.max_file_size / (1024 * 1024)
                    errors.append(
                        f"File {file_path} ({size_mb:.2f}MB) exceeds maximum size ({max_mb:.2f}MB)"
                    )
        
        return errors
    
    def _scan_sensitive_content(self, context: PluginContext) -> List[str]:
        """
        Scan for sensitive content in files.
        
        Args:
            context: Plugin context
            
        Returns:
            List of detected sensitive content
        """
        detections = []
        
        # In a real implementation, we would scan file content
        # For now, we'll check file names and metadata
        file_contents = context.operation.metadata.get("file_contents", {})
        
        for file_path, content in file_contents.items():
            if not isinstance(content, str):
                continue
            
            for pattern, description in self.sensitive_patterns:
                if pattern.search(content):
                    detections.append(f"Sensitive content detected in {file_path}: {description}")
        
        # Also check commit messages for sensitive content
        for commit in context.operation.commits:
            message = commit.get("message", "")
            for pattern, description in self.sensitive_patterns:
                if pattern.search(message):
                    commit_sha = commit.get("sha", "unknown")[:8]
                    detections.append(
                        f"Sensitive content in commit {commit_sha} message: {description}"
                    )
        
        return detections
    
    async def pre_receive(self, context: PluginContext) -> PluginResult:
        """
        Validate commits before receiving.
        
        Args:
            context: Plugin execution context
            
        Returns:
            PluginResult indicating whether to allow the push
        """
        errors = []
        
        # Check number of commits
        num_commits = len(context.operation.commits)
        if num_commits > self.max_commits_per_push:
            errors.append(
                f"Too many commits in push ({num_commits} > {self.max_commits_per_push})"
            )
        
        # Validate each commit
        for commit in context.operation.commits:
            # Validate commit message
            message_error = self._validate_commit_message(commit)
            if message_error:
                commit_sha = commit.get("sha", "unknown")[:8]
                errors.append(f"Commit {commit_sha}: {message_error}")
            
            # Validate author
            author_error = self._validate_author(commit)
            if author_error:
                commit_sha = commit.get("sha", "unknown")[:8]
                errors.append(f"Commit {commit_sha}: {author_error}")
            
            # Check if commit is signed
            if self.require_signed_commits and not commit.get("signed", False):
                commit_sha = commit.get("sha", "unknown")[:8]
                errors.append(f"Commit {commit_sha} is not signed")
        
        # Validate files
        file_errors = self._validate_files(context)
        errors.extend(file_errors)
        
        # Scan for sensitive content
        sensitive_detections = self._scan_sensitive_content(context)
        errors.extend(sensitive_detections)
        
        # Return result
        if errors:
            error_message = "Validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
            return PluginResult.deny(error_message)
        
        logger.info(
            "Commit validation passed",
            user=context.user.username,
            commits=num_commits,
            files=len(context.operation.files_changed),
        )
        
        return PluginResult.success("All validations passed")
    
    async def post_receive(self, context: PluginContext) -> PluginResult:
        """
        Log validation metrics after receiving commits.
        
        Args:
            context: Plugin execution context
            
        Returns:
            PluginResult with success status
        """
        # Collect metrics
        num_commits = len(context.operation.commits)
        num_files = len(context.operation.files_changed)
        total_size = sum(
            context.operation.metadata.get("file_sizes", {}).values()
        )
        
        logger.info(
            "Commit validation metrics",
            user=context.user.username,
            commits=num_commits,
            files=num_files,
            total_size_bytes=total_size,
            repository=f"{context.repository.namespace}/{context.repository.name}",
        )
        
        return PluginResult.success()