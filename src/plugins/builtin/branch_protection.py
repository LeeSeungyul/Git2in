"""Branch protection plugin for Git2in."""

import re
from typing import Any, Dict, List, Optional

import structlog

from src.plugins.base import (Plugin, PluginContext, PluginMetadata,
                              PluginPriority, PluginResult)

logger = structlog.get_logger(__name__)


class BranchProtectionPlugin(Plugin):
    """Plugin for enforcing branch protection rules."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return PluginMetadata(
            name="branch_protection",
            version="1.0.0",
            author="Git2in Team",
            description="Enforces branch protection rules",
            priority=PluginPriority.HIGH,
            tags=["security", "branch-protection", "builtin"],
        )

    async def initialize(self) -> None:
        """Initialize plugin."""
        # Parse configuration
        self.protected_branches = self._parse_protected_branches()
        self.admin_users = self.config.get("admin_users", [])
        self.admin_groups = self.config.get("admin_groups", ["admin"])
        self.allow_force_push = self.config.get("allow_force_push", False)
        self.require_pull_request = self.config.get("require_pull_request", False)
        self.dismiss_stale_reviews = self.config.get("dismiss_stale_reviews", True)
        self.required_approvals = self.config.get("required_approvals", 1)
        self.require_signed_commits = self.config.get("require_signed_commits", False)

        logger.info(
            "Initialized branch protection",
            protected_branches=self.protected_branches,
            admin_groups=self.admin_groups,
        )

    def _parse_protected_branches(self) -> List[Dict[str, Any]]:
        """Parse protected branch configuration."""
        default_protection = [
            {"pattern": "main", "level": "strict"},
            {"pattern": "master", "level": "strict"},
            {"pattern": "release/*", "level": "moderate"},
            {"pattern": "hotfix/*", "level": "moderate"},
        ]

        configured = self.config.get("protected_branches", [])

        if isinstance(configured, list):
            # Convert simple list to dict format
            if configured and isinstance(configured[0], str):
                configured = [{"pattern": b, "level": "strict"} for b in configured]
            return configured

        return default_protection

    def _is_protected_branch(self, ref: str) -> Optional[Dict[str, Any]]:
        """
        Check if a branch is protected.

        Args:
            ref: Git reference (e.g., refs/heads/main)

        Returns:
            Protection configuration if protected, None otherwise
        """
        # Extract branch name from ref
        if ref.startswith("refs/heads/"):
            branch = ref[11:]  # Remove "refs/heads/"
        else:
            branch = ref

        for protection in self.protected_branches:
            pattern = protection["pattern"]

            # Check if pattern matches
            if "*" in pattern:
                # Convert glob pattern to regex
                regex_pattern = pattern.replace("*", ".*")
                if re.match(f"^{regex_pattern}$", branch):
                    return protection
            elif branch == pattern:
                return protection

        return None

    def _is_admin(self, user: Any) -> bool:
        """Check if user has admin privileges."""
        # Check if user is in admin users list
        if user.username in self.admin_users or user.id in self.admin_users:
            return True

        # Check if user has admin role
        if user.role == "admin":
            return True

        # Check if user is in admin groups
        for group in user.groups:
            if group in self.admin_groups:
                return True

        return False

    def _check_force_push(self, context: PluginContext) -> Optional[str]:
        """Check for force push attempts."""
        operation = context.operation

        # Check if this is a force push (non-fast-forward update)
        if operation.old_sha and operation.new_sha:
            # In a real implementation, we would check Git history
            # For now, we'll use a simple heuristic
            if operation.old_sha != "0" * 40:  # Not a new branch
                # Check if new_sha is an ancestor of old_sha
                # This would require actual Git operations
                # For demonstration, we'll check if it's in the metadata
                if operation.metadata.get("force_push"):
                    if not self.allow_force_push:
                        return "Force push is not allowed on protected branches"
                    elif not self._is_admin(context.user):
                        return (
                            "Only administrators can force push to protected branches"
                        )

        return None

    def _check_deletion(self, context: PluginContext) -> Optional[str]:
        """Check for branch deletion attempts."""
        operation = context.operation

        # Check if this is a deletion (new_sha is all zeros)
        if operation.new_sha == "0" * 40:
            return "Deleting protected branches is not allowed"

        return None

    def _check_commit_signatures(self, context: PluginContext) -> Optional[str]:
        """Check if commits are signed."""
        if not self.require_signed_commits:
            return None

        # Check commits for signatures
        for commit in context.operation.commits:
            if not commit.get("signed", False):
                return f"Commit {commit.get('sha', 'unknown')[:8]} is not signed. Protected branches require signed commits."

        return None

    def _check_file_restrictions(
        self, context: PluginContext, protection: Dict
    ) -> Optional[str]:
        """Check file-based restrictions."""
        restricted_paths = protection.get("restricted_paths", [])
        if not restricted_paths:
            return None

        for file_path in context.operation.files_changed:
            for restricted in restricted_paths:
                if file_path.startswith(restricted):
                    if not self._is_admin(context.user):
                        return (
                            f"Modifying {file_path} requires administrator privileges"
                        )

        return None

    async def pre_receive(self, context: PluginContext) -> PluginResult:
        """
        Check branch protection rules before receiving commits.

        Args:
            context: Plugin execution context

        Returns:
            PluginResult indicating whether to allow the push
        """
        # Check if this is a branch update
        ref = context.operation.ref
        if not ref or not ref.startswith("refs/heads/"):
            return PluginResult.success("Not a branch update")

        # Check if branch is protected
        protection = self._is_protected_branch(ref)
        if not protection:
            return PluginResult.success("Branch is not protected")

        branch_name = ref[11:]  # Remove "refs/heads/"
        protection_level = protection.get("level", "moderate")

        # Check if user is admin (admins can bypass some rules)
        is_admin = self._is_admin(context.user)

        # Strict protection: No direct pushes allowed
        if protection_level == "strict" and not is_admin:
            if self.require_pull_request:
                return PluginResult.deny(
                    f"Direct pushes to {branch_name} are not allowed. Please create a pull request."
                )

        # Check for force push
        force_push_error = self._check_force_push(context)
        if force_push_error:
            return PluginResult.deny(force_push_error)

        # Check for deletion
        deletion_error = self._check_deletion(context)
        if deletion_error:
            return PluginResult.deny(deletion_error)

        # Check commit signatures
        signature_error = self._check_commit_signatures(context)
        if signature_error:
            return PluginResult.deny(signature_error)

        # Check file restrictions
        file_error = self._check_file_restrictions(context, protection)
        if file_error:
            return PluginResult.deny(file_error)

        # Check custom rules from configuration
        custom_rules = protection.get("custom_rules", {})

        # Check allowed users
        allowed_users = custom_rules.get("allowed_users", [])
        if allowed_users and context.user.username not in allowed_users:
            return PluginResult.deny(
                f"User {context.user.username} is not allowed to push to {branch_name}"
            )

        # Check allowed groups
        allowed_groups = custom_rules.get("allowed_groups", [])
        if allowed_groups:
            user_in_group = any(g in allowed_groups for g in context.user.groups)
            if not user_in_group:
                return PluginResult.deny(
                    f"User must be in one of these groups to push to {branch_name}: {allowed_groups}"
                )

        # Check time-based restrictions
        time_restrictions = custom_rules.get("time_restrictions", {})
        if time_restrictions:
            # This would check current time against allowed time windows
            # For demonstration, we'll skip this
            pass

        logger.info(
            "Branch protection check passed",
            branch=branch_name,
            user=context.user.username,
            protection_level=protection_level,
        )

        return PluginResult.success(f"Push to {branch_name} allowed")

    async def post_receive(self, context: PluginContext) -> PluginResult:
        """
        Log protected branch updates.

        Args:
            context: Plugin execution context

        Returns:
            PluginResult with success status
        """
        ref = context.operation.ref
        if not ref or not ref.startswith("refs/heads/"):
            return PluginResult.skip()

        protection = self._is_protected_branch(ref)
        if protection:
            branch_name = ref[11:]
            logger.info(
                "Protected branch updated",
                branch=branch_name,
                user=context.user.username,
                commits=len(context.operation.commits),
                protection_level=protection.get("level"),
            )

        return PluginResult.success()
