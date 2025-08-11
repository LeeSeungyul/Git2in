"""Tests for authorization and access control"""

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from src.core.auth.models import TokenClaims, TokenScope, TokenType
from src.core.authorization.models import (Action, AuthorizationRequest,
                                           AuthorizationResult, Permission,
                                           PermissionGrant,
                                           PermissionInheritance,
                                           PermissionMatrix, ResourceType,
                                           Role, RolePermissions)
from src.core.authorization.service import (AuthorizationService,
                                            authorization_service)
from src.infrastructure.audit.logger import (AuditAction, AuditLogger,
                                             AuditResult)
from src.infrastructure.security.ip_filter import (IPFilterAction,
                                                   IPFilterConfig,
                                                   IPFilterRule,
                                                   IPFilterService)


class TestPermissionModels:
    """Test permission and role models"""

    def test_permission_creation(self):
        """Test creating permissions"""
        perm = Permission(
            resource_type=ResourceType.REPOSITORY,
            action=Action.READ,
            resource_id="namespace/repo",
        )

        assert perm.resource_type == ResourceType.REPOSITORY
        assert perm.action == Action.READ
        assert perm.resource_id == "namespace/repo"

    def test_permission_matching(self):
        """Test permission matching logic"""
        perm = Permission(
            resource_type=ResourceType.REPOSITORY,
            action=Action.READ,
            resource_id="namespace/repo",
        )

        # Exact match
        assert perm.matches(ResourceType.REPOSITORY, Action.READ, "namespace/repo")

        # Different resource ID
        assert not perm.matches(ResourceType.REPOSITORY, Action.READ, "other/repo")

        # Different action
        assert not perm.matches(ResourceType.REPOSITORY, Action.WRITE, "namespace/repo")

        # Wildcard permission
        wildcard_perm = Permission(
            resource_type=ResourceType.REPOSITORY,
            action=Action.READ,
            resource_id=None,  # Matches all
        )
        assert wildcard_perm.matches(ResourceType.REPOSITORY, Action.READ, "any/repo")

    def test_permission_string_conversion(self):
        """Test permission string serialization"""
        perm = Permission(
            resource_type=ResourceType.REPOSITORY,
            action=Action.WRITE,
            resource_id="namespace/repo",
        )

        perm_str = perm.to_string()
        assert perm_str == "repository:namespace/repo:write"

        # Parse back
        parsed = Permission.from_string(perm_str)
        assert parsed.resource_type == perm.resource_type
        assert parsed.action == perm.action
        assert parsed.resource_id == perm.resource_id

    def test_role_default_permissions(self):
        """Test default permissions for roles"""
        # Owner should have all permissions
        owner_perms = RolePermissions.get_default_permissions(Role.OWNER)
        assert any(p.action == Action.DELETE for p in owner_perms)
        assert any(p.action == Action.MANAGE_USERS for p in owner_perms)

        # Developer should have read/write but not delete
        dev_perms = RolePermissions.get_default_permissions(Role.DEVELOPER)
        assert any(p.action == Action.READ for p in dev_perms)
        assert any(p.action == Action.WRITE for p in dev_perms)
        assert not any(p.action == Action.DELETE for p in dev_perms)

        # Viewer should only have read
        viewer_perms = RolePermissions.get_default_permissions(Role.VIEWER)
        assert any(p.action == Action.READ for p in viewer_perms)
        assert not any(p.action == Action.WRITE for p in viewer_perms)

    def test_permission_grant(self):
        """Test permission grant functionality"""
        grant = PermissionGrant(
            grantee_id="user123",
            grantee_type="user",
            resource_type=ResourceType.REPOSITORY,
            resource_id="namespace/repo",
            permissions=[
                Permission(resource_type=ResourceType.REPOSITORY, action=Action.READ),
                Permission(resource_type=ResourceType.REPOSITORY, action=Action.WRITE),
            ],
            role=Role.DEVELOPER,
            granted_by="admin",
        )

        assert grant.has_permission(Action.READ)
        assert grant.has_permission(Action.WRITE)
        assert not grant.has_permission(Action.DELETE)
        assert not grant.is_expired()

    def test_permission_grant_expiration(self):
        """Test permission grant expiration"""
        grant = PermissionGrant(
            grantee_id="user123",
            grantee_type="user",
            resource_type=ResourceType.REPOSITORY,
            resource_id="namespace/repo",
            permissions=[],
            granted_by="admin",
            expires_at=datetime.utcnow() - timedelta(hours=1),
        )

        assert grant.is_expired()


class TestPermissionMatrix:
    """Test permission matrix functionality"""

    def test_permission_matrix_initialization(self):
        """Test permission matrix initialization"""
        matrix = PermissionMatrix()

        # Should have default role definitions
        assert len(matrix.role_definitions) == len(Role)
        assert Role.OWNER in matrix.role_definitions

    def test_add_and_remove_grant(self):
        """Test adding and removing grants"""
        matrix = PermissionMatrix()

        grant = PermissionGrant(
            grantee_id="user123",
            grantee_type="user",
            resource_type=ResourceType.REPOSITORY,
            resource_id="namespace/repo",
            permissions=[
                Permission(resource_type=ResourceType.REPOSITORY, action=Action.READ)
            ],
            granted_by="admin",
        )

        matrix.add_grant(grant)
        assert len(matrix.grants) == 1

        # Remove grant
        removed = matrix.remove_grant(
            "user123", ResourceType.REPOSITORY, "namespace/repo"
        )
        assert removed
        assert len(matrix.grants) == 0

    def test_get_user_permissions(self):
        """Test getting user permissions"""
        matrix = PermissionMatrix()

        # Grant role to user
        matrix.grant_role(
            user_id="user123",
            role=Role.DEVELOPER,
            resource_type=ResourceType.REPOSITORY,
            resource_id="namespace/repo",
            granted_by="admin",
        )

        # Get permissions
        perms = matrix.get_user_permissions(
            "user123", ResourceType.REPOSITORY, "namespace/repo"
        )

        assert len(perms) > 0
        assert any(p.action == Action.READ for p in perms)
        assert any(p.action == Action.WRITE for p in perms)

    def test_check_permission(self):
        """Test permission checking"""
        matrix = PermissionMatrix()

        # Grant role
        matrix.grant_role(
            user_id="user123",
            role=Role.DEVELOPER,
            resource_type=ResourceType.REPOSITORY,
            resource_id="namespace/repo",
            granted_by="admin",
        )

        # Check permissions
        assert matrix.check_permission(
            "user123", ResourceType.REPOSITORY, Action.READ, "namespace/repo"
        )
        assert matrix.check_permission(
            "user123", ResourceType.REPOSITORY, Action.WRITE, "namespace/repo"
        )
        assert not matrix.check_permission(
            "user123", ResourceType.REPOSITORY, Action.DELETE, "namespace/repo"
        )


class TestAuthorizationService:
    """Test authorization service"""

    def test_admin_token_bypass(self):
        """Test that admin tokens bypass all checks"""
        service = AuthorizationService()

        token_claims = TokenClaims(
            sub="admin",
            iat=int(datetime.utcnow().timestamp()),
            exp=int(datetime.utcnow().timestamp()) + 3600,
            jti="test-admin-token",
            token_type=TokenType.ACCESS,
            scopes=[TokenScope.ADMIN],
        )

        result = service.check_permission(
            token_claims, ResourceType.REPOSITORY, Action.DELETE, "any/repo"
        )

        assert result.allowed
        assert "Admin" in result.reason

    def test_token_scope_authorization(self):
        """Test authorization based on token scopes"""
        service = AuthorizationService()

        token_claims = TokenClaims(
            sub="user123",
            iat=int(datetime.utcnow().timestamp()),
            exp=int(datetime.utcnow().timestamp()) + 3600,
            jti="test-token-1",
            token_type=TokenType.ACCESS,
            scopes=[TokenScope.REPO_READ, TokenScope.REPO_WRITE],
        )

        # Should allow read
        result = service.check_permission(
            token_claims, ResourceType.REPOSITORY, Action.READ, "namespace/repo"
        )
        assert result.allowed

        # Should allow write
        result = service.check_permission(
            token_claims, ResourceType.REPOSITORY, Action.WRITE, "namespace/repo"
        )
        assert result.allowed

        # Should deny delete (no REPO_ADMIN scope)
        result = service.check_permission(
            token_claims, ResourceType.REPOSITORY, Action.DELETE, "namespace/repo"
        )
        assert not result.allowed

    def test_namespace_scoped_token(self):
        """Test namespace-scoped token restrictions"""
        service = AuthorizationService()

        token_claims = TokenClaims(
            sub="user123",
            iat=int(datetime.utcnow().timestamp()),
            exp=int(datetime.utcnow().timestamp()) + 3600,
            jti="test-token-2",
            token_type=TokenType.ACCESS,
            scopes=[TokenScope.REPO_READ],
            namespace="allowed-namespace",
        )

        # Should allow in scoped namespace
        result = service.check_permission(
            token_claims, ResourceType.REPOSITORY, Action.READ, "allowed-namespace/repo"
        )
        assert result.allowed

        # Should deny in different namespace
        result = service.check_permission(
            token_claims, ResourceType.REPOSITORY, Action.READ, "other-namespace/repo"
        )
        assert not result.allowed
        assert "not authorized for this namespace" in result.reason

    def test_repository_scoped_token(self):
        """Test repository-scoped token restrictions"""
        service = AuthorizationService()

        token_claims = TokenClaims(
            sub="user123",
            iat=int(datetime.utcnow().timestamp()),
            exp=int(datetime.utcnow().timestamp()) + 3600,
            jti="test-token-3",
            token_type=TokenType.ACCESS,
            scopes=[TokenScope.REPO_WRITE],
            namespace="namespace",
            repository="specific-repo",
        )

        # Should allow for specific repo
        result = service.check_permission(
            token_claims,
            ResourceType.REPOSITORY,
            Action.WRITE,
            "namespace/specific-repo",
        )
        assert result.allowed

        # Should deny for different repo
        result = service.check_permission(
            token_claims, ResourceType.REPOSITORY, Action.WRITE, "namespace/other-repo"
        )
        assert not result.allowed

    def test_permission_caching(self):
        """Test authorization result caching"""
        service = AuthorizationService()

        token_claims = TokenClaims(
            sub="user123",
            iat=int(datetime.utcnow().timestamp()),
            exp=int(datetime.utcnow().timestamp()) + 3600,
            jti="test-token-4",
            token_type=TokenType.ACCESS,
            scopes=[TokenScope.REPO_READ],
        )

        # First call should cache
        result1 = service.check_permission(
            token_claims, ResourceType.REPOSITORY, Action.READ, "namespace/repo"
        )

        # Second call should use cache
        result2 = service.check_permission(
            token_claims, ResourceType.REPOSITORY, Action.READ, "namespace/repo"
        )

        assert result1.allowed == result2.allowed
        assert result1.reason == result2.reason

    def test_parse_resource_path(self):
        """Test resource path parsing"""
        service = AuthorizationService()

        # Git endpoint
        resource_type, resource_id = service.parse_resource_path(
            "/git/namespace/repo.git/info/refs"
        )
        assert resource_type == ResourceType.REPOSITORY
        assert resource_id == "namespace/repo"

        # Namespace endpoint
        resource_type, resource_id = service.parse_resource_path(
            "/namespaces/my-namespace/repos"
        )
        assert resource_type == ResourceType.NAMESPACE
        assert resource_id == "my-namespace"

        # User endpoint
        resource_type, resource_id = service.parse_resource_path(
            "/users/user123/profile"
        )
        assert resource_type == ResourceType.USER
        assert resource_id == "user123"

        # System endpoint
        resource_type, resource_id = service.parse_resource_path("/metrics")
        assert resource_type == ResourceType.SYSTEM
        assert resource_id is None


class TestAuditLogging:
    """Test audit logging functionality"""

    def test_audit_logger_initialization(self):
        """Test audit logger initialization"""
        logger = AuditLogger()
        assert logger._logger is not None

    def test_audit_log_success(self):
        """Test logging successful action"""
        logger = AuditLogger()

        logger.log_success(
            action=AuditAction.CREATE_REPO,
            user_id="user123",
            resource="namespace/repo",
            resource_type="repository",
            client_ip="192.168.1.1",
            details={"visibility": "private"},
        )

        # Log should be created without errors
        assert True

    def test_audit_log_failure(self):
        """Test logging failed action"""
        logger = AuditLogger()

        logger.log_failure(
            action=AuditAction.DELETE_REPO,
            user_id="user123",
            resource="namespace/repo",
            error="Repository not found",
        )

        assert True

    def test_audit_log_denied(self):
        """Test logging denied action"""
        logger = AuditLogger()

        logger.log_denied(
            action=AuditAction.PUSH,
            user_id="user123",
            resource="namespace/repo",
            reason="Insufficient permissions",
        )

        assert True

    def test_audit_operation_timing(self):
        """Test operation timing"""
        logger = AuditLogger()

        operation_id = "test-op-123"
        logger.start_operation(operation_id)

        import time

        time.sleep(0.1)

        duration = logger.end_operation(operation_id)
        assert duration is not None
        assert duration >= 100  # At least 100ms


class TestIPFiltering:
    """Test IP filtering functionality"""

    def test_ip_filter_rule_matching(self):
        """Test IP filter rule matching"""
        rule = IPFilterRule("192.168.1.0/24", IPFilterAction.ALLOW, "Local network")

        assert rule.matches("192.168.1.100")
        assert rule.matches("192.168.1.1")
        assert not rule.matches("192.168.2.1")
        assert not rule.matches("10.0.0.1")

    def test_ip_filter_service_initialization(self):
        """Test IP filter service initialization"""
        service = IPFilterService()

        # Should have localhost allowed by default
        rules = service.get_rules()
        assert any(r["cidr"] == "127.0.0.1/32" for r in rules)

    def test_ip_allowlist(self):
        """Test IP allowlist functionality"""
        service = IPFilterService()
        service.clear_rules()

        # Add allowlist
        service.add_allowlist(["10.0.0.0/8", "192.168.0.0/16"])

        # Should allow listed IPs
        allowed, reason = service.check_ip("10.0.0.1")
        assert allowed

        allowed, reason = service.check_ip("192.168.1.1")
        assert allowed

        # Should deny unlisted IPs (in production mode)
        # Note: In development mode, default is allow

    def test_ip_denylist(self):
        """Test IP denylist functionality"""
        service = IPFilterService()

        # Add denylist with high priority
        service.add_denylist(["10.10.10.0/24"])

        # Should deny listed IPs
        allowed, reason = service.check_ip("10.10.10.1")
        assert not allowed
        assert "Denylist" in reason

    def test_resource_specific_rules(self):
        """Test resource-specific IP rules"""
        service = IPFilterService()

        # Add resource rule
        rule = IPFilterRule("172.16.0.0/16", IPFilterAction.ALLOW)
        service.add_resource_rule("repo:namespace/secure-repo", rule)

        # Should allow for specific resource
        allowed, reason = service.check_ip(
            "172.16.1.1", resource_id="repo:namespace/secure-repo"
        )
        assert allowed

    def test_rate_limiting(self):
        """Test IP rate limiting"""
        service = IPFilterService()
        service.rate_limit_max_requests = 5
        service.rate_limit_window = 1  # 1 second window

        # Make multiple requests
        ip = "192.168.1.100"
        for i in range(5):
            allowed, _ = service.check_ip(ip)
            assert allowed

        # 6th request should be rate limited
        allowed, reason = service.check_ip(ip)
        assert not allowed
        assert "Rate limit" in reason

    def test_bypass_token(self):
        """Test bypass token for admin access"""
        service = IPFilterService()

        # Add global deny rule
        service.add_denylist(["0.0.0.0/0"])  # Deny all

        # Should be denied without bypass
        allowed, _ = service.check_ip("192.168.1.1")
        assert not allowed

        # Should be allowed with valid bypass token
        # (Would need to set up test bypass token in settings)

    def test_ip_extraction(self):
        """Test real IP extraction from headers"""
        service = IPFilterService()

        # Test X-Forwarded-For format
        ip = service._extract_real_ip("203.0.113.1, 198.51.100.2, 192.0.2.3")
        assert ip == "203.0.113.1"

        # Test single IP
        ip = service._extract_real_ip("192.168.1.1")
        assert ip == "192.168.1.1"

        # Test invalid format
        ip = service._extract_real_ip("not-an-ip")
        assert ip == "not-an-ip"
