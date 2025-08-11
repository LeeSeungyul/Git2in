"""CIDR-based IP filtering for access control"""

import ipaddress
from enum import Enum
from functools import lru_cache
from typing import Dict, List, Optional, Set, Tuple

from src.core.config import settings
from src.infrastructure.audit.logger import (AuditAction, AuditResult,
                                             audit_logger)
from src.infrastructure.logging import get_logger

logger = get_logger(__name__)


class IPFilterAction(str, Enum):
    """Action to take for IP filtering"""

    ALLOW = "allow"
    DENY = "deny"


class IPFilterRule:
    """Single IP filter rule"""

    def __init__(
        self,
        cidr: str,
        action: IPFilterAction,
        description: Optional[str] = None,
        priority: int = 0,
    ):
        self.network = ipaddress.ip_network(cidr)
        self.action = action
        self.description = description
        self.priority = priority

    def matches(self, ip: str) -> bool:
        """Check if IP matches this rule"""
        try:
            ip_addr = ipaddress.ip_address(ip)
            return ip_addr in self.network
        except ValueError:
            return False

    def __repr__(self) -> str:
        return f"IPFilterRule({self.network}, {self.action.value}, priority={self.priority})"


class IPFilterConfig:
    """IP filter configuration for a resource"""

    def __init__(self, resource_id: str):
        self.resource_id = resource_id
        self.rules: List[IPFilterRule] = []
        self.inherit_global = True

    def add_rule(self, rule: IPFilterRule):
        """Add a filter rule"""
        self.rules.append(rule)
        # Sort by priority (higher priority first)
        self.rules.sort(key=lambda r: r.priority, reverse=True)

    def remove_rule(self, cidr: str):
        """Remove a filter rule by CIDR"""
        self.rules = [r for r in self.rules if str(r.network) != cidr]

    def evaluate(self, ip: str) -> Optional[IPFilterAction]:
        """Evaluate IP against rules"""
        for rule in self.rules:
            if rule.matches(ip):
                return rule.action
        return None


class IPFilterService:
    """Service for IP-based access filtering"""

    def __init__(self):
        self.global_rules: List[IPFilterRule] = []
        self.resource_configs: Dict[str, IPFilterConfig] = {}
        self.rate_limits: Dict[str, List[float]] = {}  # IP -> timestamps
        self.rate_limit_window = 60  # seconds
        self.rate_limit_max_requests = 100

        # Initialize default rules
        self._initialize_default_rules()

    def _initialize_default_rules(self):
        """Initialize default IP filter rules"""
        # Allow localhost by default
        self.add_global_rule(
            IPFilterRule(
                "127.0.0.1/32", IPFilterAction.ALLOW, "Localhost", priority=100
            )
        )

        # Allow private networks in development
        if settings.is_development:
            self.add_global_rule(
                IPFilterRule(
                    "10.0.0.0/8",
                    IPFilterAction.ALLOW,
                    "Private network (10.x)",
                    priority=50,
                )
            )
            self.add_global_rule(
                IPFilterRule(
                    "172.16.0.0/12",
                    IPFilterAction.ALLOW,
                    "Private network (172.16-31.x)",
                    priority=50,
                )
            )
            self.add_global_rule(
                IPFilterRule(
                    "192.168.0.0/16",
                    IPFilterAction.ALLOW,
                    "Private network (192.168.x)",
                    priority=50,
                )
            )

    def add_global_rule(self, rule: IPFilterRule):
        """Add a global IP filter rule"""
        self.global_rules.append(rule)
        self.global_rules.sort(key=lambda r: r.priority, reverse=True)

        logger.info(
            "ip_filter_global_rule_added",
            cidr=str(rule.network),
            action=rule.action.value,
            priority=rule.priority,
        )

    def add_resource_rule(
        self, resource_id: str, rule: IPFilterRule, inherit_global: bool = True
    ):
        """Add an IP filter rule for a specific resource"""
        if resource_id not in self.resource_configs:
            self.resource_configs[resource_id] = IPFilterConfig(resource_id)

        config = self.resource_configs[resource_id]
        config.inherit_global = inherit_global
        config.add_rule(rule)

        logger.info(
            "ip_filter_resource_rule_added",
            resource=resource_id,
            cidr=str(rule.network),
            action=rule.action.value,
            priority=rule.priority,
        )

    def check_ip(
        self,
        ip: str,
        resource_id: Optional[str] = None,
        user_id: Optional[str] = None,
        bypass_token: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Check if IP is allowed access

        Returns:
            (allowed, reason)
        """

        # Clean IP address
        ip = self._extract_real_ip(ip)

        # Check bypass token (for admin access)
        if bypass_token and self._validate_bypass_token(bypass_token):
            logger.debug("ip_filter_bypassed", ip=ip, reason="Valid bypass token")
            return True, "Bypass token validated"

        # Check rate limiting
        if not self._check_rate_limit(ip):
            audit_logger.log_denied(
                AuditAction.VIEW_METRICS,
                user_id=user_id,
                resource=resource_id,
                client_ip=ip,
                reason="Rate limit exceeded",
            )
            return False, "Rate limit exceeded"

        # Evaluate resource-specific rules first
        if resource_id and resource_id in self.resource_configs:
            config = self.resource_configs[resource_id]
            action = config.evaluate(ip)

            if action == IPFilterAction.ALLOW:
                logger.debug(
                    "ip_filter_allowed",
                    ip=ip,
                    resource=resource_id,
                    reason="Resource rule",
                )
                return True, f"Allowed by resource rule for {resource_id}"
            elif action == IPFilterAction.DENY:
                logger.warning(
                    "ip_filter_denied",
                    ip=ip,
                    resource=resource_id,
                    reason="Resource rule",
                )
                audit_logger.log_denied(
                    AuditAction.VIEW_METRICS,
                    user_id=user_id,
                    resource=resource_id,
                    client_ip=ip,
                    reason=f"Denied by resource rule for {resource_id}",
                )
                return False, f"Denied by resource rule for {resource_id}"

            # If no resource rule matched and inherit_global is False, deny
            if not config.inherit_global:
                logger.warning(
                    "ip_filter_denied",
                    ip=ip,
                    resource=resource_id,
                    reason="No matching resource rule",
                )
                return False, "No matching resource rule"

        # Evaluate global rules
        for rule in self.global_rules:
            if rule.matches(ip):
                if rule.action == IPFilterAction.ALLOW:
                    logger.debug(
                        "ip_filter_allowed",
                        ip=ip,
                        reason=f"Global rule: {rule.description}",
                    )
                    return True, f"Allowed by global rule: {rule.description}"
                else:
                    logger.warning(
                        "ip_filter_denied",
                        ip=ip,
                        reason=f"Global rule: {rule.description}",
                    )
                    audit_logger.log_denied(
                        AuditAction.VIEW_METRICS,
                        user_id=user_id,
                        resource=resource_id,
                        client_ip=ip,
                        reason=f"Denied by global rule: {rule.description}",
                    )
                    return False, f"Denied by global rule: {rule.description}"

        # Default action (allow in development, deny in production)
        if settings.is_development:
            logger.debug("ip_filter_allowed", ip=ip, reason="Development mode default")
            return True, "Allowed by default (development mode)"
        else:
            logger.warning("ip_filter_denied", ip=ip, reason="No matching rules")
            audit_logger.log_denied(
                AuditAction.VIEW_METRICS,
                user_id=user_id,
                resource=resource_id,
                client_ip=ip,
                reason="No matching IP filter rules",
            )
            return False, "No matching IP filter rules"

    def _extract_real_ip(self, ip: str) -> str:
        """Extract real IP from X-Forwarded-For or similar headers"""
        # If it's already an IP, return it
        if self._is_valid_ip(ip):
            return ip

        # Handle X-Forwarded-For format: "client, proxy1, proxy2"
        if "," in ip:
            parts = ip.split(",")
            for part in parts:
                part = part.strip()
                if self._is_valid_ip(part):
                    return part

        return ip

    @lru_cache(maxsize=1000)
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _check_rate_limit(self, ip: str) -> bool:
        """Check if IP has exceeded rate limit"""
        import time

        current_time = time.time()

        # Clean old timestamps
        if ip in self.rate_limits:
            self.rate_limits[ip] = [
                ts
                for ts in self.rate_limits[ip]
                if current_time - ts < self.rate_limit_window
            ]
        else:
            self.rate_limits[ip] = []

        # Check rate limit
        if len(self.rate_limits[ip]) >= self.rate_limit_max_requests:
            logger.warning(
                "ip_rate_limit_exceeded",
                ip=ip,
                requests=len(self.rate_limits[ip]),
                window=self.rate_limit_window,
            )
            return False

        # Add current request
        self.rate_limits[ip].append(current_time)
        return True

    def _validate_bypass_token(self, token: str) -> bool:
        """Validate bypass token for admin access"""
        # In production, this would validate against a secure token store
        # For now, check against environment variable
        if hasattr(settings, "ip_filter_bypass_token"):
            return token == settings.ip_filter_bypass_token
        return False

    def add_allowlist(self, cidrs: List[str], resource_id: Optional[str] = None):
        """Add multiple CIDRs to allowlist"""
        for cidr in cidrs:
            try:
                rule = IPFilterRule(cidr, IPFilterAction.ALLOW, f"Allowlist: {cidr}")
                if resource_id:
                    self.add_resource_rule(resource_id, rule)
                else:
                    self.add_global_rule(rule)
            except ValueError as e:
                logger.error(f"Invalid CIDR: {cidr}: {e}")

    def add_denylist(self, cidrs: List[str], resource_id: Optional[str] = None):
        """Add multiple CIDRs to denylist"""
        for cidr in cidrs:
            try:
                rule = IPFilterRule(
                    cidr,
                    IPFilterAction.DENY,
                    f"Denylist: {cidr}",
                    priority=90,  # High priority for denylists
                )
                if resource_id:
                    self.add_resource_rule(resource_id, rule)
                else:
                    self.add_global_rule(rule)
            except ValueError as e:
                logger.error(f"Invalid CIDR: {cidr}: {e}")

    def get_rules(self, resource_id: Optional[str] = None) -> List[Dict]:
        """Get current filter rules"""
        rules = []

        # Global rules
        for rule in self.global_rules:
            rules.append(
                {
                    "scope": "global",
                    "cidr": str(rule.network),
                    "action": rule.action.value,
                    "description": rule.description,
                    "priority": rule.priority,
                }
            )

        # Resource-specific rules
        if resource_id and resource_id in self.resource_configs:
            config = self.resource_configs[resource_id]
            for rule in config.rules:
                rules.append(
                    {
                        "scope": "resource",
                        "resource": resource_id,
                        "cidr": str(rule.network),
                        "action": rule.action.value,
                        "description": rule.description,
                        "priority": rule.priority,
                    }
                )

        return rules

    def clear_rules(self, resource_id: Optional[str] = None):
        """Clear IP filter rules"""
        if resource_id:
            if resource_id in self.resource_configs:
                del self.resource_configs[resource_id]
                logger.info("ip_filter_resource_rules_cleared", resource=resource_id)
        else:
            self.global_rules.clear()
            self._initialize_default_rules()
            logger.info("ip_filter_global_rules_cleared")


# Global IP filter service instance
ip_filter_service = IPFilterService()
