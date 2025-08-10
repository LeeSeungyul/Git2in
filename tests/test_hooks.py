"""Tests for hook system"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime

from src.infrastructure.hooks import (
    HookManager, HookEvent, HookContext, Hook,
    LoggingHook, StatisticsHook, AccessControlHook, WebhookHook
)
from src.core.models import Repository, User


class TestHookContext:
    """Test hook context functionality"""
    
    def test_hook_context_creation(self):
        """Test creating a hook context"""
        repo = Repository(
            name="test-repo",
            namespace_name="test-namespace",
            owner_id="00000000-0000-0000-0000-000000000000"
        )
        
        user = User(
            username="testuser",
            email="test@example.com"
        )
        
        context = HookContext(
            event=HookEvent.PRE_PUSH,
            repository=repo,
            user=user,
            ip_address="192.168.1.1",
            user_agent="git/2.39.0",
            correlation_id="test-correlation-id",
            custom_data="test"
        )
        
        assert context.event == HookEvent.PRE_PUSH
        assert context.repository == repo
        assert context.user == user
        assert context.ip_address == "192.168.1.1"
        assert context.user_agent == "git/2.39.0"
        assert context.correlation_id == "test-correlation-id"
        assert context.data["custom_data"] == "test"
        assert isinstance(context.timestamp, datetime)
    
    def test_hook_context_add_result(self):
        """Test adding results to context"""
        context = HookContext(
            event=HookEvent.POST_RECEIVE,
            repository=Mock()
        )
        
        context.add_result("key1", "value1")
        context.add_result("key2", {"nested": "value"})
        
        assert context.results["key1"] == "value1"
        assert context.results["key2"]["nested"] == "value"
    
    def test_hook_context_add_error(self):
        """Test adding errors to context"""
        context = HookContext(
            event=HookEvent.PRE_RECEIVE,
            repository=Mock()
        )
        
        assert context.has_errors() is False
        
        context.add_error("Error 1")
        context.add_error("Error 2")
        
        assert context.has_errors() is True
        assert len(context.errors) == 2
        assert "Error 1" in context.errors
        assert "Error 2" in context.errors
    
    def test_hook_context_to_dict(self):
        """Test converting context to dictionary"""
        repo = Mock()
        repo.full_name = "test-namespace/test-repo"
        
        user = Mock()
        user.username = "testuser"
        
        context = HookContext(
            event=HookEvent.PRE_PUSH,
            repository=repo,
            user=user,
            ip_address="192.168.1.1",
            correlation_id="test-id"
        )
        
        context.add_result("test_result", "value")
        context.add_error("test error")
        
        data = context.to_dict()
        
        assert data["event"] == "pre-push"
        assert data["repository"] == "test-namespace/test-repo"
        assert data["user"] == "testuser"
        assert data["ip_address"] == "192.168.1.1"
        assert data["correlation_id"] == "test-id"
        assert "timestamp" in data
        assert data["results"]["test_result"] == "value"
        assert "test error" in data["errors"]


class TestHookBase:
    """Test base Hook class"""
    
    def test_hook_creation(self):
        """Test creating a hook"""
        
        class TestHook(Hook):
            async def execute(self, context: HookContext):
                pass
        
        hook = TestHook("test_hook", enabled=True)
        assert hook.name == "test_hook"
        assert hook.enabled is True
    
    def test_hook_should_run(self):
        """Test hook should_run method"""
        
        class TestHook(Hook):
            async def execute(self, context: HookContext):
                pass
        
        hook = TestHook("test_hook", enabled=True)
        context = Mock()
        
        assert hook.should_run(context) is True
        
        hook.enabled = False
        assert hook.should_run(context) is False


class TestLoggingHook:
    """Test logging hook"""
    
    @pytest.mark.asyncio
    async def test_logging_hook_execute(self):
        """Test logging hook execution"""
        hook = LoggingHook()
        
        repo = Mock()
        repo.full_name = "test/repo"
        
        user = Mock()
        user.username = "testuser"
        
        context = HookContext(
            event=HookEvent.PRE_PUSH,
            repository=repo,
            user=user,
            ip_address="192.168.1.1",
            correlation_id="test-id"
        )
        
        # Hook should execute without errors
        with patch("src.infrastructure.hooks.logger") as mock_logger:
            await hook.execute(context)
            
            mock_logger.info.assert_called_once()
            call_args = mock_logger.info.call_args
            
            assert call_args[0][0] == "repository_hook_event"
            assert call_args[1]["hook_event"] == "pre-push"
            assert call_args[1]["repository"] == "test/repo"
            assert call_args[1]["user"] == "testuser"


class TestStatisticsHook:
    """Test statistics hook"""
    
    @pytest.mark.asyncio
    async def test_statistics_hook_execute(self):
        """Test statistics hook execution"""
        hook = StatisticsHook()
        
        repo = Mock()
        repo.full_name = "test/repo"
        
        context1 = HookContext(
            event=HookEvent.POST_RECEIVE,
            repository=repo
        )
        
        await hook.execute(context1)
        
        assert "statistics" in context1.results
        assert context1.results["statistics"]["event_count"] == 1
        assert context1.results["statistics"]["total_events"] == 1
        
        # Execute again for same event
        context2 = HookContext(
            event=HookEvent.POST_RECEIVE,
            repository=repo
        )
        
        await hook.execute(context2)
        
        assert context2.results["statistics"]["event_count"] == 2
        assert context2.results["statistics"]["total_events"] == 2
    
    @pytest.mark.asyncio
    async def test_statistics_hook_multiple_events(self):
        """Test statistics hook with multiple events"""
        hook = StatisticsHook()
        
        repo1 = Mock()
        repo1.full_name = "test/repo1"
        
        repo2 = Mock()
        repo2.full_name = "test/repo2"
        
        # Different repositories and events
        contexts = [
            HookContext(event=HookEvent.POST_RECEIVE, repository=repo1),
            HookContext(event=HookEvent.POST_UPLOAD, repository=repo1),
            HookContext(event=HookEvent.POST_RECEIVE, repository=repo2),
            HookContext(event=HookEvent.POST_RECEIVE, repository=repo1),
        ]
        
        for context in contexts:
            await hook.execute(context)
        
        # Check last context
        assert contexts[-1].results["statistics"]["event_count"] == 2  # repo1:post-receive
        assert contexts[-1].results["statistics"]["total_events"] == 4  # All events


class TestAccessControlHook:
    """Test access control hook"""
    
    @pytest.mark.asyncio
    async def test_access_control_hook_allow(self):
        """Test access control hook allowing access"""
        
        async def check_function(context):
            return True  # Allow access
        
        hook = AccessControlHook(check_function=check_function)
        
        context = HookContext(
            event=HookEvent.PRE_PUSH,
            repository=Mock()
        )
        
        await hook.execute(context)
        
        assert context.has_errors() is False
    
    @pytest.mark.asyncio
    async def test_access_control_hook_deny(self):
        """Test access control hook denying access"""
        
        async def check_function(context):
            return False  # Deny access
        
        hook = AccessControlHook(check_function=check_function)
        
        repo = Mock()
        repo.full_name = "test/repo"
        
        context = HookContext(
            event=HookEvent.PRE_PUSH,
            repository=repo
        )
        
        with patch("src.infrastructure.hooks.logger") as mock_logger:
            await hook.execute(context)
            
            assert context.has_errors() is True
            assert "Access denied by access control hook" in context.errors
            mock_logger.warning.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_access_control_hook_error(self):
        """Test access control hook with error"""
        
        async def check_function(context):
            raise Exception("Check failed")
        
        hook = AccessControlHook(check_function=check_function)
        
        context = HookContext(
            event=HookEvent.PRE_PUSH,
            repository=Mock()
        )
        
        await hook.execute(context)
        
        assert context.has_errors() is True
        assert any("Access control error" in error for error in context.errors)
    
    @pytest.mark.asyncio
    async def test_access_control_hook_no_function(self):
        """Test access control hook without check function"""
        hook = AccessControlHook(check_function=None)
        
        context = HookContext(
            event=HookEvent.PRE_PUSH,
            repository=Mock()
        )
        
        await hook.execute(context)
        
        assert context.has_errors() is False


class TestWebhookHook:
    """Test webhook hook"""
    
    @pytest.mark.asyncio
    async def test_webhook_hook_success(self):
        """Test successful webhook call"""
        hook = WebhookHook(url="https://example.com/webhook", timeout=5.0)
        
        repo = Mock()
        repo.full_name = "test/repo"
        
        context = HookContext(
            event=HookEvent.POST_PUSH,
            repository=repo
        )
        
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = "OK"
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_class.return_value.__aexit__ = AsyncMock()
            
            await hook.execute(context)
            
            assert "webhook_response" in context.results
            assert context.results["webhook_response"]["status"] == 200
            assert context.results["webhook_response"]["body"] == "OK"
            assert context.has_errors() is False
    
    @pytest.mark.asyncio
    async def test_webhook_hook_failure(self):
        """Test webhook call with HTTP error"""
        hook = WebhookHook(url="https://example.com/webhook")
        
        context = HookContext(
            event=HookEvent.POST_PUSH,
            repository=Mock()
        )
        
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 500
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_class.return_value.__aexit__ = AsyncMock()
            
            await hook.execute(context)
            
            assert context.has_errors() is True
            assert "Webhook returned status 500" in context.errors
    
    @pytest.mark.asyncio
    async def test_webhook_hook_exception(self):
        """Test webhook call with exception"""
        hook = WebhookHook(url="https://example.com/webhook")
        
        context = HookContext(
            event=HookEvent.POST_PUSH,
            repository=Mock()
        )
        
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=Exception("Connection failed"))
            mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_class.return_value.__aexit__ = AsyncMock()
            
            await hook.execute(context)
            
            assert context.has_errors() is True
            assert any("Webhook error" in error for error in context.errors)


class TestHookManager:
    """Test hook manager"""
    
    def test_hook_manager_initialization(self):
        """Test hook manager initialization with built-in hooks"""
        manager = HookManager()
        
        # Should have hooks registered for all events
        for event in HookEvent:
            hooks = manager.get_hooks(event)
            assert len(hooks) >= 1  # At least logging hook
            
            # Check logging hook is registered
            assert any(isinstance(hook, LoggingHook) for hook in hooks)
        
        # Statistics hook should be registered for specific events
        post_receive_hooks = manager.get_hooks(HookEvent.POST_RECEIVE)
        assert any(isinstance(hook, StatisticsHook) for hook in post_receive_hooks)
    
    def test_register_hook(self):
        """Test registering a custom hook"""
        manager = HookManager()
        
        class CustomHook(Hook):
            async def execute(self, context):
                pass
        
        custom_hook = CustomHook("custom", enabled=True)
        manager.register_hook(HookEvent.PRE_PUSH, custom_hook)
        
        hooks = manager.get_hooks(HookEvent.PRE_PUSH)
        assert custom_hook in hooks
    
    def test_unregister_hook(self):
        """Test unregistering a hook"""
        manager = HookManager()
        
        class CustomHook(Hook):
            async def execute(self, context):
                pass
        
        custom_hook = CustomHook("custom", enabled=True)
        manager.register_hook(HookEvent.PRE_PUSH, custom_hook)
        manager.unregister_hook(HookEvent.PRE_PUSH, custom_hook)
        
        hooks = manager.get_hooks(HookEvent.PRE_PUSH)
        assert custom_hook not in hooks
    
    @pytest.mark.asyncio
    async def test_execute_hooks(self):
        """Test executing hooks for an event"""
        manager = HookManager()
        
        executed = []
        
        class TrackingHook(Hook):
            def __init__(self, name):
                super().__init__(name, enabled=True)
            
            async def execute(self, context):
                executed.append(self.name)
        
        hook1 = TrackingHook("hook1")
        hook2 = TrackingHook("hook2")
        
        manager.register_hook(HookEvent.PRE_PUSH, hook1)
        manager.register_hook(HookEvent.PRE_PUSH, hook2)
        
        context = HookContext(
            event=HookEvent.PRE_PUSH,
            repository=Mock()
        )
        
        result_context = await manager.execute_hooks(
            HookEvent.PRE_PUSH,
            context
        )
        
        assert "hook1" in executed
        assert "hook2" in executed
        assert result_context == context
    
    @pytest.mark.asyncio
    async def test_execute_hooks_stop_on_error(self):
        """Test stopping hook execution on error"""
        manager = HookManager()
        
        executed = []
        
        class FailingHook(Hook):
            async def execute(self, context):
                executed.append(self.name)
                raise Exception("Hook failed")
        
        class NormalHook(Hook):
            async def execute(self, context):
                executed.append(self.name)
        
        hook1 = NormalHook("hook1", enabled=True)
        hook2 = FailingHook("hook2", enabled=True)
        hook3 = NormalHook("hook3", enabled=True)
        
        manager.register_hook(HookEvent.PRE_PUSH, hook1)
        manager.register_hook(HookEvent.PRE_PUSH, hook2)
        manager.register_hook(HookEvent.PRE_PUSH, hook3)
        
        context = HookContext(
            event=HookEvent.PRE_PUSH,
            repository=Mock()
        )
        
        result_context = await manager.execute_hooks(
            HookEvent.PRE_PUSH,
            context,
            stop_on_error=True
        )
        
        assert "hook1" in executed
        assert "hook2" in executed
        assert "hook3" not in executed  # Should stop after hook2 fails
        assert result_context.has_errors() is True
    
    @pytest.mark.asyncio
    async def test_execute_hooks_timeout(self):
        """Test hook execution timeout"""
        manager = HookManager()
        
        class SlowHook(Hook):
            async def execute(self, context):
                await asyncio.sleep(10)  # Longer than timeout
        
        hook = SlowHook("slow_hook", enabled=True)
        manager.register_hook(HookEvent.PRE_PUSH, hook)
        
        context = HookContext(
            event=HookEvent.PRE_PUSH,
            repository=Mock()
        )
        
        result_context = await manager.execute_hooks(
            HookEvent.PRE_PUSH,
            context,
            timeout=0.1
        )
        
        assert result_context.has_errors() is True
        assert any("timed out" in error for error in result_context.errors)
    
    def test_clear_hooks(self):
        """Test clearing hooks"""
        manager = HookManager()
        
        # Clear specific event
        manager.clear_hooks(HookEvent.PRE_PUSH)
        assert len(manager.get_hooks(HookEvent.PRE_PUSH)) == 0
        
        # Other events should still have hooks
        assert len(manager.get_hooks(HookEvent.POST_PUSH)) > 0
        
        # Clear all hooks
        manager.clear_hooks()
        for event in HookEvent:
            assert len(manager.get_hooks(event)) == 0