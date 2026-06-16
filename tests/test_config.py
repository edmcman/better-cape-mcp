import pytest
import better_cape_mcp.server as srv


class TestAuthHelpers:
    def test_is_auth_required_false(self, monkeypatch):
        monkeypatch.setattr(srv, "AUTH_REQUIRED", False)
        assert srv.is_auth_required() is False

    def test_is_auth_required_true(self, monkeypatch):
        monkeypatch.setattr(srv, "AUTH_REQUIRED", True)
        assert srv.is_auth_required() is True

    def test_get_headers_no_token(self, monkeypatch):
        monkeypatch.setattr(srv, "API_TOKEN", "")
        assert srv.get_headers() == {}
        assert srv.get_headers(token="") == {}

    def test_get_headers_with_env_token(self, monkeypatch):
        monkeypatch.setattr(srv, "API_TOKEN", "envtok")
        assert srv.get_headers() == {"Authorization": "Token envtok"}

    def test_get_headers_arg_overrides_env(self, monkeypatch):
        monkeypatch.setattr(srv, "API_TOKEN", "envtok")
        assert srv.get_headers(token="argtok") == {"Authorization": "Token argtok"}


class TestMcpEnabled:
    def test_check_mcp_enabled_all_when_none(self, monkeypatch):
        monkeypatch.setattr(srv, "ENABLED_MCP_TOOLS", None)
        assert srv.check_mcp_enabled("anything") is True

    def test_check_mcp_enabled_explicit(self, monkeypatch):
        monkeypatch.setattr(srv, "ENABLED_MCP_TOOLS", {"filecreate", "tasksearch"})
        assert srv.check_mcp_enabled("filecreate") is True
        assert srv.check_mcp_enabled("tasksearch") is True
        assert srv.check_mcp_enabled("urlcreate") is False

    def test_mcp_tool_decorator_skips(self, monkeypatch):
        """When section is disabled, mcp_tool should return func undecorated."""
        monkeypatch.setattr(srv, "ENABLED_MCP_TOOLS", {"other"})

        @srv.mcp_tool("filecreate")
        def dummy():
            return 42

        # If disabled, the decorator returns the raw function (not wrapped by mcp.tool)
        assert dummy() == 42
