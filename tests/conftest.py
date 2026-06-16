import pytest
import better_cape_mcp.server as srv


@pytest.fixture(autouse=True)
def reset_module_state(monkeypatch):
    """Reset module-level mutable state before each test."""
    monkeypatch.setattr(srv, "AUTH_REQUIRED", False)
    monkeypatch.setattr(srv, "API_TOKEN", "")
    monkeypatch.setattr(srv, "ENABLED_MCP_TOOLS", None)
    monkeypatch.setattr(srv, "ALLOWED_SUBMISSION_DIR", "/tmp")
