import json
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
import respx
from httpx import Response
import better_cape_mcp.server as srv


@pytest.fixture(autouse=True)
def patch_api_url(monkeypatch):
    monkeypatch.setattr(srv, "API_URL", "http://localhost/apiv2")


class TestRequest:
    @respx.mock
    @pytest.mark.asyncio
    async def test_get_json_200(self):
        route = respx.get("http://localhost/apiv2/tasks/view/1/").mock(
            return_value=Response(200, json={"task": "done"})
        )
        result = await srv._request("GET", "tasks/view/1/")
        assert result == {"task": "done"}
        assert route.called

    @respx.mock
    @pytest.mark.asyncio
    async def test_post_json_200(self):
        route = respx.post("http://localhost/apiv2/tasks/create/url/").mock(
            return_value=Response(200, json={"task_id": 42})
        )
        result = await srv._request("POST", "tasks/create/url/", data={"url": "http://x"})
        assert result == {"task_id": 42}
        assert route.called

    @respx.mock
    @pytest.mark.asyncio
    async def test_400_with_json_body(self):
        route = respx.get("http://localhost/apiv2/bad/").mock(
            return_value=Response(400, json={"error": "nope"})
        )
        result = await srv._request("GET", "bad/")
        assert result == {"error": "nope"}
        assert route.called

    @respx.mock
    @pytest.mark.asyncio
    async def test_400_with_non_json_body(self):
        route = respx.get("http://localhost/apiv2/bad/").mock(
            return_value=Response(400, text="<html>oops</html>")
        )
        result = await srv._request("GET", "bad/")
        assert result["error"] is True
        assert result["message"] == "HTTP 400"
        assert "<html>" in result["body"]
        assert route.called

    @pytest.mark.asyncio
    async def test_auth_required_no_token(self, monkeypatch):
        monkeypatch.setattr(srv, "AUTH_REQUIRED", True)
        monkeypatch.setattr(srv, "API_TOKEN", "")
        result = await srv._request("GET", "tasks/view/1/")
        assert result["error"] is True
        assert "Authentication required" in result["message"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_auth_passes_token_header(self, monkeypatch):
        monkeypatch.setattr(srv, "AUTH_REQUIRED", True)
        monkeypatch.setattr(srv, "API_TOKEN", "secrettok")
        route = respx.get("http://localhost/apiv2/tasks/view/1/").mock(
            return_value=Response(200, json={"ok": True})
        )
        await srv._request("GET", "tasks/view/1/")
        assert route.called
        assert route.calls[0].request.headers["Authorization"] == "Token secrettok"


class AsyncCtxMock:
    """Utility for building async-context-manager compatible mocks."""
    def __init__(self, **attrs):
        for k, v in attrs.items():
            setattr(self, k, v)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


def _make_async_iter(*items):
    async def _aiter():
        for item in items:
            yield item
    return _aiter()


class TestDownloadFile:
    @pytest.mark.asyncio
    async def test_download_success_with_content_disposition(self, tmp_path, monkeypatch):
        stream_resp = AsyncCtxMock(
            status_code=200,
            headers={"content-disposition": 'attachment; filename="dump.pcap"'},
            aiter_bytes=lambda: _make_async_iter(b"pcapdata"),
        )
        client = AsyncCtxMock(stream=MagicMock(return_value=stream_resp))

        with patch.object(srv.httpx, "AsyncClient", return_value=client):
            result = await srv._download_file("tasks/get/pcap/1/", str(tmp_path), "default.pcap")

        data = json.loads(result)
        assert data["error"] is False
        assert data["path"].endswith("dump.pcap")
        assert (tmp_path / "dump.pcap").read_bytes() == b"pcapdata"

    @pytest.mark.asyncio
    async def test_download_404(self, tmp_path, monkeypatch):
        stream_resp = AsyncCtxMock(
            status_code=404,
            read=AsyncMock(return_value=b"Not found"),
        )
        client = AsyncCtxMock(stream=MagicMock(return_value=stream_resp))

        with patch.object(srv.httpx, "AsyncClient", return_value=client):
            result = await srv._download_file("tasks/get/pcap/1/", str(tmp_path), "default.pcap")

        data = json.loads(result)
        assert data["error"] is True
        assert data["message"] == "HTTP 404"
        assert "Not found" in data["body"]

    @pytest.mark.asyncio
    async def test_download_missing_destination(self, monkeypatch):
        result = await srv._download_file("tasks/get/pcap/1/", "/nonexistent/dir", "x.pcap")
        data = json.loads(result)
        assert data["error"] is True
        assert "does not exist" in data["message"]
