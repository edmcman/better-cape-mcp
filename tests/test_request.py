import json
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
import respx
from httpx import ConnectError, ReadTimeout, Request, Response
import better_cape_mcp.server as srv


@pytest.fixture(autouse=True)
def patch_api_url(monkeypatch):
    monkeypatch.setattr(srv, "API_URL", "http://localhost/apiv2")


class TestRequest:
    @pytest.mark.asyncio
    async def test_client_uses_15_second_timeout(self):
        client = AsyncCtxMock(
            request=AsyncMock(return_value=Response(200, json={"ok": True}))
        )

        with patch.object(
            srv.httpx, "AsyncClient", return_value=client
        ) as async_client:
            result = await srv._request("GET", "cuckoo/status/")

        assert result == {"ok": True}
        async_client.assert_called_once_with(timeout=srv.HTTPX_REQUEST_TIMEOUT)

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
    async def test_empty_error_list_response_is_preserved(self):
        expected = {"error": [], "data": {"version": "2.5"}}
        respx.get("http://localhost/apiv2/cuckoo/status/").mock(
            return_value=Response(200, json=expected)
        )
        assert await srv._request("GET", "cuckoo/status/") == expected

    @respx.mock
    @pytest.mark.asyncio
    async def test_http_200_application_error_is_preserved(self):
        expected = {
            "error": True,
            "error_value": "CAPE config for task 5 does not exist.",
        }
        respx.get("http://localhost/apiv2/tasks/get/config/5/").mock(
            return_value=Response(200, json=expected)
        )
        assert await srv._request("GET", "tasks/get/config/5/") == expected

    @respx.mock
    @pytest.mark.asyncio
    async def test_400_with_json_body(self):
        route = respx.get("http://localhost/apiv2/bad/").mock(
            return_value=Response(400, json={"error_value": "nope"})
        )
        with pytest.raises(srv.CapeAPIError) as raised:
            await srv._request("GET", "bad/")
        assert raised.value.kind == "http_status"
        assert raised.value.status_code == 400
        assert "nope" in str(raised.value)
        assert route.called

    @respx.mock
    @pytest.mark.asyncio
    async def test_400_with_non_json_body(self):
        route = respx.get("http://localhost/apiv2/bad/").mock(
            return_value=Response(400, text="<html>oops</html>")
        )
        with pytest.raises(srv.CapeAPIError) as raised:
            await srv._request("GET", "bad/")
        assert raised.value.status_code == 400
        assert "<html>oops</html>" in str(raised.value)
        assert route.called

    @respx.mock
    @pytest.mark.asyncio
    async def test_http_error_with_empty_body_has_diagnostic(self):
        respx.get("http://localhost/apiv2/bad/").mock(
            return_value=Response(503, text="")
        )
        with pytest.raises(srv.CapeAPIError) as raised:
            await srv._request("GET", "bad/")
        assert str(raised.value)
        assert "HTTP 503" in str(raised.value)
        assert "<empty response body>" in str(raised.value)

    @respx.mock
    @pytest.mark.asyncio
    async def test_blank_timeout_has_diagnostic(self):
        request = Request("GET", "http://localhost/apiv2/cuckoo/status/")
        respx.get(request.url).mock(side_effect=ReadTimeout("", request=request))
        with pytest.raises(srv.CapeAPIError) as raised:
            await srv._request("GET", "cuckoo/status/")
        assert raised.value.kind == "timeout"
        assert str(raised.value)
        assert "timed out" in str(raised.value)
        assert "ReadTimeout" in str(raised.value)

    @respx.mock
    @pytest.mark.asyncio
    async def test_connect_error_has_diagnostic(self):
        request = Request("GET", "http://localhost/apiv2/cuckoo/status/")
        respx.get(request.url).mock(
            side_effect=ConnectError("name resolution failed", request=request)
        )
        with pytest.raises(srv.CapeAPIError) as raised:
            await srv._request("GET", "cuckoo/status/")
        assert raised.value.kind == "transport"
        assert "ConnectError" in str(raised.value)
        assert "name resolution failed" in str(raised.value)

    @pytest.mark.asyncio
    async def test_auth_required_no_token(self, monkeypatch):
        monkeypatch.setattr(srv, "AUTH_REQUIRED", True)
        monkeypatch.setattr(srv, "API_TOKEN", "")
        with pytest.raises(srv.CapeAPIError) as raised:
            await srv._request("GET", "tasks/view/1/")
        assert raised.value.kind == "authentication_required"
        assert "Authentication is required" in str(raised.value)

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


class TestVerifyAuth:
    @pytest.mark.asyncio
    async def test_anonymous_success(self):
        with patch.object(
            srv,
            "_request",
            new=AsyncMock(return_value={"error": [], "data": {"version": "2.5"}}),
        ):
            result = json.loads(await srv.verify_auth())
        assert result["authenticated"] is True
        assert result["user"] == "Anonymous access"
        assert "without a token" in result["message"]

    @pytest.mark.asyncio
    async def test_token_success(self):
        with patch.object(
            srv,
            "_request",
            new=AsyncMock(return_value={"error": False, "data": {"version": "2.5"}}),
        ):
            result = json.loads(await srv.verify_auth(token="secret"))
        assert result["authenticated"] is True
        assert result["user"] == "Authenticated User"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status_code", [401, 403])
    async def test_confirmed_auth_rejection(self, status_code):
        error = srv.CapeAPIError(
            f"HTTP {status_code}",
            kind="http_status",
            method="GET",
            endpoint="cuckoo/status/",
            status_code=status_code,
        )
        with patch.object(srv, "_request", new=AsyncMock(side_effect=error)):
            result = json.loads(await srv.verify_auth(token="bad"))
        assert result["authenticated"] is False
        assert result["status_code"] == status_code

    @pytest.mark.asyncio
    async def test_missing_required_token(self):
        error = srv.CapeAPIError(
            "missing token",
            kind="authentication_required",
            method="GET",
            endpoint="cuckoo/status/",
        )
        with patch.object(srv, "_request", new=AsyncMock(side_effect=error)):
            result = json.loads(await srv.verify_auth())
        assert result["authenticated"] is False
        assert result["status_code"] is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("kind", ["timeout", "transport"])
    async def test_transport_failure_propagates(self, kind):
        error = srv.CapeAPIError(
            "diagnostic",
            kind=kind,
            method="GET",
            endpoint="cuckoo/status/",
        )
        with patch.object(srv, "_request", new=AsyncMock(side_effect=error)):
            with pytest.raises(srv.CapeAPIError) as raised:
                await srv.verify_auth(token="maybe-valid")
        assert raised.value is error

    @pytest.mark.asyncio
    async def test_application_error_is_not_auth_rejection(self):
        cape_error = {"error": True, "error_value": "database unavailable"}
        with patch.object(
            srv, "_request", new=AsyncMock(return_value=cape_error)
        ):
            with pytest.raises(srv.CapeAPIError) as raised:
                await srv.verify_auth()
        assert raised.value.kind == "api_response"
        assert "database unavailable" in str(raised.value)


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

        with patch.object(
            srv.httpx, "AsyncClient", return_value=client
        ) as async_client:
            result = await srv._download_file("tasks/get/pcap/1/", str(tmp_path), "default.pcap")

        data = json.loads(result)
        async_client.assert_called_once_with(timeout=srv.HTTPX_REQUEST_TIMEOUT)
        assert data["error"] is False
        assert data["path"].endswith("dump.pcap")
        assert (tmp_path / "dump.pcap").read_bytes() == b"pcapdata"

    @pytest.mark.asyncio
    async def test_download_404(self, tmp_path, monkeypatch):
        stream_resp = AsyncCtxMock(
            status_code=404,
            aread=AsyncMock(return_value=b"Not found"),
            json=MagicMock(side_effect=json.JSONDecodeError("bad", "", 0)),
            text="Not found",
        )
        client = AsyncCtxMock(stream=MagicMock(return_value=stream_resp))

        with patch.object(srv.httpx, "AsyncClient", return_value=client):
            with pytest.raises(srv.CapeAPIError) as raised:
                await srv._download_file(
                    "tasks/get/pcap/1/", str(tmp_path), "default.pcap"
                )

        assert raised.value.status_code == 404
        assert "Not found" in str(raised.value)

    @pytest.mark.asyncio
    async def test_download_missing_destination(self, monkeypatch):
        with pytest.raises(srv.CapeAPIError) as raised:
            await srv._download_file(
                "tasks/get/pcap/1/", "/nonexistent/dir", "x.pcap"
            )
        assert raised.value.kind == "filesystem"
        assert "does not exist" in str(raised.value)

    @pytest.mark.asyncio
    async def test_download_blank_timeout_has_diagnostic(self, tmp_path):
        request = Request("GET", "http://localhost/apiv2/tasks/get/pcap/1/")
        client = AsyncCtxMock(
            stream=MagicMock(side_effect=ReadTimeout("", request=request))
        )
        with patch.object(srv.httpx, "AsyncClient", return_value=client):
            with pytest.raises(srv.CapeAPIError) as raised:
                await srv._download_file(
                    "tasks/get/pcap/1/", str(tmp_path), "default.pcap"
                )
        assert raised.value.kind == "timeout"
        assert "ReadTimeout" in str(raised.value)


class TestSubmissionErrors:
    @pytest.mark.asyncio
    async def test_missing_submission_file_is_tool_error(self):
        with pytest.raises(srv.CapeAPIError) as raised:
            await srv.submit_file("/tmp/does-not-exist.exe")
        assert raised.value.kind == "filesystem"
        assert "does not exist" in str(raised.value)

    @pytest.mark.asyncio
    async def test_submission_outside_allowed_directory(self, tmp_path, monkeypatch):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"MZ")
        monkeypatch.setattr(srv, "ALLOWED_SUBMISSION_DIR", str(allowed))

        with pytest.raises(srv.CapeAPIError) as raised:
            await srv.submit_static(str(sample))
        assert raised.value.kind == "validation"
        assert "restricted" in str(raised.value)
