import io
import json
import zipfile

import pytest
import respx
from httpx import Response

import better_cape_mcp.server as srv


@pytest.fixture(autouse=True)
def patch_api_url(monkeypatch):
    monkeypatch.setattr(srv, "API_URL", "http://localhost/apiv2")


def binary_zip():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("reports/lite.json", '{"info":{"id":5}}')
    return output.getvalue()


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("explicit_destination", [False, True])
async def test_lite_download_preserves_zip_bytes(tmp_path, monkeypatch, explicit_destination):
    payload = binary_zip()
    with pytest.raises(UnicodeDecodeError):
        payload.decode("utf-8")
    monkeypatch.setattr(srv, "ALLOWED_SUBMISSION_DIR", str(tmp_path))
    route = respx.get("http://localhost/apiv2/tasks/get/report/5/lite/").mock(
        return_value=Response(200, content=payload, headers={
            "content-type": "application/zip",
            "content-disposition": 'attachment; filename="lite.zip"',
        })
    )
    kwargs = {"destination": str(tmp_path)} if explicit_destination else {}
    result = json.loads(await srv.get_task_report(5, "lite", "test-token", **kwargs))
    assert result["error"] is False
    assert result["path"] == str(tmp_path / "lite.zip")
    assert (tmp_path / "lite.zip").read_bytes() == payload
    assert route.calls[0].request.headers["Authorization"] == "Token test-token"


@respx.mock
@pytest.mark.asyncio
async def test_litereport_uses_json_endpoint():
    expected = {"info": {"id": 5}, "signatures": []}
    route = respx.get("http://localhost/apiv2/tasks/get/report/5/litereport/").mock(
        return_value=Response(200, json=expected)
    )
    assert json.loads(await srv.get_task_report(5, "litereport")) == expected
    assert route.called


@respx.mock
@pytest.mark.asyncio
async def test_unexpected_binary_response_is_actionable_tool_error():
    respx.get("http://localhost/apiv2/unexpected/").mock(
        return_value=Response(200, content=binary_zip(), headers={"content-type": "application/zip"})
    )
    with pytest.raises(srv.CapeAPIError) as raised:
        await srv._request("GET", "unexpected/")
    assert raised.value.kind == "unexpected_content"
    assert "GET unexpected/" in str(raised.value)
    assert "application/zip" in str(raised.value)


@respx.mock
@pytest.mark.asyncio
async def test_missing_archive_is_http_error_without_output(tmp_path):
    respx.get("http://localhost/apiv2/tasks/get/report/5/lite/").mock(
        return_value=Response(404, json={"error": True, "message": "Report not found"})
    )
    with pytest.raises(srv.CapeAPIError) as raised:
        await srv.get_task_report(5, "lite", destination=str(tmp_path))
    assert raised.value.status_code == 404
    assert list(tmp_path.iterdir()) == []


@respx.mock
@pytest.mark.asyncio
async def test_missing_litereport_names_file_and_preserves_cape_diagnostic():
    respx.get("http://localhost/apiv2/tasks/get/report/5/litereport/").mock(
        return_value=Response(200, json={
            "error": True, "error_value": "Reports directory does not exist",
        })
    )
    result = json.loads(await srv.get_task_report(5, "litereport"))
    assert result["error"] is True
    assert "reports/lite.json" in result["error_value"]
    assert "task 5" in result["error_value"]
    assert "not available on the CAPE server" in result["error_value"]
    assert "format=json" in result["error_value"]
    assert result["cape_error"] == "Reports directory does not exist"
    assert result["endpoint"] == "tasks/get/report/5/litereport/"


@respx.mock
@pytest.mark.asyncio
async def test_report_application_errors_include_request_context():
    respx.get("http://localhost/apiv2/tasks/get/report/9/json/").mock(
        return_value=Response(200, json={"error": True, "error_value": "Task Report API is Disabled"})
    )
    result = json.loads(await srv.get_task_report(9))
    assert result["error_value"] == "Task Report API is Disabled"
    assert result["task_id"] == 9
    assert result["report_format"] == "json"
    assert result["endpoint"] == "tasks/get/report/9/json/"
