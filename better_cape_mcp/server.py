import argparse
import json
import mimetypes
import os
import re
import sys
from typing import Any, Dict

try:
    import httpx
    from fastmcp import FastMCP
except ImportError:
    sys.exit("pip install fastmcp httpx")

# ---------------------------------------------------------------------------
# Inlined constants from CAPE internals (lib.cuckoo.common.web_utils)
# ---------------------------------------------------------------------------

PERFORM_SEARCH_FILTERS = {
    "info": 1,
    "virustotal_summary": 1,
    "detections.family": 1,
    "malfamily_tag": 1,
    "malscore": 1,
    "network.pcap_sha256": 1,
    "mlist_cnt": 1,
    "f_mlist_cnt": 1,
    "target.file.clamav": 1,
    "target.file.sha256": 1,
    "suri_tls_cnt": 1,
    "suri_alert_cnt": 1,
    "suri_http_cnt": 1,
    "suri_file_cnt": 1,
    "trid": 1,
    "_id": 0,
}

HASH_SEARCHES = {
    "ssdeep": "ssdeep",
    "crc32": "crc32",
    "md5": "md5",
    "sha1": "sha1",
    "sha3": "sha3_384",
    "sha256": "_id",
    "sha512": "sha512",
}

SEARCH_TERM_MAP = {
    "id": "info.id",
    "ids": "info.id",
    "tags_tasks": "info.id",
    "package": "info.package",
    "ttp": "ttps.ttp",
    "malscore": "malscore",
    "name": "target.file.name",
    "type": "target.file.type",
    "file": "behavior.summary.files",
    "command": "behavior.summary.executed_commands",
    "configs": "CAPE.configs",
    "resolvedapi": "behavior.summary.resolved_apis",
    "key": "behavior.summary.keys",
    "mutex": "behavior.summary.mutexes",
    "domain": "network.domains.domain",
    "ip": "network.hosts.ip",
    "asn": "network.hosts.asn",
    "asn_name": "network.hosts.asn_name",
    "signature": "signatures.description",
    "signame": "signatures.name",
    "detections": "detections.family",
    "url": "target.url",
    "iconhash": "static.pe.icon_hash",
    "iconfuzzy": "static.pe.icon_fuzzy",
    "surihttp": "suricata.http",
    "suritls": "suricata.tls",
    "surisid": "suricata.alerts.sid",
    "surialert": "suricata.alerts.signature",
    "surimsg": "suricata.alerts.signature",
    "suriurl": "suricata.http.uri",
    "suriua": "suricata.http.ua",
    "surireferrer": "suricata.http.referrer",
    "surihost": "suricata.http.hostname",
    "suritlssubject": "suricata.tls.subject",
    "suritlsissuerdn": "suricata.tls.issuer",
    "suritlsfingerprint": "suricata.tls.fingerprint",
    "procmemyara": ("procmemory.yara.name", "procmemory.cape_yara.name"),
    "procdumpyara": ("procdump.yara.name", "procdump.cape_yara.name"),
    "virustotal": "virustotal.results.sig",
    "machinename": "info.machine.name",
    "machinelabel": "info.machine.label",
    "comment": "info.comments.Data",
    "custom": "info.custom",
    "target_sha256": "target.file.file_ref",
    "tlp": "info.tlp",
    "ja3_hash": "suricata.tls.ja3.hash",
    "ja3_string": "suricata.tls.ja3.string",
    "dhash": "static.pe.icon_dhash",
    "dport": ("network.tcp.dport", "network.udp.dport", "network.smtp_ex.dport"),
    "sport": ("network.tcp.dport", "network.udp.dport", "network.smtp_ex.dport"),
    "port": (
        "network.tcp.dport",
        "network.udp.dport",
        "network.smtp_ex.dport",
        "network.tcp.dport",
        "network.udp.dport",
        "network.smtp_ex.dport",
    ),
    "extracted_tool": (
        "info.parent_sample.selfextract",
        "target.file.selfextract",
        "dropped.selfextract",
        "procdump.selfextract",
        "CAPE.payloads.selfextract",
    ),
}

_SEARCH_TERM_MAP_REPETITIVE_BLOCKS = {
    "ssdeep": "ssdeep",
    "clamav": "clamav",
    "yaraname": "yara.name",
    "capeyara": "cape_yara.name",
    "capetype": "cape_type.name",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha3": "sha3_384",
    "sha512": "sha512",
    "crc32": "crc32",
    "die": "die",
    "trid": "trid",
    "imphash": "imphash",
}

_SEARCH_TERM_MAP_BASE_NAMING = (
    "info.parent_sample",
    "target.file",
    "dropped",
    "CAPE.payloads",
    "procdump",
    "procmemory",
    "target.file.extracted_files",
    "dropped.extracted_files",
    "CAPE.payloads.extracted_files",
    "procdump.extracted_files",
    "procmemory.extracted_files",
)

for _k, _v in _SEARCH_TERM_MAP_REPETITIVE_BLOCKS.items():
    SEARCH_TERM_MAP[_k] = [f"{_path}.{_v}" for _path in _SEARCH_TERM_MAP_BASE_NAMING]

NORMALIZED_LOWER_TERMS = (
    "target_sha256",
    "md5",
    "sha1",
    "sha3",
    "sha256",
    "sha512",
    "ip",
    "domain",
    "ja3_hash",
    "dhash",
    "iconhash",
    "imphash",
    "package",
)

# ---------------------------------------------------------------------------
# Configuration via environment
# ---------------------------------------------------------------------------

API_URL = os.environ.get("CAPE_API_URL", "http://127.0.0.1:8000/apiv2")
API_TOKEN = os.environ.get("CAPE_API_TOKEN", "")
AUTH_REQUIRED = os.environ.get("CAPE_MCP_AUTH_REQUIRED", "").lower() in ("1", "true", "yes")

_ENABLED_TOOLS_RAW = os.environ.get("CAPE_MCP_ENABLED_TOOLS", "")
ENABLED_MCP_TOOLS: set | None = None
if _ENABLED_TOOLS_RAW:
    ENABLED_MCP_TOOLS = {t.strip() for t in _ENABLED_TOOLS_RAW.split(",") if t.strip()}

ALLOWED_SUBMISSION_DIR = os.environ.get("CAPE_ALLOWED_SUBMISSION_DIR", os.getcwd())

if AUTH_REQUIRED and not API_TOKEN:
    print(
        "WARNING: Token authentication is enabled, but CAPE_API_TOKEN is not set.",
        file=sys.stderr,
    )
    print(
        "         All MCP tool calls must include a valid 'token' argument.",
        file=sys.stderr,
    )

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_auth_required() -> bool:
    return AUTH_REQUIRED


def check_mcp_enabled(section: str) -> bool:
    if ENABLED_MCP_TOOLS is None:
        return True
    return section in ENABLED_MCP_TOOLS


def mcp_tool(section: str):
    def decorator(func):
        if check_mcp_enabled(section):
            return mcp.tool()(func)
        return func
    return decorator


def get_headers(token: str = "") -> Dict[str, str]:
    headers = {}
    auth_token = token if token else API_TOKEN
    if auth_token:
        headers["Authorization"] = f"Token {auth_token}"
    return headers


async def _request(method: str, endpoint: str, token: str = "", **kwargs) -> Any:
    if is_auth_required():
        auth_token = token if token else API_TOKEN
        if not auth_token:
            return {"error": True, "message": "Authentication required but no token provided."}

    url = f"{API_URL.rstrip('/')}/{endpoint.lstrip('/')}"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.request(method, url, headers=get_headers(token), **kwargs)
            if response.status_code >= 400:
                try:
                    return response.json()
                except json.JSONDecodeError:
                    return {"error": True, "message": f"HTTP {response.status_code}", "body": response.text}
            try:
                return response.json()
            except json.JSONDecodeError:
                return {"error": False, "data": response.text}
        except httpx.HTTPStatusError as e:
            return {"error": True, "message": str(e), "body": e.response.text}
        except Exception as e:
            return {"error": True, "message": str(e)}


async def _download_file(
    endpoint: str,
    destination: str,
    default_filename: str = "downloaded_file.bin",
    token: str = "",
) -> str:
    if is_auth_required():
        auth_token = token if token else API_TOKEN
        if not auth_token:
            return json.dumps(
                {"error": True, "message": "Authentication required but no token provided."},
                indent=2,
            )

    if not os.path.isdir(destination):
        return json.dumps(
            {"error": True, "message": "Destination directory does not exist"},
            indent=2,
        )

    url = f"{API_URL.rstrip('/')}/{endpoint.lstrip('/')}"
    headers = get_headers(token)

    async with httpx.AsyncClient() as client:
        try:
            async with client.stream("GET", url, headers=headers) as response:
                if response.status_code != 200:
                    content = await response.read()
                    return json.dumps(
                        {
                            "error": True,
                            "message": f"HTTP {response.status_code}",
                            "body": content.decode("utf-8", errors="ignore"),
                        },
                        indent=2,
                    )

                filename = default_filename
                content_disposition = response.headers.get("content-disposition")
                if content_disposition:
                    match = re.search(r'filename="?([^"]+)"?', content_disposition)
                    if match:
                        filename = os.path.basename(match.group(1))

                filepath = os.path.join(destination, filename)
                with open(filepath, "wb") as f:
                    async for chunk in response.aiter_bytes():
                        f.write(chunk)

                return json.dumps(
                    {"error": False, "message": f"Saved to {filepath}", "path": filepath},
                    indent=2,
                )
        except Exception as e:
            return json.dumps({"error": True, "message": str(e)}, indent=2)


def _build_submission_data(**kwargs) -> Dict[str, str]:
    data = {}
    for key, value in kwargs.items():
        if not value:
            continue
        if isinstance(value, bool):
            data[key] = "1"
        elif isinstance(value, int):
            data[key] = str(value)
        else:
            data[key] = value
    return data


def get_lean_cape_report(raw_cape_json: dict) -> dict:
    return {
        "score": raw_cape_json.get("info", {}).get("score", 0),
        "family": raw_cape_json.get("malfamily")
        or raw_cape_json.get("detections", {}).get("family")
        or "Unknown",
        "extracted_configs": raw_cape_json.get("CAPE", []),
        "high_severity_signatures": [
            {"name": sig["name"], "desc": sig["description"]}
            for sig in raw_cape_json.get("signatures", [])
            if isinstance(sig, dict) and sig.get("severity", 0) >= 3
        ],
        "network": {
            "domains": (
                [d["domain"] for d in raw_cape_json.get("network", {}).get("domains", [])]
                if isinstance(raw_cape_json.get("network", {}).get("domains"), list)
                else []
            ),
            "http_uris": (
                [h["uri"] for h in raw_cape_json.get("network", {}).get("http", [])]
                if isinstance(raw_cape_json.get("network", {}).get("http"), list)
                else []
            ),
        },
        "indicators": {
            "mutexes": (
                raw_cape_json.get("behavior", {}).get("summary", {}).get("mutexes", [])
                if isinstance(raw_cape_json.get("behavior", {}).get("summary"), dict)
                else []
            ),
            "commands": (
                raw_cape_json.get("behavior", {}).get("summary", {}).get("executed_commands", [])
                if isinstance(raw_cape_json.get("behavior", {}).get("summary"), dict)
                else []
            ),
        },
    }


def _apply_lean_report(result: Any) -> Any:
    if isinstance(result, dict):
        if result.get("error") is False and "data" in result:
            if isinstance(result["data"], list):
                result["data"] = [get_lean_cape_report(item) for item in result["data"]]
            elif isinstance(result["data"], dict):
                result["data"] = get_lean_cape_report(result["data"])
        elif "info" in result:
            return get_lean_cape_report(result)
    elif isinstance(result, list):
        return [get_lean_cape_report(item) for item in result]
    return result


# ---------------------------------------------------------------------------
# FastMCP
# ---------------------------------------------------------------------------
mcp = FastMCP("cape-sandbox")


# ---------------------------------------------------------------------------
# Tools — Task Creation
# ---------------------------------------------------------------------------

@mcp_tool("filecreate")
async def submit_file(
    file_path: str,
    machine: str = "",
    package: str = "",
    options: str = "",
    tags: str = "",
    priority: int = 1,
    timeout: int = 0,
    platform: str = "",
    memory: bool = False,
    enforce_timeout: bool = False,
    clock: str = "",
    custom: str = "",
    token: str = "",
) -> str:
    """Submit a local file for analysis."""
    if is_auth_required():
        auth_token = token if token else API_TOKEN
        if not auth_token:
            return json.dumps(
                {"error": True, "message": "Authentication required but no token provided."},
                indent=2,
            )

    if not os.path.exists(file_path):
        return json.dumps({"error": True, "message": "File not found"}, indent=2)

    abs_file_path = os.path.abspath(file_path)
    abs_allowed_dir = os.path.abspath(ALLOWED_SUBMISSION_DIR)
    if not abs_file_path.startswith(abs_allowed_dir):
        return json.dumps(
            {
                "error": True,
                "message": f"Security Violation: File submission is restricted to {abs_allowed_dir}",
            },
            indent=2,
        )

    filename = os.path.basename(file_path)
    mime_type, _ = mimetypes.guess_type(file_path)
    if not mime_type:
        mime_type = "application/octet-stream"

    data = _build_submission_data(
        machine=machine,
        package=package,
        options=options,
        tags=tags,
        priority=priority,
        timeout=timeout,
        platform=platform,
        memory=memory,
        enforce_timeout=enforce_timeout,
        clock=clock,
        custom=custom,
    )

    url = f"{API_URL.rstrip('/')}/tasks/create/file/"
    async with httpx.AsyncClient() as client:
        try:
            with open(file_path, "rb") as f:
                files = {"file": (filename, f, mime_type)}
                response = await client.post(url, data=data, files=files, headers=get_headers(token))
                try:
                    result = response.json()
                except json.JSONDecodeError:
                    result = {"error": response.status_code >= 400, "data": response.text}
        except Exception as e:
            result = {"error": True, "message": str(e)}

    return json.dumps(result, indent=2)


@mcp_tool("urlcreate")
async def submit_url(
    url: str,
    machine: str = "",
    package: str = "",
    options: str = "",
    tags: str = "",
    priority: int = 1,
    timeout: int = 0,
    platform: str = "",
    memory: bool = False,
    enforce_timeout: bool = False,
    clock: str = "",
    custom: str = "",
    token: str = "",
) -> str:
    """Submit a URL for analysis."""
    data = {"url": url}
    data.update(
        _build_submission_data(
            machine=machine,
            package=package,
            options=options,
            tags=tags,
            priority=priority,
            timeout=timeout,
            platform=platform,
            memory=memory,
            enforce_timeout=enforce_timeout,
            clock=clock,
            custom=custom,
        )
    )
    result = await _request("POST", "tasks/create/url/", token=token, data=data)
    return json.dumps(result, indent=2)


@mcp_tool("dlnexeccreate")
async def submit_dlnexec(
    url: str,
    machine: str = "",
    package: str = "",
    options: str = "",
    tags: str = "",
    priority: int = 1,
    token: str = "",
) -> str:
    """Submit a URL for Download & Execute analysis."""
    data = {"dlnexec": url}
    data.update(
        _build_submission_data(
            machine=machine,
            package=package,
            options=options,
            tags=tags,
            priority=priority,
        )
    )
    result = await _request("POST", "tasks/create/dlnexec/", token=token, data=data)
    return json.dumps(result, indent=2)


@mcp_tool("staticextraction")
async def submit_static(
    file_path: str,
    priority: int = 1,
    options: str = "",
    token: str = "",
) -> str:
    """Submit a file for static extraction only."""
    if is_auth_required():
        auth_token = token if token else API_TOKEN
        if not auth_token:
            return json.dumps(
                {"error": True, "message": "Authentication required but no token provided."},
                indent=2,
            )

    if not os.path.exists(file_path):
        return json.dumps({"error": True, "message": "File not found"}, indent=2)

    abs_file_path = os.path.abspath(file_path)
    abs_allowed_dir = os.path.abspath(ALLOWED_SUBMISSION_DIR)
    if not abs_file_path.startswith(abs_allowed_dir):
        return json.dumps(
            {
                "error": True,
                "message": f"Security Violation: File submission is restricted to {abs_allowed_dir}",
            },
            indent=2,
        )

    filename = os.path.basename(file_path)
    mime_type, _ = mimetypes.guess_type(file_path)
    if not mime_type:
        mime_type = "application/octet-stream"

    data = _build_submission_data(priority=priority, options=options)
    url = f"{API_URL.rstrip('/')}/tasks/create/static/"

    async with httpx.AsyncClient() as client:
        try:
            with open(file_path, "rb") as f:
                files = {"file": (filename, f, mime_type)}
                response = await client.post(url, data=data, files=files, headers=get_headers(token))
                try:
                    result = response.json()
                except json.JSONDecodeError:
                    result = {"error": response.status_code >= 400, "data": response.text}
        except Exception as e:
            result = {"error": True, "message": str(e)}

    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Tools — Task Management & Search
# ---------------------------------------------------------------------------

@mcp_tool("tasksearch")
async def search_task(hash_value: str, lean: bool = True, token: str = "") -> str:
    """Search for tasks by MD5, SHA1, or SHA256."""
    if not re.match(r"^[a-fA-F0-9]+$", hash_value):
        return json.dumps(
            {"error": True, "message": "Invalid hash value provided. Only hexadecimal characters are allowed."},
            indent=2,
        )

    algo = "md5"
    if len(hash_value) == 40:
        algo = "sha1"
    elif len(hash_value) == 64:
        algo = "sha256"

    result = await _request("GET", f"tasks/search/{algo}/{hash_value}/", token=token)
    if lean:
        result = _apply_lean_report(result)
    return json.dumps(result, indent=2)


@mcp_tool("extendedtasksearch")
async def extended_search(option: str, argument: str, lean: bool = True, token: str = "") -> str:
    """
    Search tasks using extended options.
    Options include: id, name, type, string, ssdeep, crc32, file, command, resolvedapi, key, mutex, domain, ip, signature, signame, etc.
    """
    data = {"option": option, "argument": argument}
    if lean:
        data["lean"] = True
    result = await _request("POST", "tasks/extendedsearch/", token=token, data=data)
    if lean:
        result = _apply_lean_report(result)
    return json.dumps(result, indent=2)


@mcp_tool("extendedtasksearch")
async def get_search_info() -> str:
    """
    Retrieve the available advanced search terms, filters, and hash types.
    Use this information to construct valid queries for `extended_search`.
    """
    return json.dumps(
        {
            "search_term_map": SEARCH_TERM_MAP,
            "perform_search_filters": PERFORM_SEARCH_FILTERS,
            "hash_searches": HASH_SEARCHES,
            "normalized_lower_terms": NORMALIZED_LOWER_TERMS,
        },
        indent=2,
        default=str,
    )


@mcp_tool("tasklist")
async def list_tasks(limit: int = 10, offset: int = 0, status: str = "", token: str = "") -> str:
    """List tasks with optional limit, offset and status filter."""
    params = {}
    if status:
        params["status"] = status
    endpoint = f"tasks/list/{limit}/{offset}/"
    result = await _request("GET", endpoint, token=token, params=params)
    return json.dumps(result, indent=2)


@mcp_tool("taskview")
async def view_task(task_id: int, token: str = "") -> str:
    """Get details of a specific task."""
    result = await _request("GET", f"tasks/view/{task_id}/", token=token)
    return json.dumps(result, indent=2)


@mcp_tool("taskresched")
async def reschedule_task(task_id: int, token: str = "") -> str:
    """Reschedule a task."""
    result = await _request("GET", f"tasks/reschedule/{task_id}/", token=token)
    return json.dumps(result, indent=2)


@mcp_tool("taskreprocess")
async def reprocess_task(task_id: int, token: str = "") -> str:
    """Reprocess a task."""
    result = await _request("GET", f"tasks/reprocess/{task_id}/", token=token)
    return json.dumps(result, indent=2)


@mcp_tool("taskstatus")
async def get_task_status(task_id: int, token: str = "") -> str:
    """Get the status of a task."""
    result = await _request("GET", f"tasks/status/{task_id}/", token=token)
    return json.dumps(result, indent=2)


@mcp_tool("tasks_latest")
async def get_latest_tasks(hours: int = 24, token: str = "") -> str:
    """Get IDs of tasks finished in the last X hours."""
    result = await _request("GET", f"tasks/get/latests/{hours}/", token=token)
    return json.dumps(result, indent=2)


@mcp_tool("statistics")
async def get_statistics(days: int = 7, token: str = "") -> str:
    """Get task statistics for the last X days."""
    result = await _request("GET", f"tasks/statistics/{days}/", token=token)
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Tools — Reports & IOCs
# ---------------------------------------------------------------------------

@mcp_tool("taskreport")
async def get_task_report(task_id: int, format: str = "json", token: str = "") -> str:
    """Get the analysis report for a task (json, lite, maec, metadata, lean)."""
    allowed_formats = {"json", "lite", "maec", "metadata", "lean"}
    if format not in allowed_formats:
        return json.dumps(
            {"error": True, "message": f"Invalid format. Allowed: {', '.join(allowed_formats)}"},
            indent=2,
        )

    if format == "lean":
        data = {"option": "id", "argument": str(task_id), "lean": True}
        result = await _request("POST", "tasks/extendedsearch/", token=token, data=data)
        if isinstance(result, dict) and not result.get("error") and isinstance(result.get("data"), list):
            if len(result["data"]) > 0:
                result["data"] = result["data"][0]
            else:
                result = {"error": True, "message": "Task report not found via lean search."}
        result = _apply_lean_report(result)
        return json.dumps(result, indent=2)

    result = await _request("GET", f"tasks/get/report/{task_id}/{format}/", token=token)
    return json.dumps(result, indent=2)


@mcp_tool("taskiocs")
async def get_task_iocs(task_id: int, detailed: bool = False, token: str = "") -> str:
    """Get IOCs for a task."""
    endpoint = f"tasks/get/iocs/{task_id}/"
    if detailed:
        endpoint += "detailed/"
    result = await _request("GET", endpoint, token=token)
    return json.dumps(result, indent=2)


@mcp_tool("capeconfig")
async def get_task_config(task_id: int, token: str = "") -> str:
    """Get the extracted malware configuration for a task."""
    result = await _request("GET", f"tasks/get/config/{task_id}/", token=token)
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Tools — File Downloads
# ---------------------------------------------------------------------------

@mcp_tool("taskscreenshot")
async def download_task_screenshot(
    task_id: int, destination: str, screenshot_id: str = "all", token: str = ""
) -> str:
    """Download task screenshots (zip or single image)."""
    return await _download_file(
        f"tasks/get/screenshot/{task_id}/{screenshot_id}/",
        destination,
        f"{task_id}_screenshots.zip",
        token=token,
    )


@mcp_tool("taskpcap")
async def download_task_pcap(task_id: int, destination: str, token: str = "") -> str:
    """Download the PCAP file for a task."""
    return await _download_file(
        f"tasks/get/pcap/{task_id}/", destination, f"{task_id}_dump.pcap", token=token
    )


@mcp_tool("tasktlspcap")
async def download_task_tlspcap(task_id: int, destination: str, token: str = "") -> str:
    """Download the TLS PCAP file for a task."""
    return await _download_file(
        f"tasks/get/tlspcap/{task_id}/", destination, f"{task_id}_tls.pcap", token=token
    )


@mcp_tool("taskevtx")
async def download_task_evtx(task_id: int, destination: str, token: str = "") -> str:
    """Download the EVTX logs for a task."""
    return await _download_file(
        f"tasks/get/evtx/{task_id}/", destination, f"{task_id}_evtx.zip", token=token
    )


@mcp_tool("taskdropped")
async def download_task_dropped(task_id: int, destination: str, token: str = "") -> str:
    """Download dropped files for a task."""
    return await _download_file(
        f"tasks/get/dropped/{task_id}/", destination, f"{task_id}_dropped.zip", token=token
    )


@mcp_tool("taskselfextracted")
async def download_self_extracted_files(
    task_id: int, destination: str, tool: str = "all", token: str = ""
) -> str:
    """Download self-extracted files for a task."""
    return await _download_file(
        f"tasks/get/selfextracted/{task_id}/{tool}/",
        destination,
        f"{task_id}_selfextracted_{tool}.zip",
        token=token,
    )


@mcp_tool("tasksurifile")
async def download_task_surifile(task_id: int, destination: str, token: str = "") -> str:
    """Download Suricata files for a task."""
    return await _download_file(
        f"tasks/get/surifile/{task_id}/", destination, f"{task_id}_surifiles.zip", token=token
    )


@mcp_tool("taskmitmdump")
async def download_task_mitmdump(task_id: int, destination: str, token: str = "") -> str:
    """Download mitmdump HAR file for a task."""
    return await _download_file(
        f"tasks/get/mitmdump/{task_id}/", destination, f"{task_id}_dump.har", token=token
    )


@mcp_tool("payloadfiles")
async def download_task_payloadfiles(task_id: int, destination: str, token: str = "") -> str:
    """Download CAPE payload files."""
    return await _download_file(
        f"tasks/get/payloadfiles/{task_id}/",
        destination,
        f"{task_id}_payloads.zip",
        token=token,
    )


@mcp_tool("procdumpfiles")
async def download_task_procdumpfiles(task_id: int, destination: str, token: str = "") -> str:
    """Download CAPE procdump files."""
    return await _download_file(
        f"tasks/get/procdumpfiles/{task_id}/",
        destination,
        f"{task_id}_procdumps.zip",
        token=token,
    )


@mcp_tool("taskprocmemory")
async def download_task_procmemory(
    task_id: int, destination: str, pid: str = "all", token: str = ""
) -> str:
    """Download process memory dumps."""
    return await _download_file(
        f"tasks/get/procmemory/{task_id}/{pid}/",
        destination,
        f"{task_id}_procmemory.zip",
        token=token,
    )


@mcp_tool("taskfullmemory")
async def download_task_fullmemory(task_id: int, destination: str, token: str = "") -> str:
    """Download full VM memory dump."""
    return await _download_file(
        f"tasks/get/fullmemory/{task_id}/",
        destination,
        f"{task_id}_fullmemory.dmp",
        token=token,
    )


# ---------------------------------------------------------------------------
# Tools — Files & Machines
# ---------------------------------------------------------------------------

@mcp_tool("fileview")
async def view_file(hash_value: str, hash_type: str = "sha256", token: str = "") -> str:
    """View information about a file in the database."""
    if not re.match(r"^[a-fA-F0-9]+$", hash_value):
        return json.dumps(
            {"error": True, "message": "Invalid hash value provided. Only hexadecimal characters are allowed."},
            indent=2,
        )
    return await _request("GET", f"files/view/{hash_type}/{hash_value}/", token=token)


@mcp_tool("sampledl")
async def download_sample(
    hash_value: str, destination: str, hash_type: str = "sha256", token: str = ""
) -> str:
    """Download a sample from the database."""
    if not re.match(r"^[a-fA-F0-9]+$", hash_value):
        return json.dumps(
            {"error": True, "message": "Invalid hash value provided. Only hexadecimal characters are allowed."},
            indent=2,
        )
    return await _download_file(
        f"files/get/{hash_type}/{hash_value}/",
        destination,
        f"{hash_value}.bin",
        token=token,
    )


@mcp_tool("machinelist")
async def list_machines(token: str = "") -> str:
    """List available analysis machines."""
    result = await _request("GET", "machines/list/", token=token)
    return json.dumps(result, indent=2)


@mcp_tool("machineview")
async def view_machine(name: str, token: str = "") -> str:
    """View details of a specific machine."""
    result = await _request("GET", f"machines/view/{name}/", token=token)
    return json.dumps(result, indent=2)


@mcp_tool("list_exitnodes")
async def list_exitnodes(token: str = "") -> str:
    """List available exit nodes."""
    result = await _request("GET", "exitnodes/", token=token)
    return json.dumps(result, indent=2)


@mcp_tool("cuckoostatus")
async def get_cuckoo_status(token: str = "") -> str:
    """Get the status of the CAPE host."""
    result = await _request("GET", "cuckoo/status/", token=token)
    return json.dumps(result, indent=2)


@mcp.tool()
async def verify_auth(token: str = "") -> str:
    """
    Verify if the provided API token is valid.
    Useful for checking authentication status before performing other operations.
    """
    result = await _request("GET", "cuckoo/status/", token=token)
    if isinstance(result, dict) and result.get("error"):
        return json.dumps(
            {"authenticated": False, "message": "Invalid token or authentication failed.", "details": result},
            indent=2,
        )
    return json.dumps(
        {"authenticated": True, "message": "Token is valid.", "user": "Authenticated User"},
        indent=2,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="CAPE MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http", "http"],
        default=os.environ.get("CAPE_MCP_TRANSPORT", "stdio"),
        help="Transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("CAPE_MCP_HOST", "127.0.0.1"),
        help="Host to bind for HTTP/SSE (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("CAPE_MCP_PORT", "9004")),
        help="Port to bind for HTTP/SSE (default: 9004)",
    )
    args = parser.parse_args()

    if args.transport in ("sse", "streamable-http", "http"):
        print(f"Starting {args.transport} server on {args.host}:{args.port}", file=sys.stderr)
        mcp.run(transport=args.transport, host=args.host, port=args.port)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
