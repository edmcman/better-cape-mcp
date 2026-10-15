# better-cape-mcp

Standalone MCP server for CAPEv2. Talks to the CAPE REST API over HTTP — no need to have CAPE installed or its source tree on disk.

## Install

### pip
```sh
cd better-cape-mcp
pip install -e .
```

Or run directly:
```sh
pip install fastmcp httpx
python -m better_cape_mcp.server
```

### uv / uvx (recommended)
```sh
# Run directly from GitHub without installing
CAPE_API_URL=http://192.168.56.1:8000/apiv2 \
CAPE_API_TOKEN=your_token \
uvx --from git+https://github.com/edmcman/better-cape-mcp.git cape-mcp

# Or install locally for development
uv pip install -e .
uv run cape-mcp
```

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CAPE_API_URL` | `http://127.0.0.1:8000/apiv2` | Base URL of the CAPE API |
| `CAPE_API_TOKEN` | `""` | API auth token |
| `CAPE_MCP_AUTH_REQUIRED` | `false` | Set to `true` to require tokens globally |
| `CAPE_MCP_ENABLED_TOOLS` | *(all)* | Comma-separated list of enabled tool sections (e.g. `filecreate,tasksearch`) |
| `CAPE_ALLOWED_SUBMISSION_DIR` | `cwd` | Directory file submissions must reside in |
| `CAPE_MCP_TRANSPORT` | `stdio` | Default transport: `stdio`, `sse`, `streamable-http`, `http` |
| `CAPE_MCP_HOST` | `127.0.0.1` | Bind host for HTTP/SSE |
| `CAPE_MCP_PORT` | `9004` | Bind port for HTTP/SSE |

## Error behavior

Transport failures, HTTP error responses, invalid local paths, and filesystem
failures are reported as native MCP tool errors. Diagnostics identify the CAPE
operation and failure type; timeout errors remain descriptive even when HTTPX
provides an empty exception message. The server does not retry requests because
retrying a submission could create duplicate CAPE tasks.

CAPE application responses returned with HTTP 200 are preserved as JSON. In
particular, both `"error": false` and CAPE's `"error": []` convention mean the
request succeeded. Application results such as an unavailable extracted config
remain ordinary CAPE responses rather than MCP transport errors.

`verify_auth` reports `authenticated: false` only when CAPE returns HTTP 401 or
403, or when `CAPE_MCP_AUTH_REQUIRED` is enabled without a token. Connectivity,
DNS, timeout, and server failures are MCP errors instead of authentication
failures. When CAPE accepts a request without a token, `verify_auth` identifies
the connection as anonymous access.

All CAPE API requests, including streamed downloads, use a 15-second HTTP
timeout for connection establishment, reads, writes, and connection-pool
acquisition. If a `.local` CAPE hostname resolves unreliably in the MCP
server's environment, configure `CAPE_API_URL` with a stable DNS name, IP
address, or host mapping.

## Usage

### Report formats

`get_task_report` returns `json` (the full report), `litereport` (the smaller JSON
report, if enabled in CAPE), `lean` (a search-based summary), or textual `maec`
and `metadata` reports. CAPE's `lite` format is a ZIP archive containing analysis
artifacts, not a smaller JSON response.

For `format="lite"`, the tool streams the archive to `destination`, an existing
local directory, and returns its `path`. If omitted, the directory defaults to
`CAPE_ALLOWED_SUBMISSION_DIR` (or the server's working directory). The archive is
saved as binary without JSON or UTF-8 decoding and is not extracted. For example:

```json
{"task_id": 5, "format": "lite", "destination": "/work"}
```

Use `format="litereport"` when you want JSON rather than a downloadable archive.

If a report is unavailable, the tool includes the task ID, requested format,
and endpoint. CAPE's original diagnostic is retained. In particular, CAPE's
`Reports directory does not exist` response can mean the requested file is
missing even when other reports exist. For `litereport`, the diagnostic names
`reports/lite.json`, states that the requested format is not available on the
CAPE server, and suggests trying `json`/`lean` instead.

### stdio (default — for Claude Desktop, etc.)
```sh
CAPE_API_URL=http://192.168.56.1:8000/apiv2 \
CAPE_API_TOKEN=your_token \
python -m better_cape_mcp.server
```

### HTTP / SSE
```sh
python -m better_cape_mcp.server --transport sse --host 0.0.0.0 --port 9004
```

## Claude Desktop config example

Add to `claude_desktop_config.json`:

### With uvx (no local install)
```json
{
  "mcpServers": {
    "cape": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/edmcman/better-cape-mcp.git", "cape-mcp"],
      "env": {
        "CAPE_API_URL": "http://192.168.56.1:8000/apiv2",
        "CAPE_API_TOKEN": "your_token"
      }
    }
  }
}
```

### With pip
```json
{
  "mcpServers": {
    "cape": {
      "command": "python",
      "args": ["-m", "better_cape_mcp.server"],
      "env": {
        "CAPE_API_URL": "http://192.168.56.1:8000/apiv2",
        "CAPE_API_TOKEN": "your_token"
      }
    }
  }
}
```

## Differences from upstream `CAPEv2/mcp/server.py`

- No imports from `lib.cuckoo.common.*`
- `api.conf` settings replaced by environment variables
- Search term maps (`search_term_map`, `perform_search_filters`, etc.) inlined as constants
- Successful CAPE response shapes are preserved; request failures use native MCP tool errors
