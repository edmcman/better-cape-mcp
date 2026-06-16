# better-cape-mcp

Standalone MCP server for CAPEv2. Talks to the CAPE REST API over HTTP — no need to have CAPE installed or its source tree on disk.

## Install

```sh
cd better-cape-mcp
pip install -e .
```

Or run directly:
```sh
pip install fastmcp httpx
python -m better_cape_mcp.server
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

## Usage

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
- All tool behaviour and JSON shapes are identical
