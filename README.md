# clr-openmanage-mcp

[![PyPI](https://img.shields.io/pypi/v/clr-openmanage-mcp)](https://pypi.org/project/clr-openmanage-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

MCP server for Dell OpenManage Enterprise (OME) — monitor and manage Dell servers through AI assistants like Claude.

## Features

- **Device management** — list devices, view details, health summary
- **Alert management** — list, filter, acknowledge alerts (single or bulk)
- **Warranty tracking** — list warranties, find expired ones
- **Firmware compliance** — check firmware baselines
- **Job monitoring** — view OME jobs and their status
- **Group & policy management** — list device groups and alert policies
- **OData pagination** — automatic multi-page result fetching
- **Session-based auth** — secure X-Auth-Token sessions, auto-created and cleaned up

## Installation

```bash
pip install clr-openmanage-mcp
# or
uvx clr-openmanage-mcp
```

## Configuration

**Preferred:** Configuration file at `~/.config/openmanage/credentials.json` (chmod 600):

```json
{
  "host": "ome.example.com",
  "username": "admin",
  "password": "your-password"
}
```

**Alternative:** Environment variables are also supported:

| Variable | Description | Example |
|----------|-------------|---------|
| `OME_HOST` | OME server hostname or IP | `ome.example.com` |
| `OME_USERNAME` | OME admin username | `admin` |
| `OME_PASSWORD` | OME admin password | `secretpass` |

Optional:

| Variable | Description | Default |
|----------|-------------|---------|
| `OME_TRANSPORT` | Transport protocol (`stdio` or `http`) | `stdio` |
| `OME_LOG_LEVEL` | Log level | `INFO` |

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "openmanage": {
      "command": "uvx",
      "args": ["clr-openmanage-mcp"]
    }
  }
}
```

### Claude Code

Add via CLI:

```bash
claude mcp add openmanage -- uvx clr-openmanage-mcp
```

Or add to your `.mcp.json`:

```json
{
  "openmanage": {
    "command": "uvx",
    "args": ["clr-openmanage-mcp"]
  }
}
```

### VS Code

Add to your VS Code settings or `.vscode/mcp.json`:

```json
{
  "mcp": {
    "servers": {
      "openmanage": {
        "command": "uvx",
        "args": ["clr-openmanage-mcp"]
      }
    }
  }
}
```

**Note:** Configuration is read from `~/.config/openmanage/credentials.json` or environment variables. No need to specify credentials in MCP config files.

### HTTP Transport

To run as a standalone HTTP server:

```bash
clr-openmanage-mcp --transport http --host 0.0.0.0 --port 8000
```

## Tools

### System

| Tool | Description |
|------|-------------|
| `ome_version` | Get OME version, build info, and operation status |

### Devices

| Tool | Description | Parameters |
|------|-------------|------------|
| `ome_list_devices` | List all managed devices | `top?` |
| `ome_get_device` | Get full detail for a single device | `device_id` |
| `ome_device_health` | Aggregate device health summary (count by status) | — |

### Alerts

| Tool | Description | Parameters |
|------|-------------|------------|
| `ome_list_alerts` | List alerts with optional filters | `severity?`, `category?`, `status?`, `top?` |
| `ome_get_alert` | Get full detail for a single alert | `alert_id` |
| `ome_alert_count` | Alert count aggregated by severity | — |
| `ome_alert_ack` | Acknowledge one or more alerts by ID | `alert_ids` |
| `ome_alert_ack_all` | Acknowledge all unacknowledged alerts matching filters | `severity?`, `category?` |

**Alert filter values:**

| Parameter | Accepted values |
|-----------|----------------|
| `severity` | `critical`, `warning`, `info`, `normal` |
| `status` | `unack`, `ack` |
| `category` | e.g. `Warranty`, `System Health` |

### Warranties

| Tool | Description | Parameters |
|------|-------------|------------|
| `ome_list_warranties` | List all warranty records | `top?` |
| `ome_warranties_expired` | List warranties past their end date | — |

### Groups, Jobs, Policies & Firmware

| Tool | Description | Parameters |
|------|-------------|------------|
| `ome_list_groups` | List device groups | `top?` |
| `ome_list_jobs` | List jobs (sorted by most recent) | `top?` |
| `ome_list_policies` | List alert policies | `top?` |
| `ome_list_firmware` | List firmware compliance baselines | `top?` |

## Example Usage

Once connected, you can ask your AI assistant things like:

- "Show me all devices in OpenManage"
- "Are there any critical alerts?"
- "Which server warranties have expired?"
- "Acknowledge all warranty alerts"
- "Show me recent jobs"
- "What's the firmware compliance status?"

## Safety

All tools are **read-only** except `ome_alert_ack` and `ome_alert_ack_all`, which are non-destructive write operations — they mark alerts as acknowledged but do not modify device configuration.

## Technical Notes

- **SSL:** Self-signed certificate verification is disabled (common for OME appliances)
- **Auth:** Session-based with X-Auth-Token, auto-created on startup and cleaned up on shutdown
- **Pagination:** Automatically follows OData `@odata.nextLink` to fetch all pages (unless `top` is set)
- **Jobs API:** OME Jobs API doesn't support `$orderby`, so results are sorted client-side by `LastRun`
- **Warranty dates:** OME doesn't support date comparison in OData `$filter` for warranty endpoints, so expired warranty filtering is done client-side

## Development

```bash
git clone https://github.com/clearminds/clr-openmanage-mcp.git
cd clr-openmanage-mcp
uv sync
uv run clr-openmanage-mcp
```

## License

MIT — see [LICENSE](LICENSE) for details.
