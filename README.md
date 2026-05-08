# Kali MCP Server

A Model Context Protocol (MCP) server that exposes Kali Linux tools to AI agents. This allows LLMs to discover and execute security testing tools like nmap, sqlmap, hydra, metasploit, etc.

## Overview

This server runs inside a Kali Linux Docker container and provides MCP tools to:
- List all available Kali tools
- Check if a specific tool is available
- Execute Kali tools with arguments
- Monitor server health

## Architecture

```
┌─────────────┐     ┌──────────────────────────┐
│   MCP Host  │────▶│  Kali MCP Server         │
│ (e.g., LLM) │     │  FastMCP + Docker        │
│             │◀────│  (stdio transport)       │
└─────────────┘     └──────────────────────────┐
                    │  Kali Linux Container    │
                    │  - /usr/bin tools        │
                    │  - /usr/sbin tools       │
                    └────────────────────────────┘
```

## Installation

### Prerequisites

- Docker installed on your system
- Python 3.10+ (for local development)

### Build the Docker Image

```bash
docker build -t kali-mcp-server:latest .
```

The Docker image is built from `kalilinux/kali-rolling` and includes:
- Python 3 with FastMCP SDK
- Kali Linux toolset (all tools from `/usr/bin`, `/usr/sbin`)
- MCP server configuration

## Running the Server

### Option 1: Direct Docker Run (Recommended)

The MCP server connects directly through Docker using the `mcp.json` configuration:

```bash
# Ensure Docker is running
docker ps

# The server starts automatically when your MCP client connects
```

### Option 2: Interactive Container

```bash
# Start container interactively
docker run -it --name kali-mcp kali-mcp-server:latest

# Run commands inside the container
docker exec -it kali-mcp python3 /app/server.py
```

## Configuration

### mcp.json

The `mcp.json` file contains the MCP server configuration:

```json
{
  "mcpServers": {
    "kali-linux-tools": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "--name",
        "kali-mcp-${SESSION_ID}",
        "kali-mcp-server:latest"
      ],
      "env": {
        "MCP_TRANSPORT": "stdio"
      }
    }
  }
}
```

This configuration:
- Uses Docker as the command to run
- Runs a fresh container for each session (`--rm`)
- Uses stdio transport for MCP protocol
- Names containers uniquely per session

## Client Install Script

This repository includes `add.sh`, a helper script that installs the Kali MCP server entry into supported MCP client configs.

### Supported Targets

- Claude Desktop
- Claude Code
- Cursor
- Windsurf
- VS Code / GitHub Copilot
- Continue
- Cline
- Roo Code
- OpenCode
- Zed
- Codex
- Gemini CLI

### Usage

```bash
# Show help
./add.sh --help

# Add to a single client
./add.sh --claude-desktop
./add.sh --opencode

# Add to multiple clients at once
./add.sh --claude-code --cursor --vscode

# Add to every supported target
./add.sh --all
```

### What the Script Does

- Uses the local `docker-wrapper.sh` path from this repository
- Adds or updates the `kali-linux-tools` MCP entry
- Creates missing config files and parent directories when needed
- Preserves unrelated config entries in existing files

### Config Targets

| Target | Config path |
| --- | --- |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `~/.config/Claude/claude_desktop_config.json` on Linux, `%APPDATA%/Claude/claude_desktop_config.json` on Windows |
| Claude Code | `.mcp.json` |
| Cursor | `.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` on macOS/Linux, `%USERPROFILE%/.codeium/windsurf/mcp_config.json` on Windows |
| VS Code / Copilot | `.vscode/mcp.json` |
| Continue | `~/.continue/config.json` on macOS/Linux, `%USERPROFILE%/.continue/config.json` on Windows |
| Cline | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` on macOS, `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` on Linux, `%APPDATA%/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` on Windows |
| Roo Code | `~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json` on macOS, `~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json` on Linux, `%APPDATA%/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json` on Windows |
| OpenCode | `opencode.json` |
| Zed | `~/.config/zed/settings.json` on macOS/Linux, `%APPDATA%/Zed/settings.json` on Windows |
| Codex | `.codex/config.toml` |
| Gemini CLI | `~/.gemini/settings.json` on macOS/Linux, `%USERPROFILE%/.gemini/settings.json` on Windows |

### Notes

- Project-level targets write into this repository.
- Global targets write into your home directory config locations.
- The script now handles macOS, Linux, and Windows-style config paths for supported global targets.
- On Windows, run the script from Git Bash, MSYS2, or Cygwin so `bash` and the wrapper-based command remain valid.
- After updating a client config, restart that client so it reloads MCP servers.

## Use the Server from an MCP Client

Once the Docker image is built, an MCP client can launch this server on demand and call its tools.

### Recommended Setup Flow

```bash
# 1. Build the image
docker build -t kali-mcp-server:latest .

# 2. Install the MCP entry into one or more clients
./add.sh --claude-desktop
# or
./add.sh --claude-code --cursor --vscode

# 3. Restart the client you updated
```

### How MCP Usage Works

1. Your MCP client loads the `kali-linux-tools` server entry.
2. When the client connects, it starts the Docker-backed server.
3. The client discovers the available MCP tools.
4. You ask the client to inspect tools or run a Kali command.
5. The server returns structured results over MCP.

### Verify the Client Connection

After restarting your MCP client, verify the server is available by asking it to:

- list available tools from `kali-linux-tools`
- run `health_check`
- run `server_info`

If the client is connected correctly, it should show the server tools and return a healthy status.

### Example MCP Prompts

Use prompts like these in your MCP-enabled client:

- `List the first 20 Kali tools exposed by kali-linux-tools.`
- `Check whether sqlmap is installed.`
- `Run nmap --version using the kali-linux-tools MCP server.`
- `Run health_check on the kali-linux-tools server.`
- `Show server_info for the kali-linux-tools MCP server.`

### Example Tool Mappings

| Intent | MCP tool | Example |
| --- | --- | --- |
| Discover tools | `list_tools` | `list_tools(limit=20)` |
| Check one tool | `check_tool` | `check_tool(tool_name="nmap")` |
| Execute a command | `execute_tool` | `execute_tool(tool="nmap", arguments=["--version"])` |
| Verify health | `health_check` | `health_check()` |
| Inspect server metadata | `server_info` | `server_info()` |

### Safe Usage Guidance

- Start with read-only or version-check commands such as `--help` or `--version`.
- Prefer targeted commands over broad scans until you confirm the client-server setup works.
- Treat `execute_tool` as direct command execution inside the Kali container.
- Review generated arguments in your client before approving tool execution.
- Use this server only in environments where running security tools is appropriate.

## MCP Tools

The server exposes the following tools through MCP:

### list_tools
List all available Kali tools.

**Arguments:**
- `limit` (optional): Maximum number of tools to return

### check_tool
Check if a specific Kali tool is available.

**Arguments:**
- `tool_name` (required): Name of the tool to check

### execute_tool
Execute a Kali tool with specified arguments.

**Arguments:**
- `tool` (required): Name of the Kali tool to execute
- `arguments` (optional, default: []): List of command line arguments for the tool
- `timeout` (optional, default: 60): Timeout in seconds for command execution

### health_check
Check server health status.

**Arguments:** None

### server_info
Get server information and available endpoints.

**Arguments:** None

## Development

### Run Locally (Outside Docker)

```bash
# Install dependencies
pip install "mcp[cli]" uvicorn

# Run server
python3 server.py [--transport stdio|streamable-http]
```

Server will start with stdio transport (default) or HTTP on port 3001.

### Directory Structure

- `server.py` - FastMCP server implementation
- `mcp.json` - MCP server configuration for Docker
- `Dockerfile` - Docker image definition
- `README.md` - This documentation

## Security Considerations

**⚠️ IMPORTANT**: This server executes system commands and should be used with caution:

- ⚠️ **No authentication** - This is a local development tool only
- ⚠️ **Direct command execution** - Any Kali tool can be run with any arguments
- ⚠️ **No input validation** - Arguments are passed directly to system commands

### Production Recommendations

If deploying in a production environment:

1. Add authentication (API keys, OAuth, etc.)
2. Implement input validation and sanitization
3. Add rate limiting
4. Restrict which tools can be executed
5. Run in a restricted Docker network
6. Enable logging and monitoring

## Troubleshooting

### Container won't start

```bash
# Check if Docker is running
docker ps

# Check logs
docker logs kali-mcp-${SESSION_ID}

# Ensure image exists
docker images | grep kali-mcp-server
```

### Tools not found

```bash
# Verify container is running Kali Linux
docker exec -it kali-mcp-${SESSION_ID} cat /etc/os-release

# Check tool directory
docker exec kali-mcp-${SESSION_ID} ls /usr/bin | head -20
```

### Connection refused

```bash
# Verify container is running
docker ps | grep kali-mcp

# Check container ports (if using HTTP transport)
docker port kali-mcp-${SESSION_ID}
```

### Docker not found

Ensure Docker is installed and accessible in your PATH:
```bash
docker --version
```

## License

This is a work in progress for internal/testing use only.
