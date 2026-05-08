#!/usr/bin/env bash

set -euo pipefail

SERVER_NAME="kali-linux-tools"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WRAPPER_PATH="$SCRIPT_DIR/docker-wrapper.sh"

TARGETS=()

usage() {
  cat <<'EOF'
Usage:
  ./add.sh [targets...]

Targets:
  --claude-desktop   Add to Claude Desktop
  --claude-code      Add to Claude Code project config (.mcp.json)
  --cursor           Add to Cursor project config (.cursor/mcp.json)
  --windsurf         Add to Windsurf global config
  --vscode           Add to VS Code / Copilot workspace config (.vscode/mcp.json)
  --continue         Add to Continue global config
  --cline            Add to Cline global config
  --roo              Add to Roo Code global config
  --opencode         Add to OpenCode project config (opencode.json)
  --zed              Add to Zed global config
  --codex            Add to Codex project config (.codex/config.toml)
  --gemini           Add to Gemini CLI global config
  --all              Add to every supported target above
  --help             Show this help

Notes:
  - Run this script from the repository root.
  - Project-level targets write into the current repository.
  - Global targets write into your user config directory.
EOF
}

log() {
  printf '[add.sh] %s\n' "$*"
}

os_name() {
  case "$(uname -s)" in
    Darwin) printf 'macos' ;;
    Linux) printf 'linux' ;;
    MINGW*|MSYS*|CYGWIN*) printf 'windows' ;;
    *) printf 'unknown' ;;
  esac
}

require_env_var() {
  local var_name="$1"
  if [ -z "${!var_name:-}" ]; then
    log "Skipping target: required environment variable '$var_name' is not set"
    return 1
  fi
}

claude_desktop_path() {
  case "$(os_name)" in
    macos) printf '%s' "$HOME/Library/Application Support/Claude/claude_desktop_config.json" ;;
    linux) printf '%s' "$HOME/.config/Claude/claude_desktop_config.json" ;;
    windows)
      require_env_var APPDATA || return 1
      printf '%s' "$APPDATA/Claude/claude_desktop_config.json"
      ;;
    *) return 1 ;;
  esac
}

windsurf_path() {
  case "$(os_name)" in
    windows)
      require_env_var USERPROFILE || return 1
      printf '%s' "$USERPROFILE/.codeium/windsurf/mcp_config.json"
      ;;
    *) printf '%s' "$HOME/.codeium/windsurf/mcp_config.json" ;;
  esac
}

continue_path() {
  case "$(os_name)" in
    windows)
      require_env_var USERPROFILE || return 1
      printf '%s' "$USERPROFILE/.continue/config.json"
      ;;
    *) printf '%s' "$HOME/.continue/config.json" ;;
  esac
}

cline_path() {
  case "$(os_name)" in
    macos) printf '%s' "$HOME/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json" ;;
    linux) printf '%s' "$HOME/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json" ;;
    windows)
      require_env_var APPDATA || return 1
      printf '%s' "$APPDATA/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
      ;;
    *) return 1 ;;
  esac
}

roo_path() {
  case "$(os_name)" in
    macos) printf '%s' "$HOME/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json" ;;
    linux) printf '%s' "$HOME/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json" ;;
    windows)
      require_env_var APPDATA || return 1
      printf '%s' "$APPDATA/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"
      ;;
    *) return 1 ;;
  esac
}

zed_path() {
  case "$(os_name)" in
    windows)
      require_env_var APPDATA || return 1
      printf '%s' "$APPDATA/Zed/settings.json"
      ;;
    *) printf '%s' "$HOME/.config/zed/settings.json" ;;
  esac
}

gemini_path() {
  case "$(os_name)" in
    windows)
      require_env_var USERPROFILE || return 1
      printf '%s' "$USERPROFILE/.gemini/settings.json"
      ;;
    *) printf '%s' "$HOME/.gemini/settings.json" ;;
  esac
}

ensure_parent_dir() {
  mkdir -p "$(dirname "$1")"
}

json_stdlib_write() {
  local config_path="$1"
  local root_key="$2"
  local entry_json="$3"
  local server_name="$4"

  CONFIG_PATH="$config_path" ROOT_KEY="$root_key" ENTRY_JSON="$entry_json" SERVER_NAME="$server_name" python3 <<'PY'
import json
import os
from pathlib import Path

path = Path(os.environ["CONFIG_PATH"]).expanduser()
root_key = os.environ["ROOT_KEY"]
server_name = os.environ["SERVER_NAME"]
entry = json.loads(os.environ["ENTRY_JSON"])

if path.exists():
    raw = path.read_text()
    data = json.loads(raw) if raw.strip() else {}
else:
    data = {}

if not isinstance(data, dict):
    raise SystemExit(f"Expected top-level JSON object in {path}")

bucket = data.setdefault(root_key, {})
if not isinstance(bucket, dict):
    raise SystemExit(f"Expected '{root_key}' to be an object in {path}")

bucket[server_name] = entry
path.write_text(json.dumps(data, indent=2) + "\n")
PY
}

json_preserve_write() {
  local config_path="$1"
  local update_script="$2"

  CONFIG_PATH="$config_path" python3 <<PY
import json
import os
from pathlib import Path

path = Path(os.environ["CONFIG_PATH"]).expanduser()
if path.exists():
    raw = path.read_text()
    data = json.loads(raw) if raw.strip() else {}
else:
    data = {}

if not isinstance(data, dict):
    raise SystemExit(f"Expected top-level JSON object in {path}")

$update_script

path.write_text(json.dumps(data, indent=2) + "\n")
PY
}

write_codex_toml() {
  local config_path="$1"
  local wrapper_path="$2"

  CONFIG_PATH="$config_path" WRAPPER_PATH="$wrapper_path" python3 <<'PY'
import os
from pathlib import Path

path = Path(os.environ["CONFIG_PATH"]).expanduser()
wrapper_path = os.environ["WRAPPER_PATH"]
section_header = "[mcp_servers.kali-linux-tools]"
env_header = "[mcp_servers.kali-linux-tools.env]"

block = f'''{section_header}
command = "bash"
args = ["{wrapper_path}", "run", "--rm", "-i", "-e", "MCP_TRANSPORT=stdio", "kali-mcp-server:latest"]

{env_header}
MCP_TRANSPORT = "stdio"
'''

existing = path.read_text() if path.exists() else ""
lines = existing.splitlines()
result = []
skip = False
current_section = None

for line in lines:
    stripped = line.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        current_section = stripped
        if current_section in {section_header, env_header}:
            skip = True
            continue
        skip = False
    if skip:
        continue
    result.append(line)

trimmed = "\n".join(result).strip()
final = trimmed + ("\n\n" if trimmed else "") + block.strip() + "\n"
path.write_text(final)
PY
}

install_claude_desktop() {
  local config_path
  config_path="$(claude_desktop_path)" || {
    log "Skipping Claude Desktop: unsupported OS $(uname -s)"
    return
  }

  ensure_parent_dir "$config_path"
  json_stdlib_write "$config_path" "mcpServers" "$(python3 - <<PY
import json
print(json.dumps({
  "command": "bash",
  "args": [
    "$WRAPPER_PATH",
    "run",
    "--rm",
    "-i",
    "-e",
    "MCP_TRANSPORT=stdio",
    "kali-mcp-server:latest"
  ]
}))
PY
)" "$SERVER_NAME"
  log "Updated Claude Desktop config: $config_path"
}

install_claude_code() {
  local config_path="$SCRIPT_DIR/.mcp.json"
  ensure_parent_dir "$config_path"
  json_stdlib_write "$config_path" "mcpServers" "$(python3 - <<PY
import json
print(json.dumps({
  "command": "bash",
  "args": [
    "$WRAPPER_PATH",
    "run",
    "--rm",
    "-i",
    "-e",
    "MCP_TRANSPORT=stdio",
    "kali-mcp-server:latest"
  ],
  "env": {
    "MCP_TRANSPORT": "stdio"
  }
}))
PY
)" "$SERVER_NAME"
  log "Updated Claude Code config: $config_path"
}

install_cursor() {
  local config_path="$SCRIPT_DIR/.cursor/mcp.json"
  ensure_parent_dir "$config_path"
  json_stdlib_write "$config_path" "mcpServers" "$(python3 - <<PY
import json
print(json.dumps({
  "command": "bash",
  "args": [
    "$WRAPPER_PATH",
    "run",
    "--rm",
    "-i",
    "-e",
    "MCP_TRANSPORT=stdio",
    "kali-mcp-server:latest"
  ],
  "env": {
    "MCP_TRANSPORT": "stdio"
  }
}))
PY
)" "$SERVER_NAME"
  log "Updated Cursor config: $config_path"
}

install_windsurf() {
  local config_path
  config_path="$(windsurf_path)" || return
  ensure_parent_dir "$config_path"
  json_stdlib_write "$config_path" "mcpServers" "$(python3 - <<PY
import json
print(json.dumps({
  "command": "bash",
  "args": [
    "$WRAPPER_PATH",
    "run",
    "--rm",
    "-i",
    "-e",
    "MCP_TRANSPORT=stdio",
    "kali-mcp-server:latest"
  ],
  "env": {
    "MCP_TRANSPORT": "stdio"
  }
}))
PY
)" "$SERVER_NAME"
  log "Updated Windsurf config: $config_path"
}

install_vscode() {
  local config_path="$SCRIPT_DIR/.vscode/mcp.json"
  ensure_parent_dir "$config_path"
  json_stdlib_write "$config_path" "servers" "$(python3 - <<PY
import json
print(json.dumps({
  "type": "stdio",
  "command": "bash",
  "args": [
    "$WRAPPER_PATH",
    "run",
    "--rm",
    "-i",
    "-e",
    "MCP_TRANSPORT=stdio",
    "kali-mcp-server:latest"
  ],
  "env": {
    "MCP_TRANSPORT": "stdio"
  }
}))
PY
)" "$SERVER_NAME"
  log "Updated VS Code config: $config_path"
}

install_continue() {
  local config_path
  config_path="$(continue_path)" || return
  ensure_parent_dir "$config_path"
  json_stdlib_write "$config_path" "mcpServers" "$(python3 - <<PY
import json
print(json.dumps({
  "command": "bash",
  "args": [
    "$WRAPPER_PATH",
    "run",
    "--rm",
    "-i",
    "-e",
    "MCP_TRANSPORT=stdio",
    "kali-mcp-server:latest"
  ],
  "env": {
    "MCP_TRANSPORT": "stdio"
  }
}))
PY
)" "$SERVER_NAME"
  log "Updated Continue config: $config_path"
}

install_cline() {
  local config_path
  config_path="$(cline_path)" || {
    log "Skipping Cline: unsupported OS $(uname -s)"
    return
  }

  ensure_parent_dir "$config_path"
  json_stdlib_write "$config_path" "mcpServers" "$(python3 - <<PY
import json
print(json.dumps({
  "command": "bash",
  "args": [
    "$WRAPPER_PATH",
    "run",
    "--rm",
    "-i",
    "-e",
    "MCP_TRANSPORT=stdio",
    "kali-mcp-server:latest"
  ],
  "env": {
    "MCP_TRANSPORT": "stdio"
  },
  "alwaysAllow": [],
  "disabled": False
}))
PY
)" "$SERVER_NAME"
  log "Updated Cline config: $config_path"
}

install_roo() {
  local config_path
  config_path="$(roo_path)" || {
    log "Skipping Roo Code: unsupported OS $(uname -s)"
    return
  }

  ensure_parent_dir "$config_path"
  json_stdlib_write "$config_path" "mcpServers" "$(python3 - <<PY
import json
print(json.dumps({
  "type": "stdio",
  "command": "bash",
  "args": [
    "$WRAPPER_PATH",
    "run",
    "--rm",
    "-i",
    "-e",
    "MCP_TRANSPORT=stdio",
    "kali-mcp-server:latest"
  ],
  "env": {
    "MCP_TRANSPORT": "stdio"
  },
  "alwaysAllow": [],
  "disabled": False
}))
PY
)" "$SERVER_NAME"
  log "Updated Roo Code config: $config_path"
}

install_opencode() {
  local config_path="$SCRIPT_DIR/opencode.json"
  ensure_parent_dir "$config_path"
  json_stdlib_write "$config_path" "mcp" "$(python3 - <<PY
import json
print(json.dumps({
  "type": "local",
  "command": [
    "bash",
    "$WRAPPER_PATH",
    "run",
    "--rm",
    "-i",
    "-e",
    "MCP_TRANSPORT=stdio",
    "kali-mcp-server:latest"
  ],
  "enabled": True,
  "environment": {
    "MCP_TRANSPORT": "stdio"
  }
}))
PY
)" "$SERVER_NAME"
  log "Updated OpenCode config: $config_path"
}

install_zed() {
  local config_path
  config_path="$(zed_path)" || return
  ensure_parent_dir "$config_path"
  json_stdlib_write "$config_path" "context_servers" "$(python3 - <<PY
import json
print(json.dumps({
  "command": "bash",
  "args": [
    "$WRAPPER_PATH",
    "run",
    "--rm",
    "-i",
    "-e",
    "MCP_TRANSPORT=stdio",
    "kali-mcp-server:latest"
  ],
  "env": {
    "MCP_TRANSPORT": "stdio"
  }
}))
PY
)" "$SERVER_NAME"
  log "Updated Zed config: $config_path"
}

install_codex() {
  local config_path="$SCRIPT_DIR/.codex/config.toml"
  ensure_parent_dir "$config_path"
  write_codex_toml "$config_path" "$WRAPPER_PATH"
  log "Updated Codex config: $config_path"
}

install_gemini() {
  local config_path
  config_path="$(gemini_path)" || return
  ensure_parent_dir "$config_path"
  json_stdlib_write "$config_path" "mcpServers" "$(python3 - <<PY
import json
print(json.dumps({
  "command": "bash",
  "args": [
    "$WRAPPER_PATH",
    "run",
    "--rm",
    "-i",
    "-e",
    "MCP_TRANSPORT=stdio",
    "kali-mcp-server:latest"
  ],
  "env": {
    "MCP_TRANSPORT": "stdio"
  }
}))
PY
)" "$SERVER_NAME"
  log "Updated Gemini config: $config_path"
}

expand_targets() {
  if [ ${#TARGETS[@]} -eq 0 ]; then
    usage
    exit 1
  fi

  local expanded=()
  local target
  for target in "${TARGETS[@]}"; do
    if [ "$target" = "all" ]; then
      expanded+=(claude-desktop claude-code cursor windsurf vscode continue cline roo opencode zed codex gemini)
    else
      expanded+=("$target")
    fi
  done

  TARGETS=("${expanded[@]}")
}

while [ $# -gt 0 ]; do
  case "$1" in
    --claude-desktop) TARGETS+=(claude-desktop) ;;
    --claude-code) TARGETS+=(claude-code) ;;
    --cursor) TARGETS+=(cursor) ;;
    --windsurf) TARGETS+=(windsurf) ;;
    --vscode) TARGETS+=(vscode) ;;
    --continue) TARGETS+=(continue) ;;
    --cline) TARGETS+=(cline) ;;
    --roo) TARGETS+=(roo) ;;
    --opencode) TARGETS+=(opencode) ;;
    --zed) TARGETS+=(zed) ;;
    --codex) TARGETS+=(codex) ;;
    --gemini) TARGETS+=(gemini) ;;
    --all) TARGETS+=(all) ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      log "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
  shift
done

expand_targets

declare -A seen=()
for target in "${TARGETS[@]}"; do
  if [ -n "${seen[$target]:-}" ]; then
    continue
  fi
  seen[$target]=1

  case "$target" in
    claude-desktop) install_claude_desktop ;;
    claude-code) install_claude_code ;;
    cursor) install_cursor ;;
    windsurf) install_windsurf ;;
    vscode) install_vscode ;;
    continue) install_continue ;;
    cline) install_cline ;;
    roo) install_roo ;;
    opencode) install_opencode ;;
    zed) install_zed ;;
    codex) install_codex ;;
    gemini) install_gemini ;;
    *)
      log "Unsupported target: $target"
      exit 1
      ;;
  esac
done

log "Done"
