#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_AGENT_FILE="${SCRIPT_DIR}/kali-operator.md"
SOURCE_PLUGIN_FILE="${SCRIPT_DIR}/plugin.json"

TARGET_HOME="${HOME}"
TARGET_PLUGIN_DIR=""
DRY_RUN=0
AGENT_BASENAME="$(basename "${SOURCE_AGENT_FILE}")"

usage() {
  cat <<'EOF'
Usage:
  ./install_kali_operator_plugin.sh [options]

Options:
  --home <path>         Override the target user's home directory (default: $HOME)
  --plugin-dir <path>   Override the full plugin target directory
  --dry-run             Print planned actions without writing files
  --help                Show this help

Default install layout:
  <home>/.claude/plugins/kali-operator/
  ├── .claude-plugin/plugin.json
  └── agents/kali-operator.md
EOF
}

log() {
  printf '[install_kali_operator_plugin.sh] %s\n' "$*"
}

need_file() {
  local file_path="$1"
  if [[ ! -f "${file_path}" ]]; then
    log "Missing required file: ${file_path}"
    exit 1
  fi
}

detect_plugin_name() {
  PLUGIN_FILE="${SOURCE_PLUGIN_FILE}" python3 <<'PY'
import json
import os
from pathlib import Path

path = Path(os.environ["PLUGIN_FILE"])
raw = path.read_text()
data = json.loads(raw)
name = data.get("name")
if not isinstance(name, str) or not name.strip():
    raise SystemExit("plugin.json must include a non-empty 'name' field")
print(name.strip())
PY
}

copy_file() {
  local src="$1"
  local dst="$2"
  mkdir -p "$(dirname "${dst}")"
  cp "${src}" "${dst}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --home)
      if [[ $# -lt 2 ]]; then
        usage
        exit 1
      fi
      TARGET_HOME="$2"
      shift 2
      ;;
    --plugin-dir)
      if [[ $# -lt 2 ]]; then
        usage
        exit 1
      fi
      TARGET_PLUGIN_DIR="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      log "Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

need_file "${SOURCE_AGENT_FILE}"
need_file "${SOURCE_PLUGIN_FILE}"

PLUGIN_NAME="$(detect_plugin_name)"
if [[ -z "${TARGET_PLUGIN_DIR}" ]]; then
  TARGET_PLUGIN_DIR="${TARGET_HOME}/.claude/plugins/${PLUGIN_NAME}"
fi

TARGET_AGENT_FILE="${TARGET_PLUGIN_DIR}/agents/${AGENT_BASENAME}"
TARGET_PLUGIN_FILE="${TARGET_PLUGIN_DIR}/.claude-plugin/plugin.json"

if [[ "${DRY_RUN}" -eq 1 ]]; then
  log "Dry run enabled. No files will be written."
  log "Would copy: ${SOURCE_AGENT_FILE} -> ${TARGET_AGENT_FILE}"
  log "Would copy: ${SOURCE_PLUGIN_FILE} -> ${TARGET_PLUGIN_FILE}"
  exit 0
fi

copy_file "${SOURCE_AGENT_FILE}" "${TARGET_AGENT_FILE}"
copy_file "${SOURCE_PLUGIN_FILE}" "${TARGET_PLUGIN_FILE}"

log "Installed Kali Operator plugin files."
log "Agent file: ${TARGET_AGENT_FILE}"
log "Plugin manifest: ${TARGET_PLUGIN_FILE}"
