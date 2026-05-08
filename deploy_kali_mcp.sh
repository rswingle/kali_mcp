#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IMAGE_TAG="${IMAGE_TAG:-kali-mcp-server:latest}"
CLAUDE_AGENT_DIR="${CLAUDE_AGENT_DIR:-$HOME/.claude/agents}"
AGENT_SOURCE_FILE="${SCRIPT_DIR}/kali-operator.md"
AGENT_TARGET_FILE="${CLAUDE_AGENT_DIR}/kali-operator.md"
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage:
  ./deploy_kali_mcp.sh [options]

Options:
  --dry-run                  Print planned actions without executing them
  --image-tag <tag>          Docker image tag (default: kali-mcp-server:latest)
  --claude-agent-dir <path>  Claude agent directory (default: ~/.claude/agents)
  --help                     Show this help

What this script does:
  1) Builds the Docker image
  2) Installs/updates the systemd service
  3) Installs/updates the Claude agent file
EOF
}

log() {
  printf '[deploy_kali_mcp.sh] %s\n' "$*"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log "Missing required command: $1"
    exit 1
  fi
}

run_step() {
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log "[dry-run] $*"
    return 0
  fi
  "$@"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --image-tag)
      if [[ $# -lt 2 ]]; then
        usage
        exit 1
      fi
      IMAGE_TAG="$2"
      shift 2
      ;;
    --claude-agent-dir)
      if [[ $# -lt 2 ]]; then
        usage
        exit 1
      fi
      CLAUDE_AGENT_DIR="$2"
      AGENT_TARGET_FILE="${CLAUDE_AGENT_DIR}/kali-operator.md"
      shift 2
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

if [[ "${DRY_RUN}" -eq 0 ]]; then
  need_cmd docker
fi

if [[ ! -f "${AGENT_SOURCE_FILE}" ]]; then
  log "Missing source agent file: ${AGENT_SOURCE_FILE}"
  exit 1
fi

if [[ ! -x "${SCRIPT_DIR}/install_systemd_service.sh" ]]; then
  log "Expected executable script: ${SCRIPT_DIR}/install_systemd_service.sh"
  exit 1
fi

log "Step 1/3: Building Docker image: ${IMAGE_TAG}"
run_step docker build -t "${IMAGE_TAG}" "${SCRIPT_DIR}"

log "Step 2/3: Installing/updating systemd service"
if [[ "${DRY_RUN}" -eq 1 ]]; then
  log "[dry-run] IMAGE=${IMAGE_TAG} ${SCRIPT_DIR}/install_systemd_service.sh install"
else
  IMAGE="${IMAGE_TAG}" "${SCRIPT_DIR}/install_systemd_service.sh" install
fi

log "Step 3/3: Installing Claude agent: ${AGENT_TARGET_FILE}"
if [[ "${DRY_RUN}" -eq 1 ]]; then
  log "[dry-run] mkdir -p ${CLAUDE_AGENT_DIR}"
  log "[dry-run] cp ${AGENT_SOURCE_FILE} ${AGENT_TARGET_FILE}"
else
  mkdir -p "${CLAUDE_AGENT_DIR}"
  cp "${AGENT_SOURCE_FILE}" "${AGENT_TARGET_FILE}"
fi

log "Deployment complete."
