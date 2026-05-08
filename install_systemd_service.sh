#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-kali-mcp-server}"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
IMAGE="${IMAGE:-kali-mcp-server:latest}"
CONTAINER_NAME="${CONTAINER_NAME:-kali-mcp-server}"
PORT="${PORT:-3001}"
HOST_BIND="${HOST_BIND:-127.0.0.1}"

usage() {
  cat <<'EOF'
Usage:
  ./install_systemd_service.sh install
  ./install_systemd_service.sh uninstall
  ./install_systemd_service.sh start|stop|restart|status|logs

Optional environment overrides:
  SERVICE_NAME   systemd service name (default: kali-mcp-server)
  IMAGE          docker image tag (default: kali-mcp-server:latest)
  CONTAINER_NAME docker container name (default: kali-mcp-server)
  PORT           host port for MCP HTTP transport (default: 3001)
  HOST_BIND      host bind address (default: 127.0.0.1)

Examples:
  ./install_systemd_service.sh install
  PORT=3010 HOST_BIND=0.0.0.0 ./install_systemd_service.sh install
EOF
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

SUDO=""
if [[ "${EUID}" -ne 0 ]]; then
  SUDO="sudo"
fi

run_root() {
  if [[ -n "${SUDO}" ]]; then
    "${SUDO}" "$@"
  else
    "$@"
  fi
}

write_unit_file() {
  local docker_bin
  docker_bin="$(command -v docker)"

  cat <<EOF | run_root tee "${UNIT_PATH}" >/dev/null
[Unit]
Description=Kali MCP Server (Docker)
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
Restart=always
RestartSec=5
ExecStartPre=-${docker_bin} rm -f ${CONTAINER_NAME}
ExecStart=${docker_bin} run --rm --name ${CONTAINER_NAME} -p ${HOST_BIND}:${PORT}:3001 -e MCP_TRANSPORT=streamable-http ${IMAGE}
ExecStop=${docker_bin} stop ${CONTAINER_NAME}
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF
}

install_service() {
  need_cmd systemctl
  need_cmd docker

  write_unit_file
  run_root systemctl daemon-reload
  run_root systemctl enable "${SERVICE_NAME}"
  run_root systemctl restart "${SERVICE_NAME}"

  echo "Installed and started ${SERVICE_NAME}"
  run_root systemctl --no-pager --full status "${SERVICE_NAME}" || true
}

uninstall_service() {
  need_cmd systemctl

  run_root systemctl stop "${SERVICE_NAME}" || true
  run_root systemctl disable "${SERVICE_NAME}" || true
  run_root rm -f "${UNIT_PATH}"
  run_root systemctl daemon-reload

  echo "Uninstalled ${SERVICE_NAME}"
}

manage_service() {
  need_cmd systemctl
  local action="$1"

  case "${action}" in
    start|stop|restart|status)
      run_root systemctl "${action}" "${SERVICE_NAME}"
      ;;
    logs)
      run_root journalctl -u "${SERVICE_NAME}" -n 100 --no-pager
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main() {
  if [[ $# -ne 1 ]]; then
    usage
    exit 1
  fi

  case "$1" in
    install)
      install_service
      ;;
    uninstall)
      uninstall_service
      ;;
    start|stop|restart|status|logs)
      manage_service "$1"
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
