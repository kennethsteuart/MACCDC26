#!/usr/bin/env bash
# Splunk server probe (read-only).

set -euo pipefail

MODE="full"
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    SUDO="sudo -n"
  fi
fi

SPLUNK_HOME="/opt/splunk"

usage() {
  cat <<'USAGE'
Usage: linux_splunk.sh [--summary|--full]
USAGE
}

summary() {
  local os_id="unknown"
  local os_ver="unknown"
  local ip_line=""

  if [ -f /etc/os-release ]; then
    . /etc/os-release
    os_id="${ID:-unknown}"
    os_ver="${VERSION_ID:-unknown}"
  fi

  echo "## splunk summary"
  echo "host: $(hostname)"
  echo "os: ${os_id} ${os_ver}"
  ip_line="$(ip -brief addr 2>/dev/null | awk '$1 != "lo" {print; exit}')"
  if [ -n "$ip_line" ]; then
    echo "ip: $ip_line"
  fi

  if [ -x "${SPLUNK_HOME}/bin/splunk" ]; then
    echo "## splunk status"
    "${SPLUNK_HOME}/bin/splunk" status 2>/dev/null | head -n 2 || true
  fi

  echo "## listeners 8000/8089/9997"
  if [ -n "$SUDO" ]; then
    $SUDO ss -tuln 2>/dev/null | grep -E ':(8000|8089|9997)([^0-9]|$)' | sed -n '1,5p' || true
  else
    ss -tuln 2>/dev/null | grep -E ':(8000|8089|9997)([^0-9]|$)' | sed -n '1,5p' || true
  fi

  if command -v systemctl >/dev/null 2>&1; then
    echo "## systemd"
    echo "splunk: $(systemctl is-active splunk 2>/dev/null || true)"
  fi

  if command -v getenforce >/dev/null 2>&1; then
    echo "## selinux"
    getenforce || true
  fi
}

full() {
  if [ -x "${SPLUNK_HOME}/bin/splunk" ]; then
    echo "## splunk status"
    "${SPLUNK_HOME}/bin/splunk" status || true
  fi

  echo "## listeners"
  if [ -n "$SUDO" ]; then
    $SUDO ss -tulpn 2>/dev/null | grep -E ':(8000|8089|9997)\b' || true
  else
    ss -tulpn 2>/dev/null | grep -E ':(8000|8089|9997)\b' || true
  fi

  echo "## systemd"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active splunk >/dev/null 2>&1 && systemctl status splunk --no-pager -l | sed -n '1,8p'
  fi

  echo "## selinux"
  command -v sestatus >/dev/null 2>&1 && sestatus | head -n 6 || true
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --summary) MODE="summary"; shift ;;
    --full) MODE="full"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

if [ "$MODE" = "summary" ]; then
  summary
else
  full
fi
