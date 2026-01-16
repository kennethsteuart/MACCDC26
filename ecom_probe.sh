#!/usr/bin/env bash
# Ubuntu Ecom probe (read-only).

set -euo pipefail

MODE="full"
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    SUDO="sudo -n"
  fi
fi

usage() {
  cat <<'USAGE'
Usage: linux_ecom.sh [--summary|--full]
USAGE
}

listeners_80443() {
  if [ -n "$SUDO" ]; then
    $SUDO ss -tulpn 2>/dev/null | egrep ':(80|443)\b' || true
  else
    ss -tulpn 2>/dev/null | egrep ':(80|443)\b' || true
  fi
}

summary() {
  local os_id="unknown"
  local os_ver="unknown"
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    os_id="${ID:-unknown}"
    os_ver="${VERSION_ID:-unknown}"
  fi

  echo "## ecom summary"
  echo "host: $(hostname)"
  echo "os: ${os_id} ${os_ver}"
  ip_line="$(ip -brief addr 2>/dev/null | awk '$1 != "lo" {print; exit}')"
  if [ -n "$ip_line" ]; then
    echo "ip: $ip_line"
  fi

  echo "## services"
  for svc in apache2 mysql mariadb ssh sshd; do
    if systemctl list-unit-files | grep -q "^${svc}\.service"; then
      echo "${svc}: $(systemctl is-active "$svc" 2>/dev/null || true)"
    fi
  done

  echo "## listeners 22/80/443"
  if [ -n "$SUDO" ]; then
    $SUDO ss -tuln 2>/dev/null | egrep ':(22|80|443)\b' | sed -n '1,4p' || true
  else
    ss -tuln 2>/dev/null | egrep ':(22|80|443)\b' | sed -n '1,4p' || true
  fi

  if command -v apache2ctl >/dev/null 2>&1; then
    echo "## apache vhost (summary)"
    apache2ctl -S 2>/dev/null | sed -n '2p' || true
  fi

  if command -v curl >/dev/null 2>&1; then
    echo "## local http"
    http_code="$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1/ || true)"
    echo "http: ${http_code}"
    echo "## local https"
    if listeners_80443 | grep -q ':443\b'; then
      https_code="$(curl -sS -k -o /dev/null -w '%{http_code}' https://127.0.0.1/ || true)"
      echo "https: ${https_code}"
    else
      echo "https not listening on 443"
    fi
  fi

  if command -v aa-status >/dev/null 2>&1; then
    echo "## apparmor"
    if [ -n "$SUDO" ]; then
      line="$($SUDO aa-status 2>/dev/null | head -n 1 || true)"
    else
      line="$(aa-status 2>/dev/null | head -n 1 || true)"
    fi
    [ -n "$line" ] && echo "$line"
  fi

  if command -v ufw >/dev/null 2>&1; then
    echo "## ufw"
    $SUDO ufw status | head -n 1 || true
  fi
}

full() {
  echo "## ecom web stack"
  for svc in apache2 nginx php-fpm php8.3-fpm php8.2-fpm; do
    if systemctl list-unit-files | grep -q "^${svc}\.service"; then
      systemctl is-active "$svc" >/dev/null 2>&1 && systemctl status "$svc" --no-pager -l | sed -n '1,8p'
    fi
  done

  if command -v apache2ctl >/dev/null 2>&1; then
    echo "## apache2 vhosts"
    apache2ctl -S 2>/dev/null | head -n 12 || true
  fi

  echo "## database"
  for svc in mysql mariadb; do
    if systemctl list-unit-files | grep -q "^${svc}\.service"; then
      systemctl is-active "$svc" >/dev/null 2>&1 && systemctl status "$svc" --no-pager -l | sed -n '1,8p'
    fi
  done

  echo "## web listeners"
  local listeners
  listeners="$(listeners_80443)"
  if [ -n "$listeners" ]; then
    echo "$listeners"
  else
    echo "no listeners on 80/443"
  fi

  if command -v curl >/dev/null 2>&1; then
    echo "## local http"
    curl -sS -I http://127.0.0.1/ | head -n 10 || true
    echo "## local https"
    if echo "$listeners" | grep -q ':443\b'; then
      curl -sS -k -I https://127.0.0.1/ | head -n 10 || true
    else
      echo "https not listening on 443"
    fi
  fi

  echo "## apparmor"
  if command -v aa-status >/dev/null 2>&1; then
    if [ -n "$SUDO" ]; then
      $SUDO aa-status | head -n 8 || true
    else
      aa-status | head -n 8 || true
    fi
  fi

  if command -v ufw >/dev/null 2>&1; then
    echo "## ufw"
    $SUDO ufw status verbose || true
  fi
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
