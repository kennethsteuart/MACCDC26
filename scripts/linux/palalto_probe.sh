#!/usr/bin/env bash
# Palo Alto probe wrapper (read-only).

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: palo_alto_probe.sh --host <ip> [--summary] [--user <user>] [--pass <pass>] [--key <api_key>] [--secure]
USAGE
}

MODE="list"
ARGS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --host|--user|--pass|--key|--backup-dir|--restore-from)
      ARGS+=("$1" "$2")
      shift 2
      ;;
    --summary)
      MODE="summary"
      shift
      ;;
    --full)
      MODE="list"
      shift
      ;;
    --secure)
      ARGS+=("--secure")
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

exec "$(dirname "$0")/../firewalls/palo_alto_manage.sh" --mode "$MODE" "${ARGS[@]}"
