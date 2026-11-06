#!/usr/bin/env bash
# Usage:
#   scripts/capture.sh start <label>   -- begin a background tcpdump, tagged
#                                          with <label>, on the router's
#                                          published port
#   scripts/capture.sh stop            -- stop the most recently started capture
#
# Pcaps land in ./pcaps/<label>_<timestamp>.pcap
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p pcaps

PIDFILE=".capture.pid"
IFACE="${CAPTURE_IFACE:-lo}"
PORT="${CAPTURE_PORT:-2222}"

case "${1:-}" in
  start)
    label="${2:-capture}"
    ts="$(date +%Y%m%d_%H%M%S)"
    outfile="pcaps/${label}_${ts}.pcap"
    echo "[capture] starting tcpdump on ${IFACE}:${PORT} -> ${outfile}"
    tcpdump -i "${IFACE}" -w "${outfile}" "port ${PORT}" >/tmp/capture.log 2>&1 &
    echo $! > "${PIDFILE}"
    echo "${outfile}" > .capture.lastfile
    sleep 1  # give tcpdump a moment to attach before traffic starts
    ;;
  stop)
    if [[ -f "${PIDFILE}" ]]; then
      pid="$(cat "${PIDFILE}")"
      kill "${pid}" 2>/dev/null || true
      rm -f "${PIDFILE}"
      echo "[capture] stopped. Saved to $(cat .capture.lastfile 2>/dev/null || echo '<unknown>')"
    else
      echo "[capture] no active capture pidfile found."
    fi
    ;;
  *)
    echo "usage: $0 {start <label>|stop}" >&2
    exit 1
    ;;
esac
