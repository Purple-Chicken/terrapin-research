#!/usr/bin/env bash
# Usage: scripts/connect.sh [host] [port] [remote-command]
# Connects through the router (default 127.0.0.1:2222) using the lab's
# disposable key, with host-key checking disabled since these are
# throwaway lab hosts rebuilt on every run.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${1:-127.0.0.1}"
PORT="${2:-2222}"
REMOTE_CMD="${3:-echo OK}"
KEY="${SSH_KEY:-keys/client_id_ed25519}"
USER="${SSH_USER:-labuser}"

ssh -i "${KEY}" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=10 \
    -o LogLevel=ERROR \
    -p "${PORT}" \
    "${USER}@${HOST}" -- "${REMOTE_CMD}"
