#!/usr/bin/env bash
# Runs the designated "checkable trace" sanity check: inject one
# SSH_MSG_IGNORE into the client-bound stream before NEWKEYS, then attempt
# a normal SSH login + command through the router.
#
# Usage:
#   scripts/run_sanity_check.sh survive    # expects legacy (non-strict-kex) target
#   scripts/run_sanity_check.sh rejected   # expects strict-kex-enabled target
#
# This script assumes relay.py (or the router container) is ALREADY
# running in inject_ignore mode and reachable at 127.0.0.1:2222. It does
# not start docker-compose itself, so it can be reused identically for the
# docker-compose target and for a locally-run relay.py during development
# (see README.md "Local dev loop (no Docker)").
set -euo pipefail
cd "$(dirname "$0")/.."

EXPECT="${1:?usage: run_sanity_check.sh {survive|rejected}}"
LOG_FILE="${LOG_FILE:-logs/relay.jsonl}"

echo "[sanity] starting capture..."
./scripts/capture.sh start "sanity_ignore_injection_${EXPECT}"

echo "[sanity] attempting SSH connection through the router (127.0.0.1:2222)..."
set +e
OUTPUT="$(./scripts/connect.sh 127.0.0.1 2222 "echo OK" 2>&1)"
SSH_STATUS=$?
set -e

./scripts/capture.sh stop

echo "[sanity] ssh exit status: ${SSH_STATUS}"
echo "[sanity] ssh output: ${OUTPUT}"

echo "[sanity] checking relay log (${LOG_FILE}) against expectation '${EXPECT}'..."
python3 ./scripts/check_log.py "${LOG_FILE}" --expect "${EXPECT}"
CHECK_STATUS=$?

if [[ "${EXPECT}" == "survive" ]]; then
  if [[ "${SSH_STATUS}" -eq 0 && "${OUTPUT}" == "OK" && "${CHECK_STATUS}" -eq 0 ]]; then
    echo "[sanity] RESULT: PASS (handshake and auth survived the injected IGNORE)"
    exit 0
  fi
else
  if [[ "${SSH_STATUS}" -ne 0 && "${CHECK_STATUS}" -eq 0 ]]; then
    echo "[sanity] RESULT: PASS (connection was correctly rejected -- strict kex active)"
    exit 0
  fi
fi

echo "[sanity] RESULT: FAIL -- see output and ${LOG_FILE} above"
exit 1
