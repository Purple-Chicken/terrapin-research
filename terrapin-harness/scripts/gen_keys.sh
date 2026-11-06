#!/usr/bin/env bash
# Generates a disposable Ed25519 keypair for the lab client, used for
# pubkey auth against every target. Re-run is safe: it will not overwrite
# an existing key.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p keys
if [[ -f keys/client_id_ed25519 ]]; then
    echo "[gen_keys] keys/client_id_ed25519 already exists, leaving it alone."
    exit 0
fi

ssh-keygen -t ed25519 -N "" -C "terrapin-lab-client" -f keys/client_id_ed25519
chmod 600 keys/client_id_ed25519
echo "[gen_keys] wrote keys/client_id_ed25519{,.pub}"
