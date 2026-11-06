#!/usr/bin/env python3
"""Minimal paramiko-based SSH client, used as a second, independently
implemented client stack to test the relay's injection primitive against
(OpenSSH's client enforces some hardening unconditionally on the receive
side as of 9.6; this checks whether a differently-implemented client
behaves the same way)."""
import sys

import paramiko

host, port, keyfile = sys.argv[1], int(sys.argv[2]), sys.argv[3]

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
pkey = paramiko.Ed25519Key.from_private_key_file(keyfile)
try:
    client.connect(host, port=port, username="root", pkey=pkey, timeout=10, banner_timeout=10)
    stdin, stdout, stderr = client.exec_command("echo OK")
    out = stdout.read().decode()
    print("OUTPUT:", out.strip())
    client.close()
    sys.exit(0 if out.strip() == "OK" else 1)
except Exception as exc:
    print("ERROR:", repr(exc))
    sys.exit(1)
