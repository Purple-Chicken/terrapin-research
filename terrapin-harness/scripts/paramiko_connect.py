#!/usr/bin/env python3
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
