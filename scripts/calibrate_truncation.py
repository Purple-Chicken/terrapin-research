#!/usr/bin/env python3
"""
Measures the first post-NEWKEYS server->client record's on-wire size for
a given (server, cipher, MAC) pairing, to fill in attack/truncation_profiles.py
for ciphers where the length field is NOT visible on the wire (chacha20-
poly1305@openssh.com; any cipher paired with a non-etm MAC).

Method: run this module's own handshake parser (attack/ssh_wire.py) up
through NEWKEYS on both sides, then read the s2c socket with a short
per-read timeout, logging EVERY individual recv() call's size separately
-- so a single server write() that arrives as one segment shows up as one
entry, and anything that gets split or coalesced by the kernel is visible
as such, instead of being silently hidden behind one big recv(65536).

This is a timing-boundary inference, not a protocol guarantee -- it
assumes a quiet link (nothing else contends for the connection) and
TCP_NODELAY (set on both legs here), the same assumption real Terrapin
tooling relies on for the blind half of prefix truncation. Run it at
least 3 times per pairing and only trust a number that's IDENTICAL across
all trials -- a number that varies trial to trial means the condition
isn't quiet enough to calibrate this way, and the --full-truncation path
for that pairing should stay un-confirmed rather than guess.

Usage:
    python3 scripts/calibrate_truncation.py --host 127.0.0.1 --port 2200 \\
        --ssh-user lab --password "$LAB_SSH_PASSWORD" \\
        --cipher chacha20-poly1305@openssh.com --trials 3

    # force a MAC too, for an *-etm@openssh.com comparison trial:
    python3 scripts/calibrate_truncation.py --host 127.0.0.1 --port 2200 \\
        --ssh-user lab --password "$LAB_SSH_PASSWORD" \\
        --cipher aes128-ctr --mac hmac-sha2-256-etm@openssh.com --trials 3

Requires a real `ssh` client and `sshpass` (or an --identity-file) able to
reach --host:--port directly -- point this at the real tp-server /
tp-server-patched containers (bypassing the router, since this measures
the TARGET's behavior, not the relay's). Prints a ready-to-paste
TruncationProfile entry once all trials agree.
"""

from __future__ import annotations

import argparse
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "attack"))
from ssh_wire import SSH_MSG_NEWKEYS, recv_plain_packet, recv_version_banner  # noqa: E402

IDLE_GAP_SECONDS = 0.08
MEASURE_WINDOW_SECONDS = 2.0


def run_one_trial(host: str, port: int, listen_port: int) -> tuple[bytes, int]:
    """Returns (server_banner, first_record_size). Blocks until a client
    connects through listen_port, so the caller must launch the ssh client
    concurrently (see main())."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", listen_port))
    listener.listen(1)
    listener.settimeout(15)
    client_sock, _ = listener.accept()
    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    server_sock = socket.create_connection((host, port), timeout=10)
    server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    client_banner = recv_version_banner(client_sock)
    server_sock.sendall(client_banner)
    server_banner = recv_version_banner(server_sock)
    client_sock.sendall(server_banner)

    newkeys_seen = {"c2s": False, "s2c": False}
    while not all(newkeys_seen.values()):
        if not newkeys_seen["c2s"]:
            pkt = recv_plain_packet(client_sock)
            server_sock.sendall(pkt.raw)
            if pkt.msg_type == SSH_MSG_NEWKEYS:
                newkeys_seen["c2s"] = True
        if not newkeys_seen["s2c"]:
            pkt = recv_plain_packet(server_sock)
            client_sock.sendall(pkt.raw)
            if pkt.msg_type == SSH_MSG_NEWKEYS:
                newkeys_seen["s2c"] = True

    server_sock.settimeout(IDLE_GAP_SECONDS)
    reads: list[bytes] = []
    deadline = time.monotonic() + MEASURE_WINDOW_SECONDS
    while time.monotonic() < deadline:
        try:
            chunk = server_sock.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            break
        reads.append(chunk)
        client_sock.sendall(chunk)

    # Drain the rest so the ssh client's command still completes normally.
    client_sock.settimeout(None)
    server_sock.settimeout(None)
    import threading

    def splice(a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except OSError:
            pass

    t1 = threading.Thread(target=splice, args=(client_sock, server_sock), daemon=True)
    t2 = threading.Thread(target=splice, args=(server_sock, client_sock), daemon=True)
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)

    if not reads:
        raise RuntimeError("no s2c data observed in the measurement window")
    if len(reads) > 1:
        print(
            f"  [calibrate] WARNING: {len(reads)} separate recv() calls observed, "
            f"not 1 -- link may not be quiet enough; sizes: {[len(r) for r in reads]}",
            file=sys.stderr,
        )
    return server_banner, len(reads[0])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cipher", required=True)
    parser.add_argument("--mac", default=None)
    parser.add_argument("--ssh-user", default="lab")
    parser.add_argument("--password", default=None)
    parser.add_argument("--identity-file", default=None)
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--listen-port", type=int, default=12399)
    args = parser.parse_args()

    if not args.password and not args.identity_file:
        parser.error("pass --password (uses sshpass) or --identity-file")

    sizes = []
    banner = b""
    for i in range(args.trials):
        print(f"[calibrate] trial {i + 1}/{args.trials}...", file=sys.stderr)
        ssh_cmd = [
            "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR",
            "-p", str(args.listen_port), "-c", args.cipher,
        ]
        if args.mac:
            ssh_cmd += ["-m", args.mac]
        if args.identity_file:
            ssh_cmd += ["-i", args.identity_file]
        ssh_cmd += [f"{args.ssh_user}@127.0.0.1", "--", f"echo calib-trial-{i}"]
        if args.password:
            ssh_cmd = ["sshpass", "-p", args.password] + ssh_cmd

        import threading
        result = {}

        def worker():
            result["banner"], result["size"] = run_one_trial(args.host, args.port, args.listen_port)

        th = threading.Thread(target=worker)
        th.start()
        time.sleep(0.3)
        subprocess.run(ssh_cmd, capture_output=True, timeout=15)
        th.join(timeout=10)

        if "size" not in result:
            print(f"  [calibrate] trial {i + 1} FAILED to capture a measurement", file=sys.stderr)
            continue
        sizes.append(result["size"])
        banner = result["banner"]
        print(f"  [calibrate] trial {i + 1}: first s2c record = {result['size']} bytes", file=sys.stderr)

    if not sizes:
        print("[calibrate] FAILED: no successful trials", file=sys.stderr)
        sys.exit(1)

    consistent = len(set(sizes)) == 1
    banner_text = banner.decode(errors="replace").strip()
    print(f"\n[calibrate] banner: {banner_text!r}")
    print(f"[calibrate] sizes across {len(sizes)} trial(s): {sizes}")
    if not consistent:
        print("[calibrate] INCONSISTENT -- do not trust this for a TruncationProfile; "
              "the link was not quiet enough or the server behaves non-deterministically here.")
        sys.exit(1)

    print(f"\n[calibrate] CONSISTENT: {sizes[0]} bytes across all {len(sizes)} trials.")
    print("Paste into attack/truncation_profiles.py's PROFILES dict:\n")
    banner_key = banner_text.split()[0] if banner_text else "UNKNOWN"
    print(f'    ("{banner_key}", "{args.cipher}"): TruncationProfile(')
    print(f"        first_message_bytes={sizes[0]},")
    print("        confirmed=True,")
    print(f'        source="measured via scripts/calibrate_truncation.py against {args.host}:{args.port}, '
          f'{len(sizes)}/{len(sizes)} identical trials",')
    print("    ),")


if __name__ == "__main__":
    main()
