#!/usr/bin/env python3
"""
Roadmap item 5, "Detection": a passive detector fingerprinting the
handshake anomaly this project's own injection module produces.

The fingerprint: an SSH_MSG_IGNORE (or SSH_MSG_UNIMPLEMENTED/DEBUG --
anything other than KEXINIT, the Diffie-Hellman exchange messages, or
NEWKEYS) arriving BEFORE the first SSH_MSG_NEWKEYS has been observed in
BOTH directions of a session. In a legitimate RFC 4253 handshake, nothing
of that kind is sent during the initial key exchange -- it's not part of
any real client or server's negotiation flow, patched or not. A patched
(strict-kex) peer treats exactly this as a protocol violation and closes
the connection; this detector flags the SAME condition passively, from
the wire, independent of whether the peer being attacked is patched or
not -- so it's useful precisely against a VULNERABLE pairing, which
tolerates the injection silently and gives no other signal.

This mirrors what attack/relay.py itself does when deciding to inject
(attack/ssh_wire.py's msg_type parsing) -- same framing code, read-only,
applied to observed traffic instead of traffic this tool controls.

Two input modes:
  --live HOST:PORT    passively relay/observe a live TCP session (for a
                       transparent/mirrored tap, not a MitM -- see
                       "Known gaps" in ATTACK_README.md: this mode
                       currently requires being inline, like relay.py,
                       because this sandbox could not get a true passive
                       SPAN/mirror port working; a real deployment would
                       feed it from a network tap or mirrored switch port
                       instead)
  --pcap FILE          read packets from a pcap file (NOT validated in
                       this sandbox -- see below)

VALIDATED in this sandbox: the core classification logic
(classify_handshake()), via tests/test_detector.py, against synthetic
benign and IGNORE-injected byte streams built with the exact same
ssh_wire.py framing helpers attack/relay.py uses -- not against a real
pcap or a real live capture. Raw packet capture (tcpdump) produced 0
captured packets in this sandbox despite matching 80 packets by its own
BPF filter (see ATTACK_README.md "Known gaps"), so neither --pcap nor
a genuinely passive --live mode could be exercised here end-to-end.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "attack"))
from ssh_wire import (  # noqa: E402
    SSH_MSG_KEXINIT,
    SSH_MSG_NEWKEYS,
    ConnectionClosed,
    msg_name,
    recv_plain_packet,
    recv_version_banner,
)

# RFC 4253 messages legitimately seen during the (patched or unpatched)
# initial key exchange, before NEWKEYS. Anything NOT in this set, seen
# before NEWKEYS has completed in both directions, is the anomaly.
# 30/31/32/33/34 cover the DH/DH-GEX/ECDH/GSS key-exchange-specific
# message range (RFC 4253 s8, RFC 4419, RFC 5656) -- implementation
# dependent on which KEX method was negotiated, so this is deliberately
# permissive about exact sub-type and only excludes the known-anomalous
# ones (IGNORE=2, UNIMPLEMENTED=3, DEBUG=4).
EXPECTED_PRE_NEWKEYS_RANGE = set(range(30, 50)) | {SSH_MSG_KEXINIT, SSH_MSG_NEWKEYS}
ANOMALOUS_MSG_TYPES = {2: "SSH_MSG_IGNORE", 3: "SSH_MSG_UNIMPLEMENTED", 4: "SSH_MSG_DEBUG"}


def classify_handshake(events: list[dict]) -> dict:
    """events: a list of {'direction': 'c2s'|'s2c', 'msg_type': int} dicts,
    in the order observed. Returns a verdict dict; does not care how the
    events were produced (live socket read, pcap replay, or a trace file)."""
    newkeys_seen = {"c2s": False, "s2c": False}
    anomalies = []
    for ev in events:
        direction = ev["direction"]
        msg_type = ev["msg_type"]
        if msg_type == SSH_MSG_NEWKEYS:
            newkeys_seen[direction] = True
            continue
        if all(newkeys_seen.values()):
            continue  # post-handshake ciphertext; nothing more to check
        if msg_type in ANOMALOUS_MSG_TYPES:
            anomalies.append({"direction": direction, "msg_type": msg_type,
                               "msg_name": ANOMALOUS_MSG_TYPES[msg_type]})

    return {
        "verdict": "SUSPECTED_TERRAPIN_INJECTION" if anomalies else "CLEAN",
        "anomalies": anomalies,
        "newkeys_seen": newkeys_seen,
    }


def observe_live_session(host: str, port: int, listen_port: int, timeout: float = 30.0) -> list[dict]:
    """Inline tap (see module docstring's caveat: this sandbox could not
    get a true passive mirror working, so this still sits inline like
    relay.py, just without modifying anything -- a transparent observer,
    not a MitM)."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", listen_port))
    listener.listen(1)
    listener.settimeout(timeout)
    client_sock, _ = listener.accept()
    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    server_sock = socket.create_connection((host, port), timeout=10)
    server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    client_banner = recv_version_banner(client_sock)
    server_sock.sendall(client_banner)
    server_banner = recv_version_banner(server_sock)
    client_sock.sendall(server_banner)

    events = []
    newkeys_seen = {"c2s": False, "s2c": False}
    try:
        while not all(newkeys_seen.values()):
            if not newkeys_seen["c2s"]:
                pkt = recv_plain_packet(client_sock)
                server_sock.sendall(pkt.raw)
                events.append({"direction": "c2s", "msg_type": pkt.msg_type})
                if pkt.msg_type == SSH_MSG_NEWKEYS:
                    newkeys_seen["c2s"] = True
            if not newkeys_seen["s2c"]:
                pkt = recv_plain_packet(server_sock)
                client_sock.sendall(pkt.raw)
                events.append({"direction": "s2c", "msg_type": pkt.msg_type})
                if pkt.msg_type == SSH_MSG_NEWKEYS:
                    newkeys_seen["s2c"] = True
    except ConnectionClosed:
        pass

    # hand off the rest of the session unmodified
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
    t1.join(timeout=10)
    t2.join(timeout=10)
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--live", metavar="HOST:PORT", help="observe one live session inline")
    parser.add_argument("--listen-port", type=int, default=12290)
    parser.add_argument("--pcap", type=Path, help="NOT YET IMPLEMENTED -- no pcap parser wired up; "
                         "see ATTACK_README.md Known gaps")
    args = parser.parse_args()

    if args.pcap:
        print("[detect] --pcap is not implemented in this sandbox (raw capture was unavailable "
              "to produce a test pcap against) -- see ATTACK_README.md. Use --live instead.",
              file=sys.stderr)
        sys.exit(2)

    if not args.live:
        parser.error("pass --live HOST:PORT (or see --pcap's current limitation)")

    host, port_str = args.live.rsplit(":", 1)
    events = observe_live_session(host, int(port_str), args.listen_port)
    verdict = classify_handshake(events)
    print(json.dumps(verdict, indent=2))
    sys.exit(0 if verdict["verdict"] == "CLEAN" else 1)


if __name__ == "__main__":
    main()
