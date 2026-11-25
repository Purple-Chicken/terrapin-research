#!/usr/bin/env python3
"""
Unit tests for the roadmap item 2 ("Full truncation") deletion logic in
attack/relay.py, exercised directly against a socketpair rather than a
live sshd (no Docker / no vulnerable OpenSSH build available in CI or
this sandbox -- see ATTACK_README.md).

The byte counts used as fixtures below (292, 308 total wire bytes; 272
payload, 16/32 trailing tag) are NOT invented -- they are exactly what
scripts/calibrate_truncation.py measured against a real, locally-built
OpenSSH 9.6p1 binary (see truncation_profiles.py's module docstring and
ATTACK_README.md "What's validated"). This test confirms
_delete_visible_length_record() consumes precisely that many bytes and
leaves the stream positioned at the next record's start -- i.e. it
re-validates the exact bug this calibration run caught (an earlier
version under-read by the tag/MAC length and would have desynced every
pairing using GCM or an *-etm@openssh.com MAC).

Run with: python3 -m pytest tests/test_truncation.py -v
       or: python3 tests/test_truncation.py   (falls back to plain asserts)
"""

from __future__ import annotations

import secrets
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "attack"))

from relay import _delete_fixed_length_record, _delete_visible_length_record  # noqa: E402
from truncation_profiles import trailing_tag_bytes  # noqa: E402


def _make_fake_record(payload_len: int, tag_len: int) -> bytes:
    """A syntactically-plausible fake ciphertext record: 4-byte length +
    payload_len bytes of 'ciphertext' + tag_len bytes of 'tag'. Content is
    random/meaningless -- this test only checks BYTE COUNTS are consumed
    correctly, not cryptographic correctness (the relay never decrypts)."""
    return struct.pack(">I", payload_len) + secrets.token_bytes(payload_len + tag_len)


def _sentinel_next_record() -> bytes:
    """A recognizable marker standing in for 'the next real record', so we
    can confirm the deletion didn't consume one byte too many or too few."""
    return b"NEXTRECORDSTARTSHERE"


class _NullLogger:
    def log(self, *a, **k):
        pass


def test_gcm_tag_consumed_fully():
    """Reproduces the real measurement: aes128-gcm@openssh.com, 272-byte
    payload, 16-byte GCM tag, 292 bytes total -- matches the calibration
    log exactly (4 + 272 + 16 = 292)."""
    a, b = socket.socketpair()
    record = _make_fake_record(payload_len=272, tag_len=16)
    assert len(record) == 292, "fixture should match the measured 292-byte GCM record"
    b.sendall(record + _sentinel_next_record())

    tag_bytes = trailing_tag_bytes("aes128-gcm@openssh.com", "")
    assert tag_bytes == 16

    _delete_visible_length_record(a, _NullLogger(), tag_bytes)

    remainder = a.recv(1024)
    assert remainder == _sentinel_next_record(), (
        f"expected the deletion to consume exactly the 292-byte record and leave the "
        f"sentinel untouched; got {remainder!r} instead -- an under/over-read would "
        f"show up here as truncated/missing or extra sentinel bytes."
    )
    a.close(); b.close()


def test_etm_mac_consumed_fully():
    """Reproduces the real measurement: aes128-ctr + hmac-sha2-256-etm,
    272-byte payload, 32-byte HMAC-SHA256 tag, 308 bytes total (4 + 272 +
    32 = 308) -- this is the exact pairing where the pre-fix version of
    _delete_visible_length_record under-read by 32 bytes."""
    a, b = socket.socketpair()
    record = _make_fake_record(payload_len=272, tag_len=32)
    assert len(record) == 308
    b.sendall(record + _sentinel_next_record())

    tag_bytes = trailing_tag_bytes("aes128-ctr", "hmac-sha2-256-etm@openssh.com")
    assert tag_bytes == 32

    _delete_visible_length_record(a, _NullLogger(), tag_bytes)

    remainder = a.recv(1024)
    assert remainder == _sentinel_next_record()
    a.close(); b.close()


def test_without_tag_fix_would_desync():
    """Negative control: confirms tag_bytes=0 (the OLD, buggy behavior)
    really does leave trailing tag bytes in the stream ahead of the next
    record -- i.e. that this was a real bug, not a hypothetical one."""
    a, b = socket.socketpair()
    record = _make_fake_record(payload_len=272, tag_len=32)
    b.sendall(record + _sentinel_next_record())

    _delete_visible_length_record(a, _NullLogger(), tag_bytes=0)  # old, buggy call

    remainder = a.recv(1024)
    assert remainder != _sentinel_next_record(), (
        "sanity check failed: with tag_bytes=0 the leftover 32 MAC bytes should "
        "precede the sentinel, proving the old code path desynced the stream"
    )
    assert remainder.endswith(_sentinel_next_record())
    assert len(remainder) == 32 + len(_sentinel_next_record())
    a.close(); b.close()


def test_fixed_length_deletion_matches_calibrated_chacha20_size():
    """scripts/calibrate_truncation.py measured OpenSSH 9.6p1's first
    post-NEWKEYS chacha20-poly1305@openssh.com s2c record at 284 bytes,
    3/3 identical trials. Confirms the fixed-byte deletion path consumes
    exactly that many bytes when given that profile value."""
    a, b = socket.socketpair()
    fake_284_byte_record = secrets.token_bytes(284)
    b.sendall(fake_284_byte_record + _sentinel_next_record())

    _delete_fixed_length_record(a, _NullLogger(), 284)

    remainder = a.recv(1024)
    assert remainder == _sentinel_next_record()
    a.close(); b.close()


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"PASS: {t.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL: {t.__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    sys.exit(1 if failures else 0)
