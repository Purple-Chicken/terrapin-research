#!/usr/bin/env python3
"""
Unit tests for detect/terrapin_detector.py's classify_handshake(), using
synthetic event sequences (same shape observe_live_session() produces).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "detect"))
sys.path.insert(0, str(Path(__file__).parent.parent / "attack"))

from terrapin_detector import classify_handshake  # noqa: E402
from ssh_wire import SSH_MSG_KEXINIT, SSH_MSG_NEWKEYS  # noqa: E402

DH_INIT, DH_REPLY = 30, 31


def test_clean_handshake_not_flagged():
    events = [
        {"direction": "c2s", "msg_type": SSH_MSG_KEXINIT},
        {"direction": "s2c", "msg_type": SSH_MSG_KEXINIT},
        {"direction": "c2s", "msg_type": DH_INIT},
        {"direction": "s2c", "msg_type": DH_REPLY},
        {"direction": "c2s", "msg_type": SSH_MSG_NEWKEYS},
        {"direction": "s2c", "msg_type": SSH_MSG_NEWKEYS},
    ]
    verdict = classify_handshake(events)
    assert verdict["verdict"] == "CLEAN", verdict
    assert verdict["anomalies"] == []


def test_injected_ignore_before_newkeys_is_flagged():
    """Reproduces exactly what attack/relay.py's inject_ignore mode does:
    one SSH_MSG_IGNORE (type 2) sent router_to_client (s2c, from the
    victim client's point of view) between KEXINIT and NEWKEYS."""
    events = [
        {"direction": "c2s", "msg_type": SSH_MSG_KEXINIT},
        {"direction": "s2c", "msg_type": SSH_MSG_KEXINIT},
        {"direction": "s2c", "msg_type": 2},  # SSH_MSG_IGNORE, injected
        {"direction": "c2s", "msg_type": DH_INIT},
        {"direction": "s2c", "msg_type": DH_REPLY},
        {"direction": "c2s", "msg_type": SSH_MSG_NEWKEYS},
        {"direction": "s2c", "msg_type": SSH_MSG_NEWKEYS},
    ]
    verdict = classify_handshake(events)
    assert verdict["verdict"] == "SUSPECTED_TERRAPIN_INJECTION", verdict
    assert len(verdict["anomalies"]) == 1
    assert verdict["anomalies"][0]["msg_name"] == "SSH_MSG_IGNORE"


def test_multiple_injected_ignores_all_flagged():
    """--message-count 3 (roadmap item 3) should surface as 3 anomalies."""
    events = [
        {"direction": "c2s", "msg_type": SSH_MSG_KEXINIT},
        {"direction": "s2c", "msg_type": SSH_MSG_KEXINIT},
        {"direction": "s2c", "msg_type": 2},
        {"direction": "s2c", "msg_type": 2},
        {"direction": "s2c", "msg_type": 2},
        {"direction": "c2s", "msg_type": SSH_MSG_NEWKEYS},
        {"direction": "s2c", "msg_type": SSH_MSG_NEWKEYS},
    ]
    verdict = classify_handshake(events)
    assert verdict["verdict"] == "SUSPECTED_TERRAPIN_INJECTION"
    assert len(verdict["anomalies"]) == 3


def test_ignore_after_newkeys_not_flagged():
    """Post-handshake IGNORE keepalives are completely normal (many real
    clients send them); only PRE-NEWKEYS anomalies are the fingerprint."""
    events = [
        {"direction": "c2s", "msg_type": SSH_MSG_KEXINIT},
        {"direction": "s2c", "msg_type": SSH_MSG_KEXINIT},
        {"direction": "c2s", "msg_type": DH_INIT},
        {"direction": "s2c", "msg_type": DH_REPLY},
        {"direction": "c2s", "msg_type": SSH_MSG_NEWKEYS},
        {"direction": "s2c", "msg_type": SSH_MSG_NEWKEYS},
        {"direction": "s2c", "msg_type": 2},  # post-NEWKEYS keepalive, benign
    ]
    verdict = classify_handshake(events)
    assert verdict["verdict"] == "CLEAN", verdict


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
