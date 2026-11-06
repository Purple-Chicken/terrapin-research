#!/usr/bin/env python3
"""
Verify a relay.jsonl trace against the expected outcome of the
IGNORE-injection sanity check.

Usage:
    check_log.py <relay.jsonl> --expect survive
    check_log.py <relay.jsonl> --expect rejected

  --expect survive   Exactly one SSH_MSG_IGNORE was injected, and the
                      handshake still completed (both sides reached
                      NEWKEYS, connection proceeded). This is the expected
                      result against a non-strict-kex (vulnerable) pairing.

  --expect rejected   Exactly one SSH_MSG_IGNORE was injected, and the
                      handshake subsequently failed/closed before
                      completing. This is the expected result against a
                      patched pairing that negotiated strict kex, and is
                      itself a valid, informative sanity-check outcome
                      (it demonstrates the countermeasure is active).

Exits 0 and prints PASS/FAIL plus a one-line summary either way; exits 1
only on FAIL or malformed input, so this is safe to use as a CI/script gate.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_records(path: Path) -> list[dict]:
    records = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def last_run(records: list[dict]) -> list[dict]:
    """Return only the records from the most recent relay_start onward."""
    start_indices = [i for i, r in enumerate(records) if r.get("event") == "relay_start"]
    if not start_indices:
        return records
    return records[start_indices[-1] :]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("log_file", type=Path)
    parser.add_argument("--expect", choices=["survive", "rejected"], required=True)
    args = parser.parse_args()

    if not args.log_file.exists():
        print(f"FAIL: log file not found: {args.log_file}")
        return 1

    all_records = load_records(args.log_file)
    records = last_run(all_records)

    injects = [r for r in records if r.get("event") == "inject" and r.get("msg_type") == 2]
    completed = [r for r in records if r.get("event") == "handshake_complete"]
    failed = [r for r in records if r.get("event") == "handshake_failed"]

    if len(injects) != 1:
        print(f"FAIL: expected exactly 1 injected SSH_MSG_IGNORE, found {len(injects)}")
        return 1

    if args.expect == "survive":
        if completed:
            print("PASS: 1 IGNORE injected; handshake completed (NEWKEYS both directions).")
            return 0
        print(f"FAIL: 1 IGNORE injected, but handshake did not complete. "
              f"handshake_failed entries: {len(failed)}")
        return 1

    # args.expect == "rejected"
    if failed and not completed:
        note = failed[-1].get("note", "")
        print(f"PASS: 1 IGNORE injected; handshake was rejected as expected ({note}).")
        return 0
    print(f"FAIL: 1 IGNORE injected, but handshake completed instead of being rejected "
          f"(completed={len(completed)}, failed={len(failed)}).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
