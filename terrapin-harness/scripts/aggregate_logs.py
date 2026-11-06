#!/usr/bin/env python3
"""
Aggregate per-trial logs under logs/<target>/trial_*.jsonl into one results
CSV, matching the experimental protocol's target x cipher x patched x
manual/automated matrix.

Usage:
    python3 scripts/aggregate_logs.py logs/ --out results/summary.csv

Expects each trial log's filename (or a sibling trial.json metadata file,
if present) to encode: target, cipher, patched (true/false), mode
(manual/automated). See README.md "Experimental protocol and logs".
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path

OUTCOME_EVENTS = {"handshake_complete": "success", "handshake_failed": "blocked"}

# Expected filename shape: <target>_<cipher>_<patched|vulnerable>_<manual|auto>_trialNN.jsonl
FNAME_RE = re.compile(
    r"(?P<target>[a-zA-Z0-9]+)_(?P<cipher>[a-zA-Z0-9\-]+)_(?P<patch_state>patched|vulnerable)_"
    r"(?P<mode>manual|auto)_trial(?P<trial>\d+)\.jsonl$"
)


def classify(records: list[dict]) -> str:
    for r in records:
        if r.get("event") in OUTCOME_EVENTS:
            return OUTCOME_EVENTS[r["event"]]
    return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("logs_dir", type=Path)
    parser.add_argument("--out", type=Path, default=Path("results/summary.csv"))
    args = parser.parse_args()

    rows = []
    for log_path in sorted(args.logs_dir.rglob("*.jsonl")):
        match = FNAME_RE.search(log_path.name)
        if not match:
            print(f"[aggregate] skipping unrecognized filename: {log_path.name}")
            continue
        with open(log_path) as fh:
            records = [json.loads(line) for line in fh if line.strip()]
        outcome = classify(records)
        rows.append(
            {
                "target": match["target"],
                "cipher": match["cipher"],
                "patch_state": match["patch_state"],
                "mode": match["mode"],
                "trial": match["trial"],
                "outcome": outcome,
                "log_file": str(log_path),
            }
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["target", "cipher", "patch_state", "mode", "trial", "outcome", "log_file"]
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"[aggregate] wrote {len(rows)} trial rows to {args.out}")

    # Quick per-(target, cipher, patch_state, mode) success-rate summary.
    from collections import defaultdict

    groups: dict[tuple, list[str]] = defaultdict(list)
    for row in rows:
        key = (row["target"], row["cipher"], row["patch_state"], row["mode"])
        groups[key].append(row["outcome"])

    print("\n[aggregate] success rate by condition:")
    for key, outcomes in sorted(groups.items()):
        n = len(outcomes)
        successes = outcomes.count("success")
        print(f"  {key}: {successes}/{n} success")


if __name__ == "__main__":
    main()
