#!/usr/bin/env python3
"""
Roadmap item 4, "Negative control": rerun each target in its patched/
strict-kex build and confirm rejection, the way OpenSSH's pairing already
was (project write-up, Section 2).

This is a thin loop over attack/cli.py --server patched for every target
in attack/targets.py, followed by scripts/check_log.py --expect rejected
against the resulting trial log. It does not touch the vulnerable server
at all -- that side is what the harness branch's scenarios already cover;
this script is specifically "does the fix still hold once you widen the
target list," not "does the attack still work."

Only openssh has actually been confirmed this way, twice over: once on
the harness branch against a from-source 9.5p1/9.6p1 pair, and again in
this sandbox against a real local OpenSSH 9.6p1 (see ATTACK_README.md).
dropbear / russh / gitea-ssh are new as of this roadmap and their
strict-kex support has NOT been separately confirmed -- Dropbear and
Gitea's Go ssh implementation each shipped their own strict-kex fixes
independently of OpenSSH's, on their own timelines, so "patched" for the
server bundle as a whole does not guarantee every daemon inside it
actually negotiates strict-kex. That's exactly what this script exists to
check, not assume.

Usage:
    python3 scripts/negative_control.py --identity-file keys/client_id_ed25519
    python3 scripts/negative_control.py --dry-run     # see the commands only
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CLI_PY = REPO_ROOT / "attack" / "cli.py"
CHECK_LOG_PY = REPO_ROOT / "scripts" / "check_log.py"

TARGETS_TO_CHECK = ["openssh", "dropbear", "russh", "gitea-ssh"]  # podman-api excluded: not deployed yet


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--identity-file", default=None)
    parser.add_argument("--use-sshpass", action="store_true")
    parser.add_argument("--sshpass-password", default=None)
    parser.add_argument("--log-dir", type=Path, default=REPO_ROOT / "logs")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not args.dry_run and not args.identity_file and not args.use_sshpass:
        parser.error("pass --identity-file or --use-sshpass (or --dry-run to preview)")

    results: dict[str, bool | None] = {}

    for target in TARGETS_TO_CHECK:
        cli_cmd = [
            sys.executable, str(CLI_PY),
            "--target", target,
            "--server", "patched",
            "--mode", "inject_ignore",
            "--trials", "1",
            "--log-dir", str(args.log_dir),
        ]
        if args.identity_file:
            cli_cmd += ["--identity-file", args.identity_file]
        if args.use_sshpass:
            cli_cmd.append("--use-sshpass")
            if args.sshpass_password:
                cli_cmd += ["--sshpass-password", args.sshpass_password]
        if args.dry_run:
            cli_cmd.append("--dry-run")

        print(f"\n### negative control: {target} (patched) ###")
        print(" ", " ".join(cli_cmd))
        if args.dry_run:
            results[target] = None
            continue

        subprocess.run(cli_cmd, check=False)

        matches = sorted(args.log_dir.glob(f"{target}_*_patched_auto_trial*.jsonl"))
        if not matches:
            print(f"  [negative_control] no log produced for {target}; treating as FAIL")
            results[target] = False
            continue
        latest_log = matches[-1]
        check = subprocess.run(
            [sys.executable, str(CHECK_LOG_PY), str(latest_log), "--expect", "rejected"],
            capture_output=True, text=True,
        )
        print(f"  {check.stdout.strip()}")
        results[target] = check.returncode == 0

    if args.dry_run:
        print("\n[negative_control] dry-run only; nothing was executed")
        return

    print("\n=== negative control summary (patched server, strict-kex should reject) ===")
    for target, ok in results.items():
        status = "PASS (rejected, as expected)" if ok else "FAIL (did not reject -- check the trace)"
        print(f"  {target:12s} {status}")

    if not all(results.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()
