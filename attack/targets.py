#!/usr/bin/env python3
"""
Target registry for the bounded-contribution plan's "Breadth" item.

Addresses and ports are taken straight from the main-branch README/AGENTS.md
network table: tp-server (10.5.0.10, vulnerable pins) and tp-server-patched
(10.5.0.11, patched pins), each running four SSH-speaking daemons on fixed
ports under supervisord.

NOT INDEPENDENTLY VALIDATED against the real containers: this sandbox has
no Docker, so nothing in this file has been run against tp-server or
tp-server-patched directly -- only against a locally-installed real
OpenSSH 9.6p1 on an ad hoc port (see scripts/calibrate_truncation.py and
ATTACK_README.md). Addresses/ports below are transcribed from the repo's
own docs, not independently confirmed reachable from this sandbox.

  - openssh / dropbear / russh / gitea-ssh are real, already-defined
    services in docker-compose.yml on this branch. attack/ssh_wire.py's
    framing is protocol-generic (see its module docstring), so pointing
    the relay at any of these four ports should work unmodified -- but
    "should" is doing the work in that sentence until someone with Docker
    runs it.
  - podman-api is NOT yet a distinct service in docker-compose.yml.
    Podman's SSH remote API tunnels the Podman REST API over a normal SSH
    session (the client effectively runs `ssh user@host podman system
    service --time=0`), so it rides the SAME OpenSSH transport already
    being tested, on the SAME port 22, with the only difference being
    what's validated after the handshake succeeds. Modeled here as a
    distinct logical target (so it gets its own row in the results CSV,
    per the write-up's naming convention) that reuses openssh's host/port
    but swaps the post-handshake check. It requires `podman` installed in
    Dockerfile.server (it is not, yet) -- see ATTACK_README.md for the
    exact line to add.
"""

from __future__ import annotations

from dataclasses import dataclass

SERVERS = {
    "vulnerable": "10.5.0.10",  # tp-server
    "patched": "10.5.0.11",     # tp-server-patched
}


@dataclass(frozen=True)
class Target:
    name: str          # used verbatim in the logs/<target>_... filename
    port: int
    check_command: str  # command run over the resulting session to confirm it's live
    live: bool          # False = not actually deployed in docker-compose.yml yet
    note: str = ""


TARGETS: dict[str, Target] = {
    "openssh": Target("openssh", 22, "echo OK", live=True),
    "dropbear": Target("dropbear", 2222, "echo OK", live=True),
    "russh": Target("russh", 2223, "echo OK", live=True,
                     note="custom app; confirm its auth/exec semantics match plain exec before trusting check_command"),
    "gitea-ssh": Target("gitea-ssh", 2224, "echo OK", live=True,
                         note="Gitea's builtin SSH only accepts git operations for non-admin users; "
                              "`echo OK` likely needs replacing with a real git-upload-pack probe"),
    "podman-api": Target("podman-api", 22, "podman version", live=False,
                          note="rides the openssh target's transport; needs `podman` installed "
                               "in Dockerfile.server first (not done yet)"),
}


def resolve(target_name: str, server_name: str) -> tuple[str, int, Target]:
    if target_name not in TARGETS:
        raise KeyError(f"unknown target {target_name!r}; choices: {sorted(TARGETS)}")
    if server_name not in SERVERS:
        raise KeyError(f"unknown server {server_name!r}; choices: {sorted(SERVERS)}")
    target = TARGETS[target_name]
    return SERVERS[server_name], target.port, target
