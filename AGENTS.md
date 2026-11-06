# AGENTS.md — Security Research & Lab Guide

## 1. Project Overview & Scope

This repository contains a containerized research environment designed to analyze **Terrapin (CVE-2023-48795)**—a prefix truncation attack targeting the SSH binary packet protocol (BPP)—across multiple independent SSH implementations.

### Purpose & Ethics Disclaimer
* **Primary Objective:** Academic research, protocol testing, and defensive vulnerability scanning.
* **Scope:** Restricted strictly to the local container network (`10.5.0.0/24`).
* **Environment:** Docker Compose lab on bridge `tp_net` (`10.5.0.0/24`). The bridge is open during network testing. Publishing each host as a reproducible image, and closing the bridge, is deferred until the final report.
* **Authorization:** Explicitly authorized sandbox environment for academic paper evaluation.

`README.md` is the operator document. Container names and the Bullseye client in the README override any older description. This file matches that lab as of the pinned-image work on `cursor/pin-vulnerable-lab-7b2a`.

---

## 2. Environment Network Topology

Four containers share the open Docker bridge `tp_net`. Compose does not publish host ports. Reach the services from another container on `10.5.0.0/24`.

```
 tp-client (10.5.0.30)     tp-attack (10.5.0.20)     tp-server-patched (10.5.0.11)     tp-server (10.5.0.10)
 Bullseye OpenSSH client   Kali tools on start       strict-kex fixes                  pre-strict-kex builds
 russh-client 0.40.1                                 same four SSH services            OpenSSH, Dropbear, russh, Gitea
```

### Host Details

| Compose service | Container | Image | Address | Role |
| :--- | :--- | :--- | :--- | :--- |
| `target-server` | `tp-server` | `tp-server:vulnerable` | `10.5.0.10` | Vulnerable multi-SSH server |
| `target-server-patched` | `tp-server-patched` | `tp-server:patched` | `10.5.0.11` | Same services with the strict-kex fixes |
| `attacker-kali` | `tp-attack` | `kalilinux/kali-rolling` | `10.5.0.20` | `NET_ADMIN` and `NET_RAW`. Packages install on start, then the container stays up |
| `ssh-client` | `tp-client` | `tp-client:vulnerable` | `10.5.0.30` | Vulnerable client |

`tp-attack` installs `dsniff`, `tcpdump`, `python3`, `python3-pip`, `git`, `net-tools`, `iproute2`, and `iputils-ping` at container start. That image is not pinned.

`tp-client` contains the Bullseye OpenSSH client, Git, `rsync`, `curl`, and `/usr/local/bin/russh-client`. It does not contain a Rust toolchain. `CMD` is `sleep infinity`.

Both servers listen on the same ports:

| Port | Service |
| :--- | :--- |
| `22` | OpenSSH (`sshd -D -e`) |
| `2222` | Dropbear (`-F -E`) |
| `2223` | `russh-server` |
| `2224` | Gitea built-in SSH |
| `3000` | Gitea HTTP |

Shells: `docker exec -it tp-server /bin/sh`, `docker exec -it tp-server-patched /bin/sh`, `docker exec -it tp-attack /bin/bash`, `docker exec -it tp-client /bin/bash`.

---

## 3. SSH Implementation Matrix

`tp-server` and `tp-server-patched` each run four SSH daemons under `supervisord` (`lab/supervisord.conf`). `gitea-seed` runs once after Gitea answers `/api/healthz`.

| Service | Daemon | Language | Port | Vulnerable pin | Patched pin |
| :--- | :--- | :--- | :--- | :--- | :--- |
| System SSH | OpenSSH | C | `22` | `1:9.2p1-2+deb12u1` | `1:9.2p1-2+deb12u2` |
| Dropbear | Dropbear | C | `2222` | `2022.83-1` | `2022.83-1+deb12u1` |
| Custom app | `russh-server` | Rust | `2223` | russh `0.40.1` | russh `0.40.2` |
| Gitea | Built-in Go SSH | Go (`golang.org/x/crypto/ssh`) | `2224` | Gitea `1.21.0` | Gitea `1.21.3` |

The Terrapin-affected algorithm families called out for later scanning are `chacha20-poly1305@openssh.com` and `*-etm@openssh.com` when strict key exchange is absent. The algorithm names are `kex-strict-c-v00@openssh.com` and `kex-strict-s-v00@openssh.com`. Strict key exchange is negotiated only when both peers advertise it.

The client image is the pre-fix Bullseye client, so a session from `tp-client` to `tp-server-patched` still completes without strict key exchange. `tp-server-patched` is the control image. Its `/usr/local/bin/russh-client` is built with russh `0.40.2`. The client container's `russh-client` stays on `0.40.1`. There is no patched OpenSSH client container yet.

---

## 4. Software Versions & Components

Current Bookworm and Bullseye apt already contain the Terrapin backport without bumping the upstream version number. The images therefore install from `snapshot.debian.org` and do not enable `debian-security` on the vulnerable pin.

| Role | Base | Snapshot | OpenSSH | Dropbear | Gitea | russh |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Vulnerable server | `debian:bookworm-slim` | bookworm `20231115T000000Z` | `1:9.2p1-2+deb12u1` | `2022.83-1` | `1.21.0` | `0.40.1` |
| Patched server | `debian:bookworm-slim` | bookworm `20240215T000000Z` | `1:9.2p1-2+deb12u2` | `2022.83-1+deb12u1` | `1.21.3` | `0.40.2` |
| Client | `debian:bullseye-slim` | bullseye `20231115T000000Z` | `1:8.4p1-5+deb11u2` | — | — | client `0.40.1` |

Gitea linux-amd64 SHA256 values checked in `Dockerfile.server`:

* `1.21.0`: `ff8aecf97f66f4a3ec55532f26716612457738b93f5f667124fdd6c59fddd735`
* `1.21.3`: `ccf6cc2077401e382bca0d000553a781a42c9103656bd33ef32bf093cca570eb`

The Gitea binary is downloaded in a current Debian stage. The snapshot stages do not fetch it, because snapshot CA material can be expired.

Apt details that the Dockerfiles rely on:

* Snapshot `Release` files are past `Valid-Until`, so apt uses `Acquire::Check-Valid-Until "false"` and `deb [check-valid-until=no]`.
* `snapshot.debian.org` often returns `503 No healthy backends` while the timestamped archive is still published. `apt-get update` exits 0 anyway, and the next install then reports every package as missing. The Dockerfiles treat that as failure: they retry until `apt-cache madison` shows the pinned OpenSSH version, then retry `apt-get install` when a deb download fails. Build one Compose service at a time so the three images do not hit the CDN together.
* The current slim images ship a newer `perl-base` than those snapshots. A pin of `snapshot.debian.org` at priority `1001`, plus `--allow-downgrades`, is what allows apt to install the snapshot's Perl.
* OpenSSH and Dropbear packages are held. The image build greps the binaries: vulnerable images must not contain `kex-strict`; the patched image must contain `kex-strict-s-v00@openssh.com` in both `/usr/sbin/sshd` and `/usr/sbin/dropbear`.
* `/etc/lab-release` records the role and the pins.

Rust builder is `rust:1.83-slim`. `russh-project/Cargo.toml` caps `base64ct`, `tokio`, `tokio-util`, and `zeroize` so the graph stays on crates that Rust 1.83 accepts. `Cargo.lock` is the source of truth for the 0.40.1 build. The patched image rewrites the `russh` pin to `0.40.2` and runs `cargo update -p russh --precise 0.40.2`. `russh-keys` stays `0.40.1` on both. `RUSSH_CRATE_VERSION` is compiled into the binary.

The Compose file has no top-level `version` key. Compose v2 treats that key as obsolete.

Lab password, also `LAB_SSH_PASSWORD` in the server and client images: `TerrapinTest123!`.

---

## 5. Repository Layout

```
Dockerfile.server          vulnerable and patched server, selected by build args
Dockerfile.client          Bullseye client
docker-compose.yml         tp_net and the four services
russh-project/             russh client and server crate, lockfile committed
  src/lib.rs               password and authorized_keys helpers
  src/bin/russh-server.rs
  src/bin/russh-client.rs
lab/entrypoint.sh          users, host keys, Gitea admin user, then supervisord
lab/gitea-seed.sh          private repo lab/russh-project, optional lab.pub
lab/gitea/app.ini          HTTP 3000, builtin SSH 2224, sqlite, registration off
lab/supervisord.conf
lab/sshd_lab.conf          PermitRootLogin and password auth for the lab
notes/*_commands.sh        connectivity checks; not copied into the images
README.md
```

`scanner/`, `poc/`, and `docs/` do not exist yet.

`russh-project` is the custom SSH client and server. It is not a Gitea checkout. The Gitea repository of the same name is created empty (`auto_init`) on boot so a later pubkey clone has a target. The crate source is not pushed into Gitea.

---

## 6. Accounts, Keys, and Authentication

SSH user keys for the client, the servers, and the attacker have not been generated. Do not generate them until that step is requested. Host keys are created on first boot and stay in the container filesystem:

* OpenSSH: `ssh-keygen -A`
* Dropbear: ed25519, ecdsa, and RSA 2048 under `/etc/dropbear/`
* russh: PKCS8 ed25519 at `/etc/russh/ssh_host_ed25519_key` when the file is missing

Unix users `root` and `lab` exist on both servers and use the lab password. OpenSSH (`lab/sshd_lab.conf`) allows root login and password authentication, and disables keyboard-interactive authentication. Dropbear uses those same unix accounts.

`russh-server` accepts the lab password only for `root` and `lab`. It reads an optional OpenSSH `authorized_keys` file from `/etc/russh/authorized_keys` (`RUSSH_AUTHORIZED_KEYS`). It does not read `~/.ssh/authorized_keys`. The password comes from `--password`, then `RUSSH_PASSWORD`, then `LAB_SSH_PASSWORD`. Default listen address is `0.0.0.0:2223`.

`russh-client` runs one remote command (`--` then the command). `--target HOST:PORT` or a positional target, `--user` default `lab`, `--password` or `LAB_SSH_PASSWORD`, optional `--key` for publickey auth. It accepts any host key and logs that `known_hosts` is not enabled yet. That check is a lab stand-in until host keys are distributed.

Gitea user `lab` (`lab@example.local`) is a Gitea account, separate from the unix user `lab`. The entrypoint creates it and sets the lab password. Registration is disabled. The seed creates private repository `lab/russh-project`. If `/etc/gitea/lab.pub` exists at seed time, that public key is installed on the Gitea user. The file is not in the image.

Clone URL once a key exists: `ssh://git@10.5.0.10:2224/lab/russh-project.git` (patched twin: `10.5.0.11`). The SSH login name is `git`, which is Gitea's builtin SSH user. The key belongs to Gitea user `lab`.

Three key stores stay separate:

| Service | Where a later public key goes |
| :--- | :--- |
| OpenSSH and Dropbear | unix `authorized_keys` for `lab` or `root` |
| russh | `/etc/russh/authorized_keys` |
| Gitea | `/etc/gitea/lab.pub` before `gitea-seed`, or the Gitea user-key API |

---

## 7. What Is Implemented

* Pinned Dockerfiles and Compose services for the vulnerable server, the patched twin, the Bullseye client, and the Kali attacker.
* `russh-project` client and server on russh 0.40.1, with unit tests for the password rule and `authorized_keys` parsing. A local exec against `127.0.0.1` succeeded before the image work. The patched image rebuilds the same programs at russh 0.40.2.
* Server entrypoint, supervisor programs, Gitea config, and the private-repo seed.
* Connectivity notes in `notes/`.
* `tp-client:vulnerable` built successfully. Its OpenSSH binary check found no `kex-strict` string.

## 8. What Is Not Done

* `tp-server:vulnerable` and `tp-server:patched` have not been produced. The last `docker compose build` lost the vulnerable server's `apt-get install` to `snapshot.debian.org` 503/504 responses (`libfido2`, `krb5`, `procps`, `openssh-server`, `net-tools`, and others). Compose stopped the patched server on that failure. Neither server has been booted, so sshd, Dropbear, russh-in-container, Gitea health, and the seed are untested at runtime.
* No SSH user keys, so OpenSSH, Dropbear, and Gitea pubkey login are not configured. Password login to OpenSSH and Dropbear is implemented and untested in the containers.
* No patched OpenSSH client. Strict key exchange cannot be observed on a live session with the current `tp-client`.
* `scanner/`, `docs/`, and the sequence-number proxy in `poc/` are not started. Do not add the proxy, a Metasploit module, or an interception procedure unless that work is explicitly requested. The network test below is connectivity only.
* Images are local build products. They are not published, and `tp_net` is not `internal: true`.

---

## 9. Network Test

Run this from the repository directory after Docker is available. Build one service at a time so a snapshot timeout does not discard the other server. Repeat a failed service; finished layers are cached.

```bash
docker compose build ssh-client
docker compose build target-server
docker compose build target-server-patched
docker compose up -d
docker compose ps
```

`tp-attack` is not ready for the attacker notes until its logs show the startup `apt-get` finished.

```bash
docker logs tp-attack
docker exec tp-server cat /etc/lab-release
docker exec tp-server-patched cat /etc/lab-release
docker exec tp-client cat /etc/lab-release
docker exec -i tp-server sh < notes/server_commands.sh
docker exec -i tp-server-patched sh < notes/server_commands.sh
docker exec -i tp-client sh < notes/client_commands.sh
docker exec -i tp-attack sh < notes/attacker_commands.sh
```

Expect `notes/client_commands.sh` to print `vulnerable-ok` and `patched-ok` from the russh execs. Then, from `tp-client`, confirm the other listeners answer:

```bash
docker exec tp-client sh -c '
  curl -sf http://10.5.0.10:3000/api/healthz; echo
  curl -sf http://10.5.0.11:3000/api/healthz; echo
  ssh -p 22  -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new lab@10.5.0.10 exit || true
  ssh -p 2222 -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new lab@10.5.0.10 exit || true
  ssh -p 22  -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new lab@10.5.0.11 exit || true
  ssh -p 2222 -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new lab@10.5.0.11 exit || true
'
```

Those `ssh` commands have no user key, so a working daemon answers with `Permission denied`. A timeout or `Connection refused` means the daemon is not up. Gitea can take a few seconds after the container starts; the health URL should return success, and `docker exec tp-server tail /var/log/supervisor/gitea-seed.log` should report that `lab/russh-project` was created and that `/etc/gitea/lab.pub` is absent.

Interactive password login, once that is worth trying:

```bash
docker exec -it tp-client ssh -p 22 -o StrictHostKeyChecking=accept-new lab@10.5.0.10
docker exec -it tp-client ssh -p 2222 -o StrictHostKeyChecking=accept-new lab@10.5.0.10
```

Password is `TerrapinTest123!`. Do not treat a Gitea `git clone` as part of this test. It waits on a public key.

---

## 10. Later Deliverables

After the network test passes, the remaining written tasks are:

1. **`scanner/`** — a Python client that reads the server's KEX, cipher, and MAC lists and reports whether `kex-strict-s-v00@openssh.com` or `kex-strict-c-v00@openssh.com` is offered. Flag `chacha20-poly1305@openssh.com` or `*-etm@openssh.com` when strict key exchange is absent. Compare `10.5.0.10` with `10.5.0.11`.
2. **`docs/`** — how the countermeasure shows up in the C, Rust, and Go stacks in this lab, and the mitigation of enabling strict key exchange and preferring AES-GCM over ChaCha20-Poly1305 and Encrypt-then-MAC.
3. **User keys**, when requested — one decision is still open: a single client key installed into all three stores above, or separate keys. Password authentication stays available until that decision says otherwise.
4. **Final report packaging** — bake and publish each host image, including a pinned attacker image if that is required, and decide whether `tp_net` becomes an internal bridge.

The sequence-number proxy is not part of the current step.
