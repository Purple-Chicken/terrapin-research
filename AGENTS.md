# AGENTS.md — Security Research & Lab Guide

## 1. Project Overview & Scope

This repository contains a containerized research environment designed to analyze **Terrapin (CVE-2023-48795)**—a prefix truncation attack targeting the SSH binary packet protocol (BPP)—across multiple independent SSH implementations. 

### Purpose & Ethics Disclaimer
* **Primary Objective:** Academic research, protocol testing, and defensive vulnerability scanning.
* **Scope:** Restricted strictly to the local container network (`10.5.0.0/24`).
* **Environment:** Docker Compose lab on bridge `tp_net` (`10.5.0.0/24`). The bridge is open during network testing. Image publication for an offline replay is a later step.
* **Authorization:** Explicitly authorized sandbox environment for academic paper evaluation.

---

## 2. Environment Network Topology

The lab consists of four container nodes on the Docker bridge `tp_net`. Container names follow `README.md` (`tp-server`, `tp-server-patched`, `tp-attack`, `tp-client`). The bridge is open while the network is being tested.

```
 tp-client (10.5.0.30)     tp-attack (10.5.0.20)     tp-server-patched (10.5.0.11)     tp-server (10.5.0.10)
 Bullseye OpenSSH client   Kali tools on start       strict-kex fixes                  pre-strict-kex builds
 russh-client 0.40.1                                 same four SSH services            OpenSSH, Dropbear, russh, Gitea
```

### Host Details

| Host Name | IP Address | Capabilities / Role | Key Packages |
| :--- | :--- | :--- | :--- |
| `tp-server` | `10.5.0.10` | Vulnerable multi-SSH server | Supervisor, pinned pre-strict-kex OpenSSH and Dropbear, russh 0.40.1, Gitea 1.21.0 |
| `tp-server-patched` | `10.5.0.11` | Patched twin of `tp-server` | Same services at the strict-kex fix versions |
| `tp-attack` | `10.5.0.20` | Interception node (`NET_ADMIN`, `NET_RAW`) | `dsniff`, `tcpdump`, Python 3, `git`. Packages install on start |
| `tp-client` | `10.5.0.30` | Vulnerable client | Bullseye OpenSSH client `1:8.4p1-5+deb11u2`, Git, `rsync`, `russh-client` 0.40.1 |

---

## 3. SSH Implementation Matrix

`tp-server` and `tp-server-patched` each run four SSH daemons concurrently, managed via `supervisord`:

| Service | Protocol / Daemon | Implementation Language | Port | Protocol Vulnerability Vector |
| :--- | :--- | :--- | :--- | :--- |
| **System SSH** | OpenSSH Server | C | `22` | `chacha20-poly1305@openssh.com`, `CBC-EtM` |
| **Dropbear** | Dropbear SSH | C | `2222` | Legacy cipher suites without `kex-strict` |
| **Custom App** | `russh` server | Rust | `2223` | `russh` crate sequence number handling |
| **Gitea** | Built-in Go SSH | Go (`golang.org/x/crypto/ssh`) | `2224` | Pre-patch Go SSH sequence manipulation |

---

## 4. Software Versions & Components

* **Vulnerable server OS pin:** `snapshot.debian.org` bookworm `20231115T000000Z`
* **Patched server OS pin:** `snapshot.debian.org` bookworm `20240215T000000Z`
* **Client OS pin:** `snapshot.debian.org` bullseye `20231115T000000Z` (`debian:bullseye-slim` base)
* **OpenSSH:** vulnerable `1:9.2p1-2+deb12u1` and client `1:8.4p1-5+deb11u2`; patched server `1:9.2p1-2+deb12u2`. Today's Bookworm and Bullseye archives already contain the backport, so the snapshot pin is required.
* **Dropbear:** vulnerable `2022.83-1`; patched `2022.83-1+deb12u1`
* **Gitea:** vulnerable `1.21.0`; patched `1.21.3`
* **russh:** vulnerable `0.40.1`; patched `0.40.2`. Source lives in `russh-project/` (client and server binaries).
* **Strict key exchange names:** `kex-strict-c-v00@openssh.com` and `kex-strict-s-v00@openssh.com`
* **Rust toolchain:** `rust:1.83-slim` builder. Dependency caps in `russh-project/Cargo.toml` keep the graph on releases that crate still accepts.
* **Orchestration:** Docker Compose (`v3.8` schema)
* **Lab password:** `TerrapinTest123!` for unix users `root` and `lab`, and for the Gitea user `lab`. SSH user keys are added later. Host keys are generated on first boot.
* **Gitea repository:** private `lab/russh-project`, pubkey authentication. The repo is created on boot. The public key file is `/etc/gitea/lab.pub` when it exists.

---

## 5. Attack Chain & Reproduction Steps

### Phase 1: Environment Spin-up
```bash
docker compose up -d --build
```

### Phase 2: Layer 2 Interception (Kali Node)
Initiate ARP cache poisoning to position the Kali node between the client and server interfaces:
```bash
docker exec -it tp-attack arpspoof -i eth0 -t 10.5.0.30 10.5.0.10
```

### Phase 3: Traffic Interception & Handshake Manipulation
Launch a custom Python MITM proxy script on Kali that intercepts TCP port traffic, modifies sequence numbers during early handshake negotiation, and drops specific extension negotiation packets (`SSH_MSG_EXT_INFO`).

### Phase 4: Client Interaction Workflows
The client initiates actions across the four SSH target services:
1. **OpenSSH File Transfer:** `rsync -avz -e "ssh -p 22" /tmp/test.txt root@10.5.0.10:/tmp/`
2. **Dropbear Interactive Shell:** `ssh -p 2222 root@10.5.0.10`
3. **Custom Rust Application:** `russh-client --target 10.5.0.10:2223 --user lab --password "$LAB_SSH_PASSWORD" -- echo ok` (binary on `tp-client`; the patched peer is `10.5.0.11`)
4. **Git Repository Operation:** `git clone ssh://git@10.5.0.10:2224/lab/russh-project.git` after the Gitea user's public key is installed. The repository is created on boot; the key file is not in the image yet.

---

## 6. Tasks & Guidelines for Connected AI Agents

When working inside this repository, the agent should assist with the following deliverables:

### 1. Vulnerability Scanner Development (`scanner/`)
* Assist in writing a modular Python vulnerability scanner that connects to an SSH server port, parses the supported KEX algorithms, ciphers, and MACs, and detects whether `kex-strict-s-v00@openssh.com` or `kex-strict-c-v00@openssh.com` is supported.
* Ensure the scanner flags vulnerable cipher combinations (`chacha20-poly1305@openssh.com` or `*-etm@openssh.com` without `kex-strict`).

### 2. Proof-of-Concept Proxy Script (`poc/`)
* Assist in developing a minimal TCP proxy using Python `asyncio` or `socket` programming that executes sequence number truncation against handshake messages for research evaluation.
* Include telemetry logging to output intercepted packet types (`SSH_MSG_KEXINIT`, `SSH_MSG_NEWKEYS`, `SSH_MSG_EXT_INFO`).

### 3. Documentation & Paper Material (`docs/`)
* Draft clean technical write-ups detailing how Terrapin affects each language runtime (C, Rust, Go).
* Document patch recommendations and mitigation strategies (e.g., implementing Strict KEX, removing ChaCha20-Poly1305 / Encrypt-than-MAC in favor of standard AES-GCM modes).