# AGENTS.md — Security Research & Lab Guide

## 1. Project Overview & Scope

This repository contains a containerized research environment designed to analyze **Terrapin (CVE-2023-48795)**—a prefix truncation attack targeting the SSH binary packet protocol (BPP)—across multiple independent SSH implementations. 

### Purpose & Ethics Disclaimer
* **Primary Objective:** Academic research, protocol testing, and defensive vulnerability scanning.
* **Scope:** Restricted strictly to the local container network (`10.5.0.0/24`).
* **Environment:** Fully isolated Docker Compose lab. No external network access (`internal: true` / local bridge).
* **Authorization:** Explicitly authorized sandbox environment for academic paper evaluation.

---

## 2. Environment Network Topology

The lab consists of three isolated container nodes connected via a custom Docker bridge network (`terrapin_net`):

```
                       +-------------------------------+
                       |   attacker-kali (10.5.0.20)   |
                       |  [ARP Spoof / Packet Proxy]   |
                       +---------------+---------------+
                                       |
                   (Layer 2 ARP Poisoning / Interception)
                                       |
    +----------------------------------+----------------------------------+
    |                                                                     |
    v                                                                     v
+-------------------------------+                       +-------------------------------+
|     ssh-client (10.5.0.30)    |                       |   target-server (10.5.0.10)   |
| [OpenSSH Client / Cargo / Git]|                       |  [Supervisor Multi-SSH Stack] |
+-------------------------------+                       +-------------------------------+
```

### Host Details

| Host Name | IP Address | Capabilities / Role | Key Packages |
| :--- | :--- | :--- | :--- |
| `target-server` | `10.5.0.10` | Multi-SSH Server Node | Supervisor, OpenSSH Server, Dropbear, `russh`, Gitea |
| `attacker-kali` | `10.5.0.20` | MITM Interception Node (`NET_ADMIN`, `NET_RAW`) | `dsniff` (`arpspoof`), `tcpdump`, Python 3, `git` |
| `ssh-client` | `10.5.0.30` | Target Client Node | OpenSSH Client, Git, Rust toolchain (`cargo`), `rsync` |

---

## 3. SSH Implementation Matrix

The `target-server` runs four distinct SSH daemons concurrently, managed via `supervisord`:

| Service | Protocol / Daemon | Implementation Language | Port | Protocol Vulnerability Vector |
| :--- | :--- | :--- | :--- | :--- |
| **System SSH** | OpenSSH Server | C | `22` | `chacha20-poly1305@openssh.com`, `CBC-EtM` |
| **Dropbear** | Dropbear SSH | C | `2222` | Legacy cipher suites without `kex-strict` |
| **Custom App** | `russh` server | Rust | `2223` | `russh` crate sequence number handling |
| **Gitea** | Built-in Go SSH | Go (`golang.org/x/crypto/ssh`) | `2224` | Pre-patch Go SSH sequence manipulation |

---

## 4. Software Versions & Components

* **Base OS (Server & Client):** `debian:bookworm-slim`
* **Gitea:** `v1.21.0` (built-in SSH daemon, pre-patch)
* **OpenSSH:** Version bundled in Debian Bookworm / Bullseye (pre-strict KEX patch evaluation)
* **Rust Toolchain:** `1.80+` slim rust base image for compilation
* **Orchestration:** Docker Compose (`v3.8` schema)

---

## 5. Attack Chain & Reproduction Steps

### Phase 1: Environment Spin-up
```bash
docker compose up -d --build
```

### Phase 2: Layer 2 Interception (Kali Node)
Initiate ARP cache poisoning to position the Kali node between the client and server interfaces:
```bash
docker exec -it attacker-kali arpspoof -i eth0 -t 10.5.0.30 10.5.0.10
```

### Phase 3: Traffic Interception & Handshake Manipulation
Launch a custom Python MITM proxy script on Kali that intercepts TCP port traffic, modifies sequence numbers during early handshake negotiation, and drops specific extension negotiation packets (`SSH_MSG_EXT_INFO`).

### Phase 4: Client Interaction Workflows
The client initiates actions across the four SSH target services:
1. **OpenSSH File Transfer:** `rsync -avz -e "ssh -p 22" /tmp/test.txt root@10.5.0.10:/tmp/`
2. **Dropbear Interactive Shell:** `ssh -p 2222 root@10.5.0.10`
3. **Custom Rust Application:** `cargo run --bin russh-client -- --target 10.5.0.10:2223`
4. **Git Repository Operation:** `git clone ssh://git@10.5.0.10:2224/lab/russh-project.git`

---

## 6. Tasks & Guidelines for Connected AI Agents

When working inside this repository, the agent should assist with the following deliverables:

### 1. Vulnerability Scanner Development (`scanner/`)
* Assist in writing a modular Python vulnerability scanner that connects to an SSH server port, parses the supported KEX algorithms, ciphers, and MACs, and detects whether `kex-strict-s-connection@openssh.com` or `kex-strict-c-connection@openssh.com` is supported.
* Ensure the scanner flags vulnerable cipher combinations (`chacha20-poly1305@openssh.com` or `*-etm@openssh.com` without `kex-strict`).

### 2. Proof-of-Concept Proxy Script (`poc/`)
* Assist in developing a minimal TCP proxy using Python `asyncio` or `socket` programming that executes sequence number truncation against handshake messages for research evaluation.
* Include telemetry logging to output intercepted packet types (`SSH_MSG_KEXINIT`, `SSH_MSG_NEWKEYS`, `SSH_MSG_EXT_INFO`).

### 3. Documentation & Paper Material (`docs/`)
* Draft clean technical write-ups detailing how Terrapin affects each language runtime (C, Rust, Go).
* Document patch recommendations and mitigation strategies (e.g., implementing Strict KEX, removing ChaCha20-Poly1305 / Encrypt-than-MAC in favor of standard AES-GCM modes).