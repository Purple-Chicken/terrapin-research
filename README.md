# Terrapin Research

Lab network for comparing SSH implementations from before and after the Terrapin strict key exchange countermeasure (CVE-2023-48795). Container names in this file are the ones Compose creates.

## Network

```
        Docker network tp_net
        10.5.0.0/24  (open bridge)
  +--------+--------+--------+--------+
  |        |        |        |        |
 .30      .20      .11      .10
Client  Attacker  Patched  Vulnerable
                         server    server
```

| Container | Image | Address | Role |
| --- | --- | --- | --- |
| `tp-server` | `tp-server:vulnerable` | `10.5.0.10` | Pre-strict-kex OpenSSH, Dropbear, Gitea 1.21.0, russh 0.40.1 |
| `tp-server-patched` | `tp-server:patched` | `10.5.0.11` | Same services with the strict-kex fixes |
| `tp-attack` | `kalilinux/kali-rolling` | `10.5.0.20` | Tools installed on start. Hostname `tp-attack` |
| `tp-client` | `tp-client:vulnerable` | `10.5.0.30` | Debian Bullseye OpenSSH client and `russh-client` 0.40.1 |

Shells:

```bash
docker exec -it tp-server /bin/sh
docker exec -it tp-server-patched /bin/sh
docker exec -it tp-attack /bin/bash
docker exec -it tp-client /bin/bash
```

Each server listens on the same ports:

| Port | Service |
| --- | --- |
| 22 | OpenSSH |
| 2222 | Dropbear |
| 2223 | `russh-server` |
| 2224 | Gitea built-in SSH |
| 3000 | Gitea HTTP |

## Why the package pins exist

A current `apt-get install` on Bookworm or Bullseye installs the Terrapin backport while leaving the upstream version number looking old. OpenSSH 9.2p1 and Dropbear 2022.83 in today's archives already advertise `kex-strict-s-v00@openssh.com` and `kex-strict-c-v00@openssh.com`. The lab therefore installs from `snapshot.debian.org`:

| Role | Snapshot | OpenSSH | Dropbear | Gitea | russh |
| --- | --- | --- | --- | --- | --- |
| Vulnerable server | `20231115T000000Z` bookworm | `1:9.2p1-2+deb12u1` | `2022.83-1` | `1.21.0` | `0.40.1` |
| Patched server | `20240215T000000Z` bookworm | `1:9.2p1-2+deb12u2` | `2022.83-1+deb12u1` | `1.21.3` | `0.40.2` |
| Client | `20231115T000000Z` bullseye | `1:8.4p1-5+deb11u2` | — | — | client `0.40.1` |

The image build checks the OpenSSH and Dropbear binaries for the strict key exchange algorithm name. `cat /etc/lab-release` inside a container prints the pin that was built.

Strict key exchange takes effect when both peers advertise it. This client is the pre-fix Bullseye client, so a session from `tp-client` to `tp-server-patched` still completes without strict key exchange. The patched server is the control image for later comparison with a patched client.

## Start

```bash
docker compose up -d --build
```

The bridge stays attached to the host network so images can be built and the attacker can install packages. Baking every host into a published image is planned for the final report.

Unix users `root` and `lab` on both servers use the lab password `TerrapinTest123!`. The same value is `LAB_SSH_PASSWORD` in the server and client images. SSH user keys are not generated yet.

Gitea creates user `lab` (`lab@example.local`) and a private repository `lab/russh-project` on first boot. SSH clone uses pubkey authentication. Put that public key in `/etc/gitea/lab.pub` on the server when the key exists and recreate the `gitea-seed` step; until then the repository exists and pubkey login does not.

`russh-server` also accepts a public key from `/etc/russh/authorized_keys` for `root` and `lab` when that file is added later. Host keys for OpenSSH, Dropbear, and russh are generated on first boot and stay in the container filesystem.

## russh-project

`russh-project/` builds two binaries:

- `russh-server` listens on `0.0.0.0:2223`
- `russh-client` runs one remote command

From `tp-client`:

```bash
russh-client --target 10.5.0.10:2223 --user lab --password "$LAB_SSH_PASSWORD" -- echo vulnerable-ok
russh-client --target 10.5.0.11:2223 --user lab --password "$LAB_SSH_PASSWORD" -- echo patched-ok
```

The client binary on `tp-client` is russh 0.40.1. The patched server image also contains `/usr/local/bin/russh-client` built against russh 0.40.2. `Cargo.toml` pins 0.40.1; the patched image rewrites that pin before it compiles.

Notes for a quick connectivity check live in `notes/`. They are not copied into the images. Feed them to the matching container:

```bash
docker exec -i tp-client sh < notes/client_commands.sh
docker exec -i tp-server sh < notes/server_commands.sh
docker exec -i tp-server-patched sh < notes/server_commands.sh
docker exec -i tp-attack sh < notes/attacker_commands.sh
```

Wait until `tp-attack` finishes its startup `apt-get` before running the attacker notes. `snapshot.debian.org` often returns 503/504; if a server image fails there, rerun that one Compose service. Completed layers stay cached.
