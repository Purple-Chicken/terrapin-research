# Terrapin lab harness

A runnable baseline for reproducing and later automating the Terrapin SSH
prefix-truncation attack (CVE-2023-48795, Bäumer, Brinkmann & Schwenk,
USENIX Security 2024) in an isolated lab network.

This harness currently implements the **RcvIncrease sequence-number
manipulation primitive** (the paper's Fig. 4a / Sec. 4.1): an on-path relay
injects one crafted, unsolicited `SSH_MSG_IGNORE` packet into the
client-bound stream during the still-unencrypted handshake. It does **not**
yet implement the compensating message deletion needed for a full prefix
truncation attack -- that is the bounded-contribution / Metasploit-module
work described in the project write-up.

## Layout

```
docker-compose.yml       # router + openssh-target + attacker-client topology
relay/                   # the MitM relay (Python, stdlib only)
  relay.py                 orchestrator: passthrough / inject_ignore modes
  ssh_wire.py               SSH Binary Packet Protocol framing helpers
  logger.py                 JSON-lines event logger
targets/openssh/         # Dockerfile building a pinned OpenSSH release from source
client/                  # minimal attacker/client container image
scripts/
  gen_keys.sh               one-time: generate the lab's client keypair
  capture.sh                 tcpdump wrapper
  connect.sh                 ssh wrapper through the router
  run_sanity_check.sh        docker-based sanity check runner
  check_log.py                verifies a relay.jsonl trace against expectations
  aggregate_logs.py           rolls up per-trial logs into a results CSV
  local_dev_test_all.sh      no-Docker end-to-end test (see below)
  paramiko_connect.py        secondary client stack used during development
logs/example_traces/     # three validated reference traces, see below
```

## Running the harness (Docker)

```bash
./scripts/gen_keys.sh                 # one-time: creates keys/client_id_ed25519{,.pub}
docker compose build
docker compose up -d openssh-target router

# baseline: confirm plain connectivity through the router
./scripts/connect.sh 127.0.0.1 2222 "echo OK"

# sanity check: inject one IGNORE and see what happens
RELAY_MODE=inject_ignore docker compose up -d --build router
./scripts/run_sanity_check.sh rejected   # openssh-target defaults to a pinned
                                          # pre-9.6 (vulnerable) build, so expect
                                          # "survive" here -- see note below
```

`targets/openssh/Dockerfile` defaults to `OPENSSH_TAG=V_9_5_P1` (the last
release before strict-kex), so the default `docker compose` target is
vulnerable and `run_sanity_check.sh survive` is the expectation to use
against it. Build `--build-arg OPENSSH_TAG=V_9_6_P1` for the patched
comparison target, and use `run_sanity_check.sh rejected` against that one
instead (see "Remediation" below).

**Docker was not available in the environment this harness was developed
and tested in**, so the Dockerfiles and compose topology above are written
and reviewed but not yet execution-tested end-to-end. Everything in the
next section *was* tested, against real OpenSSH binaries, and is the
authoritative description of how the relay actually behaves.

## Local dev loop (no Docker)

The relay only needs two TCP endpoints, so it can be exercised directly
against locally-run `sshd` binaries, which is how it was actually
developed and validated:

```bash
# one-time setup (see comments in the script for exact steps):
#  - a patched sshd (system OpenSSH, >=9.6) on 127.0.0.1:2200
#  - a genuinely pre-patch sshd (OpenSSH 9.5p1, built from source) on 127.0.0.1:2201
#  - keys/client_id_ed25519 authorized on both

./scripts/local_dev_test_all.sh
```

Building the pre-patch comparison binary:

```bash
git clone --depth 1 --branch V_9_5_P1 \
    https://github.com/openssh/openssh-portable.git openssh-9.5p1-src
cd openssh-9.5p1-src
autoreconf -fi
./configure --prefix=/opt/openssh-9.5p1 --with-pid-dir=/run/sshd-955
make -j"$(nproc)" && make install
```

(This is exactly what `targets/openssh/Dockerfile` automates for the
container build.)

## The checkable trace / sanity check

`scripts/local_dev_test_all.sh` runs three scenarios and checks each one
with `scripts/check_log.py`. The three reference traces it produced are
saved under `logs/example_traces/` and summarized here:

| # | Scenario | Pairing | Expectation | Result |
|---|----------|---------|-------------|--------|
| 1 | `passthrough` | patched (9.6p1) <-> patched (9.6p1) | handshake completes, zero relay modification | **PASS** |
| 2 | `inject_ignore` | patched (9.6p1) <-> patched (9.6p1) | injected packet rejected | **PASS** -- OpenSSH reports, verbatim: `strict KEX violation: unexpected packet type 2 (seqnr 1)` |
| 3 | `inject_ignore` | genuine pre-patch (9.5p1) <-> pre-patch (9.5p1) | injected packet tolerated, handshake completes | **PASS** -- `handshake_complete` logged, both `NEWKEYS` observed |

Scenario 2 is named by Claude as **the designated sanity check**: it is
deterministic (not probabilistic like the CBC-EtM cases in the paper),
cheap to reproduce (~3 seconds, no external dependencies beyond a stock
`sshd`), and its PASS/FAIL condition is unambiguous because OpenSSH's own
error message names the exact countermeasure that fired. **This is also
the designated fallback trace** if a later snapshot (e.g. a full automated
Metasploit-module run) is missing or invalid: regenerating it requires
nothing but this repository and a stock, already-installed `openssh-server`
package, with no dependency on the module's current code state or on
externally-hosted source.

Scenario 3 confirms the core RcvIncrease primitive in isolation: a
genuinely vulnerable pairing tolerates the injected packet and the
unencrypted handshake completes normally. The `ssh` client still reports
an error at that point (`Bad packet length ... Connection corrupted`),
which is *expected*: SSH sequence numbers are never reset at `NEWKEYS`
(the paper's second root cause), so the injected packet leaves the
client's receive counter one ahead of the server's send counter, and the
first real encrypted message fails to decrypt. The real attack pairs this
injection with a compensating deletion of one server-to-client message to
cancel that offset out -- that pairing is exactly the bounded-contribution
work, not part of this baseline.

An earlier version of this sanity check used a different injection
position (immediately after the version banner, before either peer's
KEXINIT) and an off-by-four bug in the packet-padding calculation; both
have been corrected (see `ssh_wire.py` docstring and `relay.py` comments)
and the three scenarios above reflect the corrected, verified behavior.

## Running the automated checker directly

```bash
python3 scripts/check_log.py logs/example_traces/02_inject_patched_pairing.jsonl --expect rejected
python3 scripts/check_log.py logs/example_traces/03_inject_legacy_pairing.jsonl --expect survive
```

Both exit 0 and print `PASS: ...` with the specific evidence found in the
trace.

## Experimental protocol and logs

As the target matrix grows (Dropbear, Gitea, Podman's SSH API, the custom
russh app; patched vs. vulnerable; manual vs. automated), name each
trial's log `logs/<target>_<cipher>_<patched|vulnerable>_<manual|auto>_trialNN.jsonl`
and run:

```bash
python3 scripts/aggregate_logs.py logs/ --out results/summary.csv
```

to produce a combined CSV and a per-condition success-rate summary.

## Known limitations / next steps

- The relay only parses the plaintext pre-`NEWKEYS` phase; everything
  after is spliced through as opaque bytes. Full prefix truncation
  requires deleting a bounded number of bytes from the start of that
  opaque stream, including determining their length when the cipher mode
  encrypts the length field (ChaCha20-Poly1305) -- see the paper, Sec. 4.3.
- `STRIP_STRICT_KEX` is a diagnostic flag, not a way to make two patched
  binaries behave as unpatched: KEXINIT content is covered by the
  handshake's exchange hash, so rewriting it in transit breaks signature
  verification instead of disabling strict-kex. See the comment block in
  `relay/relay.py`.
- `targets/openssh/Dockerfile`, `docker-compose.yml`, and the additional
  targets (Dropbear, Gitea, Podman, russh) are scaffolded but not yet
  build-tested in this environment; the next step is validating them in a
  Docker-capable environment and extending `docker-compose.yml` with one
  service per additional target.
