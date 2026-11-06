# Terrapin lab harness

A runnable baseline for reproducing and later automating the Terrapin SSH
prefix-truncation attack (CVE-2023-48795, Bäumer, Brinkmann & Schwenk,
USENIX Security 2024) in an isolated lab network.

This harness currently implements the **RcvIncrease sequence-number
manipulation primitive** (the paper's Fig. 4a / Sec. 4.1): an on-path relay
injects one crafted, unsolicited `SSH_MSG_IGNORE` packet into the
client-bound stream during the still-unencrypted handshake.

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
instead.

## The checkable trace / sanity check

`scripts/local_dev_test_all.sh` runs three scenarios and checks each one
with `scripts/check_log.py`. The three reference traces it produced are
saved under `logs/example_traces/` and summarized here:

| # | Scenario | Pairing | Expectation | Result |
|---|----------|---------|-------------|--------|
| 1 | `passthrough` | patched (9.6p1) <-> patched (9.6p1) | handshake completes, zero relay modification | **PASS** |
| 2 | `inject_ignore` | patched (9.6p1) <-> patched (9.6p1) | injected packet rejected | **PASS** -- OpenSSH reports, verbatim: `strict KEX violation: unexpected packet type 2 (seqnr 1)` |
| 3 | `inject_ignore` | genuine pre-patch (9.5p1) <-> pre-patch (9.5p1) | injected packet tolerated, handshake completes | **PASS** -- `handshake_complete` logged, both `NEWKEYS` observed |


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
