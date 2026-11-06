#!/bin/sh
# Run inside tp-attack after its startup packages finish installing.
set -eu

ip -4 addr show eth0
ping -c 1 -W 2 10.5.0.10
ping -c 1 -W 2 10.5.0.11
ping -c 1 -W 2 10.5.0.30
