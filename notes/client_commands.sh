#!/bin/sh
# Run inside tp-client after the lab is up.
set -eu

echo "---- client release ----"
cat /etc/lab-release
echo "---- OpenSSH client ----"
ssh -V
echo "---- reachability ----"
ping -c 1 -W 2 10.5.0.10
ping -c 1 -W 2 10.5.0.11
ping -c 1 -W 2 10.5.0.20

echo "---- russh exec, vulnerable server 10.5.0.10 ----"
russh-client --target 10.5.0.10:2223 --user lab --password "$LAB_SSH_PASSWORD" -- echo vulnerable-ok
echo "---- russh exec, patched server 10.5.0.11 ----"
russh-client --target 10.5.0.11:2223 --user lab --password "$LAB_SSH_PASSWORD" -- echo patched-ok

echo "OpenSSH and Dropbear password login is interactive until user keys exist:"
echo "  ssh -p 22 -o StrictHostKeyChecking=accept-new lab@10.5.0.10"
echo "  ssh -p 2222 -o StrictHostKeyChecking=accept-new lab@10.5.0.10"
echo "Gitea clone waits on a public key installed for the gitea user lab."
