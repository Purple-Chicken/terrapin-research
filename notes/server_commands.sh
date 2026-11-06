#!/bin/sh
# Run inside tp-server or tp-server-patched.
set -eu

echo "---- server release ----"
cat /etc/lab-release
echo "---- listeners ----"
ss -lnt
echo "---- package versions ----"
dpkg -l openssh-server dropbear-bin | awk 'NR==1 || /^ii/'
echo "---- daemon logs ----"
echo "supervisor logs are under /var/log/supervisor"
