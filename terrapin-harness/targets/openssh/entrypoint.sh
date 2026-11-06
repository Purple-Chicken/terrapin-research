#!/bin/sh
set -e

SSHD=/opt/openssh/sbin/sshd
SSHKEYGEN=/opt/openssh/bin/ssh-keygen
ETC=/opt/openssh/etc

if [ ! -f "${ETC}/ssh_host_rsa_key" ]; then
    "${SSHKEYGEN}" -A -f /opt/openssh
fi

mkdir -p /home/labuser/.ssh
chmod 700 /home/labuser/.ssh
if [ -f /keys/client_id_ed25519.pub ]; then
    cp /keys/client_id_ed25519.pub /home/labuser/.ssh/authorized_keys
    chmod 600 /home/labuser/.ssh/authorized_keys
    chown -R labuser:labuser /home/labuser/.ssh
fi

exec "${SSHD}" -D -e -f "${ETC}/sshd_config"
