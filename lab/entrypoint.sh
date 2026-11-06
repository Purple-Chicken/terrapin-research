#!/bin/sh
set -eu

umask 077
mkdir -p /run/sshd /etc/dropbear /etc/russh /var/lib/gitea/data /var/lib/gitea/log /var/log/supervisor /home/git

if [ -z "${LAB_SSH_PASSWORD:-}" ]; then
  echo "LAB_SSH_PASSWORD is required" >&2
  exit 1
fi

if [ -f /etc/lab-release ]; then
  echo "---- lab release ----"
  cat /etc/lab-release
  echo "---------------------"
fi

echo "root:${LAB_SSH_PASSWORD}" | chpasswd
if ! id lab >/dev/null 2>&1; then
  useradd -m -s /bin/sh lab
fi
echo "lab:${LAB_SSH_PASSWORD}" | chpasswd

ssh-keygen -A

if [ ! -s /etc/dropbear/dropbear_ed25519_host_key ]; then
  dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key >/dev/null
fi
if [ ! -s /etc/dropbear/dropbear_ecdsa_host_key ]; then
  dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key >/dev/null
fi
if [ ! -s /etc/dropbear/dropbear_rsa_host_key ]; then
  dropbearkey -t rsa -s 2048 -f /etc/dropbear/dropbear_rsa_host_key >/dev/null
fi

host=$(cat /etc/hostname)
sed -i "s/__HOSTNAME__/${host}/g" /etc/gitea/app.ini

chown -R git:git /etc/gitea /var/lib/gitea /home/git
chmod 750 /etc/gitea
chmod 640 /etc/gitea/app.ini

su -p -s /bin/sh git -c 'HOME=/home/git GITEA_WORK_DIR=/var/lib/gitea gitea migrate --config /etc/gitea/app.ini'
su -p -s /bin/sh git -c 'HOME=/home/git GITEA_WORK_DIR=/var/lib/gitea gitea admin user create --config /etc/gitea/app.ini --username lab --password "$LAB_SSH_PASSWORD" --email lab@example.local --must-change-password=false' \
  || echo "gitea user lab already exists"
su -p -s /bin/sh git -c 'HOME=/home/git GITEA_WORK_DIR=/var/lib/gitea gitea admin user change-password --config /etc/gitea/app.ini --username lab --password "$LAB_SSH_PASSWORD" --must-change-password=false'

exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
