#!/bin/sh
set -eu

attempt=0
until curl -sf http://127.0.0.1:3000/api/healthz >/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 90 ]; then
    echo "gitea did not become ready" >&2
    exit 1
  fi
  sleep 1
done

code=$(curl -s -o /dev/null -w '%{http_code}' -u "lab:${LAB_SSH_PASSWORD}" \
  http://127.0.0.1:3000/api/v1/repos/lab/russh-project || true)
case "$code" in
  200)
    echo "repository lab/russh-project already exists"
    ;;
  404)
    create=$(curl -s -o /tmp/gitea-repo.json -w '%{http_code}' -u "lab:${LAB_SSH_PASSWORD}" \
      -H 'Content-Type: application/json' \
      -d '{"name":"russh-project","private":true,"auto_init":true,"description":"Lab repository for the custom russh client and server."}' \
      http://127.0.0.1:3000/api/v1/user/repos || true)
    echo "create repository status ${create}"
    if [ "$create" != "201" ] && [ "$create" != "409" ]; then
      echo "failed to create lab/russh-project" >&2
      cat /tmp/gitea-repo.json >&2 || true
      exit 1
    fi
    ;;
  *)
    echo "unexpected repository lookup status ${code}" >&2
    exit 1
    ;;
esac

if [ -s /etc/gitea/lab.pub ]; then
  key=$(tr -d '\r\n' < /etc/gitea/lab.pub)
  key_status=$(curl -s -o /tmp/gitea-key.json -w '%{http_code}' -u "lab:${LAB_SSH_PASSWORD}" \
    -H 'Content-Type: application/json' \
    -d "{\"title\":\"lab\",\"key\":\"${key}\"}" \
    http://127.0.0.1:3000/api/v1/user/keys || true)
  echo "install lab public key status ${key_status}"
else
  echo "no /etc/gitea/lab.pub yet; Gitea SSH pubkey auth is not configured"
fi
