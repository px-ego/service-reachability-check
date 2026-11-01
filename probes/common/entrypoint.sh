#!/bin/sh
set -eu

PROBE_HOME="/home/probe"
SSH_DIR="${PROBE_HOME}/.ssh"
AUTHORIZED_KEYS="${SSH_DIR}/authorized_keys"

mkdir -p /run/sshd "${SSH_DIR}"
chmod 700 "${SSH_DIR}"

if [ -n "${PROBE_AUTHORIZED_KEYS:-}" ] || [ -n "${PROBE_AUTHORIZED_KEYS_FILE:-}" ]; then
  : > "${AUTHORIZED_KEYS}"
  if [ -n "${PROBE_AUTHORIZED_KEYS:-}" ]; then
    printf '%s\n' "${PROBE_AUTHORIZED_KEYS}" >> "${AUTHORIZED_KEYS}"
  fi
  if [ -n "${PROBE_AUTHORIZED_KEYS_FILE:-}" ]; then
    if [ ! -f "${PROBE_AUTHORIZED_KEYS_FILE}" ]; then
      echo "PROBE_AUTHORIZED_KEYS_FILE does not exist: ${PROBE_AUTHORIZED_KEYS_FILE}" >&2
      exit 1
    fi
    cat "${PROBE_AUTHORIZED_KEYS_FILE}" >> "${AUTHORIZED_KEYS}"
  fi
fi

if [ ! -s "${AUTHORIZED_KEYS}" ]; then
  echo "probe container requires PROBE_AUTHORIZED_KEYS, PROBE_AUTHORIZED_KEYS_FILE, or a mounted authorized_keys file" >&2
  exit 1
fi

chown -R probe:probe "${SSH_DIR}"
chmod 600 "${AUTHORIZED_KEYS}"
ssh-keygen -A >/dev/null

exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
