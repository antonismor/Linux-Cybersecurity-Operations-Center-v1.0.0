#!/usr/bin/env bash
set -euo pipefail

[ "$EUID" -eq 0 ] || { echo "Run with sudo."; exit 1; }

if [ "$#" -ne 3 ]; then
  echo "Usage: sudo $0 https://SERVER:8443 ENROLLMENT_TOKEN /path/controller-ca.crt"
  exit 2
fi

SERVER="$1"
TOKEN="$2"
CA="$3"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) BIN="cyberagent-linux-amd64" ;;
  aarch64|arm64) BIN="cyberagent-linux-arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 3 ;;
esac

BASE="$(printf '%s' "$SERVER" | sed 's:/*$::')"

curl --fail --cacert "$CA" -o /usr/local/sbin/cyberagent "$BASE/downloads/$BIN"
chmod 0755 /usr/local/sbin/cyberagent

install -d -m 0700 /etc/cybersecurity-agent
cp "$CA" /etc/cybersecurity-agent/controller-ca.crt
chmod 0644 /etc/cybersecurity-agent/controller-ca.crt

cat >/etc/systemd/system/cybersecurity-agent.service <<EOF
[Unit]
Description=Cybersecurity Operations Center Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/cyberagent
Restart=always
RestartSec=10
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=/etc/cybersecurity-agent

[Install]
WantedBy=multi-user.target
EOF

CYBER_AGENT_CONFIG=/etc/cybersecurity-agent/agent.json /usr/local/sbin/cyberagent --server "$SERVER" --enroll "$TOKEN" --ca /etc/cybersecurity-agent/controller-ca.crt --once

systemctl daemon-reload
systemctl enable --now cybersecurity-agent
systemctl status --no-pager cybersecurity-agent
