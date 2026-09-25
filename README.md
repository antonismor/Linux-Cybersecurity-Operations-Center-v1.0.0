# Linux Cybersecurity Operations Center v1.0.0

## XDR & Endpoint Defense Platform

Linux Cybersecurity Operations Center is a Debian 13-based defensive cybersecurity operations platform with a live Web UI, endpoint enrollment, cross-platform desktop agents, real-time telemetry, incidents, endpoint health monitoring, and agent downloads directly from the console.

> **Powered and Development by antonios.mortos@outlook.com**

---

## Overview

Version 1.0.0 provides the controller foundation and a working cross-platform desktop telemetry agent.

The controller includes:

- Dark SOC/XDR Web UI
- Live dashboard counters
- Endpoint inventory
- Heartbeat and offline detection
- Security-event ingestion
- Automatic incident creation for HIGH/CRITICAL events
- WebSocket live updates
- Recent connection and event views
- Agent downloads from the Web UI
- PostgreSQL persistence
- Nginx HTTPS reverse proxy
- systemd service management
- One-time endpoint enrollment
- Unique per-endpoint credentials
- Local controller CA and TLS certificate
- Automatic desktop-agent builds on Debian 13

The endpoint agent intentionally does not provide a generic remote shell. Version 1.0.0 is focused on defensive telemetry, enrollment, health, and a foundation for narrowly scoped response actions.

---

## Web UI

After installation the console is normally available at:

~~~text
https://SERVER-IP:8443
~~~

The dashboard contains endpoint, online, alert and incident counters, events per minute, a live threat-map visualization, recent connections, alert categories, endpoint inventory, active incidents, live events, agent downloads and system health.

The dashboard uses real controller data. It does not populate fake endpoints or fake incidents.

---

## Architecture

~~~text
                    +-------------------------------+
                    |        Web Browser / SOC      |
                    |      HTTPS + WebSocket        |
                    +---------------+---------------+
                                    |
                                    v
                           +----------------+
                           | Nginx :8443    |
                           | HTTPS / Auth   |
                           +-------+--------+
                                   |
                                   v
                          +-----------------+
                          | FastAPI Backend |
                          | 127.0.0.1:8010  |
                          +------+----------+
                                 |
                 +---------------+----------------+
                 |               |                |
                 v               v                v
            PostgreSQL      WebSocket Hub     Agent Downloads
                 |
                 v
        Events / Endpoints / Incidents

 Windows Agent --+
 Linux Agent ----+---- HTTPS + unique agent token ----> Controller
 macOS Agent ----+

 Android and iOS use platform-specific deployment models.
~~~

---

## Technology stack

Controller: Debian 13, Python 3, FastAPI, Uvicorn, SQLAlchemy, PostgreSQL, Nginx, systemd and OpenSSL.

Endpoint agent: Go, static cross-compilation, HTTPS transport, controller CA validation, one-time enrollment and a unique persistent endpoint credential.

Web UI: HTML, CSS, JavaScript and WebSocket live refresh.

---

# Installation

## Supported controller operating system

The automatic installer supports **Debian GNU/Linux 13 only**. It checks /etc/os-release and aborts on other operating systems or releases.

## 1. Clone

~~~bash
git clone https://github.com/antonismor/Linux-Cybersecurity-Operations-Center-v1.0.0.git
cd Linux-Cybersecurity-Operations-Center-v1.0.0
~~~

## 2. Install

~~~bash
sudo ./scripts/install-debian13.sh
~~~

The installer installs:

~~~text
python3
python3-venv
python3-pip
postgresql
postgresql-contrib
nginx
apache2-utils
openssl
curl
ca-certificates
golang-go
zip
~~~

It then:

1. Creates the dedicated cybersec service account.
2. Creates PostgreSQL.
3. Generates random credentials and bootstrap secrets.
4. Installs the FastAPI controller under /opt/cybersecurity-ops.
5. Creates a Python virtual environment.
6. Generates a local CA and TLS server certificate.
7. Cross-compiles desktop agents.
8. Publishes agent packages.
9. Installs the controller systemd service.
10. Configures Nginx HTTPS on TCP/8443.
11. Performs an API health check.

## 3. Open the Web UI

~~~text
https://SERVER-IP:8443
~~~

Initial Web UI username:

~~~text
admin
~~~

The admin password is generated during installation.

Retrieve generated credentials:

~~~bash
sudo cat /etc/cybersecurity-ops/credentials.txt
~~~

---

# PostgreSQL

The installer creates:

~~~text
Database : cybersecurity_ops
Username : cybersecurity
Password : random 32-character alphanumeric value
~~~

The database password is generated during installation and is not hardcoded in the repository.

Generated credentials are stored in:

~~~text
/etc/cybersecurity-ops/credentials.txt
~~~

with mode 0600.

The application connection string is stored in:

~~~text
/etc/cybersecurity-ops/controller.env
~~~

Connect locally:

~~~bash
sudo -u postgres psql cybersecurity_ops
~~~

---

# TLS

The installer creates:

~~~text
/etc/cybersecurity-ops/tls/ca.crt
/etc/cybersecurity-ops/tls/ca.key
/etc/cybersecurity-ops/tls/server.crt
/etc/cybersecurity-ops/tls/server.key
~~~

The controller CA is also published at:

~~~text
/downloads/controller-ca.crt
~~~

Agents validate the controller with this CA rather than disabling TLS verification.

For enterprise or public deployments, replace the generated server certificate with a certificate issued by your organizational PKI or public CA.

---

# Controller services

~~~bash
systemctl status cybersecurity-ops
systemctl status nginx
systemctl status postgresql
journalctl -u cybersecurity-ops -f
sudo nginx -t
~~~

Local API health check:

~~~bash
curl http://127.0.0.1:8010/api/health
~~~

Expected response:

~~~json
{
  "ok": true,
  "version": "1.0.0",
  "database": "ok",
  "event_ingestor": "ok"
}
~~~

---

# Agent builds

The Debian installer cross-compiles:

~~~text
cyberagent-linux-amd64
cyberagent-linux-arm64
cyberagent-windows-amd64.exe
cyberagent-windows-arm64.exe
cyberagent-darwin-amd64
cyberagent-darwin-arm64
cyberagent-darwin-universal.zip
~~~

They are placed in:

~~~text
/var/lib/cybersecurity-ops/downloads/
~~~

and are exposed through the Agent Downloads section of the Web UI.

---

# One-time endpoint enrollment

Each endpoint should use a unique one-time enrollment token.

The bootstrap API token is generated during controller installation and stored in the root-only credentials file.

Create an enrollment token:

~~~bash
BOOTSTRAP_TOKEN="$(awk '/Bootstrap API token:/{getline; gsub(/^ +| +$/,""); print}' /etc/cybersecurity-ops/credentials.txt)"
ADMIN_PASSWORD="$(awk '/Web UI:/{f=1;next} f && /Password/{print $3;exit}' /etc/cybersecurity-ops/credentials.txt)"

curl -k -u admin:"$ADMIN_PASSWORD" -H "X-Bootstrap-Token: $BOOTSTRAP_TOKEN" -X POST "https://127.0.0.1:8443/api/admin/enrollment-token?label=workstation-01"
~~~

The returned token can be used once. After enrollment the endpoint receives its own unique persistent agent credential. The server stores only the SHA-256 hash of that persistent token.

---

# Linux agent

Download the controller CA:

~~~bash
curl -k -u admin:WEB_PASSWORD https://SERVER-IP:8443/downloads/controller-ca.crt -o controller-ca.crt
~~~

Install:

~~~bash
sudo ./scripts/install-agent-linux.sh https://SERVER-IP:8443 ONE_TIME_ENROLLMENT_TOKEN ./controller-ca.crt
~~~

Installed locations:

~~~text
/usr/local/sbin/cyberagent
/etc/cybersecurity-agent/agent.json
/etc/cybersecurity-agent/controller-ca.crt
/etc/systemd/system/cybersecurity-agent.service
~~~

Check:

~~~bash
systemctl status cybersecurity-agent
journalctl -u cybersecurity-agent -f
~~~

---

# Windows agent

Download cyberagent-windows-amd64.exe or the ARM64 binary and controller-ca.crt from the Web UI.

Initial enrollment from elevated PowerShell:

~~~powershell
.\cyberagent-windows-amd64.exe --server https://SERVER-IP:8443 --enroll ONE_TIME_ENROLLMENT_TOKEN --ca C:\Path\controller-ca.crt
~~~

Version 1.0.0 supports enrollment, heartbeat, endpoint identity, process snapshots and active connection snapshots.

For fleet deployment, package the binary as a Windows Service using your normal endpoint or software-management platform.

---

# macOS Intel and Apple Silicon

The controller builds:

~~~text
cyberagent-darwin-amd64
cyberagent-darwin-arm64
cyberagent-darwin-universal.zip
~~~

Example Apple Silicon enrollment:

~~~bash
sudo ./cyberagent-darwin-arm64 --server https://SERVER-IP:8443 --enroll ONE_TIME_ENROLLMENT_TOKEN --ca ./controller-ca.crt
~~~

The Go agent is the working cross-platform telemetry baseline. A full production macOS EDR sensor using Apple Endpoint Security or System Extensions requires Apple signing and appropriate entitlements.

---

# Android

The Web UI publishes:

~~~text
cyberagent-android-source.zip
~~~

This is a deployment-source bundle, not a falsely labeled production APK.

A production Android package requires Android SDK, Gradle, APK or AAB signing, an application identity, and optionally managed-device, Device Owner, DPC or managed VPN capabilities.

---

# iPhone / iOS

The Web UI publishes:

~~~text
cyberagent-ios-mdm-profile.mobileconfig
~~~

Production iOS or iPadOS endpoint management requires organizational Apple MDM and, depending on functionality, supervised deployment, provisioning, signing and NetworkExtension capabilities.

iOS does not expose unrestricted Windows or Linux-style process and filesystem telemetry to ordinary applications.

---

# Current telemetry

The desktop agent sends:

- Hostname
- Platform
- OS version
- Architecture
- Logged-in user
- Agent version
- Heartbeat
- Process snapshot
- Active network snapshot

This is a working cross-platform baseline, not a claim of kernel-level EDR coverage.

Future platform-specific sensors can add Windows Event Log, ETW, Sysmon, Linux auditd/eBPF, macOS Endpoint Security, DNS, file-integrity, authentication, vulnerability, IOC or reputation and MITRE ATT&CK telemetry.

---

# Live events and endpoint state

The browser subscribes to /ws/events.

The backend publishes endpoint enrollment, heartbeat and security events so the dashboard can update without a manual reload.

The agent heartbeat interval is approximately 30 seconds. The dashboard normally considers an endpoint offline after approximately 90 seconds without a heartbeat.

---

# Incidents

Security-event severities include INFO, MEDIUM, HIGH and CRITICAL.

Version 1.0.0 automatically creates an incident for HIGH and CRITICAL events. This provides the foundation for the future correlation engine.

---

# Defensive scope

Version 1.0.0 does not expose a generic remote shell, unrestricted arbitrary command execution, hidden persistence, credential extraction, or unrestricted file collection.

Future response actions should remain explicit, authenticated and audited, for example endpoint isolation, stopping a selected malicious process, quarantining a selected file, running a defined malware scan, collecting a defined evidence package and refreshing inventory.

---

# Important filesystem locations

~~~text
/opt/cybersecurity-ops/                  Installed controller
/etc/cybersecurity-ops/controller.env    Controller environment
/etc/cybersecurity-ops/credentials.txt   Generated secrets (0600)
/etc/cybersecurity-ops/tls/              CA and HTTPS certificate
/var/lib/cybersecurity-ops/downloads/    Agent downloads
/etc/systemd/system/cybersecurity-ops.service
/etc/nginx/sites-available/cybersecurity-ops
~~~

---

# Repository layout

~~~text
Linux-Cybersecurity-Operations-Center-v1.0.0/
├── agent/
│   ├── go.mod
│   └── main.go
├── deploy/
│   ├── cybersecurity-ops.service
│   └── nginx.conf
├── docs/
│   └── ARCHITECTURE.md
├── mobile/
│   ├── android/
│   │   └── README.md
│   └── ios/
│       └── CybersecurityAgent.mobileconfig
├── scripts/
│   ├── build-agents.sh
│   ├── install-agent-linux.sh
│   └── install-debian13.sh
├── server/
│   ├── requirements.txt
│   └── app/
│       ├── db.py
│       ├── main.py
│       ├── models.py
│       └── static/
│           ├── app.js
│           ├── index.html
│           └── styles.css
├── CHANGELOG.md
├── SECURITY.md
└── README.md
~~~

---

# Production verification

After installation:

~~~bash
systemctl is-active postgresql
systemctl is-active cybersecurity-ops
systemctl is-active nginx
sudo nginx -t
curl http://127.0.0.1:8010/api/health
ss -lntp | grep -E '(:8010|:8443)'
~~~

Then open https://SERVER-IP:8443 and enroll one non-production endpoint first.

Verify that the endpoint appears, Last Seen updates, process and network telemetry arrive, WebSocket refresh works, stopping the agent eventually shows OFFLINE, and restarting it returns ONLINE.

---

# Troubleshooting

Controller:

~~~bash
systemctl status cybersecurity-ops --no-pager
journalctl -u cybersecurity-ops -n 100 --no-pager
~~~

Nginx:

~~~bash
sudo nginx -t
journalctl -u nginx -n 100 --no-pager
~~~

PostgreSQL:

~~~bash
systemctl status postgresql
sudo -u postgres psql -l
~~~

Agent TLS connectivity:

~~~bash
curl --cacert controller-ca.crt https://SERVER-IP:8443/api/health
~~~

Linux agent:

~~~bash
systemctl status cybersecurity-agent
journalctl -u cybersecurity-agent -n 100 --no-pager
~~~

If an agent cannot enroll, verify TCP/8443 reachability, certificate SAN values, whether the one-time token was already consumed, endpoint time synchronization, and the controller CA file.

---

# Security recommendations

Before broad production deployment:

- Replace initial Basic Auth with application RBAC and MFA.
- Restrict TCP/8443 to intended networks.
- Protect /etc/cybersecurity-ops/credentials.txt.
- Back up PostgreSQL.
- Rotate bootstrap credentials after initial deployment.
- Use one enrollment token per endpoint.
- Never reuse an endpoint's persistent token on another device.
- Isolate controller administrative access.
- Add database retention.
- Add complete administrator audit logging before response actions are enabled.
- Test agents and policies in a lab before fleet-wide rollout.

See SECURITY.md for additional guidance.

---

# Roadmap

Planned advanced modules include Threat Hunting, endpoint timelines, process trees, Windows Event Log and Sysmon, Linux auditd and eBPF, macOS Endpoint Security, DNS telemetry, file-integrity monitoring, authentication analytics, MITRE ATT&CK mapping, IOC feeds, vulnerability inventory, signed agent updates, controlled endpoint isolation, quarantine, evidence collection, SOC analyst RBAC, Active Directory or LDAP authentication, OIDC, MFA, complete audit logging, PostgreSQL retention, ClickHouse telemetry and NATS event streaming.

---

# Intended use

This project is intended for defensive security monitoring, endpoint administration, SOC operations and incident response on systems you own or are explicitly authorized to manage.

---

## Author

**Antonios Mortos**

**Powered and Development by antonios.mortos@outlook.com**
