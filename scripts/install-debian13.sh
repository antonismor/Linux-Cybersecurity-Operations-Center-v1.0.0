#!/usr/bin/env bash
set -euo pipefail

[ "$EUID" -eq 0 ] || { echo "Run with sudo."; exit 1; }

if [ ! -r /etc/os-release ]; then
  echo "Cannot detect operating system." >&2
  exit 2
fi

. /etc/os-release

if [ "$ID" != "debian" ] || [ "$VERSION_ID" != "13" ]; then
  echo "This installer supports Debian 13 only. Detected: $PRETTY_NAME" >&2
  exit 3
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APPDIR="/opt/cybersecurity-ops"
ETCDIR="/etc/cybersecurity-ops"
DATADIR="/var/lib/cybersecurity-ops"
DOWNLOADS="$DATADIR/downloads"
DB_NAME="cybersecurity_ops"
DB_USER="cybersecurity"

echo "[1/9] Installing Debian 13 packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip postgresql postgresql-contrib nginx apache2-utils openssl curl ca-certificates golang-go zip

rand_alnum() {
  python3 -c 'import secrets,string,sys; n=int(sys.argv[1]); chars=string.ascii_letters+string.digits; print("".join(secrets.choice(chars) for _ in range(n)))' "$1"
}

DB_PASS="$(rand_alnum 32)"
ADMIN_PASS="$(rand_alnum 20)"
BOOTSTRAP_TOKEN="$(rand_alnum 48)"
SECRET_KEY="$(rand_alnum 48)"

echo "[2/9] Creating service account and directories..."
if ! id cybersec >/dev/null 2>&1; then
  useradd --system --home "$DATADIR" --shell /usr/sbin/nologin cybersec
fi
install -d -o cybersec -g cybersec -m 0750 "$DATADIR" "$DOWNLOADS"
install -d -m 0750 "$ETCDIR/tls"

echo "[3/9] Configuring PostgreSQL..."
systemctl enable --now postgresql

runuser -u postgres -- psql -v ON_ERROR_STOP=1 --set=dbuser="$DB_USER" --set=dbpass="$DB_PASS" --set=dbname="$DB_NAME" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'dbuser', :'dbpass')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'dbuser') \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'dbuser', :'dbpass') \gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'dbname', :'dbuser')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'dbname') \gexec
SQL

echo "[4/9] Installing the controller..."
rm -rf "$APPDIR"
install -d -m 0755 "$APPDIR"
cp -a "$ROOT/server" "$APPDIR/"
cp -a "$ROOT/agent" "$APPDIR/"
cp -a "$ROOT/scripts" "$APPDIR/"
cp -a "$ROOT/mobile" "$APPDIR/"

python3 -m venv "$APPDIR/venv"
"$APPDIR/venv/bin/pip" install --upgrade pip wheel
"$APPDIR/venv/bin/pip" install -r "$APPDIR/server/requirements.txt"

chown -R cybersec:cybersec "$APPDIR" "$DATADIR"

cat >"$ETCDIR/controller.env" <<EOF
DATABASE_URL=postgresql+psycopg://$DB_USER:$DB_PASS@127.0.0.1/$DB_NAME
DOWNLOAD_DIR=$DOWNLOADS
BOOTSTRAP_TOKEN=$BOOTSTRAP_TOKEN
SECRET_KEY=$SECRET_KEY
EOF
chmod 0600 "$ETCDIR/controller.env"

cat >"$ETCDIR/credentials.txt" <<EOF
Linux Cybersecurity Operations Center v1.0.0
Generated: $(date -Is)

Database:
  Database : $DB_NAME
  Username : $DB_USER
  Password : $DB_PASS

Web UI:
  Username : admin
  Password : $ADMIN_PASS

Bootstrap API token:
  $BOOTSTRAP_TOKEN

Powered and Development by antonios.mortos@outlook.com
EOF
chmod 0600 "$ETCDIR/credentials.txt"

echo "[5/9] Generating the local TLS CA and server certificate..."
SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [ -z "$SERVER_IP" ]; then
  SERVER_IP="127.0.0.1"
fi
SERVER_HOST="$(hostname -f 2>/dev/null || hostname)"

openssl genrsa -out "$ETCDIR/tls/ca.key" 3072 >/dev/null 2>&1
openssl req -x509 -new -key "$ETCDIR/tls/ca.key" -sha256 -days 3650 -subj "/CN=Cybersecurity Operations Center Local CA" -out "$ETCDIR/tls/ca.crt"
openssl genrsa -out "$ETCDIR/tls/server.key" 3072 >/dev/null 2>&1

cat >"$ETCDIR/tls/server.cnf" <<EOF
[req]
prompt=no
distinguished_name=dn
req_extensions=req_ext

[dn]
CN=$SERVER_HOST

[req_ext]
subjectAltName=@alt_names

[alt_names]
DNS.1=$SERVER_HOST
DNS.2=localhost
IP.1=$SERVER_IP
IP.2=127.0.0.1
EOF

openssl req -new -key "$ETCDIR/tls/server.key" -out "$ETCDIR/tls/server.csr" -config "$ETCDIR/tls/server.cnf"
openssl x509 -req -in "$ETCDIR/tls/server.csr" -CA "$ETCDIR/tls/ca.crt" -CAkey "$ETCDIR/tls/ca.key" -CAcreateserial -out "$ETCDIR/tls/server.crt" -days 825 -sha256 -extensions req_ext -extfile "$ETCDIR/tls/server.cnf" >/dev/null 2>&1

chmod 0600 "$ETCDIR/tls/"*.key
cp "$ETCDIR/tls/ca.crt" "$DOWNLOADS/controller-ca.crt"
chown cybersec:cybersec "$DOWNLOADS/controller-ca.crt"

echo "[6/9] Building desktop agents..."
bash "$APPDIR/scripts/build-agents.sh" "$DOWNLOADS"
chown -R cybersec:cybersec "$DOWNLOADS"

echo "[7/9] Publishing mobile deployment packages..."
(
  cd "$ROOT/mobile/android"
  zip -qr "$DOWNLOADS/cyberagent-android-source.zip" .
)
cp "$ROOT/mobile/ios/CybersecurityAgent.mobileconfig" "$DOWNLOADS/cyberagent-ios-mdm-profile.mobileconfig"
chown cybersec:cybersec "$DOWNLOADS/"*

echo "[8/9] Installing systemd and Nginx..."
cp "$ROOT/deploy/cybersecurity-ops.service" /etc/systemd/system/cybersecurity-ops.service
cp "$ROOT/deploy/nginx.conf" /etc/nginx/sites-available/cybersecurity-ops
ln -sf /etc/nginx/sites-available/cybersecurity-ops /etc/nginx/sites-enabled/cybersecurity-ops
rm -f /etc/nginx/sites-enabled/default

printf '%s\n' "$ADMIN_PASS" | htpasswd -i -c /etc/nginx/.cybersecurity_ops_htpasswd admin >/dev/null
chmod 0640 /etc/nginx/.cybersecurity_ops_htpasswd

nginx -t
systemctl daemon-reload
systemctl enable --now cybersecurity-ops
systemctl restart nginx

echo "[9/9] Running controller health check..."
sleep 2
curl --fail --silent http://127.0.0.1:8010/api/health | python3 -m json.tool

cat <<EOF

==============================================================================
 LINUX CYBERSECURITY OPERATIONS CENTER - XDR & ENDPOINT DEFENSE
==============================================================================

Installation complete.

Web UI:
  https://$SERVER_IP:8443

Admin username:
  admin

Generated passwords and tokens:
  $ETCDIR/credentials.txt

Database:
  PostgreSQL
  Database: $DB_NAME
  Database user: $DB_USER
  Password: randomly generated 32-character alphanumeric string

Agent downloads:
  https://$SERVER_IP:8443/#downloads

Controller CA:
  https://$SERVER_IP:8443/downloads/controller-ca.crt

Keep $ETCDIR/credentials.txt secure. It is mode 0600.

Powered and Development by antonios.mortos@outlook.com
==============================================================================
EOF
