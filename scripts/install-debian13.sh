#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

[ "$EUID" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }

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
SERVICE_FILE="/etc/systemd/system/cybersecurity-ops.service"
NGINX_SITE="/etc/nginx/sites-available/cybersecurity-ops"
NGINX_LINK="/etc/nginx/sites-enabled/cybersecurity-ops"
HTPASSWD_FILE="/etc/nginx/.cybersecurity_ops_htpasswd"
BACKUP_BASE="/var/backups/cybersecurity-ops"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$BACKUP_BASE/$STAMP"
STAGE_APP="/opt/.cybersecurity-ops.stage.$$"
STAGE_ETC="/etc/.cybersecurity-ops.stage.$$"
STAGE_DOWNLOADS="/var/lib/.cybersecurity-ops-downloads.stage.$$"
STAGE_HTPASSWD="/etc/nginx/.cybersecurity_ops_htpasswd.stage.$$"
ROLLBACK_ARMED=0
INSTALL_COMMITTED=0
WAS_SERVICE_ACTIVE=0
WAS_NGINX_ACTIVE=0

rand_alnum() {
  python3 -c 'import secrets,string,sys; n=int(sys.argv[1]); chars=string.ascii_letters+string.digits; print("".join(secrets.choice(chars) for _ in range(n)))' "$1"
}

env_value() {
  local key="$1"
  local file="$2"
  [ -r "$file" ] || return 1
  sed -n "s/^\${key}=//p" "$file" | tail -n 1
}

credential_value() {
  local section="$1"
  local key="$2"
  local file="$3"
  [ -r "$file" ] || return 1
  awk -v section="$section" -v key="$key" '
    $0 == section ":" {in_section=1; next}
    in_section && /^[^[:space:]].*:$/ {in_section=0}
    in_section && $1 == key && $2 == ":" {
      $1=""; $2="";
      sub(/^[[:space:]]+/, "");
      print;
      exit
    }
  ' "$file"
}

bootstrap_from_credentials() {
  local file="$1"
  [ -r "$file" ] || return 1
  awk '
    /^Bootstrap API token:$/ {getline; gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit}
  ' "$file"
}

backup_path() {
  local src="$1"
  local name="$2"
  if [ -e "$src" ] || [ -L "$src" ]; then
    mkdir -p "$BACKUP_DIR"
    cp -a "$src" "$BACKUP_DIR/$name"
  fi
}

restore_path() {
  local dst="$1"
  local name="$2"
  rm -rf "$dst"
  if [ -e "$BACKUP_DIR/$name" ] || [ -L "$BACKUP_DIR/$name" ]; then
    cp -a "$BACKUP_DIR/$name" "$dst"
  fi
}

rollback() {
  local rc="$1"
  trap - ERR INT TERM
  set +e

  echo >&2
  echo "ERROR: installation failed (exit $rc)." >&2

  rm -rf "$STAGE_APP" "$STAGE_ETC" "$STAGE_DOWNLOADS" "$STAGE_HTPASSWD"

  if [ "$ROLLBACK_ARMED" -eq 1 ] && [ "$INSTALL_COMMITTED" -eq 0 ]; then
    echo "Rolling back filesystem and service configuration from $BACKUP_DIR ..." >&2

    systemctl stop cybersecurity-ops >/dev/null 2>&1 || true

    restore_path "$APPDIR" "app"
    restore_path "$ETCDIR" "etc"
    restore_path "$DOWNLOADS" "downloads"
    restore_path "$SERVICE_FILE" "cybersecurity-ops.service"
    restore_path "$NGINX_SITE" "nginx-site"
    restore_path "$NGINX_LINK" "nginx-link"
    restore_path "$HTPASSWD_FILE" "htpasswd"

    systemctl daemon-reload >/dev/null 2>&1 || true

    if [ "$WAS_SERVICE_ACTIVE" -eq 1 ] && [ -f "$SERVICE_FILE" ]; then
      systemctl start cybersecurity-ops >/dev/null 2>&1 || true
    fi
    if [ "$WAS_NGINX_ACTIVE" -eq 1 ]; then
      nginx -t >/dev/null 2>&1 && systemctl restart nginx >/dev/null 2>&1 || true
    fi

    echo "Rollback completed. Backup retained at: $BACKUP_DIR" >&2
  else
    echo "No previous installation was replaced. Staging files were removed." >&2
  fi

  exit "$rc"
}

trap 'rollback $?' ERR
trap 'rollback 130' INT
trap 'rollback 143' TERM

echo "[1/10] Installing Debian 13 packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  python3 python3-venv python3-pip postgresql postgresql-contrib \
  nginx apache2-utils openssl curl ca-certificates golang-go zip

EXISTING_INSTALL=0
if [ -d "$APPDIR" ] || [ -f "$ETCDIR/controller.env" ] || [ -f "$ETCDIR/credentials.txt" ] || \
   [ -f "$ETCDIR/tls/ca.key" ] || [ -f "$SERVICE_FILE" ]; then
  EXISTING_INSTALL=1
fi

if systemctl is-active --quiet cybersecurity-ops 2>/dev/null; then
  WAS_SERVICE_ACTIVE=1
fi
if systemctl is-active --quiet nginx 2>/dev/null; then
  WAS_NGINX_ACTIVE=1
fi

echo "[2/10] Loading or generating installation secrets..."
if [ "$EXISTING_INSTALL" -eq 1 ]; then
  echo "Existing installation detected. Preserving credentials and local CA."

  [ -r "$ETCDIR/controller.env" ] || {
    echo "Refusing rerun: missing $ETCDIR/controller.env; cannot safely preserve secrets." >&2
    exit 10
  }
  [ -r "$ETCDIR/credentials.txt" ] || {
    echo "Refusing rerun: missing $ETCDIR/credentials.txt; cannot safely preserve admin password." >&2
    exit 11
  }
  [ -r "$ETCDIR/tls/ca.key" ] && [ -r "$ETCDIR/tls/ca.crt" ] || {
    echo "Refusing rerun: existing local CA is incomplete; automatic CA rotation is disabled." >&2
    exit 12
  }

  DATABASE_URL="$(env_value DATABASE_URL "$ETCDIR/controller.env" || true)"
  BOOTSTRAP_TOKEN="$(env_value BOOTSTRAP_TOKEN "$ETCDIR/controller.env" || true)"
  SECRET_KEY="$(env_value SECRET_KEY "$ETCDIR/controller.env" || true)"
  ADMIN_PASS="$(credential_value "Web UI" "Password" "$ETCDIR/credentials.txt" || true)"
  DB_PASS="$(credential_value "Database" "Password" "$ETCDIR/credentials.txt" || true)"

  if [ -z "$BOOTSTRAP_TOKEN" ]; then
    BOOTSTRAP_TOKEN="$(bootstrap_from_credentials "$ETCDIR/credentials.txt" || true)"
  fi

  [ -n "$DATABASE_URL" ] || { echo "Refusing rerun: DATABASE_URL is missing." >&2; exit 13; }
  [ -n "$DB_PASS" ] || { echo "Refusing rerun: database password cannot be recovered safely." >&2; exit 14; }
  [ -n "$ADMIN_PASS" ] || { echo "Refusing rerun: admin password cannot be recovered safely." >&2; exit 15; }
  [ -n "$BOOTSTRAP_TOKEN" ] || { echo "Refusing rerun: bootstrap token cannot be recovered safely." >&2; exit 16; }
  [ -n "$SECRET_KEY" ] || { echo "Refusing rerun: SECRET_KEY is missing; automatic rotation is disabled." >&2; exit 17; }
else
  DB_PASS="$(rand_alnum 32)"
  ADMIN_PASS="$(rand_alnum 20)"
  BOOTSTRAP_TOKEN="$(rand_alnum 48)"
  SECRET_KEY="$(rand_alnum 48)"
  DATABASE_URL="postgresql+psycopg://$DB_USER:$DB_PASS@127.0.0.1/$DB_NAME"
fi

echo "[3/10] Preparing service account, backup and staging areas..."
if ! id cybersec >/dev/null 2>&1; then
  useradd --system --home "$DATADIR" --shell /usr/sbin/nologin cybersec
fi
install -d -o cybersec -g cybersec -m 0750 "$DATADIR"
install -d -m 0750 "$BACKUP_BASE"

if [ "$EXISTING_INSTALL" -eq 1 ]; then
  mkdir -p "$BACKUP_DIR"
  backup_path "$APPDIR" "app"
  backup_path "$ETCDIR" "etc"
  backup_path "$DOWNLOADS" "downloads"
  backup_path "$SERVICE_FILE" "cybersecurity-ops.service"
  backup_path "$NGINX_SITE" "nginx-site"
  backup_path "$NGINX_LINK" "nginx-link"
  backup_path "$HTPASSWD_FILE" "htpasswd"
  chmod 0700 "$BACKUP_DIR"
  ROLLBACK_ARMED=1
  echo "Rollback snapshot: $BACKUP_DIR"
fi

rm -rf "$STAGE_APP" "$STAGE_ETC" "$STAGE_DOWNLOADS" "$STAGE_HTPASSWD"
install -d -m 0755 "$STAGE_APP"
install -d -m 0750 "$STAGE_ETC/tls"
install -d -m 0750 "$STAGE_DOWNLOADS"

echo "[4/10] Configuring PostgreSQL..."
systemctl enable --now postgresql

runuser -u postgres -- psql -v ON_ERROR_STOP=1 --set=dbuser="$DB_USER" --set=dbpass="$DB_PASS" --set=dbname="$DB_NAME" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'dbuser', :'dbpass')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'dbuser') \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'dbuser', :'dbpass') \gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'dbname', :'dbuser')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'dbname') \gexec
SQL

echo "[5/10] Building staged controller..."
cp -a "$ROOT/server" "$STAGE_APP/"
cp -a "$ROOT/agent" "$STAGE_APP/"
cp -a "$ROOT/scripts" "$STAGE_APP/"
cp -a "$ROOT/mobile" "$STAGE_APP/"

python3 -m venv "$STAGE_APP/venv"
"$STAGE_APP/venv/bin/pip" install --upgrade pip wheel
"$STAGE_APP/venv/bin/pip" install -r "$STAGE_APP/server/requirements.txt"

cat >"$STAGE_ETC/controller.env" <<EOF
DATABASE_URL=$DATABASE_URL
DOWNLOAD_DIR=$DOWNLOADS
BOOTSTRAP_TOKEN=$BOOTSTRAP_TOKEN
SECRET_KEY=$SECRET_KEY
EOF
chmod 0600 "$STAGE_ETC/controller.env"

cat >"$STAGE_ETC/credentials.txt" <<EOF
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
chmod 0600 "$STAGE_ETC/credentials.txt"

echo "[6/10] Preserving or generating TLS identity..."
if [ "$EXISTING_INSTALL" -eq 1 ]; then
  cp -a "$ETCDIR/tls/." "$STAGE_ETC/tls/"
  echo "Existing CA and server TLS files preserved."
else
  SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [ -n "$SERVER_IP" ] || SERVER_IP="127.0.0.1"
  SERVER_HOST="$(hostname -f 2>/dev/null || hostname)"

  openssl genrsa -out "$STAGE_ETC/tls/ca.key" 3072 >/dev/null 2>&1
  openssl req -x509 -new -key "$STAGE_ETC/tls/ca.key" -sha256 -days 3650 \
    -subj "/CN=Cybersecurity Operations Center Local CA" \
    -out "$STAGE_ETC/tls/ca.crt"
  openssl genrsa -out "$STAGE_ETC/tls/server.key" 3072 >/dev/null 2>&1

  cat >"$STAGE_ETC/tls/server.cnf" <<EOF
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

  openssl req -new -key "$STAGE_ETC/tls/server.key" \
    -out "$STAGE_ETC/tls/server.csr" -config "$STAGE_ETC/tls/server.cnf"
  openssl x509 -req -in "$STAGE_ETC/tls/server.csr" \
    -CA "$STAGE_ETC/tls/ca.crt" -CAkey "$STAGE_ETC/tls/ca.key" -CAcreateserial \
    -out "$STAGE_ETC/tls/server.crt" -days 825 -sha256 \
    -extensions req_ext -extfile "$STAGE_ETC/tls/server.cnf" >/dev/null 2>&1
fi

chmod 0600 "$STAGE_ETC/tls/"*.key
cp "$STAGE_ETC/tls/ca.crt" "$STAGE_DOWNLOADS/controller-ca.crt"

echo "[7/10] Building staged agent packages..."
bash "$STAGE_APP/scripts/build-agents.sh" "$STAGE_DOWNLOADS"
(
  cd "$ROOT/mobile/android"
  zip -qr "$STAGE_DOWNLOADS/cyberagent-android-source.zip" .
)
cp "$ROOT/mobile/ios/CybersecurityAgent.mobileconfig" \
  "$STAGE_DOWNLOADS/cyberagent-ios-mdm-profile.mobileconfig"

chown -R cybersec:cybersec "$STAGE_APP" "$STAGE_DOWNLOADS"
chown root:root "$STAGE_ETC/controller.env" "$STAGE_ETC/credentials.txt"
chown -R root:root "$STAGE_ETC/tls"
htpasswd -b -c "$STAGE_HTPASSWD" admin "$ADMIN_PASS" >/dev/null
chown root:www-data "$STAGE_HTPASSWD"
chmod 0640 "$STAGE_HTPASSWD"

echo "[8/10] Stopping controller and committing staged files..."
if systemctl is-active --quiet cybersecurity-ops 2>/dev/null; then
  systemctl stop cybersecurity-ops
fi

rm -rf "$APPDIR"
mv "$STAGE_APP" "$APPDIR"

rm -rf "$ETCDIR"
mv "$STAGE_ETC" "$ETCDIR"

rm -rf "$DOWNLOADS"
mv "$STAGE_DOWNLOADS" "$DOWNLOADS"
chown -R cybersec:cybersec "$DOWNLOADS"

install -m 0644 "$ROOT/deploy/cybersecurity-ops.service" "$SERVICE_FILE"
install -m 0644 "$ROOT/deploy/nginx.conf" "$NGINX_SITE"
ln -sfn "$NGINX_SITE" "$NGINX_LINK"
rm -f /etc/nginx/sites-enabled/default
install -o root -g www-data -m 0640 "$STAGE_HTPASSWD" "$HTPASSWD_FILE"
rm -f "$STAGE_HTPASSWD"

echo "[9/10] Validating configuration and restarting services..."
nginx -t
systemctl daemon-reload
systemctl enable cybersecurity-ops >/dev/null
systemctl restart cybersecurity-ops
systemctl restart nginx

echo "[10/10] Verifying controller health..."
HEALTH_OK=0
for _ in $(seq 1 20); do
  if curl --fail --silent --show-error http://127.0.0.1:8010/api/health >/tmp/cybersecurity-ops-health.$$ 2>/dev/null; then
    HEALTH_OK=1
    break
  fi
  sleep 1
done

if [ "$HEALTH_OK" -ne 1 ]; then
  echo "Controller failed health verification." >&2
  journalctl -u cybersecurity-ops -n 50 --no-pager >&2 || true
  false
fi

python3 -m json.tool </tmp/cybersecurity-ops-health.$$
rm -f /tmp/cybersecurity-ops-health.$$

INSTALL_COMMITTED=1
trap - ERR INT TERM

SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$SERVER_IP" ] || SERVER_IP="127.0.0.1"

cat <<EOF

==============================================================================
 LINUX CYBERSECURITY OPERATIONS CENTER - XDR & ENDPOINT DEFENSE
==============================================================================

Installation complete.

Mode:
  $([ "$EXISTING_INSTALL" -eq 1 ] && echo "Safe rerun/upgrade (existing secrets and CA preserved)" || echo "Fresh installation")

Web UI:
  https://$SERVER_IP:8443

Admin username:
  admin

Generated/preserved passwords and tokens:
  $ETCDIR/credentials.txt

Database:
  PostgreSQL
  Database: $DB_NAME
  Database user: $DB_USER

Agent downloads:
  https://$SERVER_IP:8443/#downloads

Controller CA:
  https://$SERVER_IP:8443/downloads/controller-ca.crt

$([ "$EXISTING_INSTALL" -eq 1 ] && echo "Rollback snapshot retained at: $BACKUP_DIR" || true)

Keep $ETCDIR/credentials.txt secure. It is mode 0600.

Powered and Development by antonios.mortos@outlook.com
==============================================================================
EOF
