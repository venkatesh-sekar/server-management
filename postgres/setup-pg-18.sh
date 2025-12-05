#!/usr/bin/env bash
#
# PostgreSQL 18 + PgBouncer + pgBackRest + Backblaze B2 backup setup
#
# - [SAFE] Validates OS (Debian/Ubuntu) and all required commands.
# - [SAFE] Validates all user inputs (non-empty, CIDR format).
# - [IDEMPOTENT] Re-uses non-secret settings from /root/.pg_setup.conf on re-run.
# - [IDEMPOTENT] Creates Postgres configs in conf.d/, preventing duplicate settings.
# - [IDEMPOTENT] Saves/re-uses 'postgres' superuser password from /root/.pg_setup_superuser.pass.
# - [IDEMPOTENT] Skips pgBackRest stanza-create if already configured.
# - [IDEMPOTENT] Skips initial full backup if one already exists.
# - [NEW] Allows specifying a custom 'repo-path' (prefix) within the B2 bucket.
# - [NEW] Validates that the 'repo-path' starts with a '/'.
#
set -euo pipefail

# --- Globals ---
B2_ENDPOINT=""
B2_REGION=""
B2_BUCKET=""
PGBR_REPO_PATH=""
B2_KEY=""
B2_SECRET=""
PGBR_PASSPHRASE=""
PG_ALLOWED_CIDR=""
PG_SUPERUSER_PASS=""
PG_VERSION="18"

# --- Config File Paths ---
# Non-secret settings are saved here to pre-fill prompts on re-run
CONFIG_FILE="/root/.pg_setup.conf"
# Superuser password is saved here to ensure idempotency
PASS_FILE="/root/.pg_setup_superuser.pass"

### Helpers ###############################################################

log() {
  echo -e "[\e[32mINFO\e[0m] $*"
}

warn() {
  echo -e "[\e[33mWARN\e[0m] $*" >&2
}

err() {
  echo -e "[\e[31mERROR\e[0m] $*" >&2
}

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    err "This script must be run as root (or with sudo)."
    exit 1
  fi
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    err "Required command '$cmd' not found. Install it and rerun."
    exit 1
  fi
}

check_distro() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    if [[ "$ID" == "ubuntu" || "$ID" == "debian" ]]; then
      log "Verified Debian/Ubuntu-based distribution ($PRETTY_NAME)."
    else
      err "This script is designed for Debian or Ubuntu. Detected $PRETTY_NAME."
      exit 1
    fi
  else
    err "Could not determine OS distribution. /etc/os-release not found."
    exit 1
  fi
}

### Prompt for inputs #####################################################

prompt_inputs() {
  # Load non-secret defaults if config file exists
  if [[ -f "$CONFIG_FILE" ]]; then
    log "Loading previous settings from $CONFIG_FILE..."
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
  fi

  echo
  echo "================= Backblaze B2 (S3) Configuration ================="
  echo "This script uses Backblaze B2 via its S3-compatible API."
  echo

  # Use `while` loops to ensure no critical variable is empty
  while [[ -z "$B2_ENDPOINT" ]]; do
    read -rp "B2 S3 Endpoint [${B2_ENDPOINT:-}]: " B2_ENDPOINT_IN
    B2_ENDPOINT="${B2_ENDPOINT_IN:-$B2_ENDPOINT}"
  done
  while [[ -z "$B2_REGION" ]]; do
    read -rp "B2 S3 Region   [${B2_REGION:-}]: " B2_REGION_IN
    B2_REGION="${B2_REGION_IN:-$B2_REGION}"
  done
  while [[ -z "$B2_BUCKET" ]]; do
    read -rp "B2 S3 Bucket   [${B2_BUCKET:-}]: " B2_BUCKET_IN
    B2_BUCKET="${B2_BUCKET_IN:-$B2_BUCKET}"
  done

  ### MODIFIED ###: Added prompt and validation for B2 repo path
  echo
  echo "You can specify a 'path' (prefix) inside your bucket for this repo."
  echo "This is useful for storing multiple backups in one bucket."
  echo "Example: /postgres/my-server-prod"
  local PGBR_REPO_PATH_DEFAULT="${PGBR_REPO_PATH:-/pgbackrest}"
  while true; do
    read -rp "B2 Repo Path (prefix) in bucket [${PGBR_REPO_PATH_DEFAULT}]: " PGBR_REPO_PATH_IN
    PGBR_REPO_PATH="${PGBR_REPO_PATH_IN:-$PGBR_REPO_PATH_DEFAULT}"
    
    if [[ "$PGBR_REPO_PATH" != /* ]]; then
      warn "Invalid path. Path MUST start with a '/' (e.g., /postgres-backups)."
      # Reset variable so loop continues with the default as the hint
      PGBR_REPO_PATH="$PGBR_REPO_PATH_DEFAULT"
    else
      # Valid, starts with /
      break
    fi
  done
  ### END MODIFIED ###

  while [[ -z "$B2_KEY" ]]; do
    read -rp "B2 S3 Key ID       (Access Key ID): " B2_KEY
  done
  while [[ -z "$B2_SECRET" ]]; do
    read -rsp "B2 S3 Secret       (Secret / Application Key): " B2_SECRET
    echo
  done

  echo
  echo "================= pgBackRest Encryption ==========================="
  while [[ -z "$PGBR_PASSPHRASE" ]]; do
    read -rsp "pgBackRest repo encryption passphrase (keep this safe!): " PGBR_PASSPHRASE
    echo
  done

  echo
  echo "================= PgBouncer Network Access ========================"
  local cidr_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])$"
  local PG_ALLOWED_CIDR_DEFAULT="${PG_ALLOWED_CIDR:-0.0.0.0/0}"
  while true; do
    read -rp "CIDR allowed to access PgBouncer (default: $PG_ALLOWED_CIDR_DEFAULT): " PG_ALLOWED_CIDR_IN
    PG_ALLOWED_CIDR="${PG_ALLOWED_CIDR_IN:-$PG_ALLOWED_CIDR_DEFAULT}"
    if [[ "$PG_ALLOWED_CIDR" =~ $cidr_regex ]]; then
      break
    else
      warn "Invalid CIDR format. Please use format X.X.X.X/Y (e.g., 10.0.0.0/16)."
      # Reset variable so the loop continues with the default
      PG_ALLOWED_CIDR="$PG_ALLOWED_CIDR_DEFAULT"
    fi
  done

  # Save non-secret settings for next run
  log "Saving non-secret config to $CONFIG_FILE..."
  cat >"$CONFIG_FILE" <<EOF
# Non-secret settings for pg-setup script
B2_ENDPOINT="$B2_ENDPOINT"
B2_REGION="$B2_REGION"
B2_BUCKET="$B2_BUCKET"
PGBR_REPO_PATH="$PGBR_REPO_PATH" ### MODIFIED ###: Save the new path
PG_ALLOWED_CIDR="$PG_ALLOWED_CIDR"
EOF
  chmod 600 "$CONFIG_FILE"

  echo
  echo "================= Confirm Settings ================================"
  cat <<EOF
Backblaze B2:
  Endpoint : $B2_ENDPOINT
  Region   : $B2_REGION
  Bucket   : $B2_BUCKET
  Repo Path: $PGBR_REPO_PATH
  Key ID   : $B2_KEY

pgBackRest:
  Encrypted repo with AES-256 (passphrase NOT shown here)

PgBouncer:
  Allowed CIDR for port 6432: $PG_ALLOWED_CIDR
  (You must set this in your *external* firewall)
EOF

  read -rp "Continue with installation? [y/N]: " CONFIRM
  CONFIRM="${CONFIRM:-n}"
  if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    err "Aborting as requested."
    exit 1
  fi
}

### Install dependencies ###################################################

install_packages() {
  log "Updating system packages..."
  apt-get update -y
  # Only run upgrade if explicitly asked, or comment out. For a fresh VM it's fine.
  # apt-get upgrade -y

  log "Installing base packages..."
  apt-get install -y curl wget ca-certificates gnupg lsb-release logrotate openssl

  log "Configuring PostgreSQL PGDG repository..."
  local codename
  codename=$(lsb_release -cs)

  # Import PGDG key
  curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    | gpg --dearmor \
    | tee /usr/share/keyrings/postgresql.gpg >/dev/null

  echo "deb [signed-by=/usr/share/keyrings/postgresql.gpg] http://apt.postgresql.org/pub/repos/apt ${codename}-pgdg main" \
    > /etc/apt/sources.list.d/pgdg.list

  apt-get update -y

  log "Installing PostgreSQL ${PG_VERSION}, PgBouncer, and pgBackRest..."
  apt-get install -y "postgresql-${PG_VERSION}" pgbouncer pgbackrest

  log "Ensuring system users exist..."
  # The postgres package *definitely* creates this user.
  # The pgbouncer package *should* create this user, but we'll ensure it
  # just in case of a minimal environment or package post-install failure.
  if ! getent group pgbouncer >/dev/null; then
    log "Creating system group 'pgbouncer'..."
    addgroup --system pgbouncer
  fi
  if ! id -u pgbouncer >/dev/null 2>&1; then
    log "Creating system user 'pgbouncer'..."
    adduser --system --no-create-home --ingroup pgbouncer --disabled-password --disabled-login pgbouncer
  fi

  log "Ensuring directories for pgBackRest exist..."
  mkdir -p /etc/pgbackrest /etc/pgbackrest/conf.d /var/lib/pgbackrest /var/log/pgbackrest
  chown -R postgres:postgres /var/lib/pgbackrest /var/log/pgbackrest /etc/pgbackrest
  chmod 750 /var/lib/pgbackrest
  chmod 750 /var/log/pgbackrest
  # 700 is more secure for the config directory
  chmod 700 /etc/pgbackrest /etc/pgbackrest/conf.d
}

### Tune Postgres #########################################################

tune_postgres() {
  log "Tuning PostgreSQL ${PG_VERSION} configuration for dedicated server..."

  local PG_CONF_DIR="/etc/postgresql/${PG_VERSION}/main"
  local PG_TUNE_CONF="${PG_CONF_DIR}/conf.d/99-tuning.conf"
  mkdir -p "${PG_CONF_DIR}/conf.d"

  # Get system memory in KB and calculate tuning parameters
  local total_mem_kb
  total_mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
  local total_mem_mb=$((total_mem_kb / 1024))

  # 25% of RAM for shared_buffers
  local shared_buffers_mb=$((total_mem_mb / 4))
  # 75% of RAM for effective_cache_size
  local effective_cache_size_mb=$((total_mem_mb * 3 / 4))
  # 1GB for maintenance_work_mem (or 1/8 RAM if smaller)
  local maintenance_work_mem_mb=$((total_mem_mb / 8))
  if [[ $maintenance_work_mem_mb -gt 1024 ]]; then
    maintenance_work_mem_mb=1024
  fi
  # Set reasonable 2GB max for safety
  if [[ $maintenance_work_mem_mb -gt 2048 ]]; then
    maintenance_work_mem_mb=2048
  fi

  log "VM has ${total_mem_mb}MB RAM. Applying tuning..."
  log "  shared_buffers = ${shared_buffers_mb}MB"
  log "  effective_cache_size = ${effective_cache_size_mb}MB"
  log "  maintenance_work_mem = ${maintenance_work_mem_mb}MB"

  # Write settings to a separate .conf file. This is idempotent.
  log "Writing tuning config to $PG_TUNE_CONF"
  cat >"$PG_TUNE_CONF" <<EOF
# ---- Added by setup script for production tuning ----
shared_buffers = ${shared_buffers_mb}MB
effective_cache_size = ${effective_cache_size_mb}MB
maintenance_work_mem = ${maintenance_work_mem_mb}MB
work_mem = 32MB
wal_buffers = -1
min_wal_size = 1GB
max_wal_size = 4GB
checkpoint_completion_target = 0.9
random_page_cost = 1.1
default_statistics_target = 100
max_connections = 100
EOF
  chown postgres:postgres "$PG_TUNE_CONF"
  chmod 640 "$PG_TUNE_CONF"
}

### Configure Postgres (PITR-ready) #######################################

configure_postgres() {
  log "Configuring PostgreSQL ${PG_VERSION} for PITR & PgBouncer..."

  local PG_CONF_DIR="/etc/postgresql/${PG_VERSION}/main"
  local PG_PGBR_CONF="${PG_CONF_DIR}/conf.d/98-pgbackrest.conf"
  mkdir -p "${PG_CONF_DIR}/conf.d"

  if [[ ! -d "$PG_CONF_DIR" ]]; then
    err "Postgres ${PG_VERSION} config directory not found at $PG_CONF_DIR"
    exit 1
  fi

  # Ensure Postgres listens ONLY on localhost (PgBouncer will handle external)
  # This setting is best left in the main postgresql.conf
  log "Setting listen_addresses = '127.0.0.1' in postgresql.conf"
  sed -i "s/^#\?listen_addresses.*/listen_addresses = '127.0.0.1'/" "${PG_CONF_DIR}/postgresql.conf"

  # WAL and archive settings for pgBackRest (idempotent)
  log "Writing archive config to $PG_PGBR_CONF"
  cat >"$PG_PGBR_CONF" <<EOF
# ---- Added by pgBackRest+B2 setup script ----
wal_level = replica
archive_mode = on
archive_command = 'pgbackrest --stanza=main archive-push %p'
max_wal_senders = 3
wal_compression = on
EOF
  chown postgres:postgres "$PG_PGBR_CONF"
  chmod 640 "$PG_PGBR_CONF"

  # pg_hba.conf: allow PgBouncer to connect locally
  # We clear the file and write a secure-by-default config (idempotent)
  log "Writing secure pg_hba.conf (localhost only)"
  cat >"${PG_CONF_DIR}/pg_hba.conf" <<EOF
# PostgreSQL Client Authentication Configuration File
#
# Production config: only allow local socket and local TCP/IP
#
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             postgres                                peer
local   all             all                                     peer
host    all             all             127.0.0.1/32            scram-sha-256
host    replication     postgres        127.0.0.1/32            scram-sha-256
EOF

  # Restart Postgres
  log "Restarting PostgreSQL ${PG_VERSION} to apply all settings..."
  systemctl restart "postgresql@${PG_VERSION}-main.service"

  log "Verifying PostgreSQL is running..."
  # Give it a second to start up
  sleep 3
  if ! systemctl is-active --quiet "postgresql@${PG_VERSION}-main.service"; then
    err "PostgreSQL ${PG_VERSION} service is not running. Check logs:"
    err "journalctl -u postgresql@${PG_VERSION}-main.service"
    exit 1
  fi
  log "PostgreSQL is active."
}

### Secure Postgres Superuser #############################################

secure_postgres_user() {
  # This function is now idempotent. It saves the password to $PASS_FILE.
  # On re-run, it re-uses the password.
  if [[ -f "$PASS_FILE" ]]; then
    log "Re-using existing 'postgres' user password from $PASS_FILE."
    PG_SUPERUSER_PASS=$(cat "$PASS_FILE")
    if [[ -z "$PG_SUPERUSER_PASS" ]]; then
      err "Password file $PASS_FILE is empty. Please remove it and re-run."
      exit 1
    fi
  else
    log "Generating and setting a secure password for 'postgres' DB user..."
    PG_SUPERUSER_PASS=$(openssl rand -base64 32)
    if [[ -z "$PG_SUPERUSER_PASS" ]]; then
      err "Failed to generate password."
      exit 1
    fi

    # Use parameterized query to prevent any injection issues
    sudo -u postgres psql -v ON_ERROR_STOP=1 -v pass="$PG_SUPERUSER_PASS" <<'EOSQL'
SELECT set_config('var.pass', :'pass', false);
DO $$
BEGIN
  EXECUTE format('ALTER USER postgres WITH PASSWORD %L', current_setting('var.pass'));
END
$$;
EOSQL

    log "Saving password to $PASS_FILE for idempotency..."
    echo "${PG_SUPERUSER_PASS}" >"$PASS_FILE"
    chmod 600 "$PASS_FILE"
  fi
}

### Configure PgBouncer ###################################################

configure_pgbouncer() {
  log "Configuring PgBouncer (Port 6432)..."

  mkdir -p /etc/pgbouncer

  # Detect service user/group from systemd, fall back to 'pgbouncer'
  local svc_user svc_group
  svc_user=$(systemctl show -p User pgbouncer.service 2>/dev/null | cut -d= -f2)
  svc_group=$(systemctl show -p Group pgbouncer.service 2>/dev/null | cut -d= -f2)

  [[ -z "$svc_user" || "$svc_user" == "root" ]] && svc_user="pgbouncer"
  [[ -z "$svc_group" || "$svc_group" == "root" ]] && svc_group="$svc_user"

  log "PgBouncer service will run as ${svc_user}:${svc_group}"

  # Directory permissions
  chown root:root /etc/pgbouncer
  chmod 755 /etc/pgbouncer

  # userlist.txt – readable by service user
  echo "\"postgres\" \"${PG_SUPERUSER_PASS}\"" > /etc/pgbouncer/userlist.txt
  chown "${svc_user}:${svc_group}" /etc/pgbouncer/userlist.txt
  chmod 640 /etc/pgbouncer/userlist.txt

  # pgbouncer.ini
  cat > /etc/pgbouncer/pgbouncer.ini <<EOF
[databases]
* = host=127.0.0.1 port=5432

[pgbouncer]
listen_port = 6432
listen_addr = 0.0.0.0

; auth
auth_type = scram-sha-256
auth_file = /etc/pgbouncer/userlist.txt
pidfile = /run/pgbouncer/pgbouncer.pid
admin_users = postgres
stats_users = postgres

; Production tuning
pool_mode = transaction
server_reset_query = DISCARD ALL
max_client_conn = 1000
default_pool_size = 20
min_pool_size = 5
reserve_pool_size = 5
EOF

  chown "${svc_user}:${svc_group}" /etc/pgbouncer/pgbouncer.ini
  chmod 640 /etc/pgbouncer/pgbouncer.ini

  # /run/pgbouncer for PID file
  log "Ensuring /run/pgbouncer directory exists for PID file..."
  mkdir -p /run/pgbouncer
  chown "${svc_user}:${svc_group}" /run/pgbouncer
  chmod 755 /run/pgbouncer

  warn "ACTION REQUIRED: You MUST configure your external firewall to allow port 6432 from ${PG_ALLOWED_CIDR}."

  log "Restarting PgBouncer..."
  systemctl restart pgbouncer.service
  systemctl enable pgbouncer.service

  log "Verifying PgBouncer is running..."
  sleep 2
  if ! systemctl is-active --quiet "pgbouncer.service"; then
    err "PgBouncer service is not running. Check logs with: journalctl -xeu pgbouncer.service"
    exit 1
  fi
  log "PgBouncer is active."
}

### Configure pgBackRest with B2 (S3) #####################################

configure_pgbackrest() {
  log "Writing pgBackRest configuration..."

  # Securely store the encryption passphrase (idempotent)
  local PGBR_PASS_FILE="/etc/pgbackrest/repo1.pass"
  echo "${PGBR_PASSPHRASE}" >"${PGBR_PASS_FILE}"
  chown postgres:postgres "${PGBR_PASS_FILE}"
  chmod 600 "${PGBR_PASS_FILE}"

  # Write main config (idempotent)
  cat >/etc/pgbackrest/pgbackrest.conf <<EOF
[global]
repo1-type=s3
repo1-path=${PGBR_REPO_PATH}
repo1-s3-bucket=${B2_BUCKET}
repo1-s3-endpoint=${B2_ENDPOINT}
repo1-s3-region=${B2_REGION}
repo1-s3-key=${B2_KEY}
repo1-s3-key-secret=${B2_SECRET}
repo1-s3-uri-style=path

# Performance & storage tuning
start-fast=y
process-max=4
compress-type=lz4
compress-level=3
repo1-block=y
repo1-bundle=y

# Retention policy: Keep 1 year of weekly full backups
repo1-retention-full=53
repo1-retention-archive=60

# Encrypt backups at rest (SECURELY)
repo1-cipher-type=aes-256-cbc
repo1-cipher-pass="cat ${PGBR_PASS_FILE}"

[main]
pg1-path=/var/lib/postgresql/${PG_VERSION}/main
pg1-user=postgres
EOF

  chown postgres:postgres /etc/pgbackrest/pgbackrest.conf
  chmod 600 /etc/pgbackrest/pgbackrest.conf

  # Make stanza creation idempotent
  log "Checking pgBackRest stanza 'main'..."
  # We use `check` which will return non-zero if stanza is invalid or missing
  # `|| true` prevents `set -e` from exiting if the check fails (which we expect)
  if sudo -u postgres pgbackrest --stanza=main --log-level-console=warn check &>/dev/null; then
    log "pgBackRest stanza 'main' already exists and is valid. Skipping create."
  else
    log "pgBackRest stanza 'main' not found or invalid. Creating..."
    # This command *requires* Postgres to be running with archive_mode=on
    sudo -u postgres pgbackrest --stanza=main --log-level-console=info stanza-create
    log "Verifying new stanza..."
    # This check *should* pass now. If it fails, `set -e` will stop the script.
    sudo -u postgres pgbackrest --stanza=main --log-level-console=info check
  fi
}

### Initial full backup ####################################################

run_initial_backup() {
  # Make initial backup idempotent
  log "Checking for existing full backup..."
  # `pgbackrest info` returns non-zero if no backups exist.
  # We must disable `set -e` for this check.
  set +e
  sudo -u postgres pgbackrest --stanza=main info | grep -q 'backup:full'
  local backup_exists=$?
  set -e # Re-enable exit on error

  if [[ $backup_exists -eq 0 ]]; then
    log "A full backup already exists. Skipping initial backup."
  else
    log "No full backup found. Running initial FULL backup (this may take time)..."
    sudo -u postgres pgbackrest --stanza=main --type=full --log-level-console=info backup
    log "Initial full backup completed."
  fi
}

### Backup scheduling (cron + wrapper) ####################################

install_backup_scheduler() {
  log "Installing backup wrapper script and cron schedules..."

  # Wrapper script (idempotent)
  cat >/usr/local/sbin/pgbackrest-run.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

STANZA="main"
LOG_DIR="/var/log/pgbackrest"
mkdir -p "$LOG_DIR" # This will be run as postgres, ensure perms

run_backup() {
  local type="$1"
  local now
  now="$(date +'%Y-%m-%d %H:%M:%S')"

  local logfile="${LOG_DIR}/backup-${type}.log"

  echo "[$now] Starting ${type} backup" >> "$logfile"

  # No sudo needed, cron job runs this as postgres user
  pgbackrest --stanza="$STANZA" --type="$type" --log-level-console=info backup >> "$logfile" 2>&1

  now="$(date +'%Y-%m-%d %H:%M:%S')"
  echo "[$now] Completed ${type} backup" >> "$logfile"
}

case "${1:-}" in
  hourly)
    run_backup incr
    ;;
  daily)
    run_backup diff
    ;;
  weekly)
    run_backup full
    ;;
  *)
    echo "Usage: $0 {hourly|daily|weekly}" >&2
    exit 1
    ;;
esac
EOF

  chmod 750 /usr/local/sbin/pgbackrest-run.sh
  # Fix wrapper script permission and remove sudo
  log "Setting wrapper script permissions for 'postgres' user execution..."
  chown postgres:postgres /usr/local/sbin/pgbackrest-run.sh

  # Cron schedule (idempotent)
  cat >/etc/cron.d/pgbackrest-schedule <<EOF
# pgBackRest backup schedule
# m h dom mon dow user command

# Hourly incremental
5 * * * * postgres /usr/local/sbin/pgbackrest-run.sh hourly

# Daily differential
15 2 * * * postgres /usr/local/sbin/pgbackrest-run.sh daily

# Weekly full (Sunday)
0 3 * * 0 postgres /usr/local/sbin/pgbackrest-run.sh weekly
EOF

  chmod 644 /etc/cron.d/pgbackrest-schedule

  log "Backup schedules installed under /etc/cron.d/pgbackrest-schedule"
}

### Log rotation ##########################################################

setup_log_rotation() {
  log "Setting up log rotation for pgBackRest logs..."
  # (idempotent)
  cat >/etc/logrotate.d/pgbackrest <<EOF
/var/log/pgbackrest/*.log {
  daily
  rotate 14
  compress
  delaycompress
  missingok
  notifempty
  create 640 postgres postgres
}
EOF
}

### Main ###################################################################

main() {
  # --- Initial Validation ---
  require_root
  check_distro
  require_cmd "lsb_release"
  require_cmd "curl"
  require_cmd "gpg"
  require_cmd "openssl"

  # --- Configuration ---
  prompt_inputs

  # --- Installation & Setup ---
  install_packages
  tune_postgres
  configure_postgres # Restarts PG
  secure_postgres_user
  configure_pgbouncer # Restarts PGBouncer
  configure_pgbackrest
  run_initial_backup
  install_backup_scheduler
  setup_log_rotation

  # --- Final Summary ---
  echo
  echo "==================================================================="
  echo "✅ PostgreSQL ${PG_VERSION} + PgBouncer + B2 backup setup complete!"
  echo
  echo "!!!!!!!!!!!!! 🚨 CRITICAL: SAVE THIS PASSWORD 🚨 !!!!!!!!!!!!!"
  echo
  if [[ -f "$PASS_FILE" ]]; then
    echo "  The database superuser 'postgres' password is:"
    echo "  $(cat $PASS_FILE)"
    echo
    echo "  (This is stored in $PASS_FILE for re-runs.)"
    echo "  (You can delete this file after saving the password.)"
  else
    err "Could not read superuser password from $PASS_FILE. Check logs."
  fi
  echo
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  echo
  echo "Key details:"
  echo "  - Connect to DB via PgBouncer: Port 6432"
  echo "  - Postgres Port (local only):  Port 5432"
  echo "  - Postgres data dir:           /var/lib/postgresql/${PG_VERSION}/main"
  echo "  - pgBackRest config:           /etc/pgbackrest/pgbackrest.conf"
  echo "  - pgBackRest B2 Repo Path:     ${B2_BUCKET}${PGBR_REPO_PATH}" ### MODIFIED ###
  echo "  - Backup logs (rotated):       /var/log/pgbackrest/"
  echo
  echo "🔥 IMMEDIATE ACTION REQUIRED: FIREWALL 🔥"
  echo
  echo "  You MUST now configure your Hetzner (or other) firewall."
  echo "  Allow incoming traffic:"
  echo "    - Port 22/tcp (SSH):           From your IP only"
  echo "    - Port 6432/tcp (PgBouncer): From your application server CIDR (${PG_ALLOWED_CIDR})"
  echo
  echo "  DO NOT expose port 5432 (PostgreSQL) to the internet."
  echo
  echo "Actions recommended next:"
  echo "  1) On a separate VM, test a full restore from B2 end-to-end."
  # === FIX APPLIED HERE: Replaced unbound variable ===
  echo "  2) Monitor your app, tune 'work_mem' in /etc/postgresql/${PG_VERSION}/main/conf.d/99-tuning.conf"
  echo "==================================================================="
}

# Run main, passing all script arguments
main "$@"