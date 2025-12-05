#!/usr/bin/env bash
#
# Create a new PostgreSQL database + user and wire it into PgBouncer.
# PROD-READY VERSION [SCRAM-SHA-256 SUPPORTED]
#
# - [SAFE] SQL Injection proof (uses set_config).
# - [SECURE] Uses SCRAM-SHA-256 and fetches hash from pg_authid; PgBouncer never sees plaintext.
# - [HARDENED] Least-privilege roles + schema hardening.
# - [ATOMIC] Updates PgBouncer configs via temp files + mv.
# - [VERIFIED] Tests direct DB connection before touching PgBouncer.
#
set -euo pipefail

# --- Defaults / Globals ----------------------------------------------------

PG_VERSION="${PG_VERSION:-}"             # If empty, auto-detected (mainly sanity check)
PG_HOST="${PG_HOST:-127.0.0.1}"          # Postgres backend host
PG_PORT="${PG_PORT:-5432}"               # Postgres backend port

PASS_DIR="${PASS_DIR:-/root}"            # Where we store per-db/user password files (root-only)
PGB_USERLIST="/etc/pgbouncer/userlist.txt"
PGB_INI="/etc/pgbouncer/pgbouncer.ini"

DB_NAME="${DB_NAME:-}"
DB_USER="${DB_USER:-}"
DB_PASS="${DB_PASS:-}"                   # Optional; if empty, auto-generated / re-used
ROTATE_PASSWORD="${ROTATE_PASSWORD:-false}"

# --- Helpers ---------------------------------------------------------------

log()  { echo -e "[\e[32mINFO\e[0m] $*"; }
warn() { echo -e "[\e[33mWARN\e[0m] $*" >&2; }
err()  { echo -e "[\e[31mERROR\e[0m] $*" >&2; }

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    err "This script must be run as root (or with sudo)."
    exit 1
  fi
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    err "Required command '$cmd' not found. Please install it and rerun."
    exit 1
  fi
}

detect_pg_version() {
  if [[ -n "$PG_VERSION" ]]; then return; fi
  if [[ ! -d /etc/postgresql ]]; then
    err "/etc/postgresql directory not found. Is PostgreSQL installed?"
    exit 1
  fi
  PG_VERSION="$(ls /etc/postgresql | sort -n | tail -1 || true)"
  if [[ -z "$PG_VERSION" ]]; then
    err "Could not auto-detect PostgreSQL version."
    exit 1
  fi
  log "Auto-detected PostgreSQL version: $PG_VERSION"
}

validate_ident() {
  local ident="$1"
  local type="$2"
  if [[ ! "$ident" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
    err "Invalid $type name '$ident'. Use letters, digits, underscore; must not start with a digit."
    exit 1
  fi
}

prompt_if_empty() {
  local var_name="$1"
  local prompt="$2"
  local value="${!var_name:-}"
  if [[ -z "$value" ]]; then
    read -rp "$prompt: " value
    [[ -z "$value" ]] && { err "Value cannot be empty."; exit 1; }
    eval "$var_name=\"\$value\""
  fi
}

get_pgbouncer_service_user() {
  local svc_user svc_group
  svc_user=$(systemctl show -p User pgbouncer.service 2>/dev/null | cut -d= -f2)
  svc_group=$(systemctl show -p Group pgbouncer.service 2>/dev/null | cut -d= -f2)
  [[ -z "$svc_user" || "$svc_user" == "root" ]] && svc_user="pgbouncer"
  [[ -z "$svc_group" || "$svc_group" == "root" ]] && svc_group="$svc_user"
  echo "$svc_user:$svc_group"
}

# --- Core Logic ------------------------------------------------------------

prepare_inputs() {
  prompt_if_empty "DB_NAME" "Enter new database name"
  prompt_if_empty "DB_USER" "Enter new database user (owner) name"
  validate_ident "$DB_NAME" "database"
  validate_ident "$DB_USER" "user"

  echo
  echo "================= Confirm Settings ================="
  echo "Database Name:  $DB_NAME"
  echo "Database User:  $DB_USER"
  echo "Postgres Host:  $PG_HOST:$PG_PORT"
  echo "Password Rotation: $ROTATE_PASSWORD"
  echo "====================================================="
  echo

  read -rp "Continue with provisioning? [y/N]: " CONFIRM
  CONFIRM="${CONFIRM:-n}"
  if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    err "Aborting as requested."
    exit 1
  fi
}

ensure_password() {
  local pass_file="${PASS_DIR}/.pg_${DB_NAME}_${DB_USER}.pass"
  
  if [[ "$ROTATE_PASSWORD" == "true" ]]; then
    warn "ROTATE_PASSWORD=true -> existing password will be replaced."
    DB_PASS=""
  fi

  if [[ -z "$DB_PASS" && -f "$pass_file" ]]; then
    log "Re-using existing plain-text password from $pass_file"
    DB_PASS="$(cat "$pass_file")"
  fi

  if [[ -z "$DB_PASS" ]]; then
    log "Generating new strong password for role '$DB_USER'..."
    DB_PASS="$(openssl rand -base64 32)"
  fi

  # Save password securely (root-only)
  touch "$pass_file"
  chmod 600 "$pass_file"
  echo "$DB_PASS" > "$pass_file"
  log "Plain-text password saved to: $pass_file (use this for tools like PgAdmin / direct connections)"
}

create_or_update_role() {
  log "Ensuring DB role '$DB_USER' exists (SCRAM-SHA-256)..."
  
  sudo -u postgres psql -v ON_ERROR_STOP=1 \
       -v user_name="$DB_USER" \
       -v user_pass="$DB_PASS" <<EOF
-- Force SCRAM-SHA-256 just for this session, regardless of postgresql.conf
SET password_encryption = 'scram-sha-256';

SELECT set_config('var.user_name', :'user_name', false);
SELECT set_config('var.user_pass', :'user_pass', false);

DO \$$
DECLARE
  _user text := current_setting('var.user_name');
  _pass text := current_setting('var.user_pass');
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = _user) THEN
     EXECUTE format(
       'CREATE ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION',
       _user, _pass
     );
     RAISE NOTICE 'Role created.';
  ELSE
     EXECUTE format('ALTER ROLE %I WITH LOGIN PASSWORD %L', _user, _pass);
     RAISE NOTICE 'Role updated.';
  END IF;
END
\$$;
EOF
}

create_or_update_db() {
  log "Ensuring database '$DB_NAME' exists..."
  
  local exists
  exists=$(sudo -u postgres psql -qtAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'")

  if [[ "$exists" != "1" ]]; then
    log "Creating database '$DB_NAME'..."
    sudo -u postgres psql -v ON_ERROR_STOP=1 <<EOF
CREATE DATABASE "${DB_NAME}" OWNER "${DB_USER}";
EOF
  else
    log "Database exists. Ensuring ownership..."
    sudo -u postgres psql -v ON_ERROR_STOP=1 <<EOF
ALTER DATABASE "${DB_NAME}" OWNER TO "${DB_USER}";
EOF
  fi

  log "Hardening public schema..."
  sudo -u postgres psql -v ON_ERROR_STOP=1 -v db_name="$DB_NAME" -v db_user="$DB_USER" --dbname="$DB_NAME" <<EOF
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE :"db_name" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db_name" TO :"db_user";
GRANT USAGE, CREATE ON SCHEMA public TO :"db_user";
EOF
}

verify_connection() {
  log "Verifying direct connection as user '$DB_USER' to database '$DB_NAME'..."
  if ! PGPASSWORD="$DB_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1" >/dev/null 2>&1; then
    err "Verification failed! Could not connect to DB '$DB_NAME' as user '$DB_USER'."
    err "Check pg_hba.conf to ensure this user/host combination is allowed,"
    err "and confirm that Postgres is listening on ${PG_HOST}:${PG_PORT}."
    exit 1
  fi
  log "Direct connection verification successful."
}

atomic_update_pgbouncer_userlist() {
  log "Updating PgBouncer userlist with SCRAM hash (atomic)..."
  if [[ ! -f "$PGB_USERLIST" ]]; then
    err "$PGB_USERLIST not found. Is PgBouncer installed and configured?"
    exit 1
  fi

  # 1. Fetch the SCRAM secret from Postgres
  local scram_secret
  scram_secret=$(sudo -u postgres psql -qtAc "SELECT rolpassword FROM pg_authid WHERE rolname='${DB_USER}'")

  if [[ -z "$scram_secret" ]]; then
    err "Could not retrieve rolpassword from pg_authid for role '${DB_USER}'."
    err "Did role creation succeed? Is Postgres using password_encryption='scram-sha-256'?"
    exit 1
  fi

  # Validate that this is actually a SCRAM-SHA-256 secret
  if [[ ! "$scram_secret" =~ ^SCRAM-SHA-256\$ ]]; then
    err "Retrieved rolpassword for '${DB_USER}' is not SCRAM-SHA-256 (prefix: '${scram_secret%%\$*}')."
    err "Ensure password_encryption='scram-sha-256' and that the role's password was just updated."
    exit 1
  fi

  log "Retrieved SCRAM secret from DB for '${DB_USER}' (prefix: ${scram_secret:0:20}...)"

  local svc_user svc_group
  IFS=":" read -r svc_user svc_group <<< "$(get_pgbouncer_service_user)"

  local tmp_file
  tmp_file=$(mktemp)

  cp "$PGB_USERLIST" "$tmp_file"

  # Escape for use in sed replacement
  local esc_secret
  esc_secret=$(printf '%s\n' "$scram_secret" | sed 's/[\/&]/\\&/g')

  if grep -qE "^\"${DB_USER}\"" "$tmp_file"; then
    sed -i "s/^\"${DB_USER}\".*/\"${DB_USER}\" \"${esc_secret}\"/" "$tmp_file"
  else
    echo "\"${DB_USER}\" \"${scram_secret}\"" >> "$tmp_file"
  fi

  chown "$svc_user:$svc_group" "$tmp_file"
  chmod 640 "$tmp_file"
  mv "$tmp_file" "$PGB_USERLIST"
}

atomic_update_pgbouncer_databases() {
  log "Updating PgBouncer database mapping (atomic)..."
  if [[ ! -f "$PGB_INI" ]]; then
    err "$PGB_INI not found. Is PgBouncer installed and configured?"
    exit 1
  fi

  local svc_user svc_group
  IFS=":" read -r svc_user svc_group <<< "$(get_pgbouncer_service_user)"

  local tmp_file
  tmp_file=$(mktemp)

  # Start from current config
  cp "$PGB_INI" "$tmp_file"

  # Ensure [databases] section exists
  if ! grep -q "^\[databases\]" "$tmp_file"; then
    # Prepend [databases] at top
    {
      echo "[databases]"
      echo
      cat "$tmp_file"
    } > "${tmp_file}.new"
    mv "${tmp_file}.new" "$tmp_file"
  fi

  local desired="${DB_NAME} = host=${PG_HOST} port=${PG_PORT} dbname=${DB_NAME}"
  local esc_desired
  esc_desired=$(printf '%s\n' "$desired" | sed 's/[\/&]/\\&/g')

  # If entry exists, replace; otherwise, insert after [databases]
  if grep -qE "^${DB_NAME}[[:space:]]*=" "$tmp_file"; then
    sed -i "s/^${DB_NAME}[[:space:]]*=.*/${esc_desired}/" "$tmp_file"
  else
    # Insert right after the [databases] header
    awk -v dbline="$desired" '
      BEGIN {added=0}
      /^\[databases\]/ {
        print
        if (!added) { print dbline; added=1; next }
      }
      {print}
    ' "$tmp_file" > "${tmp_file}.new"
    mv "${tmp_file}.new" "$tmp_file"
  fi

  chown "$svc_user:$svc_group" "$tmp_file"
  chmod 640 "$tmp_file"
  mv "$tmp_file" "$PGB_INI"
}

reload_pgbouncer() {
  log "Reloading PgBouncer..."
  if systemctl reload pgbouncer.service 2>/dev/null; then
    log "PgBouncer reloaded successfully."
  else
    warn "Reload failed, attempting restart..."
    systemctl restart pgbouncer.service
  fi
  
  if ! systemctl is-active --quiet pgbouncer.service; then
    err "PgBouncer is inactive after reload/restart. Check logs:"
    err "  journalctl -xeu pgbouncer.service"
    exit 1
  fi
}

summary() {
  echo
  echo "==================================================================="
  echo "✅ Database & user provisioning complete"
  echo "==================================================================="
  echo "Database:       $DB_NAME"
  echo "DB User:        $DB_USER"
  echo "PgBouncer:      Port 6432 (host: <your-pgbouncer-host>)"
  echo "Direct DB:      ${PG_HOST}:${PG_PORT}"
  echo "-------------------------------------------------------------------"
  echo "Example direct connection (Postgres):"
  echo "  postgres://$DB_USER:***@${PG_HOST}:${PG_PORT}/$DB_NAME"
  echo "-------------------------------------------------------------------"
  echo "⚠️ IMPORTANT: Use the password below for tools like PgAdmin or psql."
  echo "   PgBouncer uses the internal SCRAM hash fetched from Postgres."
  echo "-------------------------------------------------------------------"
  echo "PASSWORD:       $DB_PASS"
  echo "Password file:  ${PASS_DIR}/.pg_${DB_NAME}_${DB_USER}.pass"
  echo "==================================================================="
}

# --- Main -----------------------------------------------------------------

main() {
  require_root
  require_cmd "psql"
  require_cmd "openssl"
  require_cmd "systemctl"
  detect_pg_version

  prepare_inputs
  ensure_password
  create_or_update_role
  create_or_update_db
  verify_connection
  atomic_update_pgbouncer_userlist
  atomic_update_pgbouncer_databases
  reload_pgbouncer
  summary
}

main "$@"