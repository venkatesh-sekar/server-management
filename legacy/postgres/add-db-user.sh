#!/usr/bin/env bash
#
# PostgreSQL User & Database Management Tool
# PROD-READY VERSION [SCRAM-SHA-256 SUPPORTED]
#
# A modular, production-ready script for managing PostgreSQL databases and users.
#
# Features:
#   - Multiple operation modes (create DB+user, read-only users, standalone DB/user)
#   - SCRAM-SHA-256 authentication (fetches hash from pg_authid)
#   - SQL injection protection (uses set_config for parameterization)
#   - Atomic PgBouncer config updates
#   - Least-privilege role creation
#   - Password rotation support
#   - Dry-run mode for testing
#
# Usage: ./add-db-user.sh <command> [options]
#
# Commands:
#   create-db-user     Create a new database with an owner user (full access)
#   create-readonly    Create a read-only user for an existing database
#   create-database    Create a database only (assign to existing user)
#   create-user        Create a user only (no database)
#   grant-access       Grant a user access to an existing database
#   rotate-password    Rotate password for an existing user
#   list-databases     List all databases
#   list-users         List all users
#   help               Show this help message
#
set -euo pipefail

# =============================================================================
# CONFIGURATION & DEFAULTS
# =============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="2.0.0"

# PostgreSQL settings
PG_VERSION="${PG_VERSION:-}"
PG_HOST="${PG_HOST:-127.0.0.1}"
PG_PORT="${PG_PORT:-5432}"

# Password storage
PASS_DIR="${PASS_DIR:-/root}"

# PgBouncer settings
PGB_USERLIST="${PGB_USERLIST:-/etc/pgbouncer/userlist.txt}"
PGB_INI="${PGB_INI:-/etc/pgbouncer/pgbouncer.ini}"
SKIP_PGBOUNCER="${SKIP_PGBOUNCER:-false}"

# Operation flags
DRY_RUN="${DRY_RUN:-false}"
FORCE="${FORCE:-false}"
QUIET="${QUIET:-false}"
NO_CONFIRM="${NO_CONFIRM:-false}"

# Colors for output
if [[ -t 1 ]]; then
  readonly C_RESET='\e[0m'
  readonly C_RED='\e[31m'
  readonly C_GREEN='\e[32m'
  readonly C_YELLOW='\e[33m'
  readonly C_BLUE='\e[34m'
  readonly C_CYAN='\e[36m'
  readonly C_BOLD='\e[1m'
else
  readonly C_RESET='' C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_CYAN='' C_BOLD=''
fi

# =============================================================================
# LOGGING & OUTPUT HELPERS
# =============================================================================

log()   { [[ "$QUIET" == "true" ]] || echo -e "${C_GREEN}[INFO]${C_RESET} $*"; }
warn()  { echo -e "${C_YELLOW}[WARN]${C_RESET} $*" >&2; }
err()   { echo -e "${C_RED}[ERROR]${C_RESET} $*" >&2; }
debug() { [[ "${DEBUG:-false}" == "true" ]] && echo -e "${C_CYAN}[DEBUG]${C_RESET} $*" >&2 || true; }
dry()   { [[ "$DRY_RUN" == "true" ]] && echo -e "${C_BLUE}[DRY-RUN]${C_RESET} Would execute: $*"; }

die() {
  err "$1"
  exit "${2:-1}"
}

# =============================================================================
# VALIDATION & PREREQUISITE CHECKS
# =============================================================================

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    die "This script must be run as root (or with sudo)."
  fi
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    die "Required command '$cmd' not found. Please install it and rerun."
  fi
}

check_prerequisites() {
  require_root
  require_cmd "psql"
  require_cmd "openssl"
  require_cmd "systemctl"

  if [[ "$SKIP_PGBOUNCER" != "true" ]]; then
    if [[ ! -f "$PGB_USERLIST" ]]; then
      warn "PgBouncer userlist not found at $PGB_USERLIST"
      warn "Use --skip-pgbouncer to skip PgBouncer configuration"
    fi
  fi
}

detect_pg_version() {
  if [[ -n "$PG_VERSION" ]]; then return; fi
  if [[ ! -d /etc/postgresql ]]; then
    die "/etc/postgresql directory not found. Is PostgreSQL installed?"
  fi
  PG_VERSION="$(ls /etc/postgresql 2>/dev/null | sort -n | tail -1 || true)"
  if [[ -z "$PG_VERSION" ]]; then
    die "Could not auto-detect PostgreSQL version."
  fi
  debug "Auto-detected PostgreSQL version: $PG_VERSION"
}

validate_identifier() {
  local ident="$1"
  local type="$2"
  if [[ ! "$ident" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
    die "Invalid $type name '$ident'. Must start with a letter or underscore, contain only letters, digits, and underscores."
  fi
  # Check reserved words
  local reserved_words="all analyse analyze and any array as asc asymmetric both case cast check collate column constraint create current_date current_role current_time current_timestamp current_user default deferrable desc distinct do else end except false fetch for foreign from grant group having in initially intersect into lateral leading limit localtime localtimestamp not null offset on only or order placing primary references returning select session_user some symmetric table then to trailing true union unique user using variadic when where window with"
  local lower_ident
  lower_ident=$(echo "$ident" | tr '[:upper:]' '[:lower:]')
  if echo "$reserved_words" | grep -qw "$lower_ident"; then
    die "'$ident' is a PostgreSQL reserved word. Choose a different $type name."
  fi
}

validate_database_exists() {
  local db_name="$1"
  local exists
  exists=$(sudo -u postgres psql -qtAc "SELECT 1 FROM pg_database WHERE datname='${db_name}'" 2>/dev/null || echo "0")
  if [[ "$exists" != "1" ]]; then
    die "Database '$db_name' does not exist."
  fi
}

validate_user_exists() {
  local user_name="$1"
  local exists
  exists=$(sudo -u postgres psql -qtAc "SELECT 1 FROM pg_roles WHERE rolname='${user_name}'" 2>/dev/null || echo "0")
  if [[ "$exists" != "1" ]]; then
    die "User '$user_name' does not exist."
  fi
}

check_database_exists() {
  local db_name="$1"
  local exists
  exists=$(sudo -u postgres psql -qtAc "SELECT 1 FROM pg_database WHERE datname='${db_name}'" 2>/dev/null || echo "0")
  [[ "$exists" == "1" ]]
}

check_user_exists() {
  local user_name="$1"
  local exists
  exists=$(sudo -u postgres psql -qtAc "SELECT 1 FROM pg_roles WHERE rolname='${user_name}'" 2>/dev/null || echo "0")
  [[ "$exists" == "1" ]]
}

# =============================================================================
# USER INPUT HELPERS
# =============================================================================

prompt_value() {
  local var_name="$1"
  local prompt="$2"
  local default="${3:-}"
  local value="${!var_name:-}"

  if [[ -z "$value" ]]; then
    if [[ -n "$default" ]]; then
      read -rp "$prompt [$default]: " value
      value="${value:-$default}"
    else
      read -rp "$prompt: " value
    fi
    [[ -z "$value" ]] && die "Value cannot be empty."
    eval "$var_name=\"\$value\""
  fi
}

prompt_password() {
  local var_name="$1"
  local prompt="$2"
  local value="${!var_name:-}"

  if [[ -z "$value" ]]; then
    read -rsp "$prompt: " value
    echo
    [[ -z "$value" ]] && die "Password cannot be empty."
    eval "$var_name=\"\$value\""
  fi
}

confirm_action() {
  local message="$1"
  if [[ "$NO_CONFIRM" == "true" || "$DRY_RUN" == "true" ]]; then
    return 0
  fi

  echo
  echo -e "${C_BOLD}$message${C_RESET}"
  read -rp "Continue? [y/N]: " response
  if [[ ! "$response" =~ ^[Yy]$ ]]; then
    die "Operation cancelled by user."
  fi
}

# =============================================================================
# PASSWORD MANAGEMENT
# =============================================================================

generate_password() {
  openssl rand -base64 32 | tr -d '/+=' | head -c 32
}

get_password_file() {
  local db_name="${1:-_global}"
  local user_name="$2"
  echo "${PASS_DIR}/.pg_${db_name}_${user_name}.pass"
}

save_password() {
  local password="$1"
  local db_name="${2:-_global}"
  local user_name="$3"
  local pass_file
  pass_file=$(get_password_file "$db_name" "$user_name")

  if [[ "$DRY_RUN" == "true" ]]; then
    dry "Save password to $pass_file"
    return
  fi

  mkdir -p "$(dirname "$pass_file")"
  touch "$pass_file"
  chmod 600 "$pass_file"
  echo "$password" > "$pass_file"
  log "Password saved to: $pass_file"
}

load_password() {
  local db_name="${1:-_global}"
  local user_name="$2"
  local pass_file
  pass_file=$(get_password_file "$db_name" "$user_name")

  if [[ -f "$pass_file" ]]; then
    cat "$pass_file"
  fi
}

ensure_password() {
  local user_name="$1"
  local db_name="${2:-_global}"
  local password="${3:-}"
  local rotate="${4:-false}"

  if [[ "$rotate" == "true" ]]; then
    warn "Password rotation requested - generating new password."
    password=""
  fi

  # Try to load existing password
  if [[ -z "$password" ]]; then
    password=$(load_password "$db_name" "$user_name")
    if [[ -n "$password" ]]; then
      log "Re-using existing password from password file."
    fi
  fi

  # Generate new if still empty
  if [[ -z "$password" ]]; then
    log "Generating new secure password..."
    password=$(generate_password)
  fi

  # Save password
  save_password "$password" "$db_name" "$user_name"

  echo "$password"
}

# =============================================================================
# POSTGRESQL OPERATIONS
# =============================================================================

create_role() {
  local user_name="$1"
  local password="$2"
  local options="${3:-}"  # Additional role options

  log "Creating/updating role '$user_name' (SCRAM-SHA-256)..."

  if [[ "$DRY_RUN" == "true" ]]; then
    dry "CREATE ROLE $user_name WITH LOGIN PASSWORD '***' $options"
    return
  fi

  sudo -u postgres psql -v ON_ERROR_STOP=1 \
       -v user_name="$user_name" \
       -v user_pass="$password" <<EOF
SET password_encryption = 'scram-sha-256';
SELECT set_config('var.user_name', :'user_name', false);
SELECT set_config('var.user_pass', :'user_pass', false);

DO \$\$
DECLARE
  _user text := current_setting('var.user_name');
  _pass text := current_setting('var.user_pass');
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = _user) THEN
    EXECUTE format(
      'CREATE ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION ${options}',
      _user, _pass
    );
    RAISE NOTICE 'Role % created.', _user;
  ELSE
    EXECUTE format('ALTER ROLE %I WITH LOGIN PASSWORD %L ${options}', _user, _pass);
    RAISE NOTICE 'Role % updated.', _user;
  END IF;
END
\$\$;
EOF
}

create_database() {
  local db_name="$1"
  local owner="${2:-}"

  log "Creating database '$db_name'..."

  if check_database_exists "$db_name"; then
    if [[ "$FORCE" != "true" ]]; then
      warn "Database '$db_name' already exists. Use --force to update ownership."
      return 0
    fi
    log "Database exists. Updating ownership..."
    if [[ "$DRY_RUN" != "true" ]]; then
      sudo -u postgres psql -v ON_ERROR_STOP=1 -c "ALTER DATABASE \"${db_name}\" OWNER TO \"${owner}\";"
    else
      dry "ALTER DATABASE $db_name OWNER TO $owner"
    fi
    return 0
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    dry "CREATE DATABASE $db_name${owner:+ OWNER $owner}"
    return
  fi

  if [[ -n "$owner" ]]; then
    sudo -u postgres psql -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"${db_name}\" OWNER \"${owner}\";"
  else
    sudo -u postgres psql -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"${db_name}\";"
  fi

  log "Database '$db_name' created."
}

harden_database() {
  local db_name="$1"
  local owner="$2"

  log "Applying security hardening to database '$db_name'..."

  if [[ "$DRY_RUN" == "true" ]]; then
    dry "REVOKE CREATE ON SCHEMA public FROM PUBLIC"
    dry "REVOKE ALL ON DATABASE $db_name FROM PUBLIC"
    dry "GRANT CONNECT ON DATABASE $db_name TO $owner"
    dry "GRANT USAGE, CREATE ON SCHEMA public TO $owner"
    return
  fi

  sudo -u postgres psql -v ON_ERROR_STOP=1 -v db_name="$db_name" -v db_user="$owner" --dbname="$db_name" <<EOF
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE :"db_name" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db_name" TO :"db_user";
GRANT USAGE, CREATE ON SCHEMA public TO :"db_user";
EOF
}

grant_readonly_access() {
  local db_name="$1"
  local user_name="$2"

  log "Granting read-only access on '$db_name' to '$user_name'..."

  if [[ "$DRY_RUN" == "true" ]]; then
    dry "GRANT CONNECT ON DATABASE $db_name TO $user_name"
    dry "GRANT USAGE ON SCHEMA public TO $user_name"
    dry "GRANT SELECT ON ALL TABLES IN SCHEMA public TO $user_name"
    dry "ALTER DEFAULT PRIVILEGES ... GRANT SELECT"
    return
  fi

  sudo -u postgres psql -v ON_ERROR_STOP=1 -v db_name="$db_name" -v db_user="$user_name" --dbname="$db_name" <<EOF
-- Grant connect privilege
GRANT CONNECT ON DATABASE :"db_name" TO :"db_user";

-- Grant schema usage
GRANT USAGE ON SCHEMA public TO :"db_user";

-- Grant SELECT on all existing tables
GRANT SELECT ON ALL TABLES IN SCHEMA public TO :"db_user";

-- Grant SELECT on all existing sequences (for reading nextval, etc.)
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO :"db_user";

-- Set default privileges for future tables (requires schema owner context)
DO \$\$
DECLARE
  schema_owner text;
BEGIN
  SELECT nspowner::regrole::text INTO schema_owner
  FROM pg_namespace WHERE nspname = 'public';

  EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT ON TABLES TO %I',
                 schema_owner, current_setting('var.db_user'));
  EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT ON SEQUENCES TO %I',
                 schema_owner, current_setting('var.db_user'));
END
\$\$;
EOF

  log "Read-only access granted."
}

grant_readwrite_access() {
  local db_name="$1"
  local user_name="$2"

  log "Granting read-write access on '$db_name' to '$user_name'..."

  if [[ "$DRY_RUN" == "true" ]]; then
    dry "GRANT CONNECT ON DATABASE $db_name TO $user_name"
    dry "GRANT USAGE, CREATE ON SCHEMA public TO $user_name"
    dry "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES"
    dry "ALTER DEFAULT PRIVILEGES ... GRANT SELECT, INSERT, UPDATE, DELETE"
    return
  fi

  sudo -u postgres psql -v ON_ERROR_STOP=1 -v db_name="$db_name" -v db_user="$user_name" --dbname="$db_name" <<EOF
-- Grant connect privilege
GRANT CONNECT ON DATABASE :"db_name" TO :"db_user";

-- Grant schema usage and create
GRANT USAGE, CREATE ON SCHEMA public TO :"db_user";

-- Grant full DML on all existing tables
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO :"db_user";

-- Grant full access on sequences
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO :"db_user";

-- Set default privileges for future objects
DO \$\$
DECLARE
  schema_owner text;
BEGIN
  SELECT nspowner::regrole::text INTO schema_owner
  FROM pg_namespace WHERE nspname = 'public';

  EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I',
                 schema_owner, current_setting('var.db_user'));
  EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %I',
                 schema_owner, current_setting('var.db_user'));
END
\$\$;
EOF

  log "Read-write access granted."
}

verify_connection() {
  local db_name="$1"
  local user_name="$2"
  local password="$3"

  log "Verifying connection as '$user_name' to '$db_name'..."

  if [[ "$DRY_RUN" == "true" ]]; then
    dry "Test connection to $db_name as $user_name"
    return
  fi

  if ! PGPASSWORD="$password" psql -h "$PG_HOST" -p "$PG_PORT" -U "$user_name" -d "$db_name" -c "SELECT 1" >/dev/null 2>&1; then
    err "Connection verification failed!"
    err "Check pg_hba.conf and ensure the user/host combination is allowed."
    return 1
  fi

  log "Connection verified successfully."
}

# =============================================================================
# PGBOUNCER OPERATIONS
# =============================================================================

get_pgbouncer_service_user() {
  local svc_user svc_group
  svc_user=$(systemctl show -p User pgbouncer.service 2>/dev/null | cut -d= -f2)
  svc_group=$(systemctl show -p Group pgbouncer.service 2>/dev/null | cut -d= -f2)
  [[ -z "$svc_user" || "$svc_user" == "root" ]] && svc_user="pgbouncer"
  [[ -z "$svc_group" || "$svc_group" == "root" ]] && svc_group="$svc_user"
  echo "$svc_user:$svc_group"
}

update_pgbouncer_userlist() {
  local user_name="$1"

  if [[ "$SKIP_PGBOUNCER" == "true" ]]; then
    debug "Skipping PgBouncer userlist update (--skip-pgbouncer)"
    return
  fi

  log "Updating PgBouncer userlist with SCRAM hash..."

  if [[ ! -f "$PGB_USERLIST" ]]; then
    warn "$PGB_USERLIST not found. Skipping PgBouncer userlist update."
    return
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    dry "Update PgBouncer userlist for $user_name"
    return
  fi

  # Fetch SCRAM secret from Postgres
  local scram_secret
  scram_secret=$(sudo -u postgres psql -qtAc "SELECT rolpassword FROM pg_authid WHERE rolname='${user_name}'")

  if [[ -z "$scram_secret" ]]; then
    err "Could not retrieve rolpassword for '${user_name}'."
    return 1
  fi

  if [[ ! "$scram_secret" =~ ^SCRAM-SHA-256\$ ]]; then
    err "Password for '${user_name}' is not SCRAM-SHA-256."
    return 1
  fi

  debug "Retrieved SCRAM secret (prefix: ${scram_secret:0:20}...)"

  local svc_user svc_group
  IFS=":" read -r svc_user svc_group <<< "$(get_pgbouncer_service_user)"

  local tmp_file
  tmp_file=$(mktemp)
  cp "$PGB_USERLIST" "$tmp_file"

  local esc_secret
  esc_secret=$(printf '%s\n' "$scram_secret" | sed 's/[\/&]/\\&/g')

  if grep -qE "^\"${user_name}\"" "$tmp_file"; then
    sed -i "s/^\"${user_name}\".*/\"${user_name}\" \"${esc_secret}\"/" "$tmp_file"
  else
    echo "\"${user_name}\" \"${scram_secret}\"" >> "$tmp_file"
  fi

  chown "$svc_user:$svc_group" "$tmp_file"
  chmod 640 "$tmp_file"
  mv "$tmp_file" "$PGB_USERLIST"

  log "PgBouncer userlist updated."
}

update_pgbouncer_databases() {
  local db_name="$1"

  if [[ "$SKIP_PGBOUNCER" == "true" ]]; then
    debug "Skipping PgBouncer database mapping (--skip-pgbouncer)"
    return
  fi

  log "Updating PgBouncer database mapping..."

  if [[ ! -f "$PGB_INI" ]]; then
    warn "$PGB_INI not found. Skipping PgBouncer database mapping."
    return
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    dry "Update PgBouncer database mapping for $db_name"
    return
  fi

  local svc_user svc_group
  IFS=":" read -r svc_user svc_group <<< "$(get_pgbouncer_service_user)"

  local tmp_file
  tmp_file=$(mktemp)
  cp "$PGB_INI" "$tmp_file"

  # Ensure [databases] section exists
  if ! grep -q "^\[databases\]" "$tmp_file"; then
    {
      echo "[databases]"
      echo
      cat "$tmp_file"
    } > "${tmp_file}.new"
    mv "${tmp_file}.new" "$tmp_file"
  fi

  local desired="${db_name} = host=${PG_HOST} port=${PG_PORT} dbname=${db_name}"
  local esc_desired
  esc_desired=$(printf '%s\n' "$desired" | sed 's/[\/&]/\\&/g')

  if grep -qE "^${db_name}[[:space:]]*=" "$tmp_file"; then
    sed -i "s/^${db_name}[[:space:]]*=.*/${esc_desired}/" "$tmp_file"
  else
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

  log "PgBouncer database mapping updated."
}

reload_pgbouncer() {
  if [[ "$SKIP_PGBOUNCER" == "true" ]]; then
    debug "Skipping PgBouncer reload (--skip-pgbouncer)"
    return
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    dry "Reload PgBouncer"
    return
  fi

  log "Reloading PgBouncer..."

  if ! systemctl is-active --quiet pgbouncer.service 2>/dev/null; then
    warn "PgBouncer service is not running. Skipping reload."
    return
  fi

  if systemctl reload pgbouncer.service 2>/dev/null; then
    log "PgBouncer reloaded successfully."
  else
    warn "Reload failed, attempting restart..."
    systemctl restart pgbouncer.service
  fi

  if ! systemctl is-active --quiet pgbouncer.service; then
    err "PgBouncer is inactive after reload/restart."
    err "Check logs: journalctl -xeu pgbouncer.service"
    return 1
  fi
}

# =============================================================================
# COMMAND IMPLEMENTATIONS
# =============================================================================

cmd_create_db_user() {
  local db_name="" user_name="" password="" rotate=false

  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--database)   db_name="$2"; shift 2 ;;
      -u|--user)       user_name="$2"; shift 2 ;;
      -p|--password)   password="$2"; shift 2 ;;
      --rotate)        rotate=true; shift ;;
      *)               shift ;;
    esac
  done

  prompt_value "db_name" "Enter database name"
  prompt_value "user_name" "Enter username (database owner)" "${db_name}_user"

  validate_identifier "$db_name" "database"
  validate_identifier "$user_name" "user"

  # Check if already exists
  if check_database_exists "$db_name" && [[ "$FORCE" != "true" ]]; then
    die "Database '$db_name' already exists. Use --force to update."
  fi

  echo
  echo "================= Configuration ================="
  echo "  Database:  $db_name"
  echo "  User:      $user_name (owner)"
  echo "  Host:      $PG_HOST:$PG_PORT"
  echo "  PgBouncer: $([ "$SKIP_PGBOUNCER" == "true" ] && echo "Skipped" || echo "Enabled")"
  echo "================================================="

  confirm_action "Create database '$db_name' with owner '$user_name'?"

  # Execute operations
  password=$(ensure_password "$user_name" "$db_name" "$password" "$rotate")
  create_role "$user_name" "$password"
  create_database "$db_name" "$user_name"
  harden_database "$db_name" "$user_name"
  verify_connection "$db_name" "$user_name" "$password" || true
  update_pgbouncer_userlist "$user_name"
  update_pgbouncer_databases "$db_name"
  reload_pgbouncer

  # Summary
  echo
  echo "==================================================================="
  echo -e "${C_GREEN}✓ Database and user created successfully${C_RESET}"
  echo "==================================================================="
  echo "  Database:      $db_name"
  echo "  User:          $user_name (owner, full access)"
  echo "  Password:      $password"
  echo "  Password file: $(get_password_file "$db_name" "$user_name")"
  echo "-------------------------------------------------------------------"
  echo "  Connection strings:"
  echo "    Direct:    postgresql://$user_name:***@${PG_HOST}:${PG_PORT}/$db_name"
  [[ "$SKIP_PGBOUNCER" != "true" ]] && echo "    PgBouncer: postgresql://$user_name:***@${PG_HOST}:6432/$db_name"
  echo "==================================================================="
}

cmd_create_readonly() {
  local db_name="" user_name="" password="" rotate=false

  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--database)   db_name="$2"; shift 2 ;;
      -u|--user)       user_name="$2"; shift 2 ;;
      -p|--password)   password="$2"; shift 2 ;;
      --rotate)        rotate=true; shift ;;
      *)               shift ;;
    esac
  done

  prompt_value "db_name" "Enter database name"
  prompt_value "user_name" "Enter read-only username" "${db_name}_readonly"

  validate_identifier "$db_name" "database"
  validate_identifier "$user_name" "user"
  validate_database_exists "$db_name"

  echo
  echo "================= Configuration ================="
  echo "  Database:    $db_name"
  echo "  User:        $user_name (read-only)"
  echo "  Host:        $PG_HOST:$PG_PORT"
  echo "  PgBouncer:   $([ "$SKIP_PGBOUNCER" == "true" ] && echo "Skipped" || echo "Enabled")"
  echo "================================================="

  confirm_action "Create read-only user '$user_name' for database '$db_name'?"

  # Execute operations
  password=$(ensure_password "$user_name" "$db_name" "$password" "$rotate")
  create_role "$user_name" "$password"
  grant_readonly_access "$db_name" "$user_name"
  verify_connection "$db_name" "$user_name" "$password" || true
  update_pgbouncer_userlist "$user_name"
  reload_pgbouncer

  # Summary
  echo
  echo "==================================================================="
  echo -e "${C_GREEN}✓ Read-only user created successfully${C_RESET}"
  echo "==================================================================="
  echo "  Database:      $db_name"
  echo "  User:          $user_name (read-only)"
  echo "  Password:      $password"
  echo "  Password file: $(get_password_file "$db_name" "$user_name")"
  echo "-------------------------------------------------------------------"
  echo "  Connection strings:"
  echo "    Direct:    postgresql://$user_name:***@${PG_HOST}:${PG_PORT}/$db_name"
  [[ "$SKIP_PGBOUNCER" != "true" ]] && echo "    PgBouncer: postgresql://$user_name:***@${PG_HOST}:6432/$db_name"
  echo "==================================================================="
}

cmd_create_database() {
  local db_name="" owner=""

  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--database)   db_name="$2"; shift 2 ;;
      -o|--owner)      owner="$2"; shift 2 ;;
      *)               shift ;;
    esac
  done

  prompt_value "db_name" "Enter database name"

  validate_identifier "$db_name" "database"

  if check_database_exists "$db_name" && [[ "$FORCE" != "true" ]]; then
    die "Database '$db_name' already exists. Use --force to update ownership."
  fi

  if [[ -n "$owner" ]]; then
    validate_identifier "$owner" "user"
    validate_user_exists "$owner"
  fi

  echo
  echo "================= Configuration ================="
  echo "  Database:  $db_name"
  echo "  Owner:     ${owner:-postgres (default)}"
  echo "================================================="

  confirm_action "Create database '$db_name'?"

  # Execute operations
  create_database "$db_name" "$owner"
  if [[ -n "$owner" ]]; then
    harden_database "$db_name" "$owner"
  fi
  update_pgbouncer_databases "$db_name"
  reload_pgbouncer

  # Summary
  echo
  echo "==================================================================="
  echo -e "${C_GREEN}✓ Database created successfully${C_RESET}"
  echo "==================================================================="
  echo "  Database: $db_name"
  echo "  Owner:    ${owner:-postgres}"
  echo "==================================================================="
}

cmd_create_user() {
  local user_name="" password="" rotate=false

  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -u|--user)       user_name="$2"; shift 2 ;;
      -p|--password)   password="$2"; shift 2 ;;
      --rotate)        rotate=true; shift ;;
      *)               shift ;;
    esac
  done

  prompt_value "user_name" "Enter username"

  validate_identifier "$user_name" "user"

  if check_user_exists "$user_name" && [[ "$FORCE" != "true" ]]; then
    die "User '$user_name' already exists. Use --force to update."
  fi

  echo
  echo "================= Configuration ================="
  echo "  User:      $user_name"
  echo "  PgBouncer: $([ "$SKIP_PGBOUNCER" == "true" ] && echo "Skipped" || echo "Enabled")"
  echo "================================================="

  confirm_action "Create user '$user_name'?"

  # Execute operations
  password=$(ensure_password "$user_name" "_global" "$password" "$rotate")
  create_role "$user_name" "$password"
  update_pgbouncer_userlist "$user_name"
  reload_pgbouncer

  # Summary
  echo
  echo "==================================================================="
  echo -e "${C_GREEN}✓ User created successfully${C_RESET}"
  echo "==================================================================="
  echo "  User:          $user_name"
  echo "  Password:      $password"
  echo "  Password file: $(get_password_file "_global" "$user_name")"
  echo "-------------------------------------------------------------------"
  echo "  Note: Use 'grant-access' command to grant database access."
  echo "==================================================================="
}

cmd_grant_access() {
  local db_name="" user_name="" access_level="readonly"

  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--database)     db_name="$2"; shift 2 ;;
      -u|--user)         user_name="$2"; shift 2 ;;
      -a|--access)       access_level="$2"; shift 2 ;;
      --readonly)        access_level="readonly"; shift ;;
      --readwrite)       access_level="readwrite"; shift ;;
      *)                 shift ;;
    esac
  done

  prompt_value "db_name" "Enter database name"
  prompt_value "user_name" "Enter username"

  validate_identifier "$db_name" "database"
  validate_identifier "$user_name" "user"
  validate_database_exists "$db_name"
  validate_user_exists "$user_name"

  if [[ "$access_level" != "readonly" && "$access_level" != "readwrite" ]]; then
    die "Invalid access level '$access_level'. Use 'readonly' or 'readwrite'."
  fi

  echo
  echo "================= Configuration ================="
  echo "  Database:     $db_name"
  echo "  User:         $user_name"
  echo "  Access Level: $access_level"
  echo "================================================="

  confirm_action "Grant $access_level access on '$db_name' to '$user_name'?"

  # Execute operations
  if [[ "$access_level" == "readonly" ]]; then
    grant_readonly_access "$db_name" "$user_name"
  else
    grant_readwrite_access "$db_name" "$user_name"
  fi

  # Summary
  echo
  echo "==================================================================="
  echo -e "${C_GREEN}✓ Access granted successfully${C_RESET}"
  echo "==================================================================="
  echo "  Database: $db_name"
  echo "  User:     $user_name"
  echo "  Access:   $access_level"
  echo "==================================================================="
}

cmd_rotate_password() {
  local user_name="" db_name=""

  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -u|--user)       user_name="$2"; shift 2 ;;
      -d|--database)   db_name="$2"; shift 2 ;;
      *)               shift ;;
    esac
  done

  prompt_value "user_name" "Enter username"

  validate_identifier "$user_name" "user"
  validate_user_exists "$user_name"

  echo
  echo "================= Configuration ================="
  echo "  User:      $user_name"
  echo "  PgBouncer: $([ "$SKIP_PGBOUNCER" == "true" ] && echo "Skipped" || echo "Enabled")"
  echo "================================================="

  confirm_action "Rotate password for user '$user_name'?"

  # Execute operations
  local password
  password=$(ensure_password "$user_name" "${db_name:-_global}" "" "true")
  create_role "$user_name" "$password"
  update_pgbouncer_userlist "$user_name"
  reload_pgbouncer

  # Summary
  echo
  echo "==================================================================="
  echo -e "${C_GREEN}✓ Password rotated successfully${C_RESET}"
  echo "==================================================================="
  echo "  User:          $user_name"
  echo "  New Password:  $password"
  echo "  Password file: $(get_password_file "${db_name:-_global}" "$user_name")"
  echo "==================================================================="
}

cmd_list_databases() {
  log "Listing databases..."
  echo
  sudo -u postgres psql -c "\l+"
}

cmd_list_users() {
  log "Listing users..."
  echo
  sudo -u postgres psql -c "\du+"
}

# =============================================================================
# HELP & USAGE
# =============================================================================

show_usage() {
  cat <<EOF
${C_BOLD}PostgreSQL User & Database Management Tool v${SCRIPT_VERSION}${C_RESET}

${C_BOLD}USAGE:${C_RESET}
  $SCRIPT_NAME <command> [options]

${C_BOLD}COMMANDS:${C_RESET}
  ${C_GREEN}create-db-user${C_RESET}    Create a new database with an owner user (full access)
  ${C_GREEN}create-readonly${C_RESET}   Create a read-only user for an existing database
  ${C_GREEN}create-database${C_RESET}   Create a database only (optionally assign to existing user)
  ${C_GREEN}create-user${C_RESET}       Create a user only (without database)
  ${C_GREEN}grant-access${C_RESET}      Grant a user access to an existing database
  ${C_GREEN}rotate-password${C_RESET}   Rotate password for an existing user
  ${C_GREEN}list-databases${C_RESET}    List all databases
  ${C_GREEN}list-users${C_RESET}        List all users
  ${C_GREEN}help${C_RESET}              Show this help message

${C_BOLD}GLOBAL OPTIONS:${C_RESET}
  --dry-run           Show what would be done without making changes
  --force             Force operation (overwrite existing resources)
  --no-confirm        Skip confirmation prompts
  --quiet             Suppress informational output
  --skip-pgbouncer    Skip PgBouncer configuration updates

${C_BOLD}COMMAND OPTIONS:${C_RESET}

  create-db-user:
    -d, --database NAME   Database name
    -u, --user NAME       Username (default: <database>_user)
    -p, --password PASS   Password (default: auto-generated)
    --rotate              Force password rotation if user exists

  create-readonly:
    -d, --database NAME   Database name (must exist)
    -u, --user NAME       Username (default: <database>_readonly)
    -p, --password PASS   Password (default: auto-generated)

  create-database:
    -d, --database NAME   Database name
    -o, --owner USER      Owner username (optional)

  create-user:
    -u, --user NAME       Username
    -p, --password PASS   Password (default: auto-generated)

  grant-access:
    -d, --database NAME   Database name
    -u, --user NAME       Username
    -a, --access LEVEL    Access level: readonly, readwrite (default: readonly)
    --readonly            Shorthand for --access readonly
    --readwrite           Shorthand for --access readwrite

  rotate-password:
    -u, --user NAME       Username
    -d, --database NAME   Database name (for password file organization)

${C_BOLD}ENVIRONMENT VARIABLES:${C_RESET}
  PG_HOST          PostgreSQL host (default: 127.0.0.1)
  PG_PORT          PostgreSQL port (default: 5432)
  PG_VERSION       PostgreSQL version (default: auto-detected)
  PASS_DIR         Password storage directory (default: /root)
  PGB_USERLIST     PgBouncer userlist file (default: /etc/pgbouncer/userlist.txt)
  PGB_INI          PgBouncer config file (default: /etc/pgbouncer/pgbouncer.ini)
  DEBUG            Enable debug output (true/false)

${C_BOLD}EXAMPLES:${C_RESET}
  # Create a new database with owner (interactive)
  $SCRIPT_NAME create-db-user

  # Create a database with owner (non-interactive)
  $SCRIPT_NAME create-db-user -d myapp -u myapp_user --no-confirm

  # Create a read-only user for analytics
  $SCRIPT_NAME create-readonly -d myapp -u analytics_user

  # Create just a database, assign to existing user
  $SCRIPT_NAME create-database -d newdb -o existing_user

  # Create a user without any database access
  $SCRIPT_NAME create-user -u service_account

  # Grant read-write access to an existing user
  $SCRIPT_NAME grant-access -d myapp -u service_account --readwrite

  # Rotate a user's password
  $SCRIPT_NAME rotate-password -u myapp_user

  # Dry run to see what would happen
  $SCRIPT_NAME create-db-user -d test -u test_user --dry-run

EOF
}

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

main() {
  local command="${1:-help}"
  shift || true

  # Parse global options first
  local args=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)        DRY_RUN=true; shift ;;
      --force)          FORCE=true; shift ;;
      --no-confirm)     NO_CONFIRM=true; shift ;;
      --quiet)          QUIET=true; shift ;;
      --skip-pgbouncer) SKIP_PGBOUNCER=true; shift ;;
      --debug)          DEBUG=true; shift ;;
      *)                args+=("$1"); shift ;;
    esac
  done

  # Set remaining args
  set -- "${args[@]}" 2>/dev/null || true

  case "$command" in
    create-db-user)
      check_prerequisites
      detect_pg_version
      cmd_create_db_user "$@"
      ;;
    create-readonly)
      check_prerequisites
      detect_pg_version
      cmd_create_readonly "$@"
      ;;
    create-database)
      check_prerequisites
      detect_pg_version
      cmd_create_database "$@"
      ;;
    create-user)
      check_prerequisites
      detect_pg_version
      cmd_create_user "$@"
      ;;
    grant-access)
      check_prerequisites
      detect_pg_version
      cmd_grant_access "$@"
      ;;
    rotate-password)
      check_prerequisites
      detect_pg_version
      cmd_rotate_password "$@"
      ;;
    list-databases|list-db)
      require_root
      require_cmd "psql"
      cmd_list_databases
      ;;
    list-users)
      require_root
      require_cmd "psql"
      cmd_list_users
      ;;
    help|--help|-h)
      show_usage
      ;;
    version|--version|-v)
      echo "$SCRIPT_NAME v$SCRIPT_VERSION"
      ;;
    *)
      err "Unknown command: $command"
      echo
      show_usage
      exit 1
      ;;
  esac
}

main "$@"
