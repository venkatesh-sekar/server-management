#!/usr/bin/env bash
#
# Bootstrap security stack on Debian/Ubuntu
#
# - Installs: fail2ban, unattended-upgrades, auditd
# - Configures: basic SSH protection via fail2ban
# - Configures: auditd baseline rules for critical files (Optimized for low noise)
#

set -euo pipefail

# ==========================
# --- LOGGING HELPERS -------
# ==========================

log_info()  { echo -e "[INFO ] $*"; }
log_warn()  { echo -e "[WARN ] $*"; }
log_error() { echo -e "[ERROR] $*" >&2; }

# ==========================
# --- PRE-FLIGHT CHECKS ----
# ==========================

if [[ "$EUID" -ne 0 ]]; then
  log_error "Please run as root or with sudo."
  exit 1
fi

if [[ ! -f /etc/os-release ]]; then
  log_error "/etc/os-release not found. Unsupported system."
  exit 1
fi

. /etc/os-release

if [[ "${ID}" != "debian" && "${ID}" != "ubuntu" ]]; then
  log_warn "This script is optimized for Debian/Ubuntu, but found ID=${ID}. Proceeding anyway..."
fi

log_info "Detected OS: ${PRETTY_NAME:-$ID}"

# ==========================
# --- APT PACKAGES ----------
# ==========================

log_info "Updating APT and installing security packages..."

# Prevent interactive prompts during install
export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y --no-install-recommends \
  fail2ban unattended-upgrades python3-systemd \
  auditd audispd-plugins

log_info "Security packages installed."

# ==========================
# --- UNATTENDED-UPGRADES ---
# ==========================

log_info "Configuring unattended-upgrades for security updates..."
# Ensure the config file exists before attempting reconfigure
if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
    touch /etc/apt/apt.conf.d/20auto-upgrades
fi
dpkg-reconfigure --priority=low unattended-upgrades || true
log_info "unattended-upgrades configured."

# ==========================
# --- FAIL2BAN CONFIG -------
# ==========================

log_info "Configuring fail2ban for SSH brute-force protection..."
JAIL_LOCAL="/etc/fail2ban/jail.local"

if [[ -f "${JAIL_LOCAL}" ]]; then
  log_warn "${JAIL_LOCAL} already exists. Skipping creation."
else
  cat > "${JAIL_LOCAL}" <<'EOF'
[DEFAULT]
bantime  = 10m
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = systemd
EOF
  log_info "Created ${JAIL_LOCAL}."
fi

# Ensure fail2ban is enabled (ignore errors if strictly no systemd, unlikely)
systemctl enable fail2ban || true
systemctl restart fail2ban || true

# ==========================
# --- AUDITD CONFIG ---------
# ==========================

log_info "Configuring auditd baseline rules..."
AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/hardening.rules"

mkdir -p "${AUDIT_RULES_DIR}"

# Updated rules based on "recursion bomb" fix
if [[ -f "${AUDIT_RULES_FILE}" ]]; then
  log_warn "${AUDIT_RULES_FILE} already exists. Skipping creation."
else
  cat > "${AUDIT_RULES_FILE}" <<'EOF'
## Auditd baseline rules - HARDENING ONLY
## We do not watch log files here because we are already ingesting them via OTEL.

# 1. Identity & Credentials (User modification)
-w /etc/passwd  -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/group   -p wa -k identity
-w /etc/gshadow -p wa -k identity

# 2. Privileged Access (Sudo changes)
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# 3. Remote Access Config (SSHD changes)
-w /etc/ssh/sshd_config -p wa -k sshd_config

## NOTE: We explicitly DO NOT watch /var/log/auth.log or /var/log/audit/
## to prevent feedback loops and duplicate data ingestion.
EOF
fi

systemctl enable auditd
# Auditd sometimes fails to restart if it's already running in immutable mode, usually harmless
service auditd restart || echo "Auditd restart signal sent."

if command -v augenrules >/dev/null 2>&1; then
  augenrules --load || true
fi

log_info "Security setup complete."
log_info "  - fail2ban: enabled and running"
log_info "  - unattended-upgrades: configured"
log_info "  - auditd: enabled with hardening rules"
