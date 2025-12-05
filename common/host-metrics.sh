#!/usr/bin/env bash
#
# Bootstrap observability stack on Debian/Ubuntu
#
# - Installs: OpenTelemetry Collector (contrib)
# - Configures: Host metrics collection (CPU, memory, disk, network, etc.)
# - Configures: Log collection (fail2ban, auth, audit logs)
# - Sends to SigNoz via OTLP
#

set -euo pipefail

# ==========================
# --- CONFIGURATION ----------
# ==========================

# OpenTelemetry Collector settings
OTEL_VERSION="0.104.0"
OTEL_URL="https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v${OTEL_VERSION}/otelcol-contrib_${OTEL_VERSION}_linux_amd64.tar.gz"
INSTALL_DIR="/opt/otel-host"
SERVICE_NAME="otel-host-metrics"

# SigNoz OTLP endpoint - will be prompted if not set via environment
SIGNOZ_OTLP="${SIGNOZ_OTLP:-}"

# ==========================
# --- LOGGING HELPERS -------
# ==========================

log_info()  { echo -e "[INFO ] $*"; }
log_warn()  { echo -e "[WARN ] $*"; }
log_error() { echo -e "[ERROR] $*" >&2; }

# ==========================
# --- INPUT PROMPTS --------
# ==========================

prompt_signoz_endpoint() {
  if [[ -n "${SIGNOZ_OTLP}" ]]; then
    log_info "Using SIGNOZ_OTLP from environment: ${SIGNOZ_OTLP}"
    return
  fi

  echo
  echo "================= SigNoz OTLP Configuration ================="
  echo "Enter the HTTP endpoint for your SigNoz/OTLP collector."
  echo "Example: http://signoz.example.com:4318"
  echo

  while [[ -z "${SIGNOZ_OTLP}" ]]; do
    read -rp "SigNoz OTLP HTTP Endpoint: " SIGNOZ_OTLP
    if [[ -z "${SIGNOZ_OTLP}" ]]; then
      log_warn "Endpoint cannot be empty."
    elif [[ ! "${SIGNOZ_OTLP}" =~ ^https?:// ]]; then
      log_warn "Endpoint must start with http:// or https://"
      SIGNOZ_OTLP=""
    fi
  done
  echo
}

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

ARCH=$(uname -m)
if [[ "${ARCH}" != "x86_64" && "${ARCH}" != "amd64" ]]; then
  log_error "This script currently supports x86_64/amd64 only. Detected: ${ARCH}"
  exit 1
fi

log_info "Detected OS: ${PRETTY_NAME:-$ID}, Arch: ${ARCH}"

# ==========================
# --- USER INPUT -----------
# ==========================

prompt_signoz_endpoint

echo "================= Confirm Settings ================="
echo "SigNoz OTLP Endpoint: ${SIGNOZ_OTLP}"
echo "OTEL Version:         ${OTEL_VERSION}"
echo "Install Directory:    ${INSTALL_DIR}"
echo "Service Name:         ${SERVICE_NAME}"
echo "====================================================="
echo

read -rp "Continue with installation? [y/N]: " CONFIRM
CONFIRM="${CONFIRM:-n}"
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
  log_error "Aborting as requested."
  exit 1
fi

# ==========================
# --- APT PACKAGES ----------
# ==========================

log_info "Updating APT and installing base packages..."

# Prevent interactive prompts during install
export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y --no-install-recommends \
  curl wget jq ca-certificates \
  net-tools gnupg

log_info "Base packages installed."

# ==========================
# --- OTEL COLLECTOR INSTALL
# ==========================

log_info "Setting up OpenTelemetry Collector Contrib v${OTEL_VERSION}..."

mkdir -p "${INSTALL_DIR}"
cd "${INSTALL_DIR}"

if [[ -x "${INSTALL_DIR}/otelcol" ]]; then
  log_warn "otelcol binary already exists. Skipping download."
else
  log_info "Downloading otelcol-contrib..."
  # Use a temp file for download
  curl -L -f -o otelcol.tar.gz "${OTEL_URL}"

  # Basic integrity check (tarball shouldn't be empty)
  if [[ ! -s otelcol.tar.gz ]]; then
     log_error "Downloaded file is empty. Check OTEL_URL."
     exit 1
  fi

  tar -xvf otelcol.tar.gz
  mv otelcol-contrib otelcol
  chmod +x otelcol
  rm otelcol.tar.gz
  log_info "otelcol installed."
fi

# ==========================
# --- OTEL CONFIG -----------
# ==========================

log_info "Generating OpenTelemetry Collector config..."

cat > "${INSTALL_DIR}/config.yaml" <<EOF
receivers:
  hostmetrics:
    collection_interval: 10s
    scrapers:
      cpu: {}
      load: {}
      memory: {}
      network: {}
      paging: {}
      disk: {}
      processes: {}
      filesystem:
        # Include all real devices (same as old \`include.devices = [".+"]\`)
        include_devices:
          devices: [".+"]
          match_type: regexp

        # Exclude noisy / ephemeral mount points (mapped from old \`exclude.mount_points\`)
        exclude_mount_points:
          mount_points:
            - "/proc.*"
            - "/sys.*"
            - "/run/user.*"
            - "/run/containerd.*"
            - "/var/lib/docker.*"
            - "/snap.*"
          match_type: regexp

        # Exclude virtual / pseudo FS types (mapped from old \`exclude.fs_types\`)
        exclude_fs_types:
          fs_types:
            - "sysfs"
            - "proc"
            - "tmpfs"
            - "devtmpfs"
            - "devfs"
            - "overlay"
            - "squashfs"
          match_type: strict

        # Keep only "real" filesystems
        include_virtual_filesystems: false

  filelog/fail2ban:
    include: ["/var/log/fail2ban.log"]
    start_at: end
    include_file_path: true
    operators:
      - type: add
        field: attributes.log_type
        value: fail2ban

  filelog/auth:
    include: ["/var/log/auth.log", "/var/log/secure"]
    start_at: end
    include_file_path: true
    operators:
      - type: add
        field: attributes.log_type
        value: auth

  filelog/audit:
    include: ["/var/log/audit/audit.log"]
    start_at: end
    include_file_path: true
    operators:
      - type: add
        field: attributes.log_type
        value: auditd

processors:
  resourcedetection:
    detectors: [system, env, gcp, ec2]
    system:
      hostname_sources: [os]
  batch: {}

exporters:
  otlphttp:
    endpoint: "${SIGNOZ_OTLP}"
    compression: gzip
    timeout: 30s

service:
  pipelines:
    metrics:
      receivers: [hostmetrics]
      processors: [resourcedetection, batch]
      exporters: [otlphttp]
    logs:
      receivers: [filelog/fail2ban, filelog/auth, filelog/audit]
      processors: [resourcedetection, batch]
      exporters: [otlphttp]
EOF

# ==========================
# --- SYSTEMD SERVICE -------
# ==========================

log_info "Creating systemd service: ${SERVICE_NAME}"

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=OpenTelemetry Host Metrics & Logs Agent
After=network.target

[Service]
ExecStart=${INSTALL_DIR}/otelcol --config=${INSTALL_DIR}/config.yaml
Restart=always
RestartSec=5
# Running as root required to read /var/log/audit/audit.log and /var/log/auth.log
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

log_info "Setup Complete. Service ${SERVICE_NAME} is running."
log_info "  - Host metrics: CPU, memory, disk, network, etc."
log_info "  - Log collection: fail2ban, auth, audit logs"
log_info "  - Exporting to: ${SIGNOZ_OTLP}"
