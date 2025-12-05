#!/bin/bash
# Apply Docker MTU fix to existing Hetzner servers
# This fixes S3/external connectivity issues in Docker Swarm on Hetzner private networks
#
# Usage:
#   ./scripts/apply-docker-mtu-fix.sh                    # Apply to local server
#   ./scripts/apply-docker-mtu-fix.sh user@server        # Apply to remote server

set -euo pipefail

# Configuration
DAEMON_JSON_PATH="/etc/docker/daemon.json"
BACKUP_PATH="/etc/docker/daemon.json.backup-$(date +%Y%m%d-%H%M%S)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Remote host (if provided)
REMOTE_HOST="${1:-}"

function log_info() {
    echo -e "${GREEN}✓${NC} $1"
}

function log_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

function log_error() {
    echo -e "${RED}✗${NC} $1"
}

function run_command() {
    if [ -n "$REMOTE_HOST" ]; then
        ssh "$REMOTE_HOST" "$@"
    else
        eval "$@"
    fi
}

function main() {
    echo "==================================="
    echo "Docker MTU Fix for Hetzner Servers"
    echo "==================================="
    echo ""

    if [ -n "$REMOTE_HOST" ]; then
        log_info "Target: Remote server ($REMOTE_HOST)"
    else
        log_info "Target: Local server"
    fi

    # Check if Docker is installed
    if ! run_command "command -v docker > /dev/null 2>&1"; then
        log_error "Docker is not installed on the target server"
        exit 1
    fi

    log_info "Docker is installed"

    # Backup existing daemon.json if it exists
    if run_command "test -f $DAEMON_JSON_PATH"; then
        log_warn "Found existing daemon.json, creating backup..."
        run_command "cp $DAEMON_JSON_PATH $BACKUP_PATH"
        log_info "Backup created at: $BACKUP_PATH"
    fi

    # Create new daemon.json with MTU fix
    log_info "Creating daemon.json with MTU 1450..."

    run_command "cat > $DAEMON_JSON_PATH <<'EOF'
{
  \"log-driver\": \"json-file\",
  \"log-opts\": {
    \"max-size\": \"10m\",
    \"max-file\": \"3\"
  },
  \"default-network-opts\": {
    \"overlay\": {
      \"com.docker.network.driver.mtu\": \"1450\"
    }
  }
}
EOF"

    log_info "daemon.json created successfully"

    # Ask for confirmation before restarting Docker
    echo ""
    log_warn "This will restart Docker (brief service interruption)"
    read -p "Continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_warn "Aborted. daemon.json is updated but Docker not restarted."
        log_warn "Run 'systemctl restart docker' when ready."
        exit 0
    fi

    # Restart Docker
    log_info "Restarting Docker daemon..."
    run_command "systemctl restart docker"
    sleep 2

    # Verify Docker is running
    if run_command "systemctl is-active docker > /dev/null 2>&1"; then
        log_info "Docker restarted successfully"
    else
        log_error "Docker failed to restart!"
        log_error "Check logs: journalctl -u docker -n 50"
        exit 1
    fi

    # Verify MTU configuration
    echo ""
    log_info "Verifying MTU configuration..."

    if run_command "docker info | grep -q 'Default Network Opts'"; then
        log_info "MTU configuration applied successfully"
    else
        log_warn "Could not verify MTU configuration"
        log_warn "Check manually: docker network inspect <overlay-network> | grep mtu"
    fi

    echo ""
    echo "==================================="
    log_info "Docker MTU fix applied successfully!"
    echo "==================================="
    echo ""
    echo "Next steps:"
    echo "  1. Verify overlay networks use MTU 1450:"
    echo "     docker network ls --filter driver=overlay"
    echo "     docker network inspect <network-name> | grep mtu"
    echo ""
    echo "  2. Test S3 connectivity:"
    echo "     curl -v https://s3.us-west-002.backblazeb2.com"
    echo ""
    echo "Note: Existing overlay networks may need to be recreated"
    echo "      to use the new MTU setting."
}

# Run main function
main "$@"
