#!/bin/bash
# =============================================================================
# SM CLI Installer
# =============================================================================
# One-liner installation:
#   curl -fsSL https://raw.githubusercontent.com/venkatesh-sekar/server-management/main/install.sh | bash
#
# Or with a specific branch:
#   curl -fsSL https://raw.githubusercontent.com/venkatesh-sekar/server-management/main/install.sh | bash -s -- --branch develop
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
SM_REPO_URL="https://github.com/venkatesh-sekar/server-management.git"
SM_BRANCH="main"
INSTALL_DIR="/opt/sm"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --branch|-b)
            SM_BRANCH="$2"
            shift 2
            ;;
        --help|-h)
            echo "SM CLI Installer"
            echo ""
            echo "Usage: curl -fsSL <url>/install.sh | bash -s -- [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --branch, -b <branch>  Branch/tag to install (default: main)"
            echo "  --help, -h             Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

echo -e "${GREEN}==> Installing SM CLI${NC}"
echo "    Repository: ${SM_REPO_URL}"
echo "    Branch: ${SM_BRANCH}"
echo ""

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo)${NC}"
    exit 1
fi

# Install dependencies
echo -e "${YELLOW}==> Installing dependencies...${NC}"
apt-get update -qq
apt-get install -y -qq git python3 python3-pip python3-venv pipx > /dev/null

# Clone or update repository
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}==> Updating existing installation...${NC}"
    cd "$INSTALL_DIR"
    git fetch origin
    git checkout "$SM_BRANCH"
    git pull origin "$SM_BRANCH"
else
    echo -e "${YELLOW}==> Cloning repository...${NC}"
    git clone --branch "$SM_BRANCH" "$SM_REPO_URL" "$INSTALL_DIR"
fi

# Install SM CLI using pipx
echo -e "${YELLOW}==> Installing SM CLI...${NC}"
PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install --force "$INSTALL_DIR"

# Verify installation
echo ""
echo -e "${GREEN}==> Installation complete!${NC}"
echo ""
sm --version
echo ""
echo -e "${GREEN}Available commands:${NC}"
echo "  sm --help              # Show all available commands"
echo "  sm security harden     # Apply security hardening"
echo "  sm postgres setup      # Setup PostgreSQL"
echo "  sm observability setup # Setup observability"
echo "  sm docker mtu          # Fix Docker MTU for Hetzner"
