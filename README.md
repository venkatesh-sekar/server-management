# Server Management CLI (`sm`)

A secure, production-ready CLI for managing servers on Debian/Ubuntu.

## Features

- **Cloud-Init Generator**: Generate cloud-init configs for Hetzner servers with Docker MTU fixes
- **Docker Management**: Fix MTU issues on Hetzner Cloud (1450 for VXLAN overlay networks)
- **PostgreSQL Management**: Setup PostgreSQL 18 with PgBouncer, pgBackRest backups, user/database management
- **Security Hardening**: fail2ban (SSH protection), auditd (security auditing), unattended-upgrades
- **Observability**: OpenTelemetry Collector for host metrics and log collection
- **Safety First**: Strict validation, dry-run mode, dangerous operation protection, audit logging

## Installation

```bash
# Install with pip (Python 3.12+)
pip install -e ".[dev]"

# Or install in development mode
pip install -e .
```

## Quick Start

```bash
# Show help
sm --help

# Initialize configuration file
sm config init

# Show current configuration
sm config show

# Validate configuration
sm config validate
```

## Command Reference

### Cloud-Init for Hetzner Servers

Use the unified cloud-init template to set up servers:

```bash
# 1. Copy the template
cp cloudinit/unified.yaml my-server.yaml

# 2. Edit variables at the top
# - SM_REPO_URL: Your fork or upstream repo
# - ENABLE_DOCKER: true/false
# - ENABLE_SECURITY: true/false (highly recommended)
# - ENABLE_OBSERVABILITY: true/false
# - ENABLE_POSTGRES: true/false
# - OTLP_ENDPOINT: Your monitoring endpoint (if observability enabled)

# 3. Paste into Hetzner Cloud Console or use with CLI
hcloud server create --name worker-1 --user-data-from-file my-server.yaml
```

**What it does:**
- ✅ Automatically installs SM CLI from GitHub
- ✅ Configures Docker with MTU 1450 fix (critical for Hetzner!)
- ✅ Sets up security hardening (fail2ban, auditd)
- ✅ Optionally enables observability and PostgreSQL
- ✅ Self-contained - no local SM CLI installation needed

**Why Docker MTU fix?** Hetzner private networks use VXLAN (MTU 1450). Docker's default overlay MTU is 1500. Mismatch causes silent packet drops and S3/external connectivity failures.

**See:** [docs/UNIFIED_CLOUDINIT.md](docs/UNIFIED_CLOUDINIT.md) for detailed guide and examples.

### Docker MTU Fix

For existing servers not provisioned with cloud-init, you can manually fix Docker MTU:

```bash
# Apply MTU 1450 fix for Hetzner Cloud
sudo sm docker fix-mtu

# Preview what would happen
sm docker fix-mtu --dry-run

# Use custom MTU value
sudo sm docker fix-mtu --mtu=1400
```

**What it does:**
- ✅ Creates/updates `/etc/docker/daemon.json` with MTU configuration
- ✅ Preserves existing Docker settings (logs, etc.)
- ✅ Restarts Docker daemon to apply changes
- ✅ Automatic rollback on errors

**When to use:** Apply this fix on existing Hetzner Cloud servers experiencing packet drops or S3 connectivity issues.

### PostgreSQL Setup

```bash
# Preview PostgreSQL + PgBouncer + pgBackRest setup
sudo sm postgres setup --dry-run

# Full setup (uses config file for backup settings)
sudo sm postgres setup

# Setup without backup configuration
sudo sm postgres setup --skip-backup
```

### PostgreSQL User Management

```bash
# Create a user for a database
sm postgres user create --user myuser --database mydb --dry-run

# List all users
sm postgres user list

# Rotate user password
sm postgres user rotate-password --user myuser

# Delete user (requires --force)
sm postgres user delete --user myuser --force --confirm-name=myuser
```

### PostgreSQL Database Management

```bash
# Create database with user (recommended)
sm postgres db create-with-user --database myapp --user myapp_user --dry-run

# Create database only
sm postgres db create --database mydb --owner myuser

# List databases
sm postgres db list

# Grant access
sm postgres db grant --database mydb --user readonly_user --level readonly

# Drop database (dangerous - requires --force)
sm postgres db drop --database mydb --force --confirm-name=mydb
```

### Security Hardening

```bash
# Preview security hardening
sm security harden --dry-run

# Full security hardening
sudo sm security harden

# Custom fail2ban settings
sudo sm security harden --bantime=1h --maxretry=3

# Skip specific components
sudo sm security harden --skip-auditd
```

### Observability Setup

```bash
# Preview OpenTelemetry Collector setup
sm observability setup --otlp-endpoint http://signoz:4318 --dry-run

# Full setup with OTLP endpoint
sudo sm observability setup --otlp-endpoint http://signoz:4318

# Metrics only (no log collection)
sudo sm observability setup --otlp-endpoint http://signoz:4318 --skip-logs
```

## Safety Features

| Feature | Description |
|---------|-------------|
| **Dry-run mode** | `--dry-run` previews all changes without executing |
| **Force flag** | Dangerous operations require `--force` |
| **Name confirmation** | Critical operations require `--confirm-name=<name>` |
| **Input validation** | PostgreSQL identifiers, CIDR ranges, URLs validated |
| **Audit logging** | All operations logged to `/var/log/sm/audit.log` |
| **Rollback** | Failed operations are automatically rolled back |

## Configuration

Configuration is stored in `/etc/sm/config.yaml`. Example:

```yaml
postgres:
  version: "18"
  host: 127.0.0.1
  port: 5432

pgbouncer:
  enabled: true
  port: 6432
  pool_mode: transaction

backup:
  enabled: true
  s3_endpoint: s3.us-west-004.backblazeb2.com
  s3_bucket: my-backups

security:
  fail2ban_enabled: true
  auditd_enabled: true

observability:
  enabled: true
  otlp_endpoint: http://signoz:4318
```

Secrets are loaded from environment variables:

- `SM_B2_KEY`: Backblaze B2 application key
- `SM_B2_SECRET`: Backblaze B2 application secret
- `SM_BACKUP_PASSPHRASE`: Backup encryption passphrase
- `SM_PG_SUPERUSER_PASS`: PostgreSQL superuser password (optional)

## Project Structure

```
server-management/
├── src/sm/                   # Main package
│   ├── cli.py               # Typer CLI entry point
│   ├── core/                # Framework components
│   │   ├── config.py        # Pydantic config models
│   │   ├── safety.py        # Safety checks
│   │   ├── validation.py    # Input validators
│   │   ├── credentials.py   # Secure credential handling
│   │   ├── audit.py         # Audit logging
│   │   └── executor.py      # Command execution
│   ├── commands/            # Command implementations
│   │   ├── postgres/        # PostgreSQL commands
│   │   ├── security/        # Security commands
│   │   └── observability/   # Observability commands
│   ├── services/            # Service abstractions
│   └── templates/           # Jinja2 config templates
├── tests/                   # Unit and integration tests
├── legacy/                  # Original bash scripts (reference)
└── pyproject.toml           # Package configuration
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check src/

# Run type checking
mypy src/
```

## License

MIT
