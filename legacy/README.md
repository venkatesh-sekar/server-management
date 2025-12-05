# Legacy Bash Scripts

This directory contains the original bash scripts that have been superseded by the new Python CLI (`sm`).

These scripts are kept for reference only. Please use the new CLI for all operations.

## Migration Guide

### PostgreSQL Setup

**Old:**
```bash
sudo bash postgres/setup-pg-18.sh
```

**New:**
```bash
sudo sm postgres setup --dry-run  # Preview
sudo sm postgres setup            # Execute
```

### PostgreSQL User/Database Management

**Old:**
```bash
sudo bash postgres/add-db-user.sh
```

**New:**
```bash
# Create database with user
sm postgres db create-with-user --database myapp --user myapp_user --dry-run

# Just create user
sm postgres user create --user myuser --database mydb

# Just create database
sm postgres db create --database mydb --owner myuser

# List users
sm postgres user list

# Rotate password
sm postgres user rotate-password --user myuser
```

### Security Hardening

**Old:**
```bash
sudo bash common/host-security.sh
```

**New:**
```bash
sudo sm security harden --dry-run  # Preview
sudo sm security harden            # Execute
```

### Observability Setup

**Old:**
```bash
sudo bash common/host-metrics.sh
```

**New:**
```bash
sudo sm observability setup --otlp-endpoint http://signoz:4318 --dry-run  # Preview
sudo sm observability setup --otlp-endpoint http://signoz:4318            # Execute
```

## Why the New CLI?

The new Python CLI provides:

1. **Safety**: Dangerous operations require `--force` flag
2. **Dry-run mode**: Preview all changes before execution
3. **Validation**: Input validation prevents mistakes
4. **Audit logging**: All operations are logged to `/var/log/sm/audit.log`
5. **Rollback**: Failed operations are automatically rolled back
6. **Better output**: Colored, formatted output with progress indicators
