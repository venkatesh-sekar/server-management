# Unified Cloud-Init Configuration Guide

## Overview

The unified cloud-init configuration provides a single, self-contained template that bootstraps the SM CLI and automatically configures your Hetzner Cloud server with your chosen components.

**Benefits:**
- ✅ Single file to copy/paste - no complex setup
- ✅ Self-installing - automatically installs SM CLI from GitHub
- ✅ Always secure - includes security hardening by default
- ✅ Customizable - simple variables control what gets installed
- ✅ Version controlled - pin to specific branches/tags
- ✅ Fork-friendly - works with your own repository forks

## Quick Start

### 1. Copy the Template

Copy the file `cloudinit/unified.yaml` from this repository.

### 2. Edit Configuration Variables

At the top of the file, edit these variables:

```yaml
# Required: Point to your fork or the upstream repository
SM_REPO_URL: "https://github.com/YOUR_USERNAME/server-management.git"

# Optional: Specify branch or tag (default: main)
SM_BRANCH: "main"

# Enable/disable components
ENABLE_DOCKER: true
ENABLE_SECURITY: true
ENABLE_OBSERVABILITY: false
ENABLE_POSTGRES: false

# If observability is enabled, set the OTLP endpoint
OTLP_ENDPOINT: ""
```

### 3. Create Server with Cloud-Init

In the Hetzner Cloud Console:
1. Create a new server
2. Choose Ubuntu 24.04 LTS
3. In the "Cloud config" section, paste your edited `unified.yaml`
4. Complete server creation

### 4. Wait for Setup

The server will automatically:
1. Update system packages
2. Install SM CLI from your specified repository
3. Configure Docker (if enabled)
4. Apply security hardening (if enabled)
5. Setup observability (if enabled)
6. Install PostgreSQL (if enabled)

Setup typically takes 3-5 minutes. Monitor progress in `/var/log/cloud-init-output.log`.

## Configuration Reference

### Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SM_REPO_URL` | string | (required) | GitHub repository URL for SM CLI |
| `SM_BRANCH` | string | `main` | Branch or tag to install from |
| `ENABLE_DOCKER` | boolean | `true` | Install Docker with MTU 1450 fix |
| `ENABLE_SECURITY` | boolean | `true` | Install fail2ban, auditd, unattended-upgrades |
| `ENABLE_OBSERVABILITY` | boolean | `false` | Install OpenTelemetry Collector |
| `ENABLE_POSTGRES` | boolean | `false` | Install PostgreSQL 18 |
| `OTLP_ENDPOINT` | string | `""` | OTLP endpoint (required if observability enabled) |
| `HOSTNAME` | string | `""` | Custom hostname (optional) |

### Component Details

#### Docker (`ENABLE_DOCKER`)

**What it does:**
- Installs Docker Engine from official get.docker.com
- Configures MTU 1450 (required for Hetzner overlay networks)
- Sets up log rotation (10MB max, 3 files)
- Enables Docker service to start on boot

**When to enable:**
- Running containerized applications
- Docker Swarm deployments
- Kubernetes nodes
- Any microservices architecture

**When to disable:**
- Traditional VM deployments
- PostgreSQL-only servers
- Specialized workloads without containers

#### Security Hardening (`ENABLE_SECURITY`)

**What it does:**
- Installs and configures fail2ban for SSH protection
- Installs auditd for security audit logging
- Configures unattended-upgrades for automatic security patches

**Settings:**
- fail2ban: 5 failed attempts → 10 minute ban
- SSH port monitoring enabled
- Automatic security updates enabled

**Recommendation:** **Always enable** for production servers.

#### Observability (`ENABLE_OBSERVABILITY`)

**What it does:**
- Installs OpenTelemetry Collector
- Exports host metrics (CPU, memory, disk, network, load)
- Exports system logs (/var/log/syslog, /var/log/auth.log)
- Sends data to your OTLP endpoint

**Requirements:**
- Must set `OTLP_ENDPOINT` variable
- Endpoint must be accessible from the server
- Endpoint must support OTLP protocol (e.g., SigNoz, Jaeger, Grafana Tempo)

**Example endpoints:**
```yaml
OTLP_ENDPOINT: "http://signoz:4318"
OTLP_ENDPOINT: "http://10.0.0.10:4318"
OTLP_ENDPOINT: "http://monitoring.internal:4318"
```

#### PostgreSQL (`ENABLE_POSTGRES`)

**What it does:**
- Installs PostgreSQL 18 from official PGDG repository
- Installs postgresql-contrib extensions
- Enables PostgreSQL service

**Note:** This is a basic installation only. For full production setup with PgBouncer and backups, SSH into the server and run:
```bash
sm postgres setup
```

## Common Use Cases

### Use Case 1: Docker Swarm Worker

**Scenario:** Standard Docker Swarm worker node with security and monitoring.

```yaml
SM_REPO_URL: "https://github.com/your-company/server-management.git"
SM_BRANCH: "main"
ENABLE_DOCKER: true
ENABLE_SECURITY: true
ENABLE_OBSERVABILITY: true
ENABLE_POSTGRES: false
OTLP_ENDPOINT: "http://10.0.0.10:4318"
```

**Result:** Server with Docker, security hardening, and metrics/logs exported to monitoring stack.

### Use Case 2: Minimal Docker Host

**Scenario:** Simple Docker host for development or testing.

```yaml
SM_REPO_URL: "https://github.com/your-company/server-management.git"
SM_BRANCH: "main"
ENABLE_DOCKER: true
ENABLE_SECURITY: true
ENABLE_OBSERVABILITY: false
ENABLE_POSTGRES: false
```

**Result:** Lightweight server with just Docker and basic security.

### Use Case 3: PostgreSQL Database Server

**Scenario:** Dedicated PostgreSQL server with monitoring.

```yaml
SM_REPO_URL: "https://github.com/your-company/server-management.git"
SM_BRANCH: "main"
ENABLE_DOCKER: false
ENABLE_SECURITY: true
ENABLE_OBSERVABILITY: true
ENABLE_POSTGRES: true
OTLP_ENDPOINT: "http://monitoring.internal:4318"
```

**Result:** PostgreSQL server with security hardening and metrics export.

**Post-setup:** Run `sm postgres setup` for full production configuration.

### Use Case 4: Full Stack Server

**Scenario:** All-in-one server for small deployments.

```yaml
SM_REPO_URL: "https://github.com/your-company/server-management.git"
SM_BRANCH: "main"
ENABLE_DOCKER: true
ENABLE_SECURITY: true
ENABLE_OBSERVABILITY: true
ENABLE_POSTGRES: true
OTLP_ENDPOINT: "http://localhost:4318"
```

**Result:** Server with all components installed and configured.

## Troubleshooting

### Check Setup Progress

```bash
# View real-time cloud-init logs
tail -f /var/log/cloud-init-output.log

# Check cloud-init status
cloud-init status

# View detailed cloud-init logs
less /var/log/cloud-init.log
```

### Common Issues

#### Issue: "ERROR: OTLP_ENDPOINT required for observability"

**Cause:** `ENABLE_OBSERVABILITY=true` but `OTLP_ENDPOINT` is empty.

**Solution:** Set the OTLP endpoint:
```yaml
OTLP_ENDPOINT: "http://your-monitoring-server:4318"
```

#### Issue: "git clone failed"

**Cause:**
- Invalid repository URL
- Repository is private and server can't access it
- Network connectivity issues

**Solution:**
- Verify `SM_REPO_URL` is correct and public
- For private repos, add deploy keys to your repository
- Check network connectivity: `curl -I https://github.com`

#### Issue: "pip install failed"

**Cause:**
- Python package conflicts
- Missing dependencies
- Corrupted repository

**Solution:**
```bash
# Retry installation
cd /opt/sm
pip3 install --break-system-packages -e .
```

#### Issue: Docker MTU issues in Swarm

**Cause:** MTU not properly applied to overlay networks.

**Verification:**
```bash
# Check Docker daemon.json
cat /etc/docker/daemon.json

# Should show: "com.docker.network.driver.mtu": "1450"

# Restart Docker if needed
systemctl restart docker
```

#### Issue: SM command not found

**Cause:** Symlink not created or PATH issue.

**Solution:**
```bash
# Recreate symlink
ln -sf /usr/local/bin/sm /usr/bin/sm

# Verify
which sm
sm --version
```

### Verify Installation

```bash
# Check SM CLI version
sm --version

# Check Docker (if enabled)
docker --version
docker info | grep -i mtu

# Check security services (if enabled)
systemctl status fail2ban
systemctl status auditd

# Check PostgreSQL (if enabled)
sudo -u postgres psql -c "SELECT version();"

# Check observability (if enabled)
systemctl status otel-collector
```

## Configuration Examples for Different Scenarios

Here's how to configure `unified.yaml` for common server types:

### Minimal Docker Host

Just Docker with security:

```yaml
ENABLE_DOCKER: true
ENABLE_SECURITY: true
ENABLE_OBSERVABILITY: false
ENABLE_POSTGRES: false
```

### Docker Swarm Worker with Monitoring

Docker + Security + Observability:

```yaml
ENABLE_DOCKER: true
ENABLE_SECURITY: true
ENABLE_OBSERVABILITY: true
ENABLE_POSTGRES: false
OTLP_ENDPOINT: "http://monitoring.internal:4318"
```

### Full Stack Server

Everything enabled:

```yaml
ENABLE_DOCKER: true
ENABLE_SECURITY: true
ENABLE_OBSERVABILITY: true
ENABLE_POSTGRES: true
OTLP_ENDPOINT: "http://your-endpoint:4318"
```

## Advanced Usage

### Using Specific Versions

Pin to a specific release tag for stability:

```yaml
SM_BRANCH: "v1.0.0"  # Use release tag
```

Or use a development branch:

```yaml
SM_BRANCH: "develop"  # Use development branch
```

### Using a Forked Repository

1. Fork the server-management repository
2. Make your customizations
3. Update `SM_REPO_URL`:

```yaml
SM_REPO_URL: "https://github.com/your-username/server-management.git"
```

### Custom Hostname

Set a custom hostname for your server:

```yaml
HOSTNAME: "web-prod-01"
```

### Multiple Servers with Different Configs

Create multiple copies of `unified.yaml` with different names:

```
unified-worker.yaml  (Docker only)
unified-db.yaml      (PostgreSQL + monitoring)
unified-full.yaml    (Everything)
```

Edit each file with appropriate settings for that server type.

## Security Considerations

### Repository Trust

**Important:** The unified cloud-init downloads and executes code from the repository specified in `SM_REPO_URL`.

**Best practices:**
- Only use repositories you trust
- Pin to specific tags instead of branches
- Review code before using
- Use your own fork for production

### Secrets Management

**Never put secrets in cloud-init YAML:**
- ❌ Database passwords
- ❌ API keys
- ❌ Private keys

**Instead:**
- Use Hetzner Cloud's secrets management
- Fetch secrets from a vault during boot
- Use environment-specific configuration post-boot

### Network Security

The cloud-init needs network access to:
- GitHub (to clone repository)
- Docker Hub (to download Docker installer)
- PGDG repository (if PostgreSQL enabled)
- Your OTLP endpoint (if observability enabled)

Ensure firewalls allow outbound HTTPS (443) traffic during boot.

## FAQ

### Q: Can I use this with other cloud providers?

**A:** The unified cloud-init is designed for Hetzner Cloud (Docker MTU 1450), but can be adapted for other providers by changing the MTU value in the Docker daemon.json section.

### Q: How long does setup take?

**A:** Typically 3-5 minutes depending on:
- Number of components enabled
- Server specs
- Network speed
- Package repository load

### Q: Can I add custom commands?

**A:** Yes! Add commands to the `runcmd` section. Place them after Phase 6 to ensure SM CLI is available.

### Q: Does this work with private repositories?

**A:** Yes, but you need to configure deploy keys or SSH keys. See GitHub documentation on deploy keys.

### Q: Can I skip security hardening?

**A:** Yes, but **not recommended**. Set `ENABLE_SECURITY: false` if you must.

### Q: What if cloud-init fails?

**A:** Cloud-init logs errors to `/var/log/cloud-init-output.log`. You can:
1. Review logs for errors
2. Fix issues manually via SSH
3. Re-run failed commands from the log

### Q: Can I update SM CLI after installation?

**A:** Yes! SSH into the server and run:
```bash
cd /opt/sm
git pull
pip3 install --break-system-packages -e .
```

## Support

### Resources

- **Documentation:** [README.md](../README.md)
- **SM CLI Help:** `sm --help`
- **Examples:** [examples/](../examples/)

### Getting Help

1. Check logs: `/var/log/cloud-init-output.log`
2. Verify configuration variables are correct
3. Review this documentation
4. Check SM CLI help: `sm --help`

