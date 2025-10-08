# Configuration Examples

This directory contains example configuration files for different use cases.

## Available Examples

- [development.toml](#developmenttoml) - Development environment
- [production.toml](#productiontoml) - Production environment
- [ci-cd.toml](#ci-cdtoml) - CI/CD pipeline
- [security-audit.toml](#security-audittoml) - Security auditing
- [team-standards.toml](#team-standardstoml) - Team-wide standards

## Usage

### Quick Setup

```bash
# Copy example to your config directory
mkdir -p ~/.config/valeris
cp examples/configs/development.toml ~/.config/valeris/config.toml

# Verify configuration
valeris config
```

### Environment-Specific Configuration

```bash
# Development
export VALERIS_CONFIG_FILE=examples/configs/development.toml
valeris scan

# Production
export VALERIS_CONFIG_FILE=examples/configs/production.toml
valeris scan

# CI/CD
export VALERIS_CONFIG_FILE=examples/configs/ci-cd.toml
valeris scan
```

---

## development.toml

Relaxed settings for local development with reduced noise.

**Features:**
- Only scan running containers
- Exclude noisy/low-priority rules
- Show low severity and above
- Colored table output

**Use when:**
- Developing locally
- Quick iterative testing
- Learning about security issues

```toml
[scan]
default_state = ["running"]
exclude = ["readonly_rootfs", "log_driver", "no_healthcheck", "image_no_digest"]
min_severity = "low"

[output]
format = "table"
colors = true
table_width = 120
```

---

## production.toml

Strict settings for production environments.

**Features:**
- Only scan running containers
- Show medium severity and above
- Fail builds on high severity
- JSON output for logging

**Use when:**
- Production deployments
- Compliance checking
- Security monitoring

```toml
[scan]
default_state = ["running"]
min_severity = "medium"
fail_on = "high"

[output]
format = "json"
colors = false

[docker]
timeout = 60
max_parallel = 10
```

---

## ci-cd.toml

Optimized for CI/CD pipelines with automated security gates.

**Features:**
- Scan running containers only
- Minimum medium severity
- Fail on high severity
- Quiet mode (only exit codes)

**Use when:**
- GitHub Actions, GitLab CI, Jenkins
- Automated security gates
- Pull request checks
- Deployment validation

```toml
[scan]
default_state = ["running"]
min_severity = "medium"
fail_on = "high"
quiet = true

[output]
format = "json"
colors = false
```

**Pipeline example:**
```yaml
# .github/workflows/security.yml
- name: Security Scan
  run: |
    export VALERIS_CONFIG_FILE=examples/configs/ci-cd.toml
    valeris scan || exit 1
```

---

## security-audit.toml

Focused on critical security issues for auditing.

**Features:**
- Only run critical security detectors
- Show high severity only
- All container states
- Detailed output

**Use when:**
- Security audits
- Compliance reviews
- Incident investigation
- Penetration testing prep

```toml
[scan]
only = [
    "privileged_mode",
    "capabilities",
    "secrets_in_env",
    "root_user",
    "writable_sensitive_mounts",
    "host_network",
    "host_ipc",
    "host_pid"
]
min_severity = "high"

[output]
format = "table"
colors = true
table_width = 140
```

---

## team-standards.toml

Standardized settings for team-wide adoption.

**Features:**
- Balanced detector selection
- Medium severity minimum
- Consistent output format
- Team-agreed exclusions

**Use when:**
- Sharing configuration across team
- Enforcing security standards
- Onboarding new developers
- Consistent CI/CD behavior

```toml
[scan]
default_state = ["running"]
exclude = ["readonly_rootfs", "log_driver"]
min_severity = "medium"
fail_on = "high"

[output]
format = "table"
colors = true
table_width = 120

[rules]
auto_download = true

[docker]
timeout = 30
max_parallel = 10
```

---

## Customizing Examples

### Override Specific Values

CLI arguments always override config file values:

```bash
# Use production config but show all severities
export VALERIS_CONFIG_FILE=examples/configs/production.toml
valeris scan --min-severity informative

# Use development config but fail on medium
export VALERIS_CONFIG_FILE=examples/configs/development.toml
valeris scan --fail-on medium
```

### Combine Examples

Create hybrid configs by merging examples:

```toml
# my-config.toml
# Based on production.toml but with team exclusions

[scan]
default_state = ["running"]
exclude = ["readonly_rootfs", "log_driver"]  # From team-standards
min_severity = "medium"                      # From production
fail_on = "high"                             # From production

[output]
format = "json"
colors = false
```

### Environment-Based Selection

Use environment variables to switch configs:

```bash
# ~/.bashrc or ~/.zshrc

# Development
alias valeris-dev='VALERIS_CONFIG_FILE=examples/configs/development.toml valeris'

# Production
alias valeris-prod='VALERIS_CONFIG_FILE=examples/configs/production.toml valeris'

# Security audit
alias valeris-audit='VALERIS_CONFIG_FILE=examples/configs/security-audit.toml valeris'
```

---

## See Also

- [Configuration Guide](../../docs/CONFIGURATION.md) - Detailed configuration options
- [CLI Reference](../../docs/CLI.md) - Complete CLI documentation
- [CI/CD Integration](../../docs/CI-CD-INTEGRATION.md) - Pipeline integration guide
