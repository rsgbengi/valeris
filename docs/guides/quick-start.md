# Quick Start Guide

Get up and running with Valeris in less than 5 minutes.

## Prerequisites

- **Docker** running locally
- **Rust 1.71+** installed
- **Linux or macOS** (Windows support coming in v0.2)

## Installation

### From Source

```bash
git clone https://github.com/rsgbengi/valeris.git
cd valeris
cargo build --release
```

The binary will be at `./target/release/valeris`

### Install to System

```bash
sudo cp target/release/valeris /usr/local/bin/
valeris --help
```

## Your First Scan

### 1. Scan Running Containers

```bash
# Scan all containers
valeris scan
# Or use the short alias
valeris s

# Scan only running containers
valeris scan --state running

# Scan specific containers by name or ID
valeris scan --container nginx
valeris scan -c redis,postgres

# Scan exited containers
valeris scan --state exited

# Combine filters
valeris scan --state running --container web-app
```

**Output:**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🐳 Container: nginx-app
   Image: nginx:latest
   Status: Running
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ⚠️  3 issues found: 1 critical, 1 medium, 1 low

┌──────────┬───────────────┬─────────────────────────────────────────┐
│ Severity │ Rule ID       │ Description                              │
╞══════════╪═══════════════╪═════════════════════════════════════════╡
│ CRITICAL │ root_user     │ Container is running as root             │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ MEDIUM   │ latest_tag    │ Container uses image with 'latest' tag   │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ LOW      │ no_healthcheck│ Container has no health check configured │
└──────────┴───────────────┴─────────────────────────────────────────┘
```

### 2. Scan a Dockerfile

```bash
# Basic scan
valeris docker-file --path ./Dockerfile --rules ./rules/dockerfile
# Or use the short alias with shortcuts
valeris df -p ./Dockerfile -r ./rules/dockerfile

# Scan example files
valeris docker-file --path examples/bad-dockerfile --rules ./rules/dockerfile
```

**Output:**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 Scanning Dockerfile: bad-dockerfile
   Path: examples/bad-dockerfile
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ⚠️  24 issues found: 7 critical, 4 medium, 12 low, 1 info

┌──────────┬───────┬──────┬──────────────────────────────────────────────┐
│ Severity │ ID    │ Line │ Description                                   │
╞══════════╪═══════╪══════╪══════════════════════════════════════════════╡
│ CRITICAL │ DF006 │ 9    │ Possible hardcoded secret in ENV variable     │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ CRITICAL │ DF202 │ 5    │ curl using insecure flag (-k/--insecure)      │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ MEDIUM   │ DF001 │ 1    │ Base image uses a mutable tag (latest or no tag) │
└──────────┴───────┴──────┴──────────────────────────────────────────────┘
```

### 3. Export Results

#### JSON Export
```bash
valeris scan --format json --output results.json

# Pretty-print
cat results.json | jq '.'
```

#### CSV Export
```bash
valeris scan --format csv --output findings.csv

# Open in spreadsheet
libreoffice findings.csv
```

## Common Use Cases

### 1. Security Audit

Check all containers for critical issues:

```bash
valeris scan --only privileged_mode,capabilities,writable_sensitive_mounts,secrets_in_env
```

### 2. Development Workflow

Quick checks during development (exclude noisy rules):

```bash
valeris scan --exclude readonly_rootfs,log_driver,no_healthcheck
```

### 3. CI/CD Pipeline

Use built-in `--fail-on` flag to fail builds automatically:

```bash
#!/bin/bash
# Fail on high severity findings
if ! valeris scan --quiet --fail-on high; then
  echo "❌ Critical security issues found!"
  exit 1
fi

echo "✅ Security scan passed"
```

Alternative with Dockerfile scanning:

```bash
#!/bin/bash
valeris docker-file --path Dockerfile --rules ./rules/dockerfile \
  --format json --output scan.json

# Check for CRITICAL findings
if jq -e '.findings[] | select(.severity == "CRITICAL")' scan.json > /dev/null; then
  echo "❌ Critical security issues found!"
  jq '.findings[] | select(.severity == "CRITICAL")' scan.json
  exit 1
fi

echo "✅ No critical issues found"
```

See also: [CI/CD Integration Guide](../CI-CD-INTEGRATION.md)

### 4. Compliance Reporting

Generate audit reports:

```bash
# Full scan with timestamps
valeris scan --format json --output "audit-$(date +%Y%m%d).json"

# Runtime compliance check
valeris scan --state running --format csv --output compliance.csv
```

## Understanding Output

### Severity Levels

| Level | Icon | Meaning | Examples |
|-------|------|---------|----------|
| **CRITICAL** | 🔴 | Immediate security risk | Hardcoded secrets, privileged mode |
| **HIGH** | 🟠 | Serious security issue | Dangerous capabilities, seccomp disabled |
| **MEDIUM** | 🟡 | Potential security concern | Root user, exposed sensitive ports |
| **LOW** | 🔵 | Best practice violation | Missing resource limits, deprecated flags |
| **INFO** | ⚪ | Informational | Missing healthcheck, no digest |

### Table Columns

**Runtime Scan:**
- **Severity** - Risk level (CRITICAL → INFO)
- **Rule ID** - Detector identifier
- **Description** - What was found

**Dockerfile Scan:**
- **Severity** - Risk level
- **ID** - Rule identifier (DF001, DF002...)
- **Line** - Line number in Dockerfile
- **Description** - Issue description

## List Available Detectors

See what rules are loaded:

```bash
# List all detectors
valeris list-plugins
# Or use the short alias
valeris ls

# Filter by target platform
valeris list-plugins --target docker
valeris ls -t docker
```

Output:
```
Available YAML detectors:
- [privileged_mode] Privileged Mode docker_runtime
- [capabilities] Linux Capabilities docker_runtime
- [root_user] Root User docker_runtime
- [secrets_in_env] Secrets in Environment docker_runtime
- [writable_sensitive_mounts] Writable Sensitive Mounts docker_runtime
... (36 total runtime rules)
```

## Configuration

### Configuration File

Valeris supports persistent configuration via TOML files:

```bash
# Create config directory
mkdir -p ~/.config/valeris

# Copy example config
cp valeris.toml.example ~/.config/valeris/config.toml

# Edit to your preferences
vi ~/.config/valeris/config.toml

# Verify configuration
valeris config
```

**Example `~/.config/valeris/config.toml`:**
```toml
[scan]
default_state = ["running"]
min_severity = "medium"
exclude = ["readonly_rootfs", "log_driver"]

[output]
format = "table"
colors = true
```

**Configuration precedence:** CLI arguments always override config file values.

See also: [Configuration Guide](../CONFIGURATION.md)

### Environment Variables

```bash
# Custom config file location
export VALERIS_CONFIG_FILE=/etc/valeris/config.toml
valeris scan

# Custom rules location
export VALERIS_RULES_DIR=/opt/valeris/custom-rules
valeris scan

# Enable debug logging
export RUST_LOG=debug
valeris scan

# Info-level logging
export RUST_LOG=info
valeris docker-file --path Dockerfile --rules ./rules/dockerfile
```

### Rules Location

Default paths (tried in order):
1. `$VALERIS_RULES_DIR` (if set)
2. `$XDG_DATA_HOME/valeris/detectors`
3. `$HOME/.local/share/valeris/detectors`

On first run, Valeris downloads rules from GitHub releases automatically.

## Filtering Results

### By Rule ID

```bash
# Only run specific detectors
valeris scan --only privileged_mode,capabilities

# Exclude specific detectors
valeris scan --exclude log_driver,image_no_digest

# Note: --only and --exclude cannot be used together
```

### By Container State

```bash
# Only running containers
valeris scan --state running

# Only stopped containers
valeris scan --state exited

# Multiple states
valeris scan --state "running,paused"
```

### By Container Name or ID

```bash
# Scan specific container by name
valeris scan --container nginx
valeris scan -c web-app

# Scan multiple containers
valeris scan --container nginx,redis,postgres

# Search by partial name or ID
valeris scan --container app-  # Matches app-1, app-2, etc.
valeris scan -c abc123         # Match by container ID prefix
```

### By Severity

```bash
# Show only high severity findings
valeris scan --severity high

# Show only medium and high
valeris scan --severity medium,high

# Show findings at or above medium
valeris scan --min-severity medium

# Note: --severity and --min-severity cannot be used together
```

**Severity levels (in order):**
- `informative` - Informational findings
- `low` - Low risk issues
- `medium` - Medium risk issues
- `high` - High risk/critical issues

### Combining Filters

```bash
# Running containers, only security checks
valeris scan \
  --state running \
  --only privileged_mode,capabilities,secrets_in_env,root_user

# Specific containers with targeted scans
valeris scan \
  --container nginx,redis \
  --state running \
  --only exposed_ports,capabilities

# Filter by state and container name with severity
valeris scan --state running --container web- --min-severity high
```

## Troubleshooting

### Docker Connection Failed

```bash
# Check Docker is running
docker ps

# Check socket permissions
ls -l /var/run/docker.sock

# Run with elevated permissions
sudo valeris scan
```

### No Rules Found

```bash
# Check rules directory
ls -la ~/.local/share/valeris/detectors

# Force re-download
rm -rf ~/.local/share/valeris/detectors
valeris scan  # Will auto-download
```

### Debug Logging

```bash
# Enable detailed logging
RUST_LOG=debug valeris scan

# Log to file
RUST_LOG=debug valeris scan 2> debug.log
```

## Next Steps

- [CLI Reference](../CLI.md) - Complete CLI documentation
- [Configuration Guide](../CONFIGURATION.md) - Detailed configuration options
- [CI/CD Integration](../CI-CD-INTEGRATION.md) - Set up automated scanning
- [Architecture Overview](../architecture/overview.md) - Understand how Valeris works
- [Dockerfile Rules](../rules/dockerfile-rules.md) - Full list of Dockerfile detectors
- [Runtime Rules](../rules/runtime-rules.md) - Full list of runtime detectors
