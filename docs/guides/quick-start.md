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

# Scan only running containers
valeris scan --state running

# Scan exited containers
valeris scan --state exited
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

Fail build on critical Dockerfile issues:

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
valeris list-plugins
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

### Environment Variables

```bash
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

### Combining Filters

```bash
# Running containers, only security checks
valeris scan \
  --state running \
  --only privileged_mode,capabilities,secrets_in_env,root_user
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

- [Architecture Overview](../architecture/overview.md) - Understand how Valeris works
- [Dockerfile Rules](../rules/dockerfile-rules.md) - Full list of Dockerfile detectors
- [Runtime Rules](../rules/runtime-rules.md) - Full list of runtime detectors
- [CI/CD Integration](ci-cd-integration.md) - Set up automated scanning
- [Custom Rules](custom-rules.md) - Write your own detectors
