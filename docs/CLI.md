# CLI Reference

Complete command-line interface reference for Valeris.

## Table of Contents

- [Overview](#overview)
- [Global Options](#global-options)
- [Commands](#commands)
  - [scan](#scan)
  - [docker-file](#docker-file)
  - [list-plugins](#list-plugins)
  - [config](#config)
- [Filtering](#filtering)
- [Output Formats](#output-formats)
- [Examples](#examples)

---

## Overview

Valeris provides a simple, intuitive CLI for security scanning. All commands support:

- **Command aliases** for faster typing
- **Short flags** for common options
- **Comprehensive help** with `--help`
- **Tab completion** (shell-dependent)

### Command Aliases

| Command | Alias | Description |
|---------|-------|-------------|
| `scan` | `s` | Scan running containers |
| `docker-file` | `df` | Scan Dockerfiles |
| `list-plugins` | `ls` | List available detectors |
| `config` | `cfg` | Show configuration status |

---

## Global Options

```bash
valeris [OPTIONS] <COMMAND>
```

| Option | Description |
|--------|-------------|
| `-h, --help` | Print help information |
| `-V, --version` | Print version information |

---

## Commands

### scan

Scan running Docker containers for security misconfigurations.

```bash
valeris scan [OPTIONS]
```

#### Options

**Target Selection:**

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--target <TARGET>` | `-t` | `docker` | Target platform (docker, k8s, both) |

**Detector Filtering:**

| Option | Short | Description |
|--------|-------|-------------|
| `--only <DETECTORS>` | | Run only specified detectors (comma-separated) |
| `--exclude <DETECTORS>` | | Exclude specified detectors (comma-separated) |

**Note:** `--only` and `--exclude` are mutually exclusive.

**Container Filtering:**

| Option | Short | Description |
|--------|-------|-------------|
| `--state <STATES>` | | Filter by container state (comma-separated) |
| `--container <PATTERN>` | `-c` | Filter by container name or ID (comma-separated) |

**Severity Filtering:**

| Option | Short | Description |
|--------|-------|-------------|
| `--severity <SEVERITIES>` | | Filter by exact severity levels (comma-separated) |
| `--min-severity <LEVEL>` | | Show only findings at or above this level |

**Note:** `--severity` and `--min-severity` are mutually exclusive.

Available severity levels (in order): `informative`, `low`, `medium`, `high`

**CI/CD Integration:**

| Option | Short | Description |
|--------|-------|-------------|
| `--fail-on <LEVEL>` | | Exit with code 1 if findings meet or exceed this severity |
| `--quiet` | | Suppress all output, only set exit code (requires --fail-on) |

**Output Options:**

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--format <FORMAT>` | `-f` | `json` | Output format (table, json, csv) |
| `--output <FILE>` | `-o` | | Write results to file |

#### Container States

Common container states for `--state`:

- `running` - Currently executing containers
- `exited` - Stopped containers
- `paused` - Paused containers
- `restarting` - Containers in restart process
- `created` - Created but not started
- `dead` - Dead containers

#### Container Patterns

The `--container` option supports flexible pattern matching:

- **Full container ID**: `abc123def456...` (64 chars)
- **Short container ID**: `abc123` (12 chars or prefix)
- **Container name**: Exact or partial match
- **Case insensitive**: Patterns are lowercased

**Examples:**
```bash
# Match by exact name
--container nginx

# Match by partial name
--container web-  # Matches web-1, web-2, web-app

# Match by ID prefix
--container abc123

# Multiple containers
--container nginx,redis,postgres
```

#### Examples

```bash
# Basic scan
valeris scan
valeris s  # Using alias

# Filter by container
valeris scan --container nginx
valeris scan -c web-app,api

# Filter by state
valeris scan --state running
valeris scan --state running,paused

# Filter by severity
valeris scan --severity high
valeris scan --min-severity medium
valeris scan --severity medium,high

# Detector filtering
valeris scan --only exposed_ports,capabilities
valeris scan --exclude readonly_rootfs

# CI/CD integration
valeris scan --fail-on high
valeris scan --quiet --fail-on medium

# Combined filtering
valeris scan --state running --container nginx --min-severity high --fail-on high

# Export to file
valeris scan --format json --output findings.json
valeris scan --format csv --output report.csv
```

---

### docker-file

Scan Dockerfiles for build-time security issues (experimental).

```bash
valeris docker-file [OPTIONS] --path <PATH> --rules <PATH>
```

#### Options

| Option | Short | Required | Description |
|--------|-------|----------|-------------|
| `--path <PATH>` | `-p` | Yes | Path to Dockerfile to scan |
| `--rules <PATH>` | `-r` | Yes | Path to rules directory |
| `--format <FORMAT>` | `-f` | No | Output format (default: table) |
| `--output <FILE>` | `-o` | No | Write results to file |

#### Examples

```bash
# Basic scan
valeris docker-file --path ./Dockerfile --rules ./rules/dockerfile
valeris df -p ./Dockerfile -r ./rules/dockerfile  # Using alias

# Export to JSON
valeris docker-file -p ./Dockerfile -r ./rules/dockerfile -f json -o scan.json

# Table output (default)
valeris docker-file --path ./Dockerfile --rules ./rules/dockerfile --format table
```

---

### list-plugins

List all available security detection rules.

```bash
valeris list-plugins [OPTIONS]
```

#### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--target <TARGET>` | `-t` | Filter by target platform (docker, k8s, both) |

#### Examples

```bash
# List all detectors
valeris list-plugins
valeris ls  # Using alias

# Filter by target
valeris list-plugins --target docker
valeris ls -t docker
```

---

### config

Show configuration file location and status.

```bash
valeris config
```

Displays information about the configuration file including:
- Environment variable status (`VALERIS_CONFIG_FILE`)
- XDG config directory location and parse status
- Home directory config location
- Setup instructions

#### Examples

```bash
# Show config status
valeris config
valeris cfg  # Using alias
```

**Output example:**
```
Valeris Configuration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📁 XDG config location:
   /home/user/.config/valeris/config.toml
   Status: ✅ File exists
   Parse: ✅ Valid TOML
   - Contains [scan] configuration
   - Contains [output] configuration

💡 To create a config file:
   mkdir -p ~/.config/valeris
   cp valeris.toml.example ~/.config/valeris/config.toml
   vi ~/.config/valeris/config.toml
```

See also: [Configuration File](#configuration-file)

---

## Filtering

### Detector Filtering

Control which security rules run:

```bash
# Run ONLY specific detectors
valeris scan --only privileged_mode,capabilities,secrets_in_env

# EXCLUDE specific detectors
valeris scan --exclude readonly_rootfs,log_driver

# Cannot use both
valeris scan --only foo --exclude bar  # ERROR: conflict
```

**Use cases:**

- `--only`: Focus on specific security concerns (e.g., only privilege checks)
- `--exclude`: Skip noisy or irrelevant rules for your environment

**List available detectors:**
```bash
valeris list-plugins
```

### Container Filtering

Filter which containers to scan:

#### By State

```bash
# Single state
valeris scan --state running

# Multiple states
valeris scan --state running,paused,restarting
```

#### By Name or ID

```bash
# Exact name match
valeris scan --container nginx

# Partial name match
valeris scan -c web  # Matches web-1, web-app, webapp, etc.

# Multiple containers
valeris scan --container nginx,redis,postgres

# By container ID
valeris scan -c abc123def456
```

#### Combined Filtering

```bash
# Running nginx containers only
valeris scan --state running --container nginx

# Multiple filters with detector selection
valeris scan \
  --state running \
  --container web-app \
  --only exposed_ports,capabilities,root_user
```

### Severity Filtering

Control which findings to display based on severity levels:

```bash
# Show only high severity findings
valeris scan --severity high

# Show only medium and high severity
valeris scan --severity medium,high

# Show findings at or above medium severity
valeris scan --min-severity medium

# Cannot use both
valeris scan --severity high --min-severity medium  # ERROR: conflict
```

**Severity levels (in order):**
- `informative` - Informational findings
- `low` - Low risk issues
- `medium` - Medium risk issues
- `high` - High risk/critical issues

**Use cases:**
- `--severity`: Show exact severity levels (e.g., only high and medium)
- `--min-severity`: Show minimum threshold and above (e.g., medium+high)

**Examples:**
```bash
# Security audit - high risk only
valeris scan --state running --severity high

# Production scan - medium and above
valeris scan --min-severity medium --state running

# Development - exclude informational
valeris scan --min-severity low
```

### CI/CD Integration

Use exit codes to fail builds when security issues are found:

```bash
# Fail build if high severity findings exist
valeris scan --fail-on high

# Fail on medium or higher
valeris scan --fail-on medium

# Quiet mode - no output, only exit code
valeris scan --quiet --fail-on high

# Combined with filtering
valeris scan --state running --min-severity medium --fail-on high
```

**Exit codes:**
- `0` - Success (no findings at fail-on threshold)
- `1` - Failure (findings found at or above fail-on threshold)

**Use cases:**
- `--fail-on high`: Fail only on critical security issues
- `--fail-on medium`: Stricter security gate
- `--quiet --fail-on`: Script-friendly mode for CI/CD pipelines

**Pipeline example:**
```bash
#!/bin/bash
# Scan containers and fail on high severity
if ! valeris scan --quiet --fail-on high; then
  echo "Critical security issues found!"
  exit 1
fi
echo "Security scan passed"
```

---

## Output Formats

Valeris supports three output formats:

### Table (default for Dockerfile scans)

Human-readable colored table output:

```bash
valeris docker-file --path ./Dockerfile --rules ./rules/dockerfile
```

Features:
- Color-coded severity levels
- UTF-8 box drawing characters
- Line numbers for Dockerfile issues
- Terminal-optimized width

### JSON

Structured JSON for CI/CD integration:

```bash
valeris scan --format json --output findings.json
```

Features:
- Machine-readable
- Easy to parse with `jq`
- Complete finding metadata
- Suitable for automation

**Example output:**
```json
{
  "findings": [
    {
      "container_id": "abc123",
      "container_name": "nginx",
      "severity": "CRITICAL",
      "rule_id": "root_user",
      "description": "Container is running as root"
    }
  ]
}
```

### CSV

Comma-separated values for spreadsheet analysis:

```bash
valeris scan --format csv --output report.csv
```

Features:
- Import into Excel, Google Sheets
- Easy filtering and sorting
- Column-based analysis
- Audit reporting

---

## Examples

### Security Audit

Quick security check of production containers:

```bash
# Critical security issues only
valeris scan --only privileged_mode,capabilities,secrets_in_env,root_user

# Running containers only
valeris scan --state running --only privileged_mode,capabilities
```

### Development Workflow

Scan during development with reduced noise:

```bash
# Exclude low-priority rules
valeris scan --exclude readonly_rootfs,log_driver,no_healthcheck

# Focus on specific service
valeris scan --container api --state running
```

### CI/CD Integration

Automated scanning in pipelines:

```bash
# Export to JSON for processing
valeris scan --state running --format json --output scan-results.json

# Dockerfile validation
valeris docker-file --path Dockerfile --rules ./rules/dockerfile \
  --format json --output dockerfile-scan.json

# Check for critical issues
jq -e '.findings[] | select(.severity == "CRITICAL")' scan-results.json
```

### Compliance Reporting

Generate audit reports:

```bash
# Full scan with timestamp
valeris scan --format csv --output "audit-$(date +%Y%m%d-%H%M%S).csv"

# Running containers compliance
valeris scan --state running --format json --output compliance-report.json
```

### Targeted Scanning

Scan specific containers or container groups:

```bash
# All web servers
valeris scan --container web- --only exposed_ports,network_mode

# Database containers
valeris scan --container postgres,mysql,redis --only capabilities,mounts

# Specific container by ID
valeris scan -c abc123 --only privileged_mode,root_user
```

---

## Configuration File

Valeris supports persistent configuration via TOML files to avoid repeating common flags.

### Configuration File Locations

Valeris searches for configuration files in the following order:

1. **Environment variable**: `$VALERIS_CONFIG_FILE` (highest priority)
2. **XDG config directory**: `~/.config/valeris/config.toml`
3. **Home directory**: `~/.valeris.toml`

### Configuration Structure

Create a configuration file to set defaults:

```toml
[scan]
default_state = ["running"]
only = ["exposed_ports", "capabilities", "secrets_in_env"]
exclude = ["readonly_rootfs", "log_driver"]
ignore_containers = ["*-test", "*-temp"]
min_severity = "medium"
fail_on = "high"
quiet = false

[output]
format = "table"
colors = true
table_width = 100

[rules]
directory = "/opt/valeris/custom-rules"
auto_download = true

[docker]
timeout = 30
max_parallel = 10
host = "unix:///var/run/docker.sock"
```

### Checking Configuration

Use the `config` command to view your configuration status:

```bash
valeris config
```

### Configuration Precedence

**CLI arguments always override config file values.**

Example:
- Config file: `min_severity = "medium"`
- CLI: `valeris scan --min-severity low`
- Result: Uses `low` (CLI takes precedence)

This allows you to:
- Set sensible defaults in the config file
- Override specific values as needed on the command line
- Use different settings for different contexts

### Setup Instructions

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

---

## Environment Variables

Configure Valeris behavior with environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `VALERIS_CONFIG_FILE` | Override config file location | (see above) |
| `VALERIS_RULES_DIR` | Custom rules directory | `$XDG_DATA_HOME/valeris/detectors` |
| `RUST_LOG` | Logging level | `warn` |

**Examples:**

```bash
# Use custom config file
export VALERIS_CONFIG_FILE=/etc/valeris/config.toml
valeris scan

# Custom rules location
export VALERIS_RULES_DIR=/opt/valeris/custom-rules
valeris scan

# Debug logging
RUST_LOG=debug valeris scan

# Info-level logging
RUST_LOG=info valeris docker-file -p Dockerfile -r ./rules/dockerfile
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success - scan completed, no findings at fail-on threshold |
| `1` | Error - scan failed, invalid arguments, or findings met fail-on threshold |
| `2` | Invalid CLI usage |

**Note:** When using `--fail-on`, exit code `1` indicates findings at or above the specified severity were found.

**Examples:**
```bash
# Exit code 0 if no high severity findings
valeris scan --fail-on high
echo $?  # 0 = safe, 1 = critical issues found

# Use in scripts
if valeris scan --quiet --fail-on high; then
  echo "Passed security scan"
else
  echo "Failed security scan - check findings"
  exit 1
fi
```

---

## See Also

- [Quick Start Guide](guides/quick-start.md) - Get started quickly
- [Architecture Overview](architecture/overview.md) - Understand how Valeris works
- [CLAUDE.md](../CLAUDE.md) - Developer documentation
