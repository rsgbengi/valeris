# Configuration Guide

Complete guide to configuring Valeris using TOML configuration files.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Configuration File Locations](#configuration-file-locations)
- [Configuration Structure](#configuration-structure)
  - [Scan Configuration](#scan-configuration)
  - [Output Configuration](#output-configuration)
  - [Rules Configuration](#rules-configuration)
  - [Docker Configuration](#docker-configuration)
- [Configuration Precedence](#configuration-precedence)
- [Common Use Cases](#common-use-cases)
- [Validation](#validation)
- [Troubleshooting](#troubleshooting)

---

## Overview

Valeris supports persistent configuration via TOML files. This allows you to:

- **Set defaults** for common flags to avoid repetition
- **Standardize settings** across teams
- **Configure different environments** (development, staging, production)
- **Override config values** with CLI arguments when needed

**Key principle:** CLI arguments always override config file values.

---

## Quick Start

```bash
# 1. Create config directory
mkdir -p ~/.config/valeris

# 2. Copy example config
cp valeris.toml.example ~/.config/valeris/config.toml

# 3. Edit to your preferences
vi ~/.config/valeris/config.toml

# 4. Verify configuration
valeris config
```

---

## Configuration File Locations

Valeris searches for configuration files in the following order (first found wins):

1. **Environment variable**: `$VALERIS_CONFIG_FILE`
   ```bash
   export VALERIS_CONFIG_FILE=/etc/valeris/config.toml
   valeris scan
   ```

2. **XDG config directory**: `~/.config/valeris/config.toml`
   - Follows XDG Base Directory specification
   - Recommended location for user configs

3. **Home directory**: `~/.valeris.toml`
   - Fallback location
   - Hidden file in home directory

**Recommendation:** Use `~/.config/valeris/config.toml` for personal configuration.

---

## Configuration Structure

All configuration sections are optional. You can configure only what you need.

### Complete Example

```toml
# Scan defaults
[scan]
default_state = ["running"]
only = ["exposed_ports", "capabilities", "secrets_in_env"]
exclude = ["readonly_rootfs", "log_driver"]
ignore_containers = ["*-test", "*-temp"]
min_severity = "medium"
fail_on = "high"
quiet = false

# Output preferences
[output]
format = "table"
colors = true
table_width = 100

# Rules management
[rules]
directory = "/opt/valeris/custom-rules"
auto_download = true

# Docker connection
[docker]
timeout = 30
max_parallel = 10
host = "unix:///var/run/docker.sock"
```

---

## Scan Configuration

The `[scan]` section configures default scan behavior.

```toml
[scan]
default_state = ["running"]                           # Container states to scan
only = ["exposed_ports", "capabilities"]              # Run only these detectors
exclude = ["readonly_rootfs"]                         # Skip these detectors
ignore_containers = ["*-test", "tmp-*"]              # Skip containers matching patterns
min_severity = "medium"                               # Minimum severity to show
fail_on = "high"                                      # Exit code 1 threshold
quiet = false                                         # Suppress output
```

### Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `default_state` | `[string]` | Container states to scan | All states |
| `only` | `[string]` | Run only specified detectors | All detectors |
| `exclude` | `[string]` | Skip specified detectors | None |
| `ignore_containers` | `[string]` | Skip containers matching patterns | None |
| `min_severity` | `string` | Minimum severity threshold | None |
| `fail_on` | `string` | Exit code 1 threshold | None |
| `quiet` | `bool` | Suppress all output | `false` |

### Severity Levels

Valid severity values (in order):
- `"informative"` - Informational findings
- `"low"` - Low risk issues
- `"medium"` - Medium risk issues
- `"high"` - High risk/critical issues

### Container States

Valid state values:
- `"running"` - Currently executing containers
- `"exited"` - Stopped containers
- `"paused"` - Paused containers
- `"restarting"` - Containers in restart process
- `"created"` - Created but not started
- `"dead"` - Dead containers

### Examples

**Development environment:**
```toml
[scan]
default_state = ["running"]
exclude = ["readonly_rootfs", "log_driver", "no_healthcheck"]
min_severity = "low"
```

**Production environment:**
```toml
[scan]
default_state = ["running"]
min_severity = "medium"
fail_on = "high"
```

**CI/CD pipeline:**
```toml
[scan]
default_state = ["running"]
min_severity = "medium"
fail_on = "high"
quiet = true
```

**Security audit:**
```toml
[scan]
only = ["privileged_mode", "capabilities", "secrets_in_env", "root_user"]
min_severity = "high"
```

---

## Output Configuration

The `[output]` section configures output formatting.

```toml
[output]
format = "table"      # Output format: table, json, csv
colors = true         # Enable colored output
table_width = 100     # Table width in characters
```

### Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `format` | `string` | Output format | `"table"` |
| `colors` | `bool` | Enable colored output | `true` |
| `table_width` | `int` | Table width in characters | Auto-detect |

### Format Options

- `"table"` - Human-readable colored table
- `"json"` - JSON for CI/CD integration
- `"csv"` - CSV for spreadsheet analysis

**Note:** CLI `--format` flag requires `--output` flag and overrides this setting.

### Examples

**Terminal output:**
```toml
[output]
format = "table"
colors = true
table_width = 120
```

**CI/CD output:**
```toml
[output]
format = "json"
colors = false
```

**Reporting:**
```toml
[output]
format = "csv"
```

---

## Rules Configuration

The `[rules]` section configures rule management.

```toml
[rules]
directory = "/opt/valeris/custom-rules"    # Custom rules directory
auto_download = true                       # Auto-download default rules
```

### Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `directory` | `string` | Custom rules directory path | `$XDG_DATA_HOME/valeris/detectors` |
| `auto_download` | `bool` | Auto-download default rules | `true` |

### Examples

**Custom rules:**
```toml
[rules]
directory = "/opt/valeris/company-rules"
auto_download = false
```

**Default behavior:**
```toml
[rules]
# Use XDG data directory
# Auto-download rules if missing
```

---

## Docker Configuration

The `[docker]` section configures Docker connection settings.

```toml
[docker]
timeout = 30                                    # Timeout in seconds
max_parallel = 10                               # Max parallel scans
host = "unix:///var/run/docker.sock"           # Docker host
```

### Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `timeout` | `int` | Docker API timeout (seconds) | `30` |
| `max_parallel` | `int` | Max parallel container scans | `10` |
| `host` | `string` | Docker host connection | `unix:///var/run/docker.sock` |

### Examples

**Remote Docker:**
```toml
[docker]
host = "tcp://192.168.1.100:2375"
timeout = 60
```

**Local Docker with custom socket:**
```toml
[docker]
host = "unix:///custom/path/docker.sock"
```

**Performance tuning:**
```toml
[docker]
timeout = 60
max_parallel = 20
```

---

## Configuration Precedence

**CLI arguments always override config file values.**

### Precedence Order

1. **CLI arguments** (highest priority)
2. **Config file values**
3. **Hardcoded defaults** (lowest priority)

### Example

**Config file (`~/.config/valeris/config.toml`):**
```toml
[scan]
min_severity = "medium"
default_state = ["running"]
```

**CLI commands:**
```bash
# Uses min_severity="medium" from config
valeris scan

# Overrides with min_severity="low"
valeris scan --min-severity low

# Uses default_state=["running"] from config
valeris scan --min-severity low

# Overrides with state=["exited"]
valeris scan --state exited
```

### Merge Behavior

- **CLI value present**: CLI value used, config ignored
- **CLI value absent**: Config value used (if present)
- **Both absent**: Hardcoded default used

---

## Common Use Cases

### Team Standards

Share a config file across your team to enforce standards:

```toml
# team-valeris.toml
[scan]
default_state = ["running"]
min_severity = "medium"
fail_on = "high"
exclude = ["readonly_rootfs", "log_driver"]

[output]
format = "json"
colors = false
```

**Usage:**
```bash
export VALERIS_CONFIG_FILE=/etc/valeris/team-valeris.toml
valeris scan
```

### Development vs Production

**Development (`~/.config/valeris/config.toml`):**
```toml
[scan]
default_state = ["running"]
exclude = ["readonly_rootfs", "log_driver", "no_healthcheck"]
min_severity = "low"

[output]
colors = true
```

**Production (via environment variable):**
```bash
# Set in production environment
export VALERIS_CONFIG_FILE=/etc/valeris/prod-config.toml
```

**`/etc/valeris/prod-config.toml`:**
```toml
[scan]
default_state = ["running"]
min_severity = "medium"
fail_on = "high"

[output]
format = "json"
colors = false
```

### CI/CD Pipeline

**Config file:**
```toml
[scan]
default_state = ["running"]
min_severity = "medium"
fail_on = "high"
quiet = true
```

**Pipeline script:**
```bash
#!/bin/bash
# valeris already configured via config file
if ! valeris scan; then
  echo "Security scan failed!"
  exit 1
fi
```

### Multi-Environment Setup

**Base config (`~/.config/valeris/config.toml`):**
```toml
[scan]
exclude = ["log_driver", "readonly_rootfs"]

[output]
colors = true
```

**Override for specific environments:**
```bash
# Development - use base config
valeris scan

# Staging - override min_severity
valeris scan --min-severity medium

# Production - use production config
VALERIS_CONFIG_FILE=/etc/valeris/prod.toml valeris scan
```

---

## Validation

### Checking Configuration

Use the `config` command to validate your configuration:

```bash
valeris config
```

**Example output:**
```
Valeris Configuration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📁 XDG config location:
   /home/user/.config/valeris/config.toml
   Status: ✅ File exists
   Parse: ✅ Valid TOML
   - Contains [scan] configuration
   - Contains [output] configuration
```

### TOML Syntax Validation

Valeris validates TOML syntax when loading config files. Common errors:

**Missing quotes:**
```toml
# ❌ WRONG
min_severity = medium

# ✅ CORRECT
min_severity = "medium"
```

**Invalid array syntax:**
```toml
# ❌ WRONG
default_state = "running"

# ✅ CORRECT
default_state = ["running"]
```

**Mixed types:**
```toml
# ❌ WRONG
default_state = ["running", 1, true]

# ✅ CORRECT
default_state = ["running", "exited"]
```

### Testing Configuration

Test your config with verbose logging:

```bash
RUST_LOG=debug valeris scan
```

This shows:
- Which config file was loaded
- Which values came from config vs CLI
- How filters are being applied

---

## Troubleshooting

### Config File Not Found

**Problem:** Config file exists but Valeris doesn't find it.

**Solution:**
```bash
# Check file location
valeris config

# Verify file path
ls -la ~/.config/valeris/config.toml

# Use explicit path
export VALERIS_CONFIG_FILE=~/.config/valeris/config.toml
valeris scan
```

### Invalid TOML Syntax

**Problem:** Parse error when loading config.

**Solution:**
```bash
# Check TOML syntax
valeris config

# Common issues:
# - Missing quotes around strings
# - Invalid array syntax
# - Typos in section names
```

### Config Values Not Applied

**Problem:** Config values seem to be ignored.

**Cause:** CLI arguments override config values.

**Solution:**
```bash
# Remove CLI argument to use config value
# Instead of:
valeris scan --min-severity low  # Overrides config

# Use:
valeris scan  # Uses config value
```

### Permission Denied

**Problem:** Cannot read config file.

**Solution:**
```bash
# Fix permissions
chmod 644 ~/.config/valeris/config.toml

# Verify
ls -la ~/.config/valeris/config.toml
```

### Unknown Configuration Keys

**Problem:** Config file has typos or invalid keys.

**Valeris behavior:** Unknown keys are silently ignored.

**Solution:**
```bash
# Verify keys match documentation exactly
# Common typos:
# - "severity" instead of "min_severity"
# - "state" instead of "default_state"
# - "detector_only" instead of "only"
```

---

## See Also

- [CLI Reference](CLI.md) - Complete CLI documentation
- [Quick Start Guide](guides/quick-start.md) - Get started quickly
- [CI/CD Integration](CI-CD-INTEGRATION.md) - Pipeline integration guide
- [CLAUDE.md](../CLAUDE.md) - Developer documentation
