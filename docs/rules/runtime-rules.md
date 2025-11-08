# Docker Runtime Security Rules

This directory contains YAML rules for analyzing running Docker containers (runtime).

## 📋 Rule Categories

### 🔐 Container Security

#### Privileged Modes and Capabilities
- `privileged_mode` (HIGH) - Detects privileged mode enabled
- `capabilities` (HIGH) - Dangerous capabilities: SYS_ADMIN, NET_ADMIN, SYS_MODULE, SYS_PTRACE
- `no_new_privileges` (MEDIUM) - No-new-privileges not configured (allows privilege escalation)

#### Security Profiles
- `seccomp_unconfined` (HIGH) - Seccomp disabled (no syscall filtering)
- `apparmor` (MEDIUM) - AppArmor disabled or unconfined
- `security_options` (MEDIUM) - Security options not configured

#### Linux Security Modules
- `user_namespace` (MEDIUM) - User namespaces not enabled (UID/GID remapping)

### 🗂️ Filesystem and Mounts

#### Sensitive Mounts
- `mounts` (HIGH) - Mounting sensitive paths: /var/run/docker.sock, /proc, /sys, /etc, /root
- `writable_sensitive_mounts` (CRITICAL) - Writable mounts of /etc, /boot, /lib, /usr
- `mount_propagation` (HIGH) - Dangerous propagation: shared, rshared, slave, rslave

#### Filesystem
- `readonly_rootfs` (MEDIUM) - Root filesystem not read-only
- `tmpfs_exec` (MEDIUM) - tmpfs without noexec flag (allows execution from memory)

### 🌐 Network Configuration

#### Network Modes
- `network_mode` (MEDIUM) - Host network mode (no isolation)
- `legacy_links` (LOW) - Using deprecated --link (use user-defined networks)

#### Port Exposure
- `exposed_ports` (MEDIUM) - Sensitive ports exposed: 22 (SSH), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), etc.
- `port_all_interfaces` (MEDIUM) - Ports bound to 0.0.0.0 (all interfaces)

#### DNS and Resolution
- `custom_dns` (LOW) - Custom DNS servers (possible exfiltration)
- `extra_hosts` (INFO) - Custom entries in /etc/hosts

### 🔧 Namespaces and Isolation

- `ipc_mode` (MEDIUM) - IPC host mode (no IPC isolation)
- `pid_mode` (MEDIUM) - PID host mode (can see all processes)
- `uts_mode` (MEDIUM) - UTS host mode (shares hostname/domain)

### 📊 Resources and Limits

#### Resource Limits
- `resource_cpu_limit` (LOW) - No CPU limits
- `resource_memory_limit` (LOW) - No memory limits
- `pid_limits` (LOW) - No PID limits (fork bombs)

#### CGroups
- `cgroup_parent` (LOW) - Custom CGroup parent (can evade limits)

### 👤 Users and Permissions

- `root_user` (HIGH) - Root user (UID 0)

### 🔑 Secrets and Configuration

- `secrets_in_env` (CRITICAL) - Hardcoded secrets in environment variables (PASSWORD, SECRET, TOKEN, API_KEY)

### 🔄 Restart Policies

- `restart_policy` (LOW) - Always restart without health check (can hide failures)

### 📝 Logging and Monitoring

- `log_driver` (LOW) - Local logging (json-file) instead of centralized
- `log_no_limit` (MEDIUM) - No log limits (disk space risk)
- `no_healthcheck` (INFO) - No HEALTHCHECK configured

### 🖼️ Images and Versions

- `latest_tag` (MEDIUM) - Using 'latest' tag (non-deterministic)
- `image_no_digest` (INFO) - Image without SHA256 digest
- `old_image` (LOW) - Potentially outdated image (>90 days)

### ⚙️ Advanced Configuration

- `device_access` (HIGH) - Host device access (/dev/*)
- `sysctls` (HIGH) - Kernel parameter modification via sysctl

## 📊 Distribution by Severity

- **CRITICAL**: 2 rules (secrets, writable sensitive mounts)
- **HIGH**: 9 rules (privileged, capabilities, seccomp, devices, sysctls, mounts)
- **MEDIUM**: 12 rules (network, security profiles, logs, images)
- **LOW**: 8 rules (resources, restart, DNS, links)
- **INFO**: 3 rules (healthcheck, digest, hosts)

**Total: 36 rules** (17 existing + 19 new)

## 🎯 New Rules Added

### Mounts (3 rules)
- `mount_propagation` - Dangerous mount propagation
- `writable_sensitive_mounts` - Writing to /etc, /boot, /lib
- `tmpfs_exec` - tmpfs without noexec

### Network (4 rules)
- `port_all_interfaces` - Ports on 0.0.0.0
- `dns_settings` - Custom DNS
- `extra_hosts` - Custom /etc/hosts
- `network_links` - Deprecated links

### Logging (3 rules)
- `log_driver` - No centralized logging
- `log_size_limit` - No log limits
- `healthcheck` - No health check

### Images (3 rules)
- `image_tag` - 'latest' tag
- `image_no_digest` - No digest
- `outdated_image` - Old image

### Runtime Security (6 rules)
- `apparmor` - AppArmor disabled
- `seccomp` - Seccomp unconfined
- `no_new_privileges` - Allows escalation
- `cgroup_parent` - Custom CGroup
- `device_access` - Device access
- `sysctls` - Dangerous sysctls

## 🚀 Usage

```bash
# Scan all containers
cargo run -- scan

# Scan only running containers
cargo run -- scan --state running

# Use only specific rules
cargo run -- scan --only privileged_mode,capabilities

# Exclude specific rules
cargo run -- scan --exclude readonly_rootfs

# Export to JSON
cargo run -- scan --format json --output results.json
```

## 📝 JSONPath Examples

Rules use JSONPath to extract data from the Docker inspect API:

```yaml
# Detect dangerous capabilities
jsonpath: "$.HostConfig.CapAdd[*]"
regex: "SYS_ADMIN|ALL|NET_ADMIN"

# Combine multiple fields
parts:
  - jsonpath: "$.Mounts[*].Source"
  - jsonpath: "$.Mounts[*].RW"
separator: ":"
regex: "^/etc:true$"

# Check for missing fields
jsonpath: "$.Config.Healthcheck"
missing: true
```

## 🔍 Container JSON Structure

Rules inspect the response from `docker inspect`:

```json
{
  "Id": "abc123...",
  "Config": {
    "Image": "nginx:latest",
    "User": "root",
    "Env": ["PASSWORD=secret"],
    "Healthcheck": {...}
  },
  "HostConfig": {
    "Privileged": false,
    "CapAdd": ["NET_ADMIN"],
    "SecurityOpt": ["seccomp=unconfined"],
    "Mounts": [...],
    "NetworkMode": "host",
    "PidMode": "host"
  },
  "Mounts": [
    {
      "Source": "/var/run/docker.sock",
      "Destination": "/var/run/docker.sock",
      "RW": true
    }
  ]
}
```

## 📚 References

- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Docker Inspect API](https://docs.docker.com/engine/api/v1.43/#tag/Container/operation/ContainerInspect)
